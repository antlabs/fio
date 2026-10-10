// Copyright 2023-2024 antlabs. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package engine

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// 事件移交（worker 池）。
//
// 默认开（worker 数 defEventWorkers），WithEventWorkers 传负数关掉、
// 传正数换数量。开了之后事件循环只做"收 epoll 事件 + 投递"，连接的
// 读写解析跑在一组 worker 上（按 fd 取模分片）。
//
// **为什么要有这条路**：一个循环一个 goroutine 时，循环就是这条路上唯一
// 的服务者——它一忙（正在读另一条连接的 socket、跑用户回调），它名下
// 所有连接的事件都得等；而循环排空的瞬间又要 park 到 runtime 的
// netpoller 上等下一次事件，那一次唤醒又是几微秒（实测 10 连接 1KB
// echo：每个事件都 park 时平均 RTT 16.1µs，worker 自旋接任务那条路
// 10.1µs）。worker 池把"服务者"从"CPU 数"加到 1.5 倍左右，而且 worker
// 等任务是在自己的环上自旋/睡，不走 netpoll。
//
// 迁移前那套 websocket（quickws）就是这个模型：3 个 event loop + 20 个
// "解析 goroutine"，同一台机器上 1KB echo 比单栈模型快几个百分点。
//
// 分片规则是 fd % len(nodes)：一条连接固定落到一个 worker 上，它的状态
// （读缓冲区、解析状态机）仍然只被一个 goroutine 碰。busy 位继续兜底：
// 真撞上了（比如循环那条 EOF 路）就把事件记进 pending 位。

// defEventWorkers 是没显式指定 worker 数时用几个。
//
// 和迁移前那套一样: NumCPU * 5/3。解析/读写这些活有相当一部分时间在等
// socket 和等内核(读写系统调用), 不是一直在算, 所以要超订才喂得满核;
// 超订多少是实测出来的——12 核上跑 1KB echo, 每核 5/3 个(12 核 -> 20 个)
// 比每核一个高 24%, 再多收益就回去了。
func defEventWorkers() int {
	return max(int(float64(runtime.NumCPU())*5.0/3.0+0.5), 1)
}

// taskRingSize 是每个 worker 的队列长度。
//
// 装单个任务，所以这个值就是"能积压多少个连接"。1024 倍于一次
// epoll_wait 能拿的事件数（maxEventNum 是 256），够吸收突发。
//
// **不能开大**：环是 make 出来的，一格 32 字节（seq + 任务），
// 20 个 worker 每个 8192 格就是 5MB 常驻（实测 echo 内存 56M -> 61M，
// 比不开池子还高）。1024 格 -> 640KB。
const taskRingSize = 1024

// task 是"某条连接有一轮事件要处理"。
type task struct {
	c       *Conn
	isRead  bool
	isWrite bool
}

// taskNode 是一个 worker 和它的队列。
type taskNode struct {
	ring *taskRing

	// waiting 是"这个 worker 在睡着"。投递方看到 >0 才去 wake——忙的
	// 时候不白投一次 channel。
	waiting atomic.Int32

	// notify 是唤醒用的信号量，传空结构体不搬数据（数据走 ring）。
	// 容量 1：一个 worker 只需要一个信号。
	notify chan struct{}

	// done 关闭后 worker 退出（Free 时关）。
	done chan struct{}

	// blocked 是环满的次数，诊断用。
	blocked int64
}

type taskPool struct {
	nodes []*taskNode
}

func newTaskPool(n int) *taskPool {
	if n <= 0 {
		return nil
	}
	p := &taskPool{nodes: make([]*taskNode, n)}
	for i := range p.nodes {
		p.nodes[i] = &taskNode{
			ring:   newTaskRing(taskRingSize),
			notify: make(chan struct{}, 1),
			done:   make(chan struct{}),
		}
	}
	return p
}

// start 起所有 worker。**要先于事件的到来**（Start 里先起 worker 再起
// 循环），不然第一批事件投进来时环没人取，要等 worker 起来才动。
func (p *taskPool) start() {
	var wg sync.WaitGroup
	for _, n := range p.nodes {
		wg.Add(1)
		go func(n *taskNode) {
			wg.Done()
			n.run()
		}(n)
	}
	wg.Wait()
}

// stop 让所有 worker 退出。Free 调，幂等由 Free 自己保证。
func (p *taskPool) stop() {
	for _, n := range p.nodes {
		close(n.done)
	}
}

// nodeFor 取一条连接归属的 worker。
func (p *taskPool) nodeFor(fd int) *taskNode {
	return p.nodes[uint64(fd)%uint64(len(p.nodes))]
}

func (n *taskNode) run() {
	for {
		// 先把环上排着的取干净
		for {
			t, ok := n.ring.pop()
			if !ok {
				break
			}
			// fnet 那套"逐跳唤醒"：环里还有活就先叫一个 worker 来接，
			// 再处理手上这个——手上这个可能要等 socket（EAGAIN 重试）
			// 或者用户回调做了重活，后面的任务不必陪它等。积压会沿着
			// worker 链一路传开，不需要中心调度点。
			if n.ring.len() > 0 {
				n.notifyIfIdle()
			}
			n.processOne(t)
		}

		// 环空了。去睡之前先把 waiting 置上再看一眼：投递方在这之后
		// wake 我们的话，那次信号会落在下面的接收上，不会丢。
		n.waiting.Add(1)
		if n.ring.len() > 0 {
			n.waiting.Add(-1)
			continue
		}
		select {
		case <-n.notify:
			n.waiting.Add(-1)
		case <-n.done:
			return
		}
	}
}

// push 投一个任务。**只有事件循环的 goroutine 调它**（每条连接的
// owner 分片固定，所以每条连接只有一个生产者）。
func (n *taskNode) push(t task) {
	if n.ring.push(t) {
		n.wakeIfWaiting()
		return
	}
	// 环满了：自旋等消费者腾位置。
	//
	// 本来不该走到这里——环按 taskRingSize 开，那个值要能装下几轮的
	// 积压。走到这里说明 worker 跟不上，那事件循环只能等，它上面的
	// 连接一起等（和迁移前那套一样）。
	atomic.AddInt64(&n.blocked, 1)
	for !n.ring.push(t) {
		runtime.Gosched()
	}
	n.wakeIfWaiting()
}

// wakeIfWaiting 有 worker 睡着就发一个信号。
func (n *taskNode) wakeIfWaiting() {
	if n.waiting.Load() == 0 {
		return
	}
	select {
	case n.notify <- struct{}{}:
	default:
	}
}

// notifyIfIdle 和 wakeIfWaiting 是一回事，名字区分调用点（逐跳唤醒）。
func (n *taskNode) notifyIfIdle() { n.wakeIfWaiting() }

// processOne 处理一条连接的一轮：读、喂给协议、写。
func (n *taskNode) processOne(t task) {
	c := t.c
	if !c.tryBusy() {
		// 别人正在处理这条连接（循环那条 EOF 路、或者上一轮还没跑完）：
		// 把事件记进 pending 位，处理完的那个会取走（见 processConn 的
		// 循环）。fd 固定分片，正常情况下这里不会撞上。
		if t.isRead {
			c.setPendingRead()
		}
		if t.isWrite {
			c.setPendingWrite()
		}
		return
	}
	// processConn 自己持有 busy，跑完负责 unbusy。
	c.parent.processConn(c, t.isRead, t.isWrite)
}
