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
	"io"
	"sync"
)

// 批量事件移交（Worker 模式的默认实现）。
//
// 旧 taskPool 是"一个事件一个任务"：event loop 每拿到一个就绪 fd 就 push
// 一次、必要时唤醒一次 worker。这样每条消息都有一次跨 goroutine 交接，
// 而且 worker 的 fd 分片只看 fd%workers，和 event loop 的连接分片无关。
// 实测 2 核上每消息多 2~3µs，Echo 从 700k 掉到 290k。
//
// 这里换成"一轮 epoll 事件 = 一个批次"：
//
//	event loop: epoll_wait 返回一批就绪 fd
//	            → 把这批 (fd, 可读/可写/EOF) 攒成一个 batch
//	            → 整批交给这个 loop 对应的 worker（一次 channel send）
//	worker:     按 batch 里的顺序处理，处理完把 batch 还给池子
//
// 一个 batch 里的连接都属于同一个 loop，也就是同一个小的 fd 分片
// （默认 384 个 loop，10k 连接时每个 loop 约 26 条），worker 处理这一批
// 时碰的连接状态是集中的，cache 局部性接近内联模式；跨 goroutine 的唤醒
// 从"每消息一次"降到"每批一次"。
//
// 所有任务仍然按 loop 固定投给同一个 worker（worker = loopIndex%workers），
// 所以同一条连接的事件顺序不变，OnOpen 也一定和它的数据落在同一个 worker 上。

// batchTask 是批次里的一个事件。只记 fd 和状态，不碰连接对象——连接对象
// 的查找和协议状态都留给 worker，event loop 保持只做 epoll/分发。
type batchTask struct {
	fd      int
	isRead  bool
	isWrite bool
	eof     bool
}

// taskBatch 是一批事件。el 是产生它的 event loop。
type taskBatch struct {
	el    *EventLoop
	tasks []batchTask
}

type batchWorker struct {
	ch   chan *taskBatch
	done chan struct{}
	p    *batchPool
}

type batchPool struct {
	workers []*batchWorker
	free    sync.Pool
}

func newBatchPool(n int) *batchPool {
	// n 是目标 worker 总数；每个 shard 上常驻 batchWorkersPerShard 个，
	// 所以 shard 数 = n/2。n=2 -> 1 个 shard、2 个 worker；n=12 -> 6 个
	// shard、12 个 worker。2 核时所有批次进一个 shard，两个 worker 抢着
	// 处理，避免某些 shard 空闲、某些排队。
	shards := n / batchWorkersPerShard
	if shards < 1 {
		shards = 1
	}
	p := &batchPool{}
	p.free.New = func() any {
		return &taskBatch{tasks: make([]batchTask, 0, 64)}
	}
	p.workers = make([]*batchWorker, shards)
	for i := range p.workers {
		p.workers[i] = &batchWorker{
			ch:   make(chan *taskBatch, 1024),
			done: make(chan struct{}),
			p:    p,
		}
	}
	return p
}

// batchWorkersPerShard 是每个 shard 上常驻的 worker 数。
//
// 一个 loop 的批次固定投到一个 shard；shard 里多个 worker 抢同一个
// channel，某个 worker 忙时别的还能接这个 loop 的下一批，避免
// "一个 loop 的批次排在一个 worker 后面"的队头阻塞。
const batchWorkersPerShard = 2

func (p *batchPool) start() {
	for _, w := range p.workers {
		for i := 0; i < batchWorkersPerShard; i++ {
			go w.run()
		}
	}
}

func (p *batchPool) stop() {
	for _, w := range p.workers {
		close(w.done)
	}
}

// workerForLoop 让一个 loop 的所有批次固定落到一个 worker 上。
func (p *batchPool) workerForLoop(loop int) *batchWorker {
	return p.workers[loop%len(p.workers)]
}

func (p *batchPool) getBatch(el *EventLoop) *taskBatch {
	b := p.free.Get().(*taskBatch)
	b.el = el
	b.tasks = b.tasks[:0]
	return b
}

func (p *batchPool) putBatch(b *taskBatch) {
	b.el = nil
	b.tasks = b.tasks[:0]
	p.free.Put(b)
}

func (w *batchWorker) run() {
	for {
		select {
		case b := <-w.ch:
			el := b.el
			for i := range b.tasks {
				w.processOne(el, b.tasks[i])
			}
			w.p.putBatch(b)
		case <-w.done:
			return
		}
	}
}

// processOne 和旧 taskNode.processOne 的语义一致：OnOpen/读/解析/回调/写
// 都在 worker 上执行，busy/pending 位保证同一条连接不会被并发处理。
func (w *batchWorker) processOne(el *EventLoop, t batchTask) {
	c := el.parent.getConn(t.fd)
	if c == nil {
		return
	}

	if t.eof {
		if !c.tryBusy() {
			if t.isRead {
				c.setPendingRead()
			}
			if t.isWrite {
				c.setPendingWrite()
			}
			return
		}
		defer c.unbusy()
		el.activateBusy(c)
		if c.IsClosed() {
			return
		}
		_ = el.readAndDispatch(c)
		c.closeWith(io.EOF)
		return
	}

	if !c.tryBusy() {
		if t.isRead {
			c.setPendingRead()
		}
		if t.isWrite {
			c.setPendingWrite()
		}
		return
	}
	// processConn 自己持有 busy，跑完负责 unbusy。
	el.processConn(c, t.isRead, t.isWrite)
}
