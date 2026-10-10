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

//go:build linux || darwin || netbsd || freebsd || openbsd || dragonfly

package engine

import (
	"errors"
	"io"
	"log/slog"

	"github.com/antlabs/pulse/core"
	"golang.org/x/sys/unix"
)

// EventLoop 是一个 epoll/kqueue 事件循环。
//
// 一个循环被一个 goroutine 跑（Loop），负责把 fd 上的事件翻译成对 Handler
// 的调用。注册的 fd 用 ET（边缘触发）——这是 pulse 的默认，也是这套东西
// 快的原因：一次边缘把数据读干净，不用反复问内核"还有没有"。
type EventLoop struct {
	core.PollingApi

	// tasks 是"要在这个循环的 goroutine 上跑"的函数（见 runOnLoop）
	tasks chan func()

	parent *MultiEventLoop

	// wakeR/wakeW 是自唤醒管道，见 wake.go
	wakeR, wakeW int

	// maxEventNum 是一次 epoll_wait 最多拿多少事件。
	maxEventNum int

	log *slog.Logger
}

// Loop 跑事件循环，直到 Free。
func (el *EventLoop) Loop() {
	// WaitGroup 的 Add 在 Start 里做（Add 要先于 Wait），这里只负责 Done
	defer el.parent.loopsWg.Done()

	for {
		if el.parent.isFreed() {
			return
		}
		// 先把投过来的任务跑掉（比如新连接的 OnOpen）。
		//
		// 放在 Poll **之前**：OnOpen 要在该连接的任何数据之前跑（协议
		// 靠它初始化状态）。投递方（Add）保证任务先入队，这里保证它先
		// 于 Poll 返回的事件被处理。
		for {
			select {
			case f := <-el.tasks:
				f()
				continue
			default:
			}
			break
		}
		// **超时必须是"永久等"（-1），不能是 100ms 这种小超时**。
		//
		// pulse 按超时选等待方式（见它 waiter_linux.go 的 parkAbove）：永久
		// 等 → park 在 runtime 的 poller 上，一瞬间就把 P 交出去；而
		// (0, 1s) 区间里的小超时 → 走 RawSyscall6 版的 epoll_wait，
		// **RawSyscall 不通知 runtime**，于是这个 goroutine 抱着 P 睡满整个
		// 超时，runtime 要等 sysmon 一个 tick 才能把 P 抢走。
		//
		// 代价实测（Linux，24 核）：单测里每轮泄漏一个 24 loop 的
		// MultiEventLoop，几轮之后 24 个 P 全被睡着的循环占住，同进程里
		// 一个 loopback 的 net.Dial 要等 95ms+，握手失败那一组用例集体超时
		// （基线用永久等，0.26s 跑完，迁移后 4.08s）。
		//
		// Free 的停止不靠超时：它往唤醒管道写一个字节（见 wake.go），
		// epoll fd 立刻可读，park 着的循环马上就醒。
		_, err := el.Poll(-1, func(fd int, state core.State, err error) {
			// io.EOF 不是"出错"，是"对端关了"。kqueue 那边尤其要紧：
			// 对端发 FIN 时它回调的是 cb(fd, WRITE, io.EOF)——状态是
			// WRITE 不是 READ，错误位带着 io.EOF。早先把 io.EOF 当成
			// 普通错误记一行日志就 return 了，OnClose 永远不会调
			// （实测：客户端发几个字节再 close，服务端一点反应都没有）。
			eof := errors.Is(err, io.EOF)
			if err != nil && !eof {
				if errors.Is(err, core.EAGAIN) {
					return
				}
				el.parent.err("apiPoll", "err", err.Error())
				return
			}

			// 唤醒管道：投过来的任务在队列里等着，循环得先醒过来。
			if fd == el.wakeR {
				el.drainWake()
				return
			}

			el.addPollEvNum(1)

			c := el.parent.getConn(fd)
			if c == nil {
				// 连接已经关了（epoll 里可能还有一个待处理的事件）
				return
			}

			if eof {
				// **必须先读**：kqueue 会把"对端最后一段数据 + FIN"合并成
				// 一个事件报过来（而且状态是 WRITE，不是 READ），这时候
				// 还没有任何人调过 Read()，ReadBuffer() 是空的——但内核
				// 缓冲区里躺着对端最后发的那段数据，直接 close 就一起丢了。
				//
				// 实测：TLS 场景下内层协议发的 "ping"（以及回显）都在 FIN
				// 前面一点点到，对端 write+close 几乎同时，这边 OnData 就
				// 永远不调——一个字节都收不到。而对端把 close 推迟 50ms 就
				// "好了"（那 50ms 让数据单独成了一个可读事件）。
				//
				// **先补 activation**：连接可能刚 Add 进来，Add 投的
				// OnOpen 任务还没轮到，而 FIN 已经到了（客户端连上就
				// close）。不激活就跑 OnData 就是和 OnOpen 抢。
				el.activate(c) // 幂等：已经激活过就直接返回
				if c.IsClosed() {
					return
				}

				// **这条路也要占 busy**：读的时候手上捏着读缓冲区（喂给
				// 协议的那段就是它的别名），而 closeWith 只在"没人在处理
				// 这条连接"时才当场释放缓冲区（见 flagFreePending）。
				// 不占的话，别的 goroutine 一句 Close() 就能把缓冲区从
				// 脚下抽走（-race 实测：用户 goroutine 的 Close 和这里的
				// ReadBuffer 抢 rbuf）。
				//
				// 同一条连接的事件不会并发到达，所以这里一定拿得到；
				// 真拿不到（不该发生）也**不能**空手去读——直接关掉。
				if !c.tryBusy() {
					c.closeWith(io.EOF)
					return
				}
				// readAndDispatch 返回的 io.EOF 不用管：下面就 closeWith(io.EOF)，
				// 这里只是要把最后的数据喂给协议、让它把该处理的处理完。
				_ = el.readAndDispatch(c)
				c.closeWith(io.EOF)
				c.unbusy()
				return
			}

			// 一个连接同时只有一个人在处理。处理期间又来的事件记在
			// pending 位上，处理完的那个取走再跑一轮——ET 的边缘只来
			// 一次，丢了就再也没有通知，连接会卡住。
			if !c.tryBusy() {
				if state.IsRead() {
					c.setPendingRead()
				}
				if state.IsWrite() {
					c.setPendingWrite()
				}
				return
			}

			el.processConn(c, state.IsRead(), state.IsWrite())
		})
		if err != nil {
			el.parent.err("apiPoll", "err", err.Error())
			return
		}
	}
}

// processConn 处理一个连接的一轮：读、喂给协议、写。
//
// 循环而不是递归：同一个连接连续有事件时（请求-响应就是这种），就地接着
// 跑省掉一次完整的投递和唤醒，也保证同一个连接还是串行的。
func (el *EventLoop) processConn(c *Conn, isRead, isWrite bool) {
	defer c.unbusy()

	for {
		if c.IsClosed() {
			return
		}
		// OnOpen 还没跑（Add 投的任务还排在队列里）就先把 OnOpen 补上。
		//
		// **不把事件记成 pending 等任务**：那个任务可能排在队列很后面
		// （比如一批新连接一起进来的 connect 风暴），而 epoll 的边缘只
		// 来一次——等着等着就没有下一次通知了。这里本来就是事件循环的
		// goroutine，和那个任务是同一个执行者，直接跑掉最省事。
		//
		// 这条路径实测撞到过：Add 返回后立刻有数据的连接（客户端连上
		// 就发）在 -race 下必报 http2.ConnHandler.conn 的竞争。
		el.activate(c) // 幂等
		if c.IsClosed() {
			return
		}
		if isWrite {
			el.addWriteEvNum()
			// 一次拿锁搞定"看有没有积压 + 有就 flush"，见 FlushIfNeeded。
			if err := c.FlushIfNeeded(); err != nil {
				c.closeWith(err)
				return
			}
		}
		if isRead {
			el.addReadEvNum()
			err := el.readAndDispatch(c)
			if err != nil {
				c.closeWith(err)
				return
			}
		}

		// 处理期间又到的那些事件
		isRead = c.takePendingRead()
		isWrite = c.takePendingWrite()
		if !isRead && !isWrite {
			return
		}
	}
}

// readAndDispatch 读一次，把数据喂给协议的 OnData。
//
// 协议返回消化了多少，引擎调 ConsumeRead；返回 0 表示"还不够凑一条报文"，
// 数据留在缓冲区里，下次读到再喂——这不是错误。
func (el *EventLoop) readAndDispatch(c *Conn) error {
	_, readErr := c.Read()

	// 读到的东西全部喂给协议，直到协议不再消费。
	// 注意要先喂再处理 readErr：FIN 到的时候缓冲区里可能还有数据
	// （Read 里"先让协议消费完"那条契约），先把它们交出去。
	for {
		buf := c.ReadBuffer()
		if len(buf) == 0 {
			break
		}
		n, err := c.handler.OnData(c, buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			// 协议说这段还不够，等下次读
			break
		}
		c.ConsumeRead(n)
		if n < len(buf) {
			// 协议没吃完这一整段，说明它自己知道后面还有（一条报文
			// 结束、后面那条不完整），交给下一次事件
			break
		}
	}

	// 轮末把"长过的"读缓冲区还回池子（起始那一档留着，见 ReleaseReadBuf）。
	// 不还的话连接会在"两批之间"攥着它——10000 连接的 Pipeline 负载下
	// 就是每连接 15KB 常驻（实测堆上 180MB）。
	c.ReleaseReadBuf()

	// 读出错（含对端关了）：缓冲区已经空了，可以把错误交给上层了
	if readErr != nil {
		return readErr
	}
	return nil
}

// runOnLoop 把一个函数丢到事件循环的 goroutine 上跑。
//
// 用在哪：Add 是调用方（accept 循环）的 goroutine 上跑的，但连接的状态
// 之后只被事件循环碰。所以 OnOpen 要挪过去，不然两边一写一读就是竞争。
//
// **必须是"一定在事件循环的 goroutine 上"**，不能有"队列满就退回同步
// 调"这种降级：那会让协议的状态在两个 goroutine 上被碰，正是要避免的
// 事。队列满（很少见，容量远大于正常的注册速率）就阻塞等，语义不变。
//
// 缓冲开得大（4096）：投递方是 accept 循环，瞬时可能有一批新连接
// （压测里的 connect 风暴），缓冲小了会把 accept 卡在这儿。真满了就
// 等一下——反正只有"注册"走这条路，不是数据路径。
func (el *EventLoop) runOnLoop(f func()) {
	el.tasks <- f
	// 不叫这一声，任务要等 Poll 超时才轮到（见 wake.go）
	el.wake()
}

// del 把连接从连接表里摘掉。**用调用方传进来的 fd**，不要从连接上读
// ——closeWith 在调这里之前已经把 c.fd 置成 -1 了，读回来的是 -1，
// delConn 直接早退：连接永远留在表里、curConn 只增不减、连接对象也
// 永远回不到池子（实测：跑一轮 autobahn，curConn 涨到 2708 不掉）。
func (el *EventLoop) del(fd int) {
	el.parent.delConn(fd)
}

// addWrite 让 fd 的可写事件再触发一次。
//
// **不能是空操作**——这是踩过的一个大坑。
//
// 注册的时候确实带了 EPOLLOUT（见 pulse 的 etAddRead），所以"第一次
// 变可写"会有事件。但 **ET 只在状态变化时报一次**：写缓冲里有数据要发
// 的时候，socket 通常**本来就是可写的**（没人灌满它），这时候内核不会
// 产生新的边缘——事件永远不来，数据就永远躺在 wbufList 里。
//
// 症状是随机性的、极难查：h2spec 的 TLS 模式十次里挂一两次，每次挂的
// 用例都不一样（缓存的 GOAWAY 有时发得出去、有时发不出去），而明文
// 模式几乎不挂（少一层加密，写入的时机不同）。
//
// 修法：用 EPOLL_CTL_MOD 重新注册一次（pulse 的 ResetRead 干的就是
// 这个）——**MOD 会重新触发一次边缘**，哪怕 fd 一直是可写的。
func (el *EventLoop) addWrite(c *Conn) error {
	return el.PollingApi.ResetRead(c.Fd())
}

// AddRead 给一条连接注册读事件。
func (el *EventLoop) AddRead(c *Conn) error {
	return el.PollingApi.AddRead(c.Fd())
}

// DelRead 取消读事件。
func (el *EventLoop) DelRead(c *Conn) error {
	return el.PollingApi.DelRead(c.Fd())
}

func closeFd(fd int) error {
	return unix.Close(fd)
}

// 让这些包被引用（别的构建组合和日志用得到）
