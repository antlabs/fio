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
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/antlabs/pulse/core"
)

// MultiEventLoop 是一组事件循环，连接按 fd 分片挂到其中一个上。
//
// 分片规则是 fd % len(loops)：同一个连接永远落在同一个循环上，所以它的
// 状态（读缓冲区、写缓冲、协议自己的状态机）只被那一个 goroutine 碰，
// 不用加锁。这是整套东西能快起来的根本。
type MultiEventLoop struct {
	loops []*EventLoop
	log   *slog.Logger

	// 连接表。分片加锁，见 pulse 的 SafeConns。
	conns core.SafeConns[Conn]

	numLoops    int
	maxEventNum int

	freed   int32
	started int32
	loopsWg sync.WaitGroup
	curConn int64

	// pool 是事件移交用的 worker 池（WithEventWorkers 开了才有），
	// 见 worker.go。
	pool *taskPool
}

// Options
type options struct {
	numLoops    int
	maxEventNum int
	level       slog.Level
	// eventWorkers > 0 时开启事件移交（worker 池），见 worker.go。
	eventWorkers int
}

// Option 配 MultiEventLoop。
type Option func(*options)

// WithEventLoops 起几个事件循环。0 表示每个 CPU 一个。
//
// 不是越多越好：循环之间要抢 CPU，连接分片多了以后每个循环上的连接就少，
// 缓存局部性反而差。实测（12 核 / 10000 连接 / 1KB echo）循环数从 1 到 24
// 都试过，差别在噪声里。
func WithEventLoops(n int) Option {
	return func(o *options) { o.numLoops = n }
}

// WithEventWorkers 让事件循环只做分发，连接的读写解析交给 n 个 worker
// goroutine（按 fd 取模分片）。0（默认）表示不开，事件就地处理。
//
// 见 worker.go 开头那段：循环既是唯一的服务者、又是唯一的等待者，
// 交出去一部分能把"每个事件都要 park 一次"和"服务者只有 CPU 数那么多"
// 这两件事都松开。
func WithEventWorkers(n int) Option {
	return func(o *options) { o.eventWorkers = n }
}

// WithMaxEventNum 一次 epoll_wait 最多拿多少事件。
func WithMaxEventNum(n int) Option {
	return func(o *options) { o.maxEventNum = n }
}

// WithLogLevel 日志级别。
func WithLogLevel(l slog.Level) Option {
	return func(o *options) { o.level = l }
}

const (
	defMaxEventNum = 256
)

// New 建一个多路事件循环。
func New(opts ...Option) (*MultiEventLoop, error) {
	o := options{}
	for _, f := range opts {
		f(&o)
	}
	if o.numLoops <= 0 {
		o.numLoops = runtime.NumCPU()
	}
	if o.maxEventNum <= 0 {
		o.maxEventNum = defMaxEventNum
	}

	// worker 数：没指定(0)用默认，负数表示关掉（事件就地处理）。
	workers := o.eventWorkers
	if workers == 0 {
		workers = defEventWorkers()
	}
	m := &MultiEventLoop{
		numLoops:    o.numLoops,
		maxEventNum: o.maxEventNum,
		pool:        newTaskPool(workers),
	}
	m.log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: o.level}))
	m.conns.Init(core.GetMaxFd())

	m.loops = make([]*EventLoop, o.numLoops)
	for i := range m.loops {
		el := &EventLoop{
			parent:      m,
			maxEventNum: o.maxEventNum,
			log:         m.log,
			// 注册连接（OnOpen 投递）走这条路，不是数据路径。
			// 压测里的 connect 风暴会瞬时挤进来一批，缓冲开大点，
			// 免得 accept 循环被卡住（见 runOnLoop）。
			tasks: make(chan func(), 4096),
		}
		api, err := core.Create(core.TriggerTypeEdge)
		if err != nil {
			return nil, err
		}
		el.PollingApi = api
		if err := el.initWake(); err != nil {
			return nil, err
		}
		m.loops[i] = el
	}
	return m, nil
}

// NewAndStart 建一个并且跑起来。
func NewAndStart(opts ...Option) (*MultiEventLoop, error) {
	m, err := New(opts...)
	if err != nil {
		return nil, err
	}
	m.Start()
	return m, nil
}

// Start 把每个事件循环跑起来。
func (m *MultiEventLoop) Start() {
	if !atomic.CompareAndSwapInt32(&m.started, 0, 1) {
		return
	}
	// Add 必须在起 goroutine **之前**：WaitGroup 的规矩是"Add 要发生在
	// Wait 之前"，在 goroutine 里 Add 的话，Free 可能已经走到 Wait 了，
	// 那个 Add 就丢了（-race 报的就是这个）。
	// worker 先起：循环一开跑就可能往环里投任务。
	if m.pool != nil {
		m.pool.start()
	}
	for _, el := range m.loops {
		m.loopsWg.Add(1)
		go el.Loop()
	}
}

// Free 停掉所有事件循环。
//
// 关停是"置标志位、等循环自己退出"，不是从外面把 PollingApi 撕掉：
// pulse 的 Free 和 Poll 并发调是数据竞争（实测 -race 会报 api_kqueue.go
// 里 kqfd 的读写撞车），而且正在处理的连接会被从脚下抽走。
//
// 循环每轮开头看一次标志位，而它平时要么 park 在 runtime 的 poller 上、
// 要么阻塞在 epoll_wait(-1) 里（见 Loop 里的说明），所以**得先把它们叫醒**：
// 往唤醒管道写一个字节，epoll fd 立刻可读，循环醒来 -> 跑任务 -> 回到开头
// 看到 freed 退出。不叫醒的话 Wait 会一直等下去。
//
// 等的是 WaitGroup，所以 Free 返回时所有循环真的已经停了。
func (m *MultiEventLoop) Free() {
	if !atomic.CompareAndSwapInt32(&m.freed, 0, 1) {
		return
	}
	for _, el := range m.loops {
		el.wake()
	}
	m.loopsWg.Wait()
	if m.pool != nil {
		m.pool.stop()
	}
	for _, el := range m.loops {
		el.PollingApi.Free()
		el.closeWake()
	}
}

func (m *MultiEventLoop) isFreed() bool { return atomic.LoadInt32(&m.freed) == 1 }

// NumLoops 有几个事件循环。
func (m *MultiEventLoop) NumLoops() int { return len(m.loops) }

// NumConns 当前连接数。
func (m *MultiEventLoop) NumConns() int64 { return atomic.LoadInt64(&m.curConn) }

// Add 把一条非阻塞 fd 挂到引擎上，h 处理它的事件。
//
// accept 完拿到 fd，设成非阻塞，然后调这个。
//
// 引擎 Free 之后调它会返回 ErrClosed——accept 循环和 Free 是并发的
// （关监听 fd 之后 accept 可能还有一个已经拿到的连接要挂），不能假设
// 调用方先停 accept 再 Free。
func (m *MultiEventLoop) Add(fd int, h Handler) (*Conn, error) {
	if m.isFreed() {
		return nil, ErrClosed
	}
	c := &Conn{}
	el := m.loops[fd%len(m.loops)]
	c.Init(fd, h, el)
	// 注册之前给协议一次"在调用方 goroutine 上建连接对象"的机会，见 Binder。
	//
	// 放在 m.conns.Add 和 AddRead **之前**是关键：那两步之后事件循环就能
	// 看见这个 fd 了，而 Bind 里协议要做的事（newConn、喂握手多读的字节、
	// 调用户的 OnOpen）都不是并发安全的，必须发生在"没人看得见"的时候。
	if b, ok := h.(Binder); ok {
		if err := b.Bind(c); err != nil {
			return nil, err
		}
	}
	m.conns.Add(fd, c)
	if err := el.AddRead(c); err != nil {
		m.conns.Del(fd)
		return nil, err
	}
	atomic.AddInt64(&m.curConn, 1)
	if h != nil {
		// OnOpen 投到事件循环的 goroutine 上跑。
		//
		// **不能在这里同步调**：Add 是 accept 循环（调用方的 goroutine）
		// 调的，而 OnOpen 里协议要初始化自己的状态（http2 建 Conn、
		// tls 建状态机、SetUserData……），那些状态之后只被事件循环碰
		// ——两边一写一读就是数据竞争。实测过：http2.ConnHandler 的
		// ch.conn 字段在 -race 下必报。
		//
		// 也不能往任务队列一扔就完事：投递和 epoll 事件之间**没有先后
		// 保证**——Add 返回时数据可能已经到了、事件已经排进 epoll。那
		// 就成了先跑 OnData、再跑 OnOpen，和上面那个竞争是一回事。
		//
		// 所以：任务里跑 OnOpen，跑完置 activated 位；事件处理那边看到
		// 位没置就把事件记成 pending，由 OnOpen 跑完时自己取走（见
		// activate 和 processConn）。
		el.runOnLoop(func() {
			el.activate(c)
		})
	}
	return c, nil
}

// activate 跑 OnOpen，再把它跑完之前攒下的事件补处理掉。
//
// **谁把 flagActivated 从 0 变 1，谁跑 OnOpen**，其余调用者直接返回。
// 原来这里是"先 isActivated() 看一眼"，靠"两条路都在同一个 goroutine 上"
// 成立（Add 投的任务在事件循环的 goroutine 上、事件处理也在）；
// 开了 worker 池（见 worker.go）之后，任务在循环的 goroutine 上跑、
// 事件在 worker 上跑，两边可能同时进来——必须原子地决出一个执行者，
// 不然 OnOpen 跑两遍（http2/tls 的状态机初始化跑两遍就是状态错乱）。
//
// **可重入**：Add 投的任务和事件处理两条路都可能调它（后者是"事件比
// 任务先到"的情况，见 EventLoop.processConn 的 activateBusy）。
func (el *EventLoop) activate(c *Conn) { el.activateInner(c, false) }

// activateBusy 同上，但调用方**已经持有 busy**（processConn 里那条路）。
//
// 这条路不能再 tryBusy/unbusy 一次：会把人家持有的位清掉——之后另一个
// goroutine 就能同时进来处理同一条连接，状态直接乱掉（实测：多线程下
// 大量 TLS 握手卡在 Start，因为连接被两个 goroutine 交错处理）。
func (el *EventLoop) activateBusy(c *Conn) { el.activateInner(c, true) }

func (el *EventLoop) activateInner(c *Conn, alreadyBusy bool) {
	if c.IsClosed() {
		return
	}
	// 原子抢执行权，见上。
	if atomic.OrUint32(&c.packed, flagActivated)&flagActivated != 0 {
		return
	}

	// busy 位：没人持有就自己占上、跑完自己还；alreadyBusy 那条路不碰。
	owned := false
	if !alreadyBusy {
		owned = c.tryBusy()
	}
	if c.handler != nil {
		c.handler.OnOpen(c)
	}
	if owned {
		c.unbusy()
	}

	// OnOpen 之前（或者期间）到的事件：补处理掉。
	//
	// 有 pending 的话要接着处理（那些是 epoll 边缘，丢了就没有下一次
	// 通知了）。alreadyBusy 那条路不补：processConn 自己会接着跑，
	// 它拿着循环去取 pending。
	if owned {
		pendingRead, pendingWrite := c.takePendingRead(), c.takePendingWrite()
		if pendingRead || pendingWrite {
			if c.tryBusy() {
				el.processConn(c, pendingRead, pendingWrite)
			}
		}
	}
}

func (m *MultiEventLoop) getConn(fd int) *Conn {
	return m.conns.Get(fd)
}

func (m *MultiEventLoop) delConn(fd int) {
	if fd < 0 {
		return
	}
	if c := m.conns.Get(fd); c != nil {
		m.conns.Del(fd)
		atomic.AddInt64(&m.curConn, -1)
	}
}

// 连接对象不做池化。以前有个 sync.Pool，但还回去的时机很难找对：
// closeWith 返回之后，**调用方还在碰这条连接**——processConn 的 defer
// unbusy、事件循环 EOF 分支的 unbusy、用户回调里拿着的那个 *Conn。这时候
// 对象要是被新连接取走，新连接会接着改 fd/handler/状态位，和这些读改写
// 撞上（-race 会报，实际后果是清掉别人的 busy 位）。
//
// 一条连接一个 &Conn{} 就够：结构体不到 200 字节，省下的那点分配换不来
// 这个风险。

func (m *MultiEventLoop) addWrite(c *Conn) {
	// 委托给连接所在的那个事件循环（见 EventLoop.addWrite 里
	// "为什么不能是空操作"的说明）
	if c.parent != nil {
		_ = c.parent.addWrite(c)
	}
}

func (m *MultiEventLoop) err(msg string, args ...any) {
	if m.log != nil {
		m.log.Error(msg, args...)
	}
}
