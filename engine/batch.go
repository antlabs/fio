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
	"sync/atomic"
	"time"
)

// classifyBytesPerTask 是分类拓扑的阈值：一个 loop 平均每个 read 任务
// 读到这么多字节，就按 pipeline（一次读多个 frame）走固定 worker。
// echo 1KB 请求约 1KB/任务，pipeline 15 个 in-flight 约 15KB/任务。
const classifyBytesPerTask = 4096

// batchTaskLimit 是一批最多装多少事件。
//
// 不只是省内存：业务回调慢时，event loop 要能**继续提交后面的批次**，
// 动态扩容才有东西可扩。如果一轮 epoll 的 100 个事件装成一批交给一个
// worker，worker 在第一个慢回调里睡 50ms，队列是空的、event loop 也没
// 有新事件可提交，扩容永远触发不了（实测 100 条 50ms 回调串行 2.57s）。
// 批小一点，慢回调占住一个 worker 时，后面的批次已经在队列里，扩容
// worker 可以并行处理。
// 批次上限按拓扑分：per-core 的 loop 少、每 loop 连接多，大批次能少
// 拆几次（Echo/Pipeline 的低核 TPS 敏感）；批量池 8/12 核用 64，内存
// 更低。慢回调的并行靠 watchdog/offload，不靠把批次切得很小。
const (
	batchTaskLimitPerCore = 256
	batchTaskLimitBatch   = 64
)

// slowTaskThreshold / slowSplitChunk：worker 处理一个任务超过 10ms 就
// 认为业务回调慢，把这一批里**还没处理**的任务拆成小批重新入队，
// 让动态扩容的 worker 并行处理；慢任务本身不可抢占，但后面的任务
// 不用陪它排队。
const slowSplitChunk = 8

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
// （默认 loop 数 = 32×核数，10k 连接时每个 loop 几十到一百多条），
// worker 处理这一批时碰的连接状态是集中的；跨 goroutine 的唤醒从
// "每消息一次"降到"每批一次"。
//
// 一个 loop 的批次固定投到它对应的 shard（loopIndex%shards）；shard 里
// 2 个 worker 抢同一个 channel，某个 worker 忙时另一个还能接下一批，
// 减少队头阻塞。同一条连接的事件顺序由 busy/pending 位保证，不靠
// 单 worker 串行。

// batchTask 是批次里的一个事件。记 fd、连接指针和状态；event loop 从
// 指针表里取一次 *Conn，但不碰它上面的任何字段，协议的读取/解析/回调
// 都留给 worker。
type batchTask struct {
	c       *Conn
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

// workerState 是每个 worker goroutine 的进度状态，watchdog 用它检测
// "某个 worker 卡在慢回调里"。
type workerState struct {
	busy     atomic.Int32
	seq      atomic.Int64
	slowFlag atomic.Int32
	last     int64 // watchdog 专用
	stall    int32 // 连续多少个 1ms tick 没有任务进展
}

type batchWorker struct {
	id   int
	ch   chan *taskBatch
	done chan struct{}
	p    *batchPool

	// running 是这个 shard 当前的 worker goroutine 数（base + 扩容）。
	running atomic.Int32
	max     int32

	mu     sync.Mutex
	states []*workerState
}

type batchPool struct {
	workers     []*batchWorker
	perShard    []int
	perCore     bool
	maxPerShard int32
	stallTicks  int32
	taskLimit   int
	tickerDone  chan struct{}
	free        sync.Pool

	// 按负载给 loop 选 worker 组：小读（echo，每任务 ~1KB）走共享队列，
	// 大读（pipeline，每任务 ~15KB）走固定 worker（loop%fixedShards），
	// 兼顾 echo 的低延迟和 pipeline 的 cache 亲和。
	classify     bool
	sharedShards int
	fixedShards  int
}

func newBatchPool(n int, perCore bool) *batchPool {
	// n 是目标 worker 总数；默认每个 shard 常驻 batchWorkersPerShard 个，
	// 所以 shard 数 = n/2。n=2 -> 1 个 shard、2 个 worker；n=12 -> 6 个
	// shard、12 个 worker。
	// ≤4 核默认按负载分两组：小读（echo）走共享组，大读（pipeline）
	// 走固定组。5 核以上继续单一共享拓扑（实测 Pipeline 已领先）。
	classify := !perCore && n <= 4
	var counts []int
	sharedShards, fixedShards := 0, 0
	switch {
	case perCore:
		// per-core：一个 shard 一个 worker，loop i 的批次固定到
		// worker i；两边绑同一个 CPU。
		counts = make([]int, n)
		for i := range counts {
			counts[i] = 1
		}
	case classify:
		// 共享组：n/2 个 shard ×2 worker（小读、低延迟）；
		// 固定组：n 个 shard ×1 worker（大读、cache 亲和）。
		sharedShards = n / 2
		if sharedShards < 1 {
			sharedShards = 1
		}
		fixedShards = n
		counts = make([]int, sharedShards+fixedShards)
		for i := range counts {
			if i < sharedShards {
				counts[i] = 2
			} else {
				counts[i] = 1
			}
		}
	default:
		per := batchWorkersPerShard
		shards := n / per
		if shards < 1 {
			shards = 1
		}
		counts = make([]int, shards)
		for i := range counts {
			counts[i] = per
		}
	}
	shards := len(counts)
	perShardMax := int32(256)
	// 慢回调判定：per-core 的 loop/worker 绑核，调度抖动小，10ms；
	// 批量池在 8/12 核上 384 个 loop 会抢 CPU，worker 被调走 >10ms
	// 很常见，10ms 会误扩容（12 核 Echo 1.9M -> 0.36M），用 100ms。
	stallTicks := int32(100)
	if perCore {
		// per-core 的 shard 多（每个 loop 一个），每个 shard 最多再扩
		// 16 个；慢业务时扩容 worker 不绑核，能跑别的 CPU。
		perShardMax = 16
		stallTicks = 10
	}
	taskLimit := batchTaskLimitBatch
	if perCore {
		taskLimit = batchTaskLimitPerCore
	}
	p := &batchPool{perShard: counts, perCore: perCore, classify: classify, sharedShards: sharedShards, fixedShards: fixedShards, maxPerShard: perShardMax, stallTicks: stallTicks, taskLimit: taskLimit, tickerDone: make(chan struct{})}
	p.free.New = func() any {
		// 初始只开 16 格，不按上限 64/256 开：echo 一批往往只有 1~3 条，
		// 按上限开会让队列里每个 batch 都攥着 64×24B 的数组（pprof 里
		// 3MB 就花在这）。真装不下 append 会自己长。
		return &taskBatch{tasks: make([]batchTask, 0, 16)}
	}
	// 每个 shard 的队列深度：默认只有 1 个 shard（2 核）时给 1024；多
	// shard（4 核以上）给 512。实测 4+4：512 的 Echo 是 1.00M，1024 是
	// 881k（队列短、延迟低）；但 2+2 只有 1 个 shard、2 个 worker，512
	// 会满、退回临时 goroutine，Echo 从 504k 掉到 397k，所以 1 个 shard
	// 时不能减半。8+8 也是 512 更好（1.27M vs 1.24M）。
	// 分类拓扑：共享组沿用上面的规则；固定组是 1 worker/shard，用 1024。
	p.workers = make([]*batchWorker, shards)
	for i := range p.workers {
		capN := 1024
		if shards > 1 {
			capN = 512
		}
		if classify {
			if i < sharedShards {
				if sharedShards == 1 {
					capN = 1024
				} else {
					capN = 512
				}
			} else {
				capN = 1024
			}
		}
		p.workers[i] = &batchWorker{
			id:   i,
			ch:   make(chan *taskBatch, capN),
			done: make(chan struct{}),
			p:    p,
			max:  perShardMax,
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
	for i, w := range p.workers {
		for j := 0; j < p.perShard[i]; j++ {
			// 只有 per-core 拓扑把 base worker 绑核；默认批量池（8/12
			// 核）不能绑，否则 12 个 worker 被钉在 6 个 CPU 上，Echo
			// 会从 1.87M 掉到 0.34M。
			w.spawn(p.perCore, true)
		}
	}
	go p.watch()
}

// spawn 加一个 worker。pin 只给 base worker（per-core 绑核）；扩容出来的
// worker 不绑核，业务慢时才能跑到别的 CPU 上，不被慢回调所在核困住。
func (w *batchWorker) spawn(pin, base bool) {
	for {
		n := w.running.Load()
		if n >= w.max {
			return
		}
		if w.running.CompareAndSwap(n, n+1) {
			st := &workerState{}
			w.mu.Lock()
			w.states = append(w.states, st)
			w.mu.Unlock()
			go func() {
				if pin {
					pinLoop(w.id)
				}
				w.run(st, base)
			}()
			return
		}
	}
}

func (w *batchWorker) unregister(st *workerState) {
	w.mu.Lock()
	for i, v := range w.states {
		if v == st {
			w.states[i] = w.states[len(w.states)-1]
			w.states = w.states[:len(w.states)-1]
			break
		}
	}
	w.mu.Unlock()
}

// watch 每 1ms 看一次每个 worker 的任务进度：worker 在处理批次，但 seq
// 1ms 没动，说明某条业务回调卡住了；置 slowFlag、必要时加不绑核 worker。
//
// 不能按"整批处理时长"或"队列长度"判断慢：正常快业务一批 512 条在
// 2 核上也可能 >10ms，按批次时长会误扩容，把 per-core 的 cache 打掉
// （Echo 382k -> 133k）。这里看的是"单条任务是否有进展"。
func (p *batchPool) watch() {
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-p.tickerDone:
			return
		case <-t.C:
			for _, w := range p.workers {
				w.mu.Lock()
				sts := make([]*workerState, len(w.states))
				copy(sts, w.states)
				w.mu.Unlock()
				for _, st := range sts {
					if st.busy.Load() == 0 {
						st.last = st.seq.Load()
						st.stall = 0
						continue
					}
					seq := st.seq.Load()
					if seq == st.last {
						// 1ms 太敏感：2 核上 loop/worker 抢 P，worker
						// 被调走 1~2ms 很常见，会误判成慢回调、把
						// per-core 的 cache 打掉（Echo 382k -> 131k）。
						// 连续 stallTicks 个 tick 没进展才算慢。
						st.stall++
						if st.stall >= p.stallTicks {
							st.slowFlag.Store(1)
							if len(w.ch) > 0 && w.running.Load() < w.max {
								w.spawn(false, false)
							}
						}
					} else {
						st.stall = 0
						st.last = seq
					}
				}
			}
		}
	}
}

// submit 把一批交给这个 shard。**不能阻塞 event loop**：channel 满时
// 起一个临时 goroutine 处理这一批（fnet 的池子也是这个兜底），
// 业务再慢也不会把事件循环卡住。
func (w *batchWorker) submit(b *taskBatch) {
	select {
	case w.ch <- b:
	default:
		go w.processBatch(&workerState{}, b)
	}
}

func (p *batchPool) stop() {
	close(p.tickerDone)
	for _, w := range p.workers {
		close(w.done)
	}
}

// pipelineLoop 判断这个 loop 是不是一次读多个 frame 的 pipeline 负载：
// 平均每个 read 任务读到的字节数 >= classifyBytesPerTask。样本不足 8 个
// 任务时先按 echo（共享组）走，避免启动时误判。
func (p *batchPool) pipelineLoop(el *EventLoop) bool {
	if !p.classify {
		return false
	}
	n := el.readStatTasks.Load()
	return n >= 8 && el.readStatBytes.Load()/n >= classifyBytesPerTask
}

// workerForClass 选这个 loop 这一批交给哪个 shard。
// 分类拓扑里大读 loop 走固定组，其余走共享组；默认拓扑按 loop 固定映射。
func (p *batchPool) workerForClass(loop int, pipeline bool) *batchWorker {
	if p.classify {
		if pipeline {
			return p.workers[p.sharedShards+loop%p.fixedShards]
		}
		return p.workers[loop%p.sharedShards]
	}
	return p.workers[loop%len(p.workers)]
}

func (p *batchPool) getBatch(el *EventLoop) *taskBatch {
	b := p.free.Get().(*taskBatch)
	b.el = el
	b.tasks = b.tasks[:0]
	return b
}

func (p *batchPool) putBatch(b *taskBatch) {
	// 清掉 *Conn，避免池里的 backing array 把已经关掉的连接留住。
	clear(b.tasks)
	b.el = nil
	b.tasks = b.tasks[:0]
	p.free.Put(b)
}

func (w *batchWorker) run(st *workerState, base bool) {
	for {
		select {
		case b := <-w.ch:
			st.busy.Add(1)
			w.processBatch(st, b)
			st.busy.Add(-1)
			// 扩容 worker 空闲就退休；base worker 常驻。正常快业务没有
			// 扩容，退休不会发生在热路径上。退休前再看一眼队列，防止
			// 正好有批次进来没人接（有的话补一个）。
			if !base && len(w.ch) == 0 {
				w.running.Add(-1)
				w.unregister(st)
				if len(w.ch) > 0 {
					w.spawn(false, false)
				}
				return
			}
		case <-w.done:
			return
		}
	}
}

func (w *batchWorker) processBatch(st *workerState, b *taskBatch) {
	el := b.el
	const checkEvery = 16
	check := 0
	for i := range b.tasks {
		st.seq.Add(1)
		w.processOne(el, b.tasks[i])
		// 每 16 条查一次慢标志，不要每条都 Swap：Pipeline 每条消息
		// 一次 atomic RMW，12 核上会掉 10%+。慢任务本身不可抢占，
		// 最多多跑 15 条快任务就发现并 offload。
		check++
		if check >= checkEvery {
			check = 0
			if st.slowFlag.Load() != 0 {
				st.slowFlag.Store(0)
				if i+1 < len(b.tasks) {
					w.offload(el, b.tasks[i+1:])
				}
				w.p.putBatch(b)
				return
			}
		}
	}
	// 短批次里也可能有慢任务：标志留着会污染下一批，清掉。
	if st.slowFlag.Load() != 0 {
		st.slowFlag.Store(0)
	}
	w.p.putBatch(b)
}

func (w *batchWorker) offload(el *EventLoop, tasks []batchTask) {
	for len(tasks) > 0 {
		n := slowSplitChunk
		if n > len(tasks) {
			n = len(tasks)
		}
		nb := w.p.getBatch(el)
		nb.tasks = append(nb.tasks, tasks[:n]...)
		w.submit(nb)
		if w.running.Load() < w.max {
			w.spawn(false, false)
		}
		tasks = tasks[n:]
	}
}

// processOne 和旧 taskNode.processOne 的语义一致：OnOpen/读/解析/回调/写
// 都在 worker 上执行，busy/pending 位保证同一条连接不会被并发处理。
func (w *batchWorker) processOne(el *EventLoop, t batchTask) {
	c := t.c
	if c == nil {
		c = el.parent.getConn(t.fd)
	}
	if c == nil {
		return
	}

	// Add 投来的 OnOpen 任务：没有读/写/EOF 标志。必须拿到 busy 才能跑
	// OnOpen（activate 会等），不能和事件处理并发。
	if !t.isRead && !t.isWrite && !t.eof {
		el.activate(c)
		return
	}

	if t.eof {
		if !c.tryBusy() && !c.markPendingAndRetry(t.isRead, t.isWrite) {
			return
		}
		defer c.unbusy()
		el.activateBusy(c)
		if c.IsClosed() {
			return
		}
		if w.p.classify {
			c.readBytes.Store(0)
		}
		_ = el.readAndDispatch(c)
		if w.p.classify {
			el.recordRead(c)
		}
		c.closeWith(io.EOF)
		return
	}

	if !c.tryBusy() {
		// 记下事件后重抢一次；抢到说明原处理者已经放掉，归我们跑。
		if c.markPendingAndRetry(t.isRead, t.isWrite) {
			if w.p.classify {
				c.readBytes.Store(0)
			}
			el.processConn(c, false, false)
			if w.p.classify {
				el.recordRead(c)
			}
		}
		return
	}
	// processConn 自己管理 busy，跑完负责 unbusy。
	if w.p.classify {
		c.readBytes.Store(0)
	}
	el.processConn(c, t.isRead, t.isWrite)
	if w.p.classify {
		el.recordRead(c)
	}
}
