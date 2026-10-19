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
package websocket

import (
	"log/slog"
	"os"
	"runtime"
	"sync"
	"syscall"

	"github.com/antlabs/fio/engine"
)

// 这一层只留着"把 EvOption 收成一堆配置、再转成 engine 的选项"。
//
// 以前 websocket 自己有一整套事件循环(MultiEventLoop/EventLoop/taskParse),
// 事件注册、读、解析、攒包都自己管; 现在这些全归 engine, websocket 只把
// 用户的 EvOption 翻译过去。
//
// **EvOption 和 WithXxx 的名字/签名必须保留**: 它们是公开 API, 用户代码里
// (WithEventLoops、WithLogLevel、WithBusinessGoNum……)写死了在用。能翻译成
// engine 选项的翻译过去, 翻译不了的保留签名但不生效(见各 WithXxx 的注释)。

// evOptionConfig 是 EvOption 们填的东西。
//
// 字段和以前 multiEventLoopOption 里能映射到 engine 的那几个一一对应:
// numLoops/level/maxEventNum。剩下的(业务协程池、解析池、gosched……)engine
// 现在没有对应的开关, 收在这里但不往下传。

// Event 模式（内联模式）的默认事件循环数，见 toEngineOptions。
//
// 2 核以上统一 384 个：2/4/8/12 核实测 384 的 Pipeline 比 192 高
// 4%~23%（12+12、1KB：23.2M vs 18.8M），Echo 基本持平或略高；
// 每消息的堆分配清掉之后，这个数不再把内存推高（12+12 Pipeline 192
// 是 40MB、384 是 50MB，仍然低于清分配前的 72MB）。
//
// 单核上几百个循环挤一个 P 反而慢，实测 56 个最好（Pipeline 2.49M）。
const (
	defaultEventLoops          = 384
	defaultEventLoopsSingleCPU = 56
)

// Worker 模式的默认 loop 数：32×worker，封顶 384。
//
// loop 只 poll + 攒批，读/解析/回包在 worker。loop 越多，每个 loop 的
// 连接集合越小、一个批次越集中，cache 局部性越好；但 fd/事件数组/栈和
// 内存线性涨，384 之后收益抵不过开销。
//
// 实测（10k×1KB、同场交替 A/B fnet，lab 24 核）：
//
//	配置       loop/worker  GOMAXPROCS   Echo        Pipeline
//	2+2        64/2         8            530k        4.8M
//	4+4        128/4        16           863-889k    8.7-8.9M
//	8+8        256/8        8            1.26-1.29M  12.4-12.5M
//	12+12      384/12       12           1.90M       15.3M
//
// GOMAXPROCS 规律见 toEngineOptions：≤4 核抬到 4N，≥5 核用 N。
const defaultWorkerMaxLoops = 384

// defaultWorkerMaxEvent 是 Worker 模式默认一次 epoll_wait 最多取多少事件。
// 64 足够：loop 分片多，每个 loop 一次没那么多就绪 fd；压小事件数组能省
// 内存，也不再让 epoll_wait 一次拷 1000 条。调用方显式设置的不动。
const defaultWorkerMaxEvent = 64

// workerTopology 返回 Worker 模式的默认拓扑：worker 数 = 核数，
// loop 数 = 32×worker（封顶 384）。所有 loop/worker 都不绑核，由 Go
// 调度器分配；batch pool 每 shard 2 个 worker 共享一个队列，低延迟。
//
// 以前低核（<=4）默认是 per-core（loop/worker 1:1 绑核），实测 2+2 只有
// 377k Echo，而这个拓扑能到 530k：per-core 把 loop 和 worker 钉死在同一
// 个核上，一条连接的状态在两个 pinned 线程之间来回搬，反而更慢。
// WithPerCoreWorkers 仍然保留，给需要手动绑核的场景用。
func workerTopology(n int) (loops, workers int, perCore bool) {
	workers = n
	if workers < 1 {
		workers = 1
	}
	loops = 32 * workers
	// 8 核以上直接给到封顶 384：256 个 loop（32/核）时 8+8 的 Echo 比
	// 384 低约 3%（1.26M vs 1.285M），Pipeline 基本不变；384 和 12 核
	// 的 32/核 是同一个数。
	if workers >= 8 {
		loops = defaultWorkerMaxLoops
	}
	if loops > defaultWorkerMaxLoops {
		loops = defaultWorkerMaxLoops
	}
	if loops < 32 {
		loops = 32
	}
	return loops, workers, false
}

type evOptionConfig struct {
	numLoops    int        // 起多少个 event loop
	level       slog.Level // 日志级别
	maxEventNum int        // 一次 epoll/kqueue 最多处理多少事件

	// inline = true 是 Event 模式（内联）：读/解析/回调/写都在 event loop
	// 的 goroutine 上。默认 false 是 Worker 模式：event loop 只 poll/分发，
	// 读/解析/回调/回包在 batch worker 池里（engine/batch.go）。
	inline bool

	// eventWorkers 是 Worker 模式的 worker 总数；<=0 表示按核数取默认。
	// 迁移前的 WithParseInWorkerPool / WithParseGoroutines /
	// WithParseInEventLoop 仍然映射到这两个字段。
	eventWorkers int

	// 下面几个只为了"保留 WithXxx 签名且能编译"。
	businessInit int
	businessMin  int
	businessMax  int
}

// EvOption 配置事件循环。
//
// 保留这个名字和签名: 用户传的是 websocket 的 EvOption, 不是 engine.Option。
type EvOption func(*evOptionConfig)

// MultiEventLoop 是 engine 的事件循环 + 几个 websocket 侧的诊断接口。
//
// **不是别名**: 别名加不了方法, 而 autobahn 那些控制口在读
// GetApiName/GetCurConnNum/GetCurTaskNum(公开 API), 得留一个能挂方法的
// 具名类型。内嵌 *engine.MultiEventLoop, 所以 Start/Add/Free/NumLoops
// 这些直接透上去。
type MultiEventLoop struct {
	*engine.MultiEventLoop
}

// 默认事件循环: 用户没显式传 WithXxxMultiEventLoop 时用它。
var (
	defaultOnce           sync.Once
	DefaultMultiEventLoop *MultiEventLoop
)

func getDefaultMultiEventLoop() *MultiEventLoop {
	defaultOnce.Do(func() {
		el, err := engine.NewAndStart(toEngineOptions(
			WithLogLevel(slog.LevelError),
		)...)
		if err != nil {
			panic(err)
		}
		DefaultMultiEventLoop = &MultiEventLoop{MultiEventLoop: el}
	})
	return DefaultMultiEventLoop
}

// NewMultiEventLoop 按 websocket 的 EvOption 建一个事件循环(不启动)。
func NewMultiEventLoop(opts ...EvOption) (*MultiEventLoop, error) {
	el, err := engine.New(toEngineOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	return &MultiEventLoop{MultiEventLoop: el}, nil
}

// NewMultiEventLoopMust 同上, 出错 panic。
func NewMultiEventLoopMust(opts ...EvOption) *MultiEventLoop {
	m, err := NewMultiEventLoop(opts...)
	if err != nil {
		panic(err)
	}
	return m
}

// NewMultiEventLoopAndStartMust 建一个并且跑起来。
func NewMultiEventLoopAndStartMust(opts ...EvOption) *MultiEventLoop {
	el, err := engine.NewAndStart(toEngineOptions(opts...)...)
	if err != nil {
		panic(err)
	}
	return &MultiEventLoop{MultiEventLoop: el}
}

// capEventLoopsForFD 按 RLIMIT_NOFILE 给默认事件循环数封顶。
//
// 一个 event loop 要 4 个 fd: pulse 的 epoll、pulse waiter 为了 park
// 在 runtime netpoller 上 dup 的 epoll、唤醒管道的读写两端。默认 384
// 个 loop 就是 1500+ 个 fd——ulimit 1024 的进程连服务都起不来，而很多
// 小服务确实用默认 ulimit。这里按 5 个 fd/loop、最多占一半 fd 来封顶，
// 剩下的留给连接。显式 WithEventLoops 不封顶，调用方自己负责。
func capEventLoopsForFD(loops int) int {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return loops
	}
	const fdsPerLoop = 5
	if rl.Cur >= uint64(loops)*fdsPerLoop*2 {
		return loops
	}
	budget := int(rl.Cur / (fdsPerLoop * 2))
	if budget < 1 {
		budget = 1
	}
	return budget
}

// toEngineOptions 把 websocket 的 EvOption 收一遍, 再翻译成 engine 的选项。
func toEngineOptions(opts ...EvOption) []engine.Option {
	var cfg evOptionConfig
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	n := runtime.NumCPU()
	loops := cfg.numLoops
	workers := -1
	perCore := false
	if cfg.inline {
		// Event 模式（内联）：读/解析/回调/写都在 event loop 上。
		if loops <= 0 {
			loops = defaultEventLoops
			if n == 1 {
				loops = defaultEventLoopsSingleCPU
			}
			loops = capEventLoopsForFD(loops)
		}
	} else {
		// Worker 模式（默认）：event loop 只 poll + 攒批，读/解析/
		// 回调/回包在 batch worker 池里。拓扑见 workerTopology。
		//
		// GOMAXPROCS 是进程级副作用：≤4 核抬到 4N（实测 2/4 核都要
		// 更多 P 才跑得满），≥5 核用 N（8 核抬到 16 反而把 Echo 从
		// 1.26M 打到 1.11M）。只在默认拓扑下抬；显式
		// WithEventLoops/WithParseGoroutines 不动；调用方显式设了
		// GOMAXPROCS 环境变量也不动（压测对照）。
		if cfg.numLoops <= 0 && cfg.eventWorkers <= 0 {
			loops, workers, perCore = workerTopology(n)
			loops = capEventLoopsForFD(loops)
			target := n
			if n <= 4 {
				target = 4 * n
			}
			if cur := runtime.GOMAXPROCS(0); cur < target && os.Getenv("GOMAXPROCS") == "" {
				runtime.GOMAXPROCS(target)
			}
		} else {
			if loops <= 0 {
				loops = 32 * n
				if loops > defaultWorkerMaxLoops {
					loops = defaultWorkerMaxLoops
				}
				if loops < 32 {
					loops = 32
				}
				loops = capEventLoopsForFD(loops)
			}
			workers = cfg.eventWorkers
			if workers <= 0 {
				workers = n
			}
			if workers < 2 {
				workers = 2
			}
		}
	}
	// Worker 模式默认每次 epoll_wait 取 64 条（见 defaultWorkerMaxEvent）；
	// Event 模式保持引擎默认（256）。显式 WithMaxEventNum 优先。
	maxEventNum := cfg.maxEventNum
	if !cfg.inline && workers > 0 && maxEventNum <= 0 {
		maxEventNum = defaultWorkerMaxEvent
	}
	engOpts := []engine.Option{
		engine.WithEventLoops(loops),
		engine.WithMaxEventNum(maxEventNum),
		engine.WithLogLevel(cfg.level),
		engine.WithEventWorkers(workers),
	}
	if workers > 0 {
		// Worker 模式默认用批量移交（一轮 epoll 事件 = 一个批次），
		// 见 engine/batch.go。
		engOpts = append(engOpts, engine.WithBatchPool())
		// per-core 拓扑里 loop 和 worker 绑同一个 CPU：entersyscall 让出的
		// P 没有别的 goroutine 能跑，只剩 runtime 的进入/退出开销，用
		// RawSyscall。批量池（8 核以上）多个 worker 挤在少量核上，
		// syscall 期间让出 P 才有意义。
		// FIO_ENTER_SYSCALL 非空时强制开启，便于同场 A/B。
		if !perCore || os.Getenv("FIO_ENTER_SYSCALL") != "" {
			engOpts = append(engOpts, engine.WithEnterSyscall())
		}
		// per-core 拓扑（一个 loop 一个 worker，绑同一个 CPU）：
		// 默认低核拓扑或显式环境开关。
		if perCore || os.Getenv("FIO_PER_CORE_WORKERS") != "" {
			engOpts = append(engOpts, engine.WithPerCoreWorkers())
		}
	}
	return engOpts
}
