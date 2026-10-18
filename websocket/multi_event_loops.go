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

// Worker 模式的默认 loop 数：每核 32 个 poller。
//
// Worker 模式的 event loop 只 poll + 攒批，读/解析/回包在 batch worker 上。
// loop 仍然按 fd 分片，每个 loop 的连接集合小，它 poll 时碰的 socket 少；
// 批次也小。实测 2+2 核 64 个 loop、12+12 核 384 个 loop 是 Worker 模式的
// 平衡点（再多 worker 侧排队/调度开销上来）。
const defaultWorkerLoopsPerCPU = 32

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
			WithMaxEventNum(256),
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
		// 回调/回包在 batch worker 池里。
		//
		// loop 数按 32/核：2 核 64、12 核 384。loop 还是按 fd 分片，
		// 每个 loop 的连接少，poll 时碰的 socket 少，一个批次也小。
		// worker 数默认 = 核数；batch pool 每 shard 2 个 worker、shard
		// = worker/2：2 核 1 个 shard、2 个 worker；12 核 6 个 shard、
		// 12 个 worker。
		//
		// 实测（2+2 核、10k×1KB、C++ 客户端）：这个默认下 Echo 约
		// 345k、Pipeline 4.3M；4/8/12 核见 lab 报告。
		if loops <= 0 {
			loops = defaultWorkerLoopsPerCPU * n
			if loops < defaultWorkerLoopsPerCPU {
				loops = defaultWorkerLoopsPerCPU
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
	engOpts := []engine.Option{
		engine.WithEventLoops(loops),
		engine.WithMaxEventNum(cfg.maxEventNum),
		engine.WithLogLevel(cfg.level),
		engine.WithEventWorkers(workers),
	}
	if workers > 0 {
		// Worker 模式默认用批量移交（一轮 epoll 事件 = 一个批次），
		// 见 engine/batch.go；syscall 期间让出 P，别的 worker/loop 才能跑。
		engOpts = append(engOpts, engine.WithBatchPool(), engine.WithEnterSyscall())
	}
	return engOpts
}
