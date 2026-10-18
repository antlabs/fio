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

// 默认事件循环数，见 toEngineOptions。
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

// eventWorkersPoolAuto 是 "显式要 worker 池、worker 数按核数算" 的哨兵值。
// 0 留给了 "没填 = 默认 inline"。
const eventWorkersPoolAuto = -2

type evOptionConfig struct {
	numLoops    int        // 起多少个 event loop
	level       slog.Level // 日志级别
	maxEventNum int        // 一次 epoll/kqueue 最多处理多少事件

	// eventWorkers 是解析池（engine 那边叫事件移交: event loop 只分发,
	// 读/解析/回调交给一组 worker）。
	//
	//	0                     默认：就地执行（inline），见下面 toEngineOptions
	//	eventWorkersPoolAuto  显式要 worker 池，worker 数按核数取
	//	> 0                   指定 worker 数
	//	< 0                   就地执行
	//
	// 迁移前这几个选项（WithParseInWorkerPool / WithParseGoroutines /
	// WithParseInEventLoop）配置的就是这条路径，现在接着往下传。
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
	if loops <= 0 {
		// 默认事件循环数：2 核以上 192，单核 64。
		//
		// 这个数看着大，但每个循环是独立的 epoll 分片，连接按 fd 取模
		// 分过去：循环越多，每个循环负责的连接越少，一次醒来要碰的
		// 连接状态/读缓冲区/socket 越少，越能留在 cache 里。
		//
		// 实测（lab，10000 连接 1KB echo，C++ 客户端，server/client 对半）：
		// 2 核上 2 个循环时每个循环 5000 条连接，LLC-load-miss 59%，
		// 每消息 5.2µs；192 个循环（每循环约 50 条）时 miss 降到 1%，
		// 每消息 2.8µs。2/4/8/12 核的 Echo 和 Pipeline 都在 96~384 个
		// 循环之间接近峰值，192 是这个区间里内存和 TPS 的折中。
		//
		// 显式 WithEventLoops 仍然优先；连接数特别大（几十万以上）的
		// 场景可以按"每个循环几百条连接"自己给一个更大的值。
		loops = defaultEventLoops
		if n == 1 {
			loops = defaultEventLoopsSingleCPU
		}
		// 每个 loop 要占 4 个 fd（epoll、pulse waiter 的 dup、唤醒管道
		// 两端）。按 5 个算，最多用一半的 RLIMIT_NOFILE，剩下的留给
		// 连接；不然默认 1024 fd 的进程光 loop 就 EMFILE 了。
		// 显式 WithEventLoops 不受这个限制（调用方自己负责）。
		loops = capEventLoopsForFD(loops)
	}
	workers := cfg.eventWorkers
	switch workers {
	case 0:
		// 默认就地执行：读/解析/回调都在事件循环上，省掉一次跨
		// goroutine 投递 + 唤醒。worker 池那套在 2 核上实测反而慢
		// （每消息多 2~3µs 的交接和调度），高核数下也不如多个小循环。
		workers = -1
	case eventWorkersPoolAuto:
		// 显式要 worker 池：沿用迁移前的默认 NumCPU*5/3，下限 24
		// （低核数下 5/3 的 worker 队列经常满）。
		workers = n * 5 / 3
		if workers < 24 {
			workers = 24
		}
	}
	engOpts := []engine.Option{
		engine.WithEventLoops(loops),
		engine.WithMaxEventNum(cfg.maxEventNum),
		engine.WithLogLevel(cfg.level),
		engine.WithEventWorkers(workers),
	}
	if workers > 0 {
		// worker 池模式：syscall 期间让出 P，别的 worker/event loop 才能跑。
		engOpts = append(engOpts, engine.WithEnterSyscall())
	}
	return engOpts
}
