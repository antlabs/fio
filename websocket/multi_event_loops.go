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
type evOptionConfig struct {
	numLoops    int        // 起多少个 event loop
	level       slog.Level // 日志级别
	maxEventNum int        // 一次 epoll/kqueue 最多处理多少事件

	// eventWorkers 是解析池（engine 那边叫事件移交: event loop 只分发,
	// 读/解析/回调交给一组 worker）。0 = 没填，用 engine 的默认（和
	// 迁移前一样，NumCPU*5/3）；负数 = 就地执行。
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
		// WebSocket 的默认不是 engine 的"每 CPU 一个"：大核数下 4/3 路
		// 超订能把 syscall 的等待盖住（12 核 -> 16，实测比 12 路高约 4%）；
		// 低核数下 event loop 只做 poll/投递，2 个就够，多出来的会抢
		// worker 的核（4 核实测：2 loops 比 5 loops 高约 2%）。
		if n <= 4 {
			loops = 2
		} else {
			loops = n + n/3
		}
	}
	workers := cfg.eventWorkers
	if workers == 0 {
		// 任务池的 worker 数是 Echo 在低核数上的主要瓶颈：默认 5/3
		// （4 核 6 个）时 worker 队列经常满，4 核 Echo 0.51M；24 个
		// worker 时 0.65M，且 profile 里 taskRing/scheduler 的尖峰消失。
		// 大核数下 24 不低于原来的 5/3（12 核 20 -> 24），先统一取下限。
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
