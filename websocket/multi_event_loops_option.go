// Copyright 2021-2024 antlabs. All rights reserved.
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
)

// 这里所有 WithXxx 的名字和签名都保留——它们是公开 API。能映射到 engine
// 的选项映射过去(WithEventLoops/WithLogLevel/WithMaxEventNum), 映射不了的
// 就保留签名、在注释里说明"engine 现在只支持就地执行", 填了不生效。
//
// 这么做的原因: 用户代码里这些函数名写死了, 删掉就是编译不过的 breaking
// change。留着一个"接受但不生效"的开关, 比让用户改代码好。

// 开启几个事件循环, 控制io go程数量。
// -> engine.WithEventLoops
func WithEventLoops(num int) EvOption {
	return func(e *evOptionConfig) {
		e.numLoops = num
	}
}

// 设置日志级别。
// -> engine.WithLogLevel
func WithLogLevel(level slog.Level) EvOption {
	return func(e *evOptionConfig) {
		e.level = level
	}
}

// 设置每个事件循环一次返回的最大事件数量。
// -> engine.WithMaxEventNum
func WithMaxEventNum(num int) EvOption {
	return func(e *evOptionConfig) {
		e.maxEventNum = num
	}
}

// event loop 只做事件的分发，websocket frame 的读取和解析放到一组
// goroutine 里面做。
//
// 现在落到 engine 的事件移交（worker 池）上, 见 engine.WithEventWorkers:
// event loop 只收事件和投递, 读/解析/回调跑在一组 worker 上, 按 fd 取模
// 分片。**迁移前的默认行为就是它**。
func WithParseInWorkerPool() EvOption {
	return func(e *evOptionConfig) { e.eventWorkers = 0 }
}

// 解析 goroutine 的数量。engine 那边是 worker 池的 worker 数。
func WithParseGoroutines(n int) EvOption {
	return func(e *evOptionConfig) { e.eventWorkers = n }
}

// WithParseWorkersPerShard 让每个解析分片起 n 个常驻 worker。
// engine 现在没有解析分片, 不生效。
func WithParseWorkersPerShard(n int) EvOption {
	return func(e *evOptionConfig) {}
}

// 最小业务goroutine数量, 控制业务go程数量。
//
// engine 现在只支持就地执行(回调在事件循环上跑), 没有业务协程池, 所以
// 这个选项填了不生效。保留签名是为了不改用户代码。
func WithBusinessGoNum(initCount, min, max int) EvOption {
	return func(e *evOptionConfig) {
		e.businessInit = initCount
		e.businessMin = min
		e.businessMax = max
	}
}

// 关掉解析池, 让 event loop 自己读和解析 websocket frame（事件就地处理,
// 不往 worker 池投）。
func WithParseInEventLoop() EvOption {
	return func(e *evOptionConfig) { e.eventWorkers = -1 }
}

// 投完一批让出 P。engine 现在不给这个开关, 不生效。
func WithGosched() EvOption {
	return func(e *evOptionConfig) {}
}

// 一次投给解析 goroutine 的连接数上限。engine 现在没有这条投递路径,
// 不生效。
func WithParseBatchSize(n int) EvOption {
	return func(e *evOptionConfig) {}
}
