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

// 诊断接口。
//
// **数字本身现在归 engine 数**（syscall 发生在它那儿，协议层看不见），
// 这里只把方法名转发过去——名字是公开 API，压测的控制口（bench-ws 的
// greatws-io / greatws-onebyone）每秒读一次这些数，改名就是编译不过。
//
// 想量"没有诊断开销时能跑多快"用 FIO_NO_STAT（或老的 GREATWS_NO_STAT）
// 环境变量把计数关掉，见 engine/stats.go。

// GetCurConnNum 当前连接数。
func (m *MultiEventLoop) GetCurConnNum() int64 { return m.NumConns() }

// GetCurGoNum 当前业务协程数。
//
// 以前是"每个 event loop 一个业务池"的协程数之和；现在回调默认就地执行
// （在事件循环自己的 goroutine 上），进程里唯一的池子是给非 io 模式用的
// selectTask，没启用就是 0。
func (m *MultiEventLoop) GetCurGoNum() (total int) {
	return defaultTasks.GetGoroutines()
}

// GetCurTaskNum 当前正在跑的业务数。
//
// 同 GetCurGoNum：就地执行下没有独立的业务协程，所以和协程数同值。
func (m *MultiEventLoop) GetCurTaskNum() (total int64) {
	return int64(defaultTasks.GetGoroutines())
}

// GetApiName 当前用的多路复用 api 名字（epoll / kqueue）。
func (m *MultiEventLoop) GetApiName() string { return m.ApiName() }

// GetReadSyscallNum 读系统调用次数。
func (m *MultiEventLoop) GetReadSyscallNum() int64 { return m.ReadSyscallNum() }

// GetWriteSyscallNum 写系统调用次数。攒包的效果就是看它。
func (m *MultiEventLoop) GetWriteSyscallNum() int64 { return m.WriteSyscallNum() }

// GetReallocNum 读缓冲区重新分配次数。
func (m *MultiEventLoop) GetReallocNum() int64 { return m.ReallocNum() }

// GetMoveBytesNum compact 时移动的字节数。
func (m *MultiEventLoop) GetMoveBytesNum() uint64 { return m.MoveBytesNum() }

// GetReadEvNum 读事件次数。
func (m *MultiEventLoop) GetReadEvNum() int64 { return m.ReadEvNum() }

// GetWriteEvNum 写事件次数。
func (m *MultiEventLoop) GetWriteEvNum() int64 { return m.WriteEvNum() }

// GetPollEvNum Poll 返回的事件总数。
func (m *MultiEventLoop) GetPollEvNum() int64 { return m.PollEvNum() }
