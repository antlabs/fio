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
	"os"
	"sync/atomic"
)

// 诊断计数。
//
// **为什么放在 engine 里**：压测的控制口每秒读一次 syscall 数——它是验证
// 攒包(cork)有效的手段(写系统调用 2,000,000/s → 200,000/s 就是这么看出来
// 的)。这些 syscall 现在全发生在这里, 协议层数不到了, 只能由引擎来数。
//
// 每个计数就是一次原子加, 而且都打在同一个 cache line 上, 多核之间来回
// 争抢。**实测代价约 1.7% 吞吐**，所以留了 FIO_NO_STAT 一个开关: 关掉之后
// 这些函数直接返回, 量"没有诊断开销时能跑多快"用。
type stats struct {
	readSyscall  int64  // 读系统调用次数
	writeSyscall int64  // 写系统调用次数
	readEv       int64  // 读事件次数
	writeEv      int64  // 写事件次数
	pollEv       int64  // 一次 Poll 返回的事件数
	realloc      int64  // 重新分配读缓冲区次数
	moveBytes    uint64 // compact 时移动的字节数
}

// statOff 关掉每消息的原子计数。
//
// 两个环境变量名都认: GREATWS_NO_STAT 是迁移前就在用的(压测脚本里有),
// FIO_NO_STAT 是 engine 抽出来之后的正名。
var statOff = os.Getenv("GREATWS_NO_STAT") != "" || os.Getenv("FIO_NO_STAT") != ""

func (el *EventLoop) addReadSyscall() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.parent.stats.readSyscall, 1)
}

func (el *EventLoop) addWriteSyscall() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.parent.stats.writeSyscall, 1)
}

func (el *EventLoop) addReadEvNum() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.parent.stats.readEv, 1)
}

func (el *EventLoop) addWriteEvNum() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.parent.stats.writeEv, 1)
}

func (el *EventLoop) addPollEvNum(n int64) {
	if statOff {
		return
	}
	atomic.AddInt64(&el.parent.stats.pollEv, n)
}

func (el *EventLoop) addRealloc() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.parent.stats.realloc, 1)
}

func (el *EventLoop) addMoveBytes(n int) {
	if statOff || n <= 0 {
		return
	}
	atomic.AddUint64(&el.parent.stats.moveBytes, uint64(n))
}

// ApiName 当前用的多路复用 api 名字（epoll / kqueue / iocp）。
//
// 一个进程里的循环用同一个 api，取第一个就够。没有循环时返回空串。
func (m *MultiEventLoop) ApiName() string {
	if len(m.loops) == 0 {
		return ""
	}
	return m.loops[0].Name()
}

// 下面是给诊断用的读取接口（压测的控制口每秒读一次）。

// ReadSyscallNum 读系统调用次数。
func (m *MultiEventLoop) ReadSyscallNum() int64 { return atomic.LoadInt64(&m.stats.readSyscall) }

// WriteSyscallNum 写系统调用次数。
func (m *MultiEventLoop) WriteSyscallNum() int64 { return atomic.LoadInt64(&m.stats.writeSyscall) }

// ReadEvNum 读事件次数。
func (m *MultiEventLoop) ReadEvNum() int64 { return atomic.LoadInt64(&m.stats.readEv) }

// WriteEvNum 写事件次数。
func (m *MultiEventLoop) WriteEvNum() int64 { return atomic.LoadInt64(&m.stats.writeEv) }

// PollEvNum Poll 返回的事件总数。
func (m *MultiEventLoop) PollEvNum() int64 { return atomic.LoadInt64(&m.stats.pollEv) }

// ReallocNum 读缓冲区重新分配次数。
func (m *MultiEventLoop) ReallocNum() int64 { return atomic.LoadInt64(&m.stats.realloc) }

// MoveBytesNum compact 时移动的字节数。
func (m *MultiEventLoop) MoveBytesNum() uint64 { return atomic.LoadUint64(&m.stats.moveBytes) }
