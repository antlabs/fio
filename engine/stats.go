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
// **每个事件循环一份，不是全进程一份**：这些计数每条消息要加五次(读/
// 写系统调用各一次、读/写事件各一次、poll 事件一次)，全进程一份时 12 个
// loop 全往同几条 cache line 上做原子加——line 在核间弹来弹去，每次加都
// 要等它到手。实测(echo 场景)：全局一份比每 loop 一份多花约 1 微秒/消息
// 的 CPU，同一批数在基线(迁移前)里根本不在热路径上(它的 addReadEvNum 们
// 是死代码)，这就是迁移后 echo 慢几个百分点的来源之一。
//
// 分片之后每次加只是本 loop 自己那条线（独占，无跨核竞争），读的时候把
// 各个 loop 加起来——控制口一秒读一次，汇总那点开销无所谓。
//
// **每个字段一条 cache line**（pad 到 64 字节）：同一个 loop 内这几个计数
// 虽然只被自己写，但它们和别的热点字段挤一行时，跨 loop 的读(汇总)会把
// 整行拉来拉去，顺带把别的字段一起拖走。
//
// 留了 FIO_NO_STAT 一个开关: 关掉之后这些函数直接返回, 量"没有诊断开销时
// 能跑多快"用。
type stats struct {
	readSyscall  int64 // 读系统调用次数（热，独占一条 line）
	_            [56]byte
	writeSyscall int64 // 写系统调用次数（热，独占一条 line）
	_            [56]byte
	readEv       int64 // 读事件次数
	_            [56]byte
	writeEv      int64 // 写事件次数
	_            [56]byte
	pollEv       int64 // 一次 Poll 返回的事件数
	_            [56]byte
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
	atomic.AddInt64(&el.stats.readSyscall, 1)
}

func (el *EventLoop) addWriteSyscall() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.stats.writeSyscall, 1)
}

func (el *EventLoop) addReadEvNum() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.stats.readEv, 1)
}

func (el *EventLoop) addWriteEvNum() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.stats.writeEv, 1)
}

func (el *EventLoop) addPollEvNum(n int64) {
	if statOff {
		return
	}
	atomic.AddInt64(&el.stats.pollEv, n)
}

func (el *EventLoop) addRealloc() {
	if statOff {
		return
	}
	atomic.AddInt64(&el.stats.realloc, 1)
}

func (el *EventLoop) addMoveBytes(n int) {
	if statOff || n <= 0 {
		return
	}
	atomic.AddUint64(&el.stats.moveBytes, uint64(n))
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

// 下面是给诊断用的读取接口（压测的控制口每秒读一次）。分片的计数在这里
// 汇总，每个循环自己的那条线只被它自己写，这里读的时候也是各读各的。

// ReadSyscallNum 读系统调用次数。
func (m *MultiEventLoop) ReadSyscallNum() int64 {
	return m.sumStats(func(s *stats) *int64 { return &s.readSyscall })
}

// WriteSyscallNum 写系统调用次数。
func (m *MultiEventLoop) WriteSyscallNum() int64 {
	return m.sumStats(func(s *stats) *int64 { return &s.writeSyscall })
}

// ReadEvNum 读事件次数。
func (m *MultiEventLoop) ReadEvNum() int64 {
	return m.sumStats(func(s *stats) *int64 { return &s.readEv })
}

// WriteEvNum 写事件次数。
func (m *MultiEventLoop) WriteEvNum() int64 {
	return m.sumStats(func(s *stats) *int64 { return &s.writeEv })
}

// PollEvNum Poll 返回的事件总数。
func (m *MultiEventLoop) PollEvNum() int64 {
	return m.sumStats(func(s *stats) *int64 { return &s.pollEv })
}

// ReallocNum 读缓冲区重新分配次数。
func (m *MultiEventLoop) ReallocNum() int64 {
	return m.sumStats(func(s *stats) *int64 { return &s.realloc })
}

// MoveBytesNum compact 时移动的字节数。
func (m *MultiEventLoop) MoveBytesNum() uint64 {
	var total uint64
	for _, el := range m.loops {
		total += atomic.LoadUint64(&el.stats.moveBytes)
	}
	return total
}

// sumStats 把一个 int64 计数在全部事件循环上求和。
func (m *MultiEventLoop) sumStats(field func(*stats) *int64) int64 {
	var total int64
	for _, el := range m.loops {
		total += atomic.LoadInt64(field(&el.stats))
	}
	return total
}
