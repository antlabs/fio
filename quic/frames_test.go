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

package quic

import "testing"

// frameKinds 走一遍 parseFrames，把帧类型收集起来。
func frameKinds(t *testing.T, b []byte) []uint64 {
	t.Helper()
	var kinds []uint64
	if err := parseFrames(b, func(kind uint64, raw []byte, n int) error {
		kinds = append(kinds, kind)
		return nil
	}); err != nil {
		t.Fatalf("解帧失败: %v", err)
	}
	return kinds
}

// NEW_CONNECTION_ID 的 retire prior to 不能漏。
//
// 漏了的话"长度"读到的是它的值，帧边界错位，后面**同一包里的帧全解不出来**
// （帧没有长度前缀，解偏一次就停）——整包被丢。踩过：ngtcp2 的客户端把
// NEW_CONNECTION_ID 和请求的 STREAM 帧放同一个包，我们只解出前半截，
// 表现成"客户端发了请求、服务端装死"。
func TestParseNewConnID(t *testing.T) {
	var b []byte
	b = appendVarint(b, frNewConnID)
	b = appendVarint(b, 1) // 序号
	b = appendVarint(b, 0) // retire prior to
	b = appendVarint(b, 8) // 长度
	b = append(b, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)
	b = append(b, make([]byte, 16)...) // 重置令牌
	b = appendVarint(b, frPing)        // 跟着一帧，验证边界

	kinds := frameKinds(t, b)
	if len(kinds) != 2 || kinds[0] != frNewConnID || kinds[1] != frPing {
		t.Fatalf("帧序列 %v，期望 [%#x %#x]", kinds, frNewConnID, frPing)
	}
}

// STOP_SENDING（客户端中止一条响应）也要能跳过。
func TestParseStopSending(t *testing.T) {
	var b []byte
	b = appendVarint(b, frStopSending)
	b = appendVarint(b, 4) // 流 ID
	b = appendVarint(b, 1) // 错误码
	b = appendVarint(b, frPing)

	kinds := frameKinds(t, b)
	if len(kinds) != 2 || kinds[1] != frPing {
		t.Fatalf("帧序列 %v", kinds)
	}
}

// 一包里塞多种帧、末尾还有 STREAM（ngtcp2 的打包方式）。
func TestParseMixedFrames(t *testing.T) {
	var b []byte
	b = appendAck(b, []uint64{0, 1, 2}, 0)
	b = appendVarint(b, frNewConnID)
	b = appendVarint(b, 2)
	b = appendVarint(b, 0)
	b = appendVarint(b, 8)
	b = append(b, make([]byte, 8)...)
	b = append(b, make([]byte, 16)...)
	b = appendStream(b, 0, 0, []byte("hello"), true)

	kinds := frameKinds(t, b)
	if len(kinds) != 3 || kinds[0] != frAck || kinds[1] != frNewConnID {
		t.Fatalf("帧序列 %v", kinds)
	}
	if kinds[2] < frStreamBase || kinds[2] > 0x0f {
		t.Fatalf("最后一帧不是 STREAM: %#x", kinds[2])
	}
}
