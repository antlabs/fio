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

package qpack

import (
	"bytes"
	"io"
	"strings"
	"testing"

	qpackgo "github.com/quic-go/qpack"
)

// decodeAll 把 ours 的字段块整个解出来。
func decodeAll(t *testing.T, block []byte) []HeaderField {
	t.Helper()
	dec := NewDecoder().Decode(block)
	var out []HeaderField
	for {
		hf, err := dec()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("解码失败: %v", err)
		}
		out = append(out, hf)
	}
}

// encodeAll 用 ours 编一块头。
func encodeAll(t *testing.T, fields []HeaderField) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	fields := []HeaderField{
		{Name: ":method", Value: "GET"},        // 静态表完整匹配（18）
		{Name: ":scheme", Value: "https"},      // 完整匹配（24）
		{Name: ":authority", Value: "a.com"},   // 名字在表里、值不在
		{Name: ":path", Value: "/x?y=1"},       // 同上
		{Name: "x-custom", Value: "hello"},     // 名字也不在
		{Name: "x-custom", Value: ""},          // 空值
		{Name: "content-length", Value: "7"},   // 名字在表里
		{Name: "user-agent", Value: "fio/1.0"}, // 都不在
	}
	block := encodeAll(t, fields)
	got := decodeAll(t, block)
	if len(got) != len(fields) {
		t.Fatalf("解出 %d 个字段，期望 %d", len(got), len(fields))
	}
	for i := range fields {
		if got[i] != fields[i] {
			t.Fatalf("第 %d 个字段: 得到 %+v，期望 %+v", i, got[i], fields[i])
		}
	}
}

// 字段块前缀必须是两个 0 字节（RIC=0 用 8 位前缀，Delta Base=0 用 7 位前缀）。
func TestPrefixBytes(t *testing.T) {
	block := encodeAll(t, []HeaderField{{Name: ":status", Value: "200"}})
	want := []byte{0x00, 0x00, 0xd9} // 索引字段行：1 T=1 index=25（:status 200）
	if !bytes.Equal(block, want) {
		t.Fatalf("编码结果 % x，期望 % x", block, want)
	}
}

// 和 quic-go/qpack 的编解码器互通：我们编、它解；它编、我们解。
//
// **这是这个包最重要的测试**：客户端（arena 的压测端）用的是 quic-go 的
// qpack，两边任何一个字节对不上都是整条请求挂掉。
func TestInteropWithQuicGo(t *testing.T) {
	fields := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "127.0.0.1:8443"},
		{Name: ":path", Value: "/plaintext"},
		{Name: "user-agent", Value: "quic-go"},
		{Name: "accept", Value: "*/*"},
		{Name: "x-weird-header-with-a-long-name", Value: strings.Repeat("v", 100)},
	}

	// 1. 我们编 -> quic-go 解
	ours := encodeAll(t, fields)
	godec := qpackgo.NewDecoder().Decode(ours)
	for i, want := range fields {
		hf, err := godec()
		if err != nil {
			t.Fatalf("quic-go 解第 %d 个字段失败: %v", i, err)
		}
		got := HeaderField{Name: hf.Name, Value: hf.Value}
		if got != want {
			t.Fatalf("第 %d 个字段: quic-go 解出 %+v，期望 %+v", i, got, want)
		}
	}
	if _, err := godec(); err != io.EOF {
		t.Fatalf("解完之后的 err = %v，期望 io.EOF", err)
	}

	// 2. quic-go 编 -> 我们解
	var buf bytes.Buffer
	genc := qpackgo.NewEncoder(&buf)
	for _, f := range fields {
		if err := genc.WriteField(qpackgo.HeaderField{Name: f.Name, Value: f.Value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := genc.Close(); err != nil {
		t.Fatal(err)
	}
	got := decodeAll(t, buf.Bytes())
	if len(got) != len(fields) {
		t.Fatalf("解出 %d 个字段，期望 %d", len(got), len(fields))
	}
	for i := range fields {
		if got[i] != fields[i] {
			t.Fatalf("第 %d 个字段: 得到 %+v，期望 %+v", i, got[i], fields[i])
		}
	}
}

// 空块就是两个前缀字节。
func TestEmptyBlock(t *testing.T) {
	block := encodeAll(t, nil)
	if len(block) != 2 || block[0] != 0 || block[1] != 0 {
		t.Fatalf("空块 % x", block)
	}
	if got := decodeAll(t, block); len(got) != 0 {
		t.Fatalf("空块解出 %d 个字段", len(got))
	}
}

// 动态表引用（RIC != 0）必须报错——我们的 SETTINGS 声明容量为 0。
func TestDynamicTableRejected(t *testing.T) {
	dec := NewDecoder().Decode([]byte{0x01, 0x00, 0x80})
	if _, err := dec(); err == nil {
		t.Fatal("RIC != 0 应该报错")
	}
}

// 索引越界要报错（静态表只有 99 项）。
func TestBadIndex(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc.WriteField(HeaderField{Name: ":status", Value: "200"}); err != nil {
		t.Fatal(err)
	}
	enc.Close()
	block := buf.Bytes()
	block[2] = 0xff // 索引字段行、6 位前缀全 1 → 后面跟续字节
	block = append(block[:3], 0x7f)
	dec := NewDecoder().Decode(block)
	if _, err := dec(); err == nil {
		t.Fatal("索引越界应该报错")
	}
}
