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

package grpc

import (
	"bytes"
	"errors"
	"testing"
)

// collect 把 data 全喂进去，返回切出来的消息。
func collect(t *testing.T, p *MessageParser, data []byte) [][]byte {
	t.Helper()
	var msgs [][]byte
	n, err := p.Parse(data, func(msg []byte) error {
		msgs = append(msgs, append([]byte(nil), msg...))
		return nil
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if n != len(data) {
		t.Fatalf("消化了 %d 字节, 喂进去 %d", n, len(data))
	}
	return msgs
}

// 一条消息：编码再解码，对得上。
func TestMessageRoundTrip(t *testing.T) {
	msg := []byte("hello grpc")
	encoded := Encode(nil, msg)

	p := NewMessageParser(0)
	got := collect(t, p, encoded)
	if len(got) != 1 {
		t.Fatalf("切出 %d 条消息, want 1", len(got))
	}
	if !bytes.Equal(got[0], msg) {
		t.Errorf("消息 = %q, want %q", got[0], msg)
	}
}

// 一个 DATA 帧里好几条消息，都要切出来。
func TestMultipleMessages(t *testing.T) {
	msgs := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	encoded := EncodeAll(nil, msgs...)

	p := NewMessageParser(0)
	got := collect(t, p, encoded)
	if len(got) != len(msgs) {
		t.Fatalf("切出 %d 条, want %d", len(got), len(msgs))
	}
	for i := range msgs {
		if !bytes.Equal(got[i], msgs[i]) {
			t.Errorf("#%d = %q, want %q", i, got[i], msgs[i])
		}
	}
}

// 一条消息跨好几个 DATA 帧（真实客户端会这么干）。
func TestMessageSplitAcrossFrames(t *testing.T) {
	msg := []byte("a message that spans several data frames")
	encoded := Encode(nil, msg)

	// 逐字节喂
	p := NewMessageParser(0)
	var got [][]byte
	pending := 0
	for i := 0; i < len(encoded); i++ {
		n, err := p.Parse(encoded[i:i+1], func(m []byte) error {
			got = append(got, append([]byte(nil), m...))
			return nil
		})
		if err != nil {
			t.Fatalf("第 %d 字节: %v", i, err)
		}
		if n < 0 || n > 1 {
			t.Fatalf("第 %d 字节: 消化量 %d", i, n)
		}
		pending = p.Buffered()
		_ = pending
	}
	if len(got) != 1 {
		t.Fatalf("切出 %d 条消息, want 1", len(got))
	}
	if !bytes.Equal(got[0], msg) {
		t.Errorf("消息 = %q", got[0])
	}
	if p.Buffered() != 0 {
		t.Errorf("还有 %d 字节攒着", p.Buffered())
	}
}

// 大消息跨很多帧：每次都把未消费的部分往前搬的话是 O(n²)，这里用
// 1MB / 4KB 一帧把正确性和攒缓冲的路径都过一遍。
func TestLargeMessageAcrossManyFrames(t *testing.T) {
	const (
		size  = 1 << 20
		frame = 4096
	)
	msg := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	wire := Encode(nil, msg)

	p := NewMessageParser(0)
	var got []byte
	for off := 0; off < len(wire); {
		n := frame
		if off+n > len(wire) {
			n = len(wire) - off
		}
		if _, err := p.Parse(wire[off:off+n], func(m []byte) error {
			got = append(got, m...)
			return nil
		}); err != nil {
			t.Fatalf("offset %d: %v", off, err)
		}
		off += n
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("消息长度 = %d, want %d", len(got), len(msg))
	}
	if p.Buffered() != 0 {
		t.Errorf("还有 %d 字节攒着", p.Buffered())
	}
}

// 一次喂一条半：切出一条，剩下半条留着。
func TestPartialMessageBuffered(t *testing.T) {
	first := Encode(nil, []byte("first"))
	second := Encode(nil, []byte("second"))
	all := append(append([]byte(nil), first...), second...)

	p := NewMessageParser(0)

	// 先喂"第一条 + 第二条的头"
	cut := len(first) + 3
	got := collect(t, p, all[:cut])
	if len(got) != 1 || string(got[0]) != "first" {
		t.Fatalf("第一次: 切出 %v", got)
	}
	if p.Buffered() == 0 {
		t.Fatal("第二条的半截应该攒着")
	}

	// 再喂剩下的
	var got2 [][]byte
	if _, err := p.Parse(all[cut:], func(m []byte) error {
		got2 = append(got2, append([]byte(nil), m...))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got2) != 1 || string(got2[0]) != "second" {
		t.Fatalf("第二次: 切出 %v, want [second]", got2)
	}
	if p.Buffered() != 0 {
		t.Errorf("还有 %d 字节攒着", p.Buffered())
	}
}

// 空消息（长度 0）是合法的。
func TestEmptyMessage(t *testing.T) {
	encoded := Encode(nil, []byte{})
	p := NewMessageParser(0)
	got := collect(t, p, encoded)
	if len(got) != 1 {
		t.Fatalf("切出 %d 条, want 1", len(got))
	}
	if len(got[0]) != 0 {
		t.Errorf("消息应该是空的, got %q", got[0])
	}
}

// 压缩标志为 1 要报错（我们还没做压缩）。
func TestCompressedRejected(t *testing.T) {
	// 手工拼一个压缩标志为 1 的头
	buf := []byte{1, 0, 0, 0, 3, 'a', 'b', 'c'}
	p := NewMessageParser(0)
	_, err := p.Parse(buf, func([]byte) error { return nil })
	if !errors.Is(err, ErrCompressed) {
		t.Fatalf("err = %v, want ErrCompressed", err)
	}
}

// 超过大小上限要报错（防对端声明一个 4GB 的消息）。
func TestMessageTooLarge(t *testing.T) {
	// 头里声明 100 字节，上限设 10
	buf := []byte{0, 0, 0, 0, 100}
	p := NewMessageParser(10)
	_, err := p.Parse(buf, func([]byte) error { return nil })
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err = %v, want ErrMessageTooLarge", err)
	}
}

// 回调返回错误要停下来，错误要传出来。
func TestCallbackError(t *testing.T) {
	msgs := [][]byte{[]byte("a"), []byte("b")}
	encoded := EncodeAll(nil, msgs...)

	p := NewMessageParser(0)
	boom := errors.New("boom")
	count := 0
	_, err := p.Parse(encoded, func([]byte) error {
		count++
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if count != 1 {
		t.Errorf("回调被调了 %d 次, want 1", count)
	}
}

// 空输入不该 panic，也不该产出消息。
func TestEmptyInput(t *testing.T) {
	p := NewMessageParser(0)
	n, err := p.Parse(nil, func([]byte) error {
		t.Fatal("空输入不该有消息")
		return nil
	})
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

// Reset 之后状态清干净（一个流结束、复用它）。
func TestReset(t *testing.T) {
	p := NewMessageParser(0)
	all := Encode(nil, []byte("abcde"))
	// 喂一半，攒着
	p.Parse(all[:4], func([]byte) error { return nil })
	if p.Buffered() == 0 {
		t.Fatal("应该有半条攒着")
	}
	p.Reset()
	if p.Buffered() != 0 {
		t.Fatalf("Reset 之后还有 %d 字节", p.Buffered())
	}
	// Reset 之后完整喂一条要能切出来
	got := collect(t, p, all)
	if len(got) != 1 || string(got[0]) != "abcde" {
		t.Fatalf("切出 %v", got)
	}
}
