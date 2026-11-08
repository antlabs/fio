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

package http2

import (
	"sync"
	"testing"
)

// TestConcurrentSendAndFeed 覆盖「发送路径」和「收包路径」并发：
//
//	writer goroutine × N : NewStreamID + WriteHeaders + WriteData
//	producer goroutine   : 用另一条 Conn 造响应帧
//	feed goroutine       : 把响应帧喂回同一条 Conn
//
// 修复前这条连接上的 streams 表、HPACK 编码器和 outBuf 会被收发两边
// 同时读写（go test -race 直接报；map 上还可能直接 fatal）。
func TestConcurrentSendAndFeed(t *testing.T) {
	const (
		writers   = 8
		perWriter = 50
		total     = writers * perWriter
	)

	cli := NewConn(true, nil) // 被并发读写的连接
	srv := NewConn(false, nil)

	ids := make(chan uint32, total)
	resp := make(chan []byte, 64)

	// 响应生产者：给每个客户端流写 HEADERS + DATA(END_STREAM)。
	var producerWG sync.WaitGroup
	producerWG.Add(1)
	go func() {
		defer producerWG.Done()
		for id := range ids {
			if err := srv.WriteHeaders(id, []HeaderField{
				{Name: ":status", Value: "200"},
			}, false); err != nil {
				t.Errorf("WriteHeaders(%d): %v", id, err)
				return
			}
			if err := srv.WriteData(id, []byte("ok"), true); err != nil {
				t.Errorf("WriteData(%d): %v", id, err)
				return
			}
			if out := srv.TakeOutput(); len(out) > 0 {
				resp <- append([]byte(nil), out...)
			}
		}
	}()

	// 收包：和上面的 writer 并发跑在同一条 cli 上。
	var feedWG sync.WaitGroup
	feedWG.Add(1)
	go func() {
		defer feedWG.Done()
		for b := range resp {
			if _, _, err := cli.Feed(b); err != nil {
				t.Errorf("Feed: %v", err)
				return
			}
		}
	}()

	reqFields := []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/echo"},
		{Name: ":authority", Value: "example.test"},
	}

	var (
		writerWG sync.WaitGroup
		mu       sync.Mutex
		seen     = make(map[uint32]struct{}, total)
	)
	for w := 0; w < writers; w++ {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			for i := 0; i < perWriter; i++ {
				id := cli.NewStreamID()
				if err := cli.WriteHeaders(id, reqFields, false); err != nil {
					t.Errorf("client WriteHeaders(%d): %v", id, err)
					return
				}
				if err := cli.WriteData(id, []byte("hello"), true); err != nil {
					t.Errorf("client WriteData(%d): %v", id, err)
					return
				}

				mu.Lock()
				if _, dup := seen[id]; dup {
					t.Errorf("重复的流 ID: %d", id)
				}
				seen[id] = struct{}{}
				mu.Unlock()

				// 请求已经完整写出去了，才让对端回响应。
				ids <- id

				// 顺手把发送缓冲取走，避免 outBuf 无限增长。
				_ = cli.TakeOutput()
			}
		}()
	}

	writerWG.Wait()
	close(ids)
	producerWG.Wait()
	close(resp)
	feedWG.Wait()

	if len(seen) != total {
		t.Fatalf("流 ID 数量 = %d, want %d", len(seen), total)
	}
}

// ConnHandler.Conn / OnClose 用 atomic.Pointer：用户从别的 goroutine 取
// Conn() 和连接关闭并发时不能有竞争。
func TestConnHandlerConnAtomic(t *testing.T) {
	ch := NewStreamConnHandler(nil)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10000; j++ {
				_ = ch.Conn()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 10000; j++ {
			ch.OnClose(nil, nil)
		}
	}()
	wg.Wait()

	if ch.Conn() != nil {
		t.Fatal("关闭后 Conn() 应该返回 nil")
	}
}

// SetHandler 可以在收包期间并发调用（atomic.Pointer）。
func TestSetHandlerConcurrent(t *testing.T) {
	c := NewConn(false, &recorder{})
	if _, _, err := c.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			c.SetHandler(&recorder{})
		}
	}()

	// 每条请求都会走到 getHandler()，和上面的 SetHandler 并发。
	cli := NewConn(true, nil)
	fields := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
	}
	for i := 0; i < 2000; i++ {
		in := cli.MustHeaders(uint32(2*i+1), fields, true)
		if _, _, err := c.Feed(in); err != nil {
			t.Fatalf("Feed: %v", err)
		}
	}
	<-done
}

// TestConcurrentTrailers 检查 trailer 路径也在锁内推进流状态。
//
// 小头块的 WriteTrailers 原来只写帧、不调 applyLocalEndStreamLocked，
// 流会一直停在 half-closed(remote) 留在表里；并发下更是直接漏状态。
func TestConcurrentTrailers(t *testing.T) {
	const total = 100

	c := NewConn(false, nil)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			if err := c.WriteHeaders(id, []HeaderField{
				{Name: ":status", Value: "200"},
			}, false); err != nil {
				t.Errorf("WriteHeaders(%d): %v", id, err)
				return
			}
			// 模拟请求方向已经 END_STREAM（gRPC 一元调用就是这种）：
			// 之后 trailer 发出去，流两边都结束，应该从表里删掉。
			c.mu.Lock()
			c.applyRecvEndStream(c.streams[id], true)
			c.mu.Unlock()

			if err := c.WriteTrailers(id, []HeaderField{
				{Name: "grpc-status", Value: "0"},
			}); err != nil {
				t.Errorf("WriteTrailers(%d): %v", id, err)
			}
		}(uint32(2 * (i + 1)))
	}
	wg.Wait()

	if n := len(c.streams); n != 0 {
		t.Fatalf("trailer 之后残留 %d 条流, want 0", n)
	}
}
