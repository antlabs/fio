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
	"sync"
	"testing"

	"github.com/antlabs/fio/http2"
)

// Call 的收包侧字段由回调 goroutine 写，Status/Done/Headers 可能由用户
// goroutine 读——-race 下必须干净。
func TestCallConcurrentReads(t *testing.T) {
	c := NewCall(1)

	resp := []http2.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: ContentType},
	}
	trailer := []http2.HeaderField{
		{Name: headerStatus, Value: "0"},
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.Done()
				_ = c.Status()
				_ = c.Headers()
			}
		}()
	}

	// 收包 goroutine：先反复收响应头，再收 trailer。
	for i := 0; i < 2000; i++ {
		c.OnHeaders(resp, false)
	}
	c.OnHeaders(trailer, true)
	close(stop)
	readers.Wait()

	if !c.Done() {
		t.Fatal("Done() = false, trailer 已经收到了")
	}
	if st := c.Status(); st == nil || st.Code != OK {
		t.Fatalf("Status() = %v", st)
	}
	if got := c.Headers(); len(got) != len(resp) {
		t.Fatalf("Headers() = %v", got)
	}
}

// ServerCall.replied 用 atomic：并发 Reply/Replied 不能有竞争。
func TestServerCallConcurrentReply(t *testing.T) {
	conn := http2.NewConn(false, nil)
	sc := &ServerCall{StreamID: 2, parser: NewMessageParser(0)}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = sc.Reply(conn, nil, nil)
				_ = sc.Replied()
			}
		}()
	}
	wg.Wait()
	if !sc.Replied() {
		t.Fatal("Replied() = false, Reply 已经调用过")
	}
}
