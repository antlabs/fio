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
	"testing"

	"github.com/antlabs/fio/http"
)

// 请求带 trailer：协议层要把第二个 HEADERS 当 trailer，而不是当成一个
// 缺 :method 的新请求（h2spec "POST with trailers" 的回归）。
func TestRequestTrailers(t *testing.T) {
	rec := &recorder{}
	srv := NewConn(false, rec)
	if _, _, err := srv.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}

	cli := NewConn(true, nil)
	in := cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
	}, false)
	in = append(in, AppendData(nil, 1, []byte("body"), false)...)
	in = append(in, cli.MustHeaders(1, []HeaderField{
		{Name: "x-checksum", Value: "abc"},
	}, true)...)

	if _, _, err := srv.Feed(in); err != nil {
		t.Fatalf("Feed: %v", err)
	}

	if len(rec.headers) != 2 {
		t.Fatalf("OnHeaders 调用 %d 次, want 2（请求头 + trailer）", len(rec.headers))
	}
	if rec.headers[0].endStream {
		t.Errorf("请求头不应该带 END_STREAM")
	}
	if !rec.headers[1].endStream {
		t.Errorf("trailer 应该带 END_STREAM")
	}
	if len(rec.headers[1].fields) != 1 || rec.headers[1].fields[0].Name != "x-checksum" ||
		rec.headers[1].fields[0].Value != "abc" {
		t.Errorf("trailer 字段 = %v", rec.headers[1].fields)
	}
	if string(rec.data) != "body" {
		t.Errorf("body = %q, want body", rec.data)
	}

	s := srv.GetStream(1)
	if s == nil {
		t.Fatal("流 1 不见了")
	}
	// **原来的请求头不能被 trailer 覆盖**
	if len(s.headers) == 0 || s.headers[0].Name != ":method" {
		t.Errorf("Stream.headers 被覆盖了: %v", s.headers)
	}
	if len(s.trailers) != 1 || s.trailers[0].Name != "x-checksum" {
		t.Errorf("Stream.trailers = %v", s.trailers)
	}
}

// GetStream 返回快照：拿到之后再来的 trailer 不能改已经返回的对象。
func TestGetStreamSnapshot(t *testing.T) {
	srv := NewConn(false, &recorder{})
	if _, _, err := srv.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}
	cli := NewConn(true, nil)
	if _, _, err := srv.Feed(cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
	}, false)); err != nil {
		t.Fatal(err)
	}

	before := srv.GetStream(1)
	if before == nil {
		t.Fatal("流 1 不见了")
	}
	if len(before.trailers) != 0 {
		t.Fatalf("快照里不该有 trailer: %v", before.trailers)
	}

	// 再来 trailer，活流会变，但 before 不能变。
	in := cli.MustHeaders(1, []HeaderField{{Name: "x-checksum", Value: "abc"}}, true)
	if _, _, err := srv.Feed(in); err != nil {
		t.Fatal(err)
	}
	if len(before.trailers) != 0 {
		t.Errorf("已经返回的快照被后续 trailer 改了: %v", before.trailers)
	}
	after := srv.GetStream(1)
	if after == nil || len(after.trailers) != 1 {
		t.Fatalf("新快照的 trailer = %v", after)
	}
	if before == after {
		t.Error("GetStream 应该每次返回新的快照")
	}
}

// 请求级 bridge：带 trailer 的请求只交给 handler 一次，body/请求头/
// trailer 都要对。
func TestRequestTrailersBridge(t *testing.T) {
	var (
		calls int
		got   http.Request
	)
	b := &httpBridge{
		h: http.HandlerFunc(func(c *http.Ctx) error {
			calls++
			// Request 的 Header/Body/Trailer 在 ServeHTTP 返回后会被
			// 还回池子，测试要留就得深拷。
			r := c.Request()
			got = *r
			got.Header = make(map[string]string, len(r.Header))
			for k, v := range r.Header {
				got.Header[k] = v
			}
			got.Body = append([]byte(nil), r.Body...)
			if len(r.Trailer) > 0 {
				got.Trailer = make(map[string]string, len(r.Trailer))
				for k, v := range r.Trailer {
					got.Trailer[k] = v
				}
			}
			return c.String("ok")
		}),
		maxHeaderSize: defMaxHeaderSize,
		streams:       make(map[uint32]*streamReq),
	}
	srv := NewConn(false, b)
	if _, _, err := srv.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}

	cli := NewConn(true, nil)
	in := cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
		{Name: "content-type", Value: "text/plain"},
	}, false)
	in = append(in, AppendData(nil, 1, []byte("hello"), false)...)
	in = append(in, cli.MustHeaders(1, []HeaderField{
		{Name: "x-checksum", Value: "abc"},
	}, true)...)

	if _, _, err := srv.Feed(in); err != nil {
		t.Fatalf("Feed: %v", err)
	}

	if calls != 1 {
		t.Fatalf("handler 调用 %d 次, want 1", calls)
	}
	if got.Method != "POST" || got.Target != "/upload" {
		t.Errorf("method/target = %s %s", got.Method, got.Target)
	}
	if string(got.Body) != "hello" {
		t.Errorf("body = %q", got.Body)
	}
	if got.Trailer["x-checksum"] != "abc" {
		t.Errorf("trailer = %v", got.Trailer)
	}
	if got.Header["content-type"] != "text/plain" {
		t.Errorf("请求头被覆盖了: %v", got.Header)
	}
}

// 1xx 信息响应不能当最终响应头：100 之后还要能正常收 200 + body。
func TestInformationalResponse(t *testing.T) {
	rec := &recorder{}
	cli := NewConn(true, rec)
	srv := NewConn(false, nil)

	// 客户端先开流并让服务端看到请求（服务端才知道流 1 存在）。
	req := cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
	}, true)
	if _, _, err := srv.Feed(req); err != nil {
		t.Fatal(err)
	}

	out := srv.MustHeaders(1, []HeaderField{{Name: ":status", Value: "100"}}, false)
	out = append(out, srv.MustHeaders(1, []HeaderField{{Name: ":status", Value: "200"}}, false)...)
	out = append(out, AppendData(nil, 1, []byte("ok"), true)...)

	if _, _, err := cli.Feed(out); err != nil {
		t.Fatalf("Feed: %v", err)
	}

	if len(rec.headers) != 2 {
		t.Fatalf("OnHeaders 调用 %d 次, want 2（100 + 200）", len(rec.headers))
	}
	if rec.headers[0].fields[0].Value != "100" || rec.headers[1].fields[0].Value != "200" {
		t.Errorf("状态 = %v / %v", rec.headers[0].fields, rec.headers[1].fields)
	}
	if string(rec.data) != "ok" {
		t.Errorf("body = %q", rec.data)
	}
}
