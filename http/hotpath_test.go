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

package http

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestStatusTextArray(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{200, "OK"},
		{404, "Not Found"},
		{511, "Network Authentication Required"},
		{599, "Status 599"},
		{999, "Status 999"},
	}
	for _, c := range cases {
		if got := StatusText(c.code); got != c.want {
			t.Errorf("StatusText(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

func TestInternHeaderName(t *testing.T) {
	for _, name := range []string{
		"Host", "host", "Content-Length", "content-length",
		"User-Agent", "user-agent", "X-Unknown", "",
	} {
		if got := internHeaderName([]byte(name)); got != name {
			t.Errorf("internHeaderName(%q) = %q", name, got)
		}
	}
}

// 命中 intern 表时不能分配（map 查找的 string(name) 是只读 key，
// 编译器不该把它堆分配）。
func TestInternHeaderNameNoAlloc(t *testing.T) {
	name := []byte("content-length")
	allocs := testing.AllocsPerRun(1000, func() {
		_ = internHeaderName(name)
	})
	if allocs != 0 {
		t.Fatalf("internHeaderName 每次分配 %.2f 次, want 0", allocs)
	}
}

func TestWantCloseFromParser(t *testing.T) {
	cases := []struct {
		name string
		req  string
		want bool
	}{
		{"1.1 默认复用", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", false},
		{"1.1 close", "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", true},
		{"1.0 默认关", "GET / HTTP/1.0\r\nHost: x\r\n\r\n", true},
		{"1.0 keep-alive", "GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n", false},
		{"多 token", "GET / HTTP/1.1\r\nConnection: keep-alive, close\r\n\r\n", true},
		{"无关 token", "GET / HTTP/1.1\r\nConnection: upgrade\r\n\r\n", false},
	}
	for _, c := range cases {
		p := NewParser(0)
		if _, err := p.Parse([]byte(c.req)); err != nil {
			t.Fatalf("%s: Parse: %v", c.name, err)
		}
		r := p.Request()
		if r == nil {
			t.Fatalf("%s: 没解析出 Request", c.name)
		}
		if got := wantClose(r); got != c.want {
			t.Errorf("%s: wantClose = %v, want %v", c.name, got, c.want)
		}
	}

	// 手工构造、没经过 parser 的 Request 走兼容路径。
	r := &Request{
		Proto:  proto11,
		Header: map[string]string{"Connection": "close"},
	}
	if !wantClose(r) {
		t.Error("手工 Request 的 Connection: close 没生效")
	}
}

// 小块走 chunkBuf 一次写、大块走 writev：两种路径的字节都要对。
func TestChunkedSmallAndLargeChunk(t *testing.T) {
	small := []byte("small-")
	large := bytes.Repeat([]byte("x"), 5000)

	addr, stop := startHTTPServer(t, HandlerFunc(func(c *Ctx) error {
		if _, err := c.Write(small); err != nil {
			return err
		}
		_, err := c.Write(large)
		return err
	}))
	defer stop()

	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Get("http://" + addr + "/chunked")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读 body: %v", err)
	}
	want := append(append([]byte(nil), small...), large...)
	if !bytes.Equal(body, want) {
		t.Fatalf("body 长度 = %d, want %d", len(body), len(want))
	}
}
