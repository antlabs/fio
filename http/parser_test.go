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
	"strings"
	"testing"
)

// feedAll 一次喂完整个报文, 返回解出来的请求。
func feedAll(t *testing.T, raw string) *Request {
	t.Helper()
	p := NewParser(0)
	n, err := p.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Done() {
		t.Fatalf("报文没解完(消化了 %d/%d)", n, len(raw))
	}
	return p.Request()
}

func TestSimpleGet(t *testing.T) {
	req := feedAll(t, "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.Target != "/hello" {
		t.Errorf("Target = %q, want /hello", req.Target)
	}
	if got, _ := req.Get("host"); got != "example.com" {
		t.Errorf("Host = %q, want example.com", got)
	}
}

// 头名大小写无关: Get 用小写也能查到 "Content-Length"。
func TestHeaderLookupCaseInsensitive(t *testing.T) {
	req := feedAll(t, "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
	if got, _ := req.Get("content-length"); got != "5" {
		t.Errorf("content-length = %q, want 5", got)
	}
	if req.ContentLength != 5 {
		t.Errorf("ContentLength = %d, want 5", req.ContentLength)
	}
	if string(req.Body) != "hello" {
		t.Errorf("Body = %q, want hello", req.Body)
	}
}

// 分帧用的头名也大小写无关（RFC 9110 5.1）。
//
// Get 那边一直是无关的（上面那个测试），但**解析器认头决定分帧**的地方
// 原来是精确比：小写 `content-length` 看不见，请求被当成没有体。arena 的
// 碎裂测试就发小写，响应因此少了那 20 字节的 body。
func TestFramingHeadersCaseInsensitive(t *testing.T) {
	req := feedAll(t, "POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello")
	if string(req.Body) != "hello" {
		t.Errorf("小写 content-length: Body = %q, want hello", req.Body)
	}
	if req.ContentLength != 5 {
		t.Errorf("小写 content-length: ContentLength = %d, want 5", req.ContentLength)
	}

	raw := "POST / HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n0\r\n\r\n"
	req = feedAll(t, raw)
	if string(req.Body) != "hello" {
		t.Errorf("小写 transfer-encoding: Body = %q, want hello", req.Body)
	}

	p := NewParser(0)
	if _, err := p.Parse([]byte("GET / HTTP/1.1\r\nupgrade: websocket\r\n\r\n")); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Upgrade() {
		t.Error("小写 upgrade 没被认出来")
	}
}

// POST 带 Content-Length 的 body。
func TestPostBody(t *testing.T) {
	req := feedAll(t, "POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world")
	if string(req.Body) != "hello world" {
		t.Errorf("Body = %q, want %q", req.Body, "hello world")
	}
	if req.ContentLength != 11 {
		t.Errorf("ContentLength = %d, want 11", req.ContentLength)
	}
}

// chunked body。
func TestChunkedBody(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n" +
		"6\r\n world\r\n" +
		"0\r\n\r\n"
	req := feedAll(t, raw)
	if string(req.Body) != "hello world" {
		t.Errorf("Body = %q, want %q", req.Body, "hello world")
	}
}

// 逐字节喂。这是非阻塞 io 最要紧的一条: TCP 会在任意位置切, 解析器不能
// 假设一次拿到一整行——包括 CR 和 LF 分在两次里(自己写解析器时就是这里
// 出的 bug)。
func TestByteByByte(t *testing.T) {
	raw := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world"

	// 按契约来: 没消化的字节留着, 和新读到的拼一起再喂。
	p := NewParser(0)
	var pending []byte
	for i := 0; i < len(raw); i++ {
		pending = append(pending, raw[i])
		n, err := p.Parse(pending)
		if err != nil {
			t.Fatalf("第 %d 个字节: %v", i, err)
		}
		pending = pending[n:]
		if p.Done() {
			if i != len(raw)-1 {
				t.Fatalf("提前结束: 第 %d 个字节就 done 了, 一共 %d", i, len(raw))
			}
			break
		}
	}
	if !p.Done() {
		t.Fatal("逐字节喂完之后还没解完")
	}
	req := p.Request()
	if req.Method != "POST" || req.Target != "/submit" {
		t.Errorf("Method/Target = %q/%q", req.Method, req.Target)
	}
	if string(req.Body) != "hello world" {
		t.Errorf("Body = %q", req.Body)
	}
	if got, _ := req.Get("Host"); got != "example.com" {
		t.Errorf("Host = %q", got)
	}
}

// chunked 也逐字节喂一遍。
func TestChunkedByteByByte(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"a\r\n0123456789\r\n0\r\n\r\n"

	p := NewParser(0)
	var pending []byte
	for i := 0; i < len(raw); i++ {
		pending = append(pending, raw[i])
		n, err := p.Parse(pending)
		if err != nil {
			t.Fatalf("第 %d 个字节: %v", i, err)
		}
		pending = pending[n:]
		if p.Done() {
			break
		}
	}
	if !p.Done() {
		t.Fatal("没解完")
	}
	if got := string(p.Request().Body); got != "0123456789" {
		t.Errorf("Body = %q, want 0123456789", got)
	}
}

// keep-alive: 一个 read 里两个请求, 第一个解析完返回消化量, 剩下的留给
// 下一个。
func TestPipelinedRequests(t *testing.T) {
	first := "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
	second := "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
	raw := first + second

	p := NewParser(0)
	n, err := p.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Done() {
		t.Fatal("第一个请求没解完")
	}
	if p.Request().Target != "/a" {
		t.Fatalf("Target = %q, want /a", p.Request().Target)
	}
	// 消化量应该停在第一个请求的末尾(后面还有第二个请求的字节)
	if n >= len(raw) {
		t.Fatalf("消化了 %d 字节, 应该停在第一个请求结束(%d)", n, len(first))
	}

	// 剩下的字节是第二个请求
	p.Reset()
	if _, err := p.Parse([]byte(raw[n:])); err != nil {
		t.Fatal(err)
	}
	if !p.Done() || p.Request().Target != "/b" {
		t.Fatalf("第二个请求: done=%v target=%q", p.Done(), p.Request().Target)
	}
}

// websocket 握手是 Upgrade 请求: Done 为真、Upgrade 为真, 升级之后同一个
// 缓冲区里跟的是帧数据(不是 HTTP), 所以消化量要停在报文末尾。
func TestUpgradeRequest(t *testing.T) {
	raw := "GET /ws HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	p := NewParser(0)
	n, err := p.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Done() {
		t.Fatal("握手请求没解完")
	}
	if !p.Upgrade() {
		t.Fatal("Upgrade() = false, 这明明是一个升级请求")
	}
	if n != len(raw) {
		t.Errorf("消化了 %d 字节, 报文是 %d 字节", n, len(raw))
	}
	req := p.Request()
	if got, _ := req.Get("Sec-WebSocket-Key"); got != "dGhlIHNhbXBsZSBub25jZQ==" {
		t.Errorf("Sec-WebSocket-Key = %q", got)
	}
}

// 同一个头出现两次, 值要合并。
func TestDuplicateHeader(t *testing.T) {
	req := feedAll(t, "GET / HTTP/1.1\r\nX-A: 1\r\nX-A: 2\r\n\r\n")
	got, _ := req.Get("X-A")
	if !strings.Contains(got, "1") || !strings.Contains(got, "2") {
		t.Errorf("X-A = %q, 两个值都该在", got)
	}
}

// 没有 Content-Length 也没有 chunked 的请求: 没有 body。
func TestNoBody(t *testing.T) {
	req := feedAll(t, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if len(req.Body) != 0 {
		t.Errorf("Body = %q, want empty", req.Body)
	}
	if req.ContentLength != -1 {
		t.Errorf("ContentLength = %d, want -1(没有这个头)", req.ContentLength)
	}
}

// Reset 之后可以解析下一个请求(keep-alive 的常规用法)。
func TestResetReuses(t *testing.T) {
	p := NewParser(0)
	for i := 0; i < 3; i++ {
		raw := "GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
		if _, err := p.Parse([]byte(raw)); err != nil {
			t.Fatalf("第 %d 轮: %v", i, err)
		}
		if !p.Done() || p.Request().Target != "/x" {
			t.Fatalf("第 %d 轮: done=%v", i, p.Done())
		}
		p.Reset()
	}
}

// 超长的头要被 MaxHeaderSize 挡住(防"一直发头不结尾"把内存吃光)。
//
// httparser 的 MaxHeaderSize 是**单行**上限(它自己的注释: "header单行
// 最大限制为4k"), 而且判断是 len(buf[i:]) > MaxHeaderSize——看的是这次
// 喂进来的缓冲里还剩多少, 不是这一行的长度。所以要用"一行很长、而且
// 没有行尾"的报文来触发它, 一次喂完整行反而可能绕过(行尾一到, 判断就
// 不是那条路了)。
func TestHeaderSizeLimit(t *testing.T) {
	p := NewParser(1024) // 1KB 上限, 方便测
	// 一行 4KB 的头而且不带 CRLF: 解析器在这一行里出不去, 应该被拦住
	raw := "GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("v", 4096)
	_, err := p.Parse([]byte(raw))
	if err == nil {
		t.Fatal("超长的一行应该报错")
	}
}

// 坏报文要报错, 不能悄悄当成好报文。
func TestBadRequests(t *testing.T) {
	for _, c := range []struct {
		name, raw string
	}{
		{"chunk size 非法", "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"},
	} {
		p := NewParser(0)
		if _, err := p.Parse([]byte(c.raw)); err == nil {
			t.Errorf("%s: 应该报错", c.name)
		}
	}
}
