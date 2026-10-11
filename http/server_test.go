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

//go:build linux || darwin

package http

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antlabs/fio/engine"
)

// startServer 起一个真实的 HTTP 服务端（engine 的 epoll 循环 + 这个包的
// ConnHandler）。
func startServer(t *testing.T, h Handler) (string, func()) {
	t.Helper()

	m, err := engine.NewAndStart(engine.WithEventLoops(1), engine.WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatal(err)
	}

	// accept 循环交给 engine.Listener：非阻塞 accept + 停止标志，
	// 两个平台的 Close 行为一致（见那个类型的说明）。
	ln, err := engine.ListenAndServe(m, "127.0.0.1:0", func() engine.Handler {
		// 每个连接一个 ConnHandler（各自的解析器和状态）
		return NewConnHandler(h, 0)
	})
	if err != nil {
		t.Fatal(err)
	}

	stop := func() {
		ln.Close()
		m.Free()
	}
	return ln.Addr(), stop
}

// 一个最简单的 GET，校验响应行、头、体。
func TestServerSimpleGet(t *testing.T) {
	addr, stop := startServer(t, HandlerFunc(func(c *Ctx) error {
		c.Set("Content-Type", "text/plain")
		c.Set("Content-Length", "5")
		c.Write([]byte("hello"))

		return nil
	}))
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET /hi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// 状态行
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 200 ") {
		t.Fatalf("状态行 = %q", line)
	}

	// 头
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}

	// 体
	body, err := io.ReadAll(br)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Errorf("响应体 = %q, want hello", body)
	}
}

// POST 带 body：服务端要能读出来。
func TestServerPostBody(t *testing.T) {
	type got struct{ method, path, body string }
	gotCh := make(chan got, 1)

	addr, stop := startServer(t, HandlerFunc(func(c *Ctx) error {
		select {
		case gotCh <- got{c.Method(), c.Target(), string(c.Body())}:
		default:
		}
		c.Set("Content-Length", "2")
		c.Write([]byte("ok"))

		return nil
	}))
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadAll(conn)

	select {
	case g := <-gotCh:
		if g.method != "POST" || g.path != "/submit" {
			t.Errorf("方法/路径 = %q/%q", g.method, g.path)
		}
		if g.body != "hello world" {
			t.Errorf("body = %q, want %q", g.body, "hello world")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler 没被调到")
	}
}

// keep-alive：一个连接上连续两个请求。
func TestKeepAlive(t *testing.T) {
	var mu sync.Mutex
	var paths []string

	addr, stop := startServer(t, HandlerFunc(func(c *Ctx) error {
		mu.Lock()
		paths = append(paths, c.Target())
		mu.Unlock()
		c.Set("Content-Length", "2")
		c.Write([]byte("ok"))

		return nil
	}))
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	br := bufio.NewReader(conn)

	send := func(path string) {
		req := "GET " + path + " HTTP/1.1\r\nHost: x\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		// 读状态行 + 头 + 2 字节体
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !strings.HasPrefix(line, "HTTP/1.1 200 ") {
			t.Fatalf("%s: 状态行 = %q", path, line)
		}
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if l == "\r\n" {
				break
			}
		}
		body := make([]byte, 2)
		if _, err := io.ReadFull(br, body); err != nil {
			t.Fatal(err)
		}
	}

	send("/first")
	send("/second")
	send("/third")

	mu.Lock()
	defer mu.Unlock()
	want := []string{"/first", "/second", "/third"}
	if len(paths) != len(want) {
		t.Fatalf("收到 %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("#%d = %q, want %q", i, paths[i], want[i])
		}
	}
}

// pipelining：一次把所有请求都发过去。
func TestPipelining(t *testing.T) {
	var mu sync.Mutex
	var paths []string

	addr, stop := startServer(t, HandlerFunc(func(c *Ctx) error {
		mu.Lock()
		paths = append(paths, c.Target())
		mu.Unlock()
		c.Set("Content-Length", "1")
		c.Write([]byte("x"))

		return nil
	}))
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 一口气发三个请求
	var all strings.Builder
	for _, p := range []string{"/a", "/b", "/c"} {
		all.WriteString("GET " + p + " HTTP/1.1\r\nHost: x\r\n\r\n")
	}
	if _, err := conn.Write([]byte(all.String())); err != nil {
		t.Fatal(err)
	}

	// 读三个响应
	br := bufio.NewReader(conn)
	for i := 0; i < 3; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("第 %d 个响应: %v", i, err)
		}
		if !strings.HasPrefix(line, "HTTP/1.1 200 ") {
			t.Fatalf("第 %d 个: 状态行 = %q", i, line)
		}
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if l == "\r\n" {
				break
			}
		}
		b := make([]byte, 1)
		if _, err := io.ReadFull(br, b); err != nil {
			t.Fatal(err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"/a", "/b", "/c"}
	if len(paths) != len(want) {
		t.Fatalf("收到 %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("#%d = %q, want %q", i, paths[i], want[i])
		}
	}
}

// 坏报文要回 400，不能把连接挂着。
//
// 用"chunk size 不是十六进制"来构造坏报文：httparser 对有些畸形是宽容的
// （比如头里没有冒号，它会跳过那一行继续解），真正会报错的是语法上没法
// 继续的地方。测试要挑后者，不然测的是 httparser 的宽容度而不是我们的
// 错误处理。
func TestBadRequest(t *testing.T) {
	addr, stop := startServer(t, HandlerFunc(func(c *Ctx) error {
		t.Error("坏报文不该走到业务处理")

		return nil
	}))
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	req := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "400") {
		t.Errorf("响应 = %q, 应该有 400", resp)
	}
}

// 响应没设状态码时默认 200。
func TestDefaultStatus(t *testing.T) {
	addr, stop := startServer(t, HandlerFunc(func(c *Ctx) error {
		c.Set("Content-Length", "2")
		c.Write([]byte("hi")) // 没调 WriteHeader

		return nil
	}))
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200 ") {
		t.Errorf("响应 = %q, 应该是 200", buf[:n])
	}
}

// 请求被切成很多小段发，服务端要能拼起来。
func TestSlowRequest(t *testing.T) {
	// 用 channel 而不是普通变量：handler 在事件循环的 goroutine 上跑，
	// 测试在另一个上读，普通变量就是数据竞争（-race 会报）。
	gotPath := make(chan string, 1)
	addr, stop := startServer(t, HandlerFunc(func(c *Ctx) error {
		select {
		case gotPath <- c.Target():
		default:
		}
		c.Set("Content-Length", "1")
		c.Write([]byte("x"))

		return nil
	}))
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n"
	for i := 0; i < len(req); i++ {
		if _, err := conn.Write([]byte{req[i]}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}

	buf := make([]byte, 256)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-gotPath:
		if p != "/slow" {
			t.Errorf("路径 = %q, want /slow", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler 没被调到")
	}
}
