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

package engine

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// echoHandler 是给测试用的协议：收到什么原样写回去。
//
// 这也是 Handler 接口该有的样子——协议的实现者只要管"这些字节什么意思"，
// epoll 注册、非阻塞读写、部分写、EAGAIN 全是引擎的事。
type echoHandler struct{}

func (echoHandler) OnOpen(*Conn) {}

func (echoHandler) OnData(c *Conn, buf []byte) (int, error) {
	n := len(buf)
	if err := c.Write(buf); err != nil {
		return 0, err
	}
	return n, nil
}

func (echoHandler) OnClose(*Conn, error) {}

// lineHandler 每次只吃一行，测试"协议说还不够"这条路。
type lineHandler struct {
	mu    sync.Mutex
	lines []string
	done  chan struct{}
}

func (h *lineHandler) OnOpen(*Conn) {}

func (h *lineHandler) OnData(c *Conn, buf []byte) (int, error) {
	// 找一行
	for i, b := range buf {
		if b != '\n' {
			continue
		}
		line := string(buf[:i])
		h.mu.Lock()
		h.lines = append(h.lines, line)
		closed := len(h.lines) >= 3
		h.mu.Unlock()
		if closed && h.done != nil {
			select {
			case <-h.done:
			default:
				close(h.done)
			}
		}
		// 吃掉这一行（含换行），剩下的留给下一次
		return i + 1, nil
	}
	// 还没有换行，一行都没凑齐
	return 0, nil
}

func (h *lineHandler) OnClose(*Conn, error) {}

// startServer 起一个监听 fd，用 engine 的循环 accept 它。
//
// 返回监听地址和一个关停函数。
func startServer(t *testing.T, h Handler) (string, func()) {
	t.Helper()

	m, err := NewAndStart(WithEventLoops(1), WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatal(err)
	}

	// 监听 socket 和 accept 循环交给 engine.Listener。
	//
	// **不能用"阻塞 accept + close(lfd) 唤醒"那套**：Linux 上 close()
	// 不唤醒另一个线程里已经阻塞在 accept() 的调用（那个线程持有文件
	// 描述的引用），于是 stop() 里 <-acceptDone 永远等不到，测试挂到
	// 超时；darwin 的 kqueue 会唤醒，所以本机跑得通——这种平台差异
	// 只有跨平台跑才打得出来。Listener 用非阻塞 accept + 停止标志，
	// 两个平台行为一致（见那个类型的说明）。
	ln, err := ListenAndServe(m, "127.0.0.1:0", func() Handler { return h })
	if err != nil {
		t.Fatal(err)
	}

	stop := func() {
		ln.Close() // 停 accept 循环、关监听 fd
		m.Free()
	}
	return ln.Addr(), stop
}

// TestEcho 最基本的一条：连上、发数据、原样收回来。
func TestEcho(t *testing.T) {
	addr, stop := startServer(t, echoHandler{})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("hello engine")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Errorf("got %q, want %q", got, msg)
	}
}

// 一次写多条，服务端一次 read 可能全收到——echo 要原样回来，不能串。
func TestEchoBatch(t *testing.T) {
	addr, stop := startServer(t, echoHandler{})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const n = 50
	const each = 100
	var want []byte
	for i := 0; i < n; i++ {
		chunk := make([]byte, each)
		for j := range chunk {
			chunk[j] = byte('a' + i%26)
		}
		want = append(want, chunk...)
	}
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个字节: got %q, want %q", i, got[i], want[i])
		}
	}
}

// 对端一次灌进来一大片数据时，读缓冲区不能为了"一次把 socket 读空"
// 一路翻倍——每批最多 batchReadBufferSize，协议消费完再读下一批。
//
// 这是 Pipeline 内存的回归测试：改之前 10000 连接、客户端 send-ahead
// 几十 KB 时，每条连接的读缓冲区会长到 128KB，堆上 1GB；这里用一次
// 256KB 的写入复现"socket 里有一大片"的条件。
type burstHandler struct {
	want   int
	got    int
	maxBuf int
	done   chan struct{}
	once   sync.Once
}

func (h *burstHandler) OnOpen(*Conn) {}

func (h *burstHandler) OnData(_ *Conn, buf []byte) (int, error) {
	if len(buf) > h.maxBuf {
		h.maxBuf = len(buf)
	}
	h.got += len(buf)
	if h.got >= h.want {
		h.once.Do(func() { close(h.done) })
	}
	return len(buf), nil
}

func (h *burstHandler) OnClose(*Conn, error) {}

func TestReadBatchStaysBounded(t *testing.T) {
	const want = 256 * 1024
	h := &burstHandler{want: want, done: make(chan struct{})}
	addr, stop := startServer(t, h)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 一次写一大片，让服务端的 socket 接收队列里同时躺着多批数据。
	if _, err := conn.Write(make([]byte, want)); err != nil {
		t.Fatal(err)
	}

	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("只收到 %d/%d 字节，maxBuf=%d", h.got, want, h.maxBuf)
	}
	if h.got != want {
		t.Fatalf("收到 %d 字节，want %d", h.got, want)
	}
	// 池按 1KB 分档、每档多带一个帧头的余量（16KB 档实际 16398），
	// 这里留一点余量；要抓的是 32KB/128KB 那种翻倍增长。
	if h.maxBuf > batchReadBufferSize+64 {
		t.Fatalf("单次交给协议的缓冲区 %d 字节，超过一批 %d", h.maxBuf, batchReadBufferSize)
	}
}

// 协议说"还不够"时数据要留着：一行一行地喂，每行到齐才回调一次。
//
// 这是 Handler 契约的核心——OnData 返回 0 不是错误，是"再给我点"。
func TestPartialMessage(t *testing.T) {
	h := &lineHandler{done: make(chan struct{})}
	addr, stop := startServer(t, h)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 一次只发一个字节，中间还有停顿
	lines := []string{"aaa", "bbb", "ccc"}
	for _, ln := range lines {
		for i := 0; i < len(ln); i++ {
			if _, err := conn.Write([]byte{ln[i]}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Millisecond)
		}
		if _, err := conn.Write([]byte{'\n'}); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		h.mu.Lock()
		t.Fatalf("超时, 收到 %v", h.lines)
		h.mu.Unlock()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.lines) != len(lines) {
		t.Fatalf("收到 %d 行, want %d: %v", len(h.lines), len(lines), h.lines)
	}
	for i := range lines {
		if h.lines[i] != lines[i] {
			t.Errorf("第 %d 行 = %q, want %q", i, h.lines[i], lines[i])
		}
	}
}

// 多条连接同时在。它们按 fd 分片到同一个循环上，互不干扰。
func TestManyConns(t *testing.T) {
	addr, stop := startServer(t, echoHandler{})
	defer stop()

	const conns = 20
	var wg sync.WaitGroup
	errCh := make(chan error, conns)

	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()

			msg := []byte{byte('A' + id%26), byte('0' + id%10), 'x', 'y', 'z'}
			if _, err := conn.Write(msg); err != nil {
				errCh <- err
				return
			}
			got := make([]byte, len(msg))
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				errCh <- err
				return
			}
			if string(got) != string(msg) {
				errCh <- io.ErrUnexpectedEOF
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// 对端关了以后，OnClose 要调到（连接要能回收）。
func TestClose(t *testing.T) {
	closed := make(chan struct{}, 1)
	h := &closeHandler{onClose: func() {
		select {
		case closed <- struct{}{}:
		default:
		}
	}}
	addr, stop := startServer(t, h)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	// 发点东西确认连上了，再关
	conn.Write([]byte("hi"))
	time.Sleep(50 * time.Millisecond)
	conn.Close()

	// 对端关掉之后，服务端下一次读会读到 EOF。往下要主动去读——ET 模式
	// 下 FIN 会来一个可读事件，引擎会读到 0。这里给它个机会。
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("5 秒内没等到 OnClose")
	}
}

type closeHandler struct {
	onClose func()
}

func (h *closeHandler) OnOpen(*Conn) {}

func (h *closeHandler) OnData(c *Conn, buf []byte) (int, error) {
	// 读到 0 字节说明是 FIN
	if len(buf) == 0 {
		return 0, io.EOF
	}
	return len(buf), nil
}

func (h *closeHandler) OnClose(*Conn, error) {
	if h.onClose != nil {
		h.onClose()
	}
}

// TestPostOnLoop 投到循环上的任务会被执行，而且投递方不等它。
//
// 和 SyncOnLoop 的区别就是这个"不等"：投完立刻返回，任务在循环上跑。
// http 的 /delay 收尾走这条路（见 PostOnLoop 的说明）。
func TestPostOnLoop(t *testing.T) {
	ran := make(chan struct{}, 1)
	h := &postHandler{onPost: func() {
		select {
		case ran <- struct{}{}:
		default:
		}
	}}
	addr, stop := startServer(t, h)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("5 秒内没等到投上去的任务执行")
	}
}

// postHandler 收到任何数据就在自己的循环上投一个任务。
type postHandler struct {
	onPost func()
}

func (h *postHandler) OnOpen(*Conn) {}

func (h *postHandler) OnData(c *Conn, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, io.EOF
	}
	c.PostOnLoop(h.onPost)
	return len(buf), nil
}

func (h *postHandler) OnClose(*Conn, error) {}
