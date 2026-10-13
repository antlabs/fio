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

// HTTP/2 客户端：fio 自己的客户端连接（跑在事件循环上，不用 net/http）。
//
// 流程：
//
//  1. net.Dial 建 TCP，dup 出 fd 交给事件循环（m.Add）
//  2. Add 会往事件循环投递 OnOpen——里面发客户端序言 + SETTINGS
//     （fio 的 ConnHandler 自动做）
//  3. SyncOnLoop 保证 OnOpen 跑完，然后在事件循环 goroutine 上发请求
//  4. 响应在 clientHandler 的回调里收
//
// 两条请求发在两条流上、共用一条连接——这就是 HTTP/2 的多路复用，
// HTTP/1.1 的例子里做不到（那边只能排队或者开两条连接）。
//
// 运行（先起服务端）：
//
//	go run ./examples/http2/client
package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/http2"
	"golang.org/x/sys/unix"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8002", "服务端地址")
	flag.Parse()

	m, err := engine.NewAndStart(
		engine.WithEventLoops(1),
		engine.WithLogLevel(slog.LevelError),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer m.Free()

	// 建非阻塞连接，fd 交给事件循环
	fd, err := dial(*addr)
	if err != nil {
		log.Fatalf("连接 %s: %v", *addr, err)
	}

	h := newClientHandler(2 /* 等两条响应 */)
	ch := http2.NewClientConnHandler(h)
	c, err := m.Add(fd, ch)
	if err != nil {
		unix.Close(fd)
		log.Fatal(err)
	}

	// **SyncOnLoop**：把函数投到这条连接所属的事件循环上跑，等它跑完。
	// 任务队列是 FIFO，Add 时投的 OnOpen 保证在这之前执行，所以此时
	// ch.Conn()（OnOpen 里建的协议状态）一定已经好了。
	c.SyncOnLoop(func() {
		conn := ch.Conn()

		// 流 1：GET /hello，没有体，HEADERS 直接带 END_STREAM
		s1 := conn.NewStreamID()
		if err := ch.WriteHeaders(c, s1, requestHeaders("GET", "/hello", *addr), true); err != nil {
			log.Printf("流 %d 写请求头: %v", s1, err)
			return
		}

		// 流 2：POST /echo，先头发体（END_STREAM=false），再 DATA 收尾
		s2 := conn.NewStreamID()
		if err := ch.WriteHeaders(c, s2, requestHeaders("POST", "/echo", *addr), false); err != nil {
			log.Printf("流 %d 写请求头: %v", s2, err)
			return
		}
		if err := ch.WriteData(c, s2, []byte("你好, fio"), true); err != nil {
			log.Printf("流 %d 写请求体: %v", s2, err)
		}
	})

	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		log.Fatal("等响应超时")
	}
}

// requestHeaders 攒一条请求的头。
//
// :method/:scheme/:authority/:path 是 HTTP/2 的伪头（RFC 9113 8.3），
// 必须在普通头前面。HTTP/2 没有请求行（"GET /hello HTTP/1.1" 那行），
// 方法、路径全在这里。
func requestHeaders(method, path, authority string) []http2.HeaderField {
	return []http2.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
}

// dial 建 TCP 连接，给事件循环一份**非阻塞的 fd**。
//
// 为什么要 dup：net.Conn 析构时会关它那个 fd，事件循环得用自己的一份。
// 这是 websocket 客户端 Dial 同样的做法（见 websocket/upgrade.go 的
// getFdFromConn）。
func dial(addr string) (int, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("net.Dial 返回的连接不支持 SyscallConn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}

	var fd int
	if err := raw.Control(func(f uintptr) { fd = int(f) }); err != nil {
		return 0, err
	}

	nfd, err := unix.Dup(fd)
	if err != nil {
		return 0, err
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return 0, err
	}
	return nfd, nil
}

// clientHandler 收响应，实现 http2.StreamHandler。
//
// 回调在事件循环的 goroutine 上跑，main 在 done 上等——两边碰的
// resp/want 要加锁。
type clientHandler struct {
	mu   sync.Mutex
	resp map[uint32]*response
	want int
	done chan struct{}
}

type response struct {
	status int
	body   []byte
}

func newClientHandler(want int) *clientHandler {
	return &clientHandler{
		resp: make(map[uint32]*response),
		want: want,
		done: make(chan struct{}),
	}
}

func (h *clientHandler) OnHeaders(c *http2.Conn, streamID uint32, headers []http2.HeaderField, endStream bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	r := h.get(streamID)
	for _, f := range headers {
		if f.Name == ":status" {
			r.status, _ = strconv.Atoi(f.Value)
		}
	}
}

func (h *clientHandler) OnData(c *http2.Conn, streamID uint32, data []byte, endStream bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	r := h.get(streamID)
	r.body = append(r.body, data...)
	if !endStream {
		return
	}

	fmt.Printf("流 %d: %d, 响应体: %s", streamID, r.status, r.body)

	h.want--
	if h.want == 0 {
		close(h.done)
	}
}

func (h *clientHandler) OnRSTStream(c *http2.Conn, streamID uint32, code http2.ErrCode) {
	log.Printf("流 %d 被服务端重置: %s", streamID, code)
}

// get 取流的响应状态，没有就建一个。调用方持有 h.mu。
func (h *clientHandler) get(streamID uint32) *response {
	r := h.resp[streamID]
	if r == nil {
		r = &response{}
		h.resp[streamID] = r
	}
	return r
}
