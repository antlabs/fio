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

// gRPC 客户端：fio 自己的连接（跑在事件循环上，不用 grpc-go）。
//
// 连接和 examples/http2/client 一个路子（dial -> engine -> 自己的
// StreamHandler），区别在流上跑的东西：gRPC 的消息要过 grpc.Call 那一层
// ——写出去的消息加 5 字节头分帧，收到的 DATA 流切成一条条消息，调用的
// 成败看 trailer 里的 grpc-status（不是 HTTP 状态码）。
//
// 运行（先起服务端）：
//
//	go run ./examples/grpc/client
package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/grpc"
	"github.com/antlabs/fio/http2"
	"golang.org/x/sys/unix"
)

const (
	service = "helloworld.Greeter"
	method  = "SayHello"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8004", "服务端地址")
	msg := flag.String("msg", "world", "发给服务端的消息")
	flag.Parse()

	m, err := engine.NewAndStart(
		engine.WithEventLoops(1),
		engine.WithLogLevel(slog.LevelError),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer m.Free()

	fd, err := dial(*addr)
	if err != nil {
		log.Fatalf("连接 %s: %v", *addr, err)
	}

	h := newClientHandler()
	ch := http2.NewClientConnHandler(h)
	c, err := m.Add(fd, ch)
	if err != nil {
		unix.Close(fd)
		log.Fatal(err)
	}

	// SyncOnLoop：等 OnOpen（客户端序言 + SETTINGS）跑完再发调用。
	// 闭包在事件循环 goroutine 上跑，和响应回调是同一个 goroutine，
	// 所以 h.call 不用加锁。
	c.SyncOnLoop(func() {
		conn := ch.Conn()
		call, err := grpc.NewClientConn(conn).Call(service, method, []byte(*msg))
		if err != nil {
			log.Printf("发起调用: %v", err)
			return
		}
		h.call = call

		// grpc 的写先进 http2.Conn 的发送缓冲，这里把它刷给引擎。
		// （业务平时走 ConnHandler.WriteHeaders 那套，里面自带 flush；
		// grpc.Call 直接写协议状态，所以要自己刷。）
		if out := conn.TakeOutput(); len(out) > 0 {
			if err := c.Write(out); err != nil {
				log.Printf("发送: %v", err)
			}
		}
	})

	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		log.Fatal("等响应超时")
	}
}

// dial 建 TCP 连接，dup 出非阻塞 fd 给事件循环
// （和 examples/http2/client 里那份一样）。
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

// clientHandler 把 http2 的流事件转给 grpc.Call。
//
// 回调都在事件循环的 goroutine 上跑；h.call 也是在同一个 goroutine 上写
// 的（SyncOnLoop 的闭包），main 只在 done 上等——所以字段不用加锁。
type clientHandler struct {
	// call 当前这次调用（例子只有一条流，就不按 streamID 建表了）
	call *grpc.Call
	// done 调用结束（trailer 到了）
	done chan struct{}
}

func newClientHandler() *clientHandler {
	return &clientHandler{done: make(chan struct{})}
}

func (h *clientHandler) OnHeaders(c *http2.Conn, streamID uint32, headers []http2.HeaderField, endStream bool) {
	if h.call == nil || streamID != h.call.StreamID {
		return
	}
	// 响应头和 trailer 都走这里。带 grpc-status 的那次是 trailer，
	// Call 自己会认（认到就 Done）。
	h.call.OnHeaders(headers, endStream)
	h.finishIfDone()
}

func (h *clientHandler) OnData(c *http2.Conn, streamID uint32, data []byte, endStream bool) {
	if h.call == nil || streamID != h.call.StreamID {
		return
	}
	// 从 DATA 流里切消息：一条消息可能跨多个 DATA 帧，Call 的解析器
	// 会自己攒，攒齐一条回调一次。
	if err := h.call.OnData(data, func(msg []byte) error {
		fmt.Printf("收到消息: %s\n", msg)
		return nil
	}); err != nil {
		log.Printf("解消息: %v", err)
	}
}

func (h *clientHandler) OnRSTStream(c *http2.Conn, streamID uint32, code http2.ErrCode) {
	log.Printf("流 %d 被服务端重置: %s", streamID, code)
}

// finishIfDone 调用结束了（trailer 到了）就打印状态收尾。
func (h *clientHandler) finishIfDone() {
	if h.call == nil || !h.call.Done() {
		return
	}
	st := h.call.Status()
	fmt.Printf("调用结束: code=%s message=%q\n", st.Code, st.Message)

	select {
	case <-h.done:
	default:
		close(h.done)
	}
}
