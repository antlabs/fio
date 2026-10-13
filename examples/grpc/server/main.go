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

// gRPC 服务端（h2c，明文）。
//
// 分层：
//
//	engine（epoll/kqueue + 非阻塞 io）
//	  -> http2.StreamConnHandler（解帧、管流、HPACK）
//	    -> grpc.ServerHandler（认 :path 拆服务/方法、切消息、发 trailer 状态）
//	      -> 业务 Handler（下面这个 greeter）
//
// 全在事件循环的线程上，没有 per-connection 的 goroutine。
//
// **protobuf 编解码是业务的事**：fio 的 grpc 包管的是消息分帧（5 字节
// 头）和 trailer 里的状态，所以例子里直接把裸字节当消息。接真实业务时
// 在 Handler 里 Unmarshal 就行。
//
// 运行：
//
//	go run ./examples/grpc/server
//
// 验证：
//
//	go run ./examples/grpc/client
package main

import (
	"flag"
	"log"
	"log/slog"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/grpc"
	"github.com/antlabs/fio/http2"
)

// service / method 是这个例子的接口。gRPC 的 :path 是 "/服务/方法"，
// grpc.ServerHandler 会替业务拆好，放在 ServerCall.Service/Method 里。
const (
	service = "helloworld.Greeter"
	method  = "SayHello"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8004", "监听地址")
	flag.Parse()

	m, err := engine.NewAndStart(
		engine.WithEventLoops(0),
		engine.WithLogLevel(slog.LevelError),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer m.Free()

	ln, err := engine.ListenAndServe(m, *addr, func() engine.Handler {
		// gRPC 走**流级入口** NewStreamConnHandler：它要在帧上做文章
		// （认 :path、从 DATA 流里切消息、发 trailer）。
		// 请求级那个（NewConnHandler + http.Handler）是给普通 HTTP/2
		// 业务的，见 examples/http2/server。
		//
		// 每条连接一个：流的表是连接级的。
		return http2.NewStreamConnHandler(grpc.NewServerHandler(&greeter{}))
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("gRPC 服务端（h2c）: %s，接口 /%s/%s", ln.Addr(), service, method)
	select {}
}

// greeter 是业务，实现 grpc.Handler。
//
// 生命周期：OnCall（请求头到了）-> OnMessage（每收到一条完整消息）-> OnEnd
// （流的 END_STREAM 到了）。一元调用在 OnMessage 里回即可。
//
// 每条连接一个实例，回调都在同一条连接的 goroutine 上，不用加锁。
type greeter struct{}

func (g *greeter) OnCall(c *http2.Conn, call *grpc.ServerCall) error {
	log.Printf("调用开始: /%s/%s (流 %d)", call.Service, call.Method, call.StreamID)

	// 没实现的方法按 gRPC 的规矩回 UNIMPLEMENTED
	if call.Service != service || call.Method != method {
		return call.ReplyError(c, grpc.StatusUnimplemented("unknown method: /"+call.Service+"/"+call.Method))
	}
	return nil
}

func (g *greeter) OnMessage(c *http2.Conn, call *grpc.ServerCall, msg []byte) error {
	// **msg 只在下一次回调前有效**（指向解析器的内部缓冲），这里用完就回。
	// 要留着的话自己拷一份。
	return call.Reply(c, append([]byte("hello, "), msg...), grpc.StatusOK())
}

func (g *greeter) OnEnd(c *http2.Conn, call *grpc.ServerCall) error {
	// 一元调用在 OnMessage 里回过了。这里兜底：空请求（没有任何消息）
	// 也要回一条，不然客户端拿不到 trailer 里的状态。
	if !call.Replied() {
		return call.Reply(c, []byte("hello"), grpc.StatusOK())
	}
	return nil
}
