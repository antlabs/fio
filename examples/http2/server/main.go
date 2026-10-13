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

// HTTP/2 服务端（h2c，明文）。
//
// fio 的 http2 包是帧层 + 流 + HPACK 的完整实现，挂在 engine 的事件
// 循环上：引擎喂字节 -> Conn.Feed 解帧 -> 业务回调。
//
// **业务这一端的形状和 HTTP/1.1 那边一模一样**（见 examples/http1/server）：
//
//	func serveHTTP(c *http.Ctx) error
//
//	http2.NewConnHandler(http.HandlerFunc(serveHTTP), 0)
//	http.NewConnHandler(http.HandlerFunc(serveHTTP), 0)
//
// 同一个 serveHTTP 两个协议都能挂——HTTP/2 那层（HEADERS/DATA 拼成请求、
// 响应编回帧）由请求级的 ConnHandler 做。
//
// 要自己处理流级事件（HEADERS/DATA/RST 自己管状态）的话用
// NewStreamConnHandler：gRPC 走那条（conformance/server 的 -proto=grpc），
// 客户端本来就是流级的（见 examples/http2/client）。
//
// 这里用 h2c（明文）而不是 TLS：例子里只有帧和流，没有 TLS 的干扰。
// TLS 上的 HTTP/2 见 conformance/server（-proto=h2）——HTTP/2 外面
// 包一层 fiotls.NewConnHandler，NextProtos 配 "h2" 即可。
//
// 运行：
//
//	go run ./examples/http2/server
//
// 验证：
//
//	go run ./examples/http2/client
//
// 接口（业务在 serveHTTP 里）：
//
//	GET  /hello   回 "hello, GET /hello"
//	POST /echo    回显请求体
package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/http"
	"github.com/antlabs/fio/http2"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8002", "监听地址")
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
		// **每条连接一个 ConnHandler**：HPACK 的动态表和流表都是连接级的，
		// 不能跨连接共用（见 http2/conn.go 里 Conn 的说明）。
		// maxHeaderSize 传 0 = 用默认值。
		return http2.NewConnHandler(http.HandlerFunc(serveHTTP), 0)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("HTTP/2（h2c）服务端: http://%s", ln.Addr())
	select {}
}

// serveHTTP 是业务。形状和 HTTP/1.1 那边完全一样：一个 Ctx 参数、
// 返回 error（Ctx 包着 Request/ResponseWriter 那套）。
//
// **跑在事件循环上，不能阻塞**——要等什么东西得自己记状态、让出，
// 等下一次回调。
func serveHTTP(c *http.Ctx) error {
	body := fmt.Sprintf("hello, %s %s\n", c.Method(), c.Target())
	if c.Path() == "/echo" {
		body = string(c.Body())
	}

	// HTTP/2 的流靠 END_STREAM 结束，content-length 不是必须的；设上是为了
	// 和 HTTP/1.1 那边的行为对齐。
	c.Set("Content-Type", "text/plain; charset=utf-8")
	c.Set("Content-Length", fmt.Sprint(len(body)))
	return c.String(body)
}
