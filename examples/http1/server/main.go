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

// HTTP/1.1 服务端：fio 的 http 包直接挂在 engine 的事件循环上。
//
// 运行：
//
//	go run ./examples/http1/server
//
// 验证：
//
//	go run ./examples/http1/client
//	curl -v http://127.0.0.1:8001/hello
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
	"strconv"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8001", "监听地址")
	flag.Parse()

	// 0 = 每个 CPU 一个事件循环。循环里跑 epoll/kqueue +
	// 非阻塞 io，handler 都在循环的 goroutine 上执行。
	m, err := engine.NewAndStart(
		engine.WithEventLoops(0),
		engine.WithLogLevel(slog.LevelError),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer m.Free()

	// accept 循环交给 engine.Listener
	ln, err := engine.ListenAndServe(m, *addr, func() engine.Handler {
		// **每条连接一个 ConnHandler**：HTTP/1.1 的解析器、keep-alive
		// 状态、ResponseWriter 都是连接级的，不能跨连接共用。
		// maxHeaderSize 传 0 = 用默认值。
		return http.NewConnHandler(http.HandlerFunc(serveHTTP), 0)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("HTTP/1.1 服务端: http://%s", ln.Addr())
	select {}
}

// serveHTTP 是业务。形状是 fiber 那种：一个 Ctx 参数，返回 error
// （Ctx 包着 fio 自己的 Request/ResponseWriter，解析器攒出来的）。
//
// **跑在事件循环上，不能阻塞**——要等什么东西得自己记状态、让出，
// 等下一次回调。
func serveHTTP(c *http.Ctx) error {
	body := fmt.Sprintf("hello, %s %s\n", c.Method(), c.Target())
	if c.Path() == "/echo" {
		body = string(c.Body())
	}

	// 设了 Content-Length 就不会走 chunked（RFC 9112 6.3）。
	// 两个都不给的话体的边界就没了，客户端会一直等——所以这里必须设。
	c.Set("Content-Type", "text/plain; charset=utf-8")
	c.Set("Content-Length", strconv.Itoa(len(body)))
	return c.String(body)
}
