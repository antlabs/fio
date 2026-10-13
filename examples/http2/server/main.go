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
// 循环上：引擎喂字节 -> Conn.Feed 解帧 -> 业务回调（StreamHandler）。
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
// 接口（业务在 echoHandler 里）：
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
		// **每条连接一个 ConnHandler + 一个业务 handler**：
		// HPACK 的动态表和流表都是连接级的，不能跨连接共用
		// （见 http2/conn.go 里 Conn 的说明）。
		return http2.NewConnHandler(newEchoHandler())
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("HTTP/2（h2c）服务端: http://%s", ln.Addr())
	select {}
}

// echoHandler 是流上的业务：收齐一条请求（头 + 体）就回一条响应。
//
// 实现 http2.StreamHandler 三个方法。每条连接一个实例，回调都在
// 同一条连接的事件循环 goroutine 上跑，所以下面这些 map 不用加锁。
type echoHandler struct {
	method map[uint32]string
	path   map[uint32]string
	body   map[uint32][]byte
}

func newEchoHandler() *echoHandler {
	return &echoHandler{
		method: make(map[uint32]string),
		path:   make(map[uint32]string),
		body:   make(map[uint32][]byte),
	}
}

// OnHeaders 一个流的请求头解完了（HPACK 已经解开）。
// headers 里 :method/:scheme/:authority/:path 是伪头（RFC 9113 8.3）。
func (h *echoHandler) OnHeaders(c *http2.Conn, streamID uint32, headers []http2.HeaderField, endStream bool) {
	for _, f := range headers {
		switch f.Name {
		case ":method":
			h.method[streamID] = f.Value
		case ":path":
			h.path[streamID] = f.Value
		}
	}

	// endStream：没有体的请求（GET），头收完就可以回了
	if endStream {
		h.reply(c, streamID)
	}
}

// OnData 流上的数据。endStream 为真的那次是这条流的最后一个数据块。
func (h *echoHandler) OnData(c *http2.Conn, streamID uint32, data []byte, endStream bool) {
	h.body[streamID] = append(h.body[streamID], data...)
	if endStream {
		h.reply(c, streamID)
	}
}

// OnRSTStream 对端重置了这条流，把状态清掉。
func (h *echoHandler) OnRSTStream(c *http2.Conn, streamID uint32, code http2.ErrCode) {
	log.Printf("流 %d 被对端重置: %s", streamID, code)
	h.cleanup(streamID)
}

// reply 回一条 200。和 HTTP/1.1 一样是两个动作：先头后体，
// 区别是 HTTP/2 里没有"连接"的概念，一切按流来。
func (h *echoHandler) reply(c *http2.Conn, streamID uint32) {
	body := fmt.Sprintf("hello, %s %s\n", h.method[streamID], h.path[streamID])
	if h.path[streamID] == "/echo" {
		body = string(h.body[streamID])
	}

	// :status 是响应伪头，必须在普通头前面。content-length 不是必须的
	// （流靠 END_STREAM 结束），写上只是让客户端提前知道长度。
	_ = c.WriteHeaders(streamID, []http2.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/plain; charset=utf-8"},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
	}, false)
	// 最后一个 DATA 带 END_STREAM，结束这条流
	_ = c.WriteData(streamID, []byte(body), true)

	h.cleanup(streamID)
}

func (h *echoHandler) cleanup(streamID uint32) {
	delete(h.method, streamID)
	delete(h.path, streamID)
	delete(h.body, streamID)
}
