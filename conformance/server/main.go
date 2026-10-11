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

// 这个程序是给**协议一致性测试套件**打的服务端。
//
// 它不做什么业务，就是把 fio 的各协议栈按真实的样子挂起来，让外面的
// 测试工具（h2spec、Autobahn、openssl……）来打。
//
// 用法：
//
//	go run ./conformance/server -proto=h2c  -addr=127.0.0.1:8080
//	go run ./conformance/server -proto=h2   -addr=127.0.0.1:8443   # TLS + h2
//	go run ./conformance/server -proto=http -addr=127.0.0.1:8081
//	go run ./conformance/server -proto=grpc -addr=127.0.0.1:8082
//
// 用命令行参数而不是配置文件：一致性测试要能一条命令起一个干净的进程，
// 测完就杀掉（测试套件自己会反复重启服务端）。
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/grpc"
	"github.com/antlabs/fio/http"
	"github.com/antlabs/fio/http2"
	fiotls "github.com/antlabs/fio/tls"
)

func main() {
	proto := flag.String("proto", "h2c", "h2c | h2 | http | grpc")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	m, err := engine.NewAndStart(engine.WithEventLoops(4))
	if err != nil {
		log.Fatal(err)
	}

	var newHandler func() engine.Handler
	switch *proto {
	case "h2c":
		// 明文 HTTP/2（h2spec 默认打这个）
		newHandler = func() engine.Handler {
			return http2.NewConnHandler(&h2Handler{})
		}
	case "h2":
		// TLS 上的 HTTP/2——**必须配 NextProtos**，不然客户端
		// （h2spec、浏览器、grpc-go）会因为协商不出 ALPN 直接拒绝
		cert, err := fiotls.SelfSignedCert()
		if err != nil {
			log.Fatal(err)
		}
		newHandler = func() engine.Handler {
			return fiotls.NewConnHandler(&fiotls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{fiotls.ALPNProtoH2},
			}, http2.NewConnHandler(&h2Handler{}))
		}
	case "http":
		newHandler = func() engine.Handler {
			return http.NewConnHandler(http.HandlerFunc(serveHTTP), 0)
		}
	case "grpc":
		newHandler = func() engine.Handler {
			return http2.NewConnHandler(grpc.NewServerHandler(&grpcHandler{}))
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown proto %q\n", *proto)
		os.Exit(2)
	}

	ln, err := engine.ListenAndServe(m, *addr, newHandler)
	if err != nil {
		log.Fatal(err)
	}
	// 打到 stdout 上是为了让脚本能读到实际端口（-addr 用 :0 的时候）
	fmt.Printf("listening %s proto=%s\n", ln.Addr(), *proto)
	os.Stdout.Sync()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ln.Close()
	m.Free()
}

// h2Handler 是最小的 HTTP/2 业务：回 200 + 一点内容。
//
// 一致性测试关心的是**帧层面的行为**（流状态、SETTINGS、流控、错误
// 处理），不是业务语义——所以这里越简单越好，别让它成为干扰因素。
type h2Handler struct{}

func (h *h2Handler) OnHeaders(c *http2.Conn, streamID uint32, headers []http2.HeaderField, endStream bool) {
	if err := c.WriteHeaders(streamID, []http2.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/plain"},
	}, false); err != nil {
		return
	}
	if endStream {
		_ = c.WriteData(streamID, nil, true)
	}
}

func (h *h2Handler) OnData(c *http2.Conn, streamID uint32, data []byte, endStream bool) {
	if endStream {
		_ = c.WriteData(streamID, nil, true)
	}
}

func (h *h2Handler) OnRSTStream(c *http2.Conn, streamID uint32, code http2.ErrCode) {}

// serveHTTP 是 HTTP/1.1 的业务。
//
// 形状就是 fiber 那种：一个参数，返回 error。
func serveHTTP(c *http.Ctx) error {
	body := "hello from fio\n"
	c.Set("Content-Length", fmt.Sprint(len(body)))
	return c.String(body)
}

// grpcHandler 是 gRPC 的业务：把请求消息前面加个 "echo: " 回过去。
type grpcHandler struct{}

func (g *grpcHandler) OnCall(c *http2.Conn, call *grpc.ServerCall) error { return nil }

func (g *grpcHandler) OnMessage(c *http2.Conn, call *grpc.ServerCall, msg []byte) error {
	if call.Replied() {
		return nil
	}
	return call.Reply(c, append([]byte("echo: "), msg...), grpc.StatusOK())
}

func (g *grpcHandler) OnEnd(c *http2.Conn, call *grpc.ServerCall) error {
	if !call.Replied() {
		return call.Reply(c, []byte("echo: "), grpc.StatusOK())
	}
	return nil
}
