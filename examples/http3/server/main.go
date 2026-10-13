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

// HTTP/3 服务端。
//
// 分工：QUIC 那层（UDP 上的可靠传输、握手、重传、拥塞控制）用 quic-go；
// HTTP/3 的帧层/varint 是 fio 自己实现的（http3/frame.go、varint.go）。
//
// 所以 handler 直接用 net/http 的接口——已有的业务代码搬过来就能跑
// （HTTP/3 在语义上和 HTTP/1.1、HTTP/2 是一回事）。
//
// QUIC 强制 TLS 1.3、必须有证书，这里用自签的（客户端要跳过验证）。
//
// 运行：
//
//	go run ./examples/http3/server
//
// 验证：
//
//	go run ./examples/http3/client
//
// 接口（业务在 serveHTTP 里）：
//
//	GET  /hello   回 "hello, GET /hello"
//	POST /echo    回显请求体
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/antlabs/fio/http3"
	fiotls "github.com/antlabs/fio/tls"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8003", "监听地址（UDP）")
	flag.Parse()

	cert, err := fiotls.SelfSignedCert()
	if err != nil {
		log.Fatal(err)
	}

	srv := &http3.Server{
		Addr:    *addr,
		Handler: http.HandlerFunc(serveHTTP),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Printf("HTTP/3 服务端: https://%s (UDP)", *addr)
	log.Fatal(srv.ListenAndServe())
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	body := fmt.Sprintf("hello, %s %s\n", r.Method, r.URL.Path)
	if r.URL.Path == "/echo" {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = string(b)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, body)
}
