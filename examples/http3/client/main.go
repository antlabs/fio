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

// HTTP/3 客户端。
//
// http3.NewClient 返回的就是标准库的 *http.Client，Transport 换成
// fio 的 http3.Transport（底层 quic-go 走 UDP）——请求/响应的代码
// 和 HTTP/1.1 那份一模一样，差别只在 Transport。打印的 resp.Proto
// 会是 "HTTP/3.0"。
//
// 运行（先起服务端）：
//
//	go run ./examples/http3/client
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/antlabs/fio/http3"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8003", "服务端地址")
	flag.Parse()

	// 服务端是自签证书，跳过验证。真实场景这里换成正常的证书配置
	client := http3.NewClient(&tls.Config{InsecureSkipVerify: true})
	defer client.CloseIdleConnections()

	base := "https://" + *addr

	// GET
	resp, err := client.Get(base + "/hello")
	if err != nil {
		log.Fatal(err)
	}
	printResp(resp)

	// POST
	resp, err = client.Post(base+"/echo", "text/plain", strings.NewReader("你好, fio"))
	if err != nil {
		log.Fatal(err)
	}
	printResp(resp)
}

func printResp(resp *http.Response) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s %s -> %s %d, 响应体: %s",
		resp.Request.Method, resp.Request.URL.Path, resp.Proto, resp.StatusCode, body)
}
