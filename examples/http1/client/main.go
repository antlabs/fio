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

// HTTP/1.1 客户端：**用标准库的 net/http**。
//
// fio 目前在 HTTP/1.1 上只有服务端（http/ 包做的是解析 + 响应），
// 客户端借标准库——对 fio 服务端来说，它就是个普通对端，正好也
// 验证了互通性。
//
// 运行（先起服务端）：
//
//	go run ./examples/http1/client
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8001", "服务端地址")
	flag.Parse()

	client := &http.Client{Timeout: 10 * time.Second}
	base := "http://" + *addr

	// GET：响应体是 "hello, GET /hello"
	resp, err := client.Get(base + "/hello")
	if err != nil {
		log.Fatal(err)
	}
	printResp(resp)

	// POST：服务端把请求体原样回显
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
