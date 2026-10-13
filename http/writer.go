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

package http

import "github.com/antlabs/fio/engine"

// Writer 是 Ctx 对"写响应"的全部要求。
//
// **抽成接口是为了让 http2 复用同一套 Ctx 和同一个 handler**：http1 的实现
// 是 ResponseWriter（本包，先攒头、第一次 Write 时一次发出去）；http2 的
// 实现在 http2 包里（响应编成 HEADERS/DATA 帧）。handler 只看得到 Ctx，
// 所以 `func(c *Ctx) error` 这种 handler 两个协议都能挂——和 net/http
// 一个 handler 既能服务 h1 又能服务 h2 是一个意思。
type Writer interface {
	// Header 是还没发出去的头（名字 -> 值）。
	Header() map[string][]string

	// WriteHeader 设状态码（重复调只认第一次）。
	WriteHeader(code int)

	// Write 写响应体。第一次写会把头一起发出去。
	Write(body []byte) (int, error)

	// WriteRaw 绕过响应拼装直接写（要手写一整条响应时用）。
	WriteRaw(b []byte) error

	// WritePrepared 写一整条已经拼好的响应（静态文件那种）。
	WritePrepared(b []byte) error

	// Defer 声明这次响应稍后再写。**只有 http1 支持**（见 Ctx.Defer）；
	// http2 那边是个空操作。
	Defer()

	// Conn 底层 engine 连接（拿对端地址、或者查协议状态用）。没有底层
	// 连接的实现可以返回 nil。
	Conn() *engine.Conn

	// PutString 把值包成单元素切片交给 Header 用。
	//
	// 存在的理由是实现方可以复用上一次的切片（见 ResponseWriter 里
	// putString 的说明：那一步曾经占全部堆分配的 19.9%）。
	PutString(value string) []string
}
