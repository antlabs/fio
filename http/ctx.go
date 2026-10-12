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

import (
	"strconv"
	"strings"

	"github.com/antlabs/fio/engine"
)

// Ctx 是一次请求的上下文：请求和响应都在它身上。
//
// 形状取自 fiber 的回调——**handler 只收一个参数**，返回 error：
//
//	http.HandlerFunc(func(c *http.Ctx) error {
//	    return c.String("ok")
//	})
//
// 为什么合成一个参数：net/http 那两个参数（w, r）每次都得写两个名字，而
// 绝大多数 handler 两样都要碰。合成一个之后签名短了，而且能返回 error
// 让收尾统一处理（见 ConnHandler.OnData 里对 err 的分支）。
//
// **一次请求一个，不跨请求存活**：keep-alive 的下一个请求会复用同一个
// Ctx（重新绑到新的请求和响应上），所以别把它存起来——要留的东西自己拷。
type Ctx struct {
	req *Request
	w   *ResponseWriter
}

// reset 把 Ctx 绑到这一轮的请求和响应上（连接级复用）。
func (c *Ctx) reset(w *ResponseWriter, r *Request) {
	c.w = w
	c.req = r
}

// ── 请求 ────────────────────────────────────────────────────────────────────

// Method 请求方法，原样（"GET"、"POST"……）。
func (c *Ctx) Method() string { return c.req.Method }

// Proto 请求的版本（"HTTP/1.1"、"HTTP/1.0"）。
func (c *Ctx) Proto() string { return c.req.Proto }

// Target 请求目标，原样（可能带查询串、可能是绝对 URI）。
func (c *Ctx) Target() string { return c.req.Target }

// Path 请求目标里 '?' 之前那一段。
func (c *Ctx) Path() string {
	if i := strings.IndexByte(c.req.Target, '?'); i >= 0 {
		return c.req.Target[:i]
	}
	return c.req.Target
}

// Query 取一个查询参数，没有就是空串。
//
// **不做 URL 解码**：请求行里的百分号编码原样返回。要解码的话调用方自己
// url.QueryUnescape——路由匹配用的是原样的字节，两处用同一份值不容易出
// 岔子。
func (c *Ctx) Query(name string) string {
	query := c.req.Target
	if i := strings.IndexByte(query, '?'); i >= 0 {
		query = query[i+1:]
	} else {
		return ""
	}
	for query != "" {
		var pair string
		if i := strings.IndexByte(query, '&'); i >= 0 {
			pair, query = query[:i], query[i+1:]
		} else {
			pair, query = query, ""
		}
		k, v, _ := strings.Cut(pair, "=")
		if k == name {
			return v
		}
	}
	return ""
}

// Get 按名字取一个请求头，大小写无关。
func (c *Ctx) Get(name string) (string, bool) { return c.req.Get(name) }

// Body 请求体。Content-Length 的和 chunked 的都已经拼成完整一块。
func (c *Ctx) Body() []byte { return c.req.Body }

// Request 要原样的请求（结构和 Ctx 一样，一次请求内有效）。
func (c *Ctx) Request() *Request { return c.req }

// ── 响应 ────────────────────────────────────────────────────────────────────

// Status 设状态码。重复调只认第一次。
func (c *Ctx) Status(code int) *Ctx {
	c.w.WriteHeader(code)
	return c
}

// Set 设一个响应头。**同名会覆盖**（fiber 的 Set 也是这个语义）：路由里
// 写头的顺序不好保证，追加的话会出现两个同名头。
func (c *Ctx) Set(name, value string) *Ctx {
	h := c.w.Header()
	if _, ok := h[name]; ok {
		h[name] = append(h[name][:0], value)
		return c
	}
	h[name] = c.w.putString(value)
	return c
}

// Write 写响应体。第一次写会把头一起发出去。
func (c *Ctx) Write(body []byte) (int, error) { return c.w.Write(body) }

// Bytes 写一段字节（没设 Content-Type 的话设成 application/octet-stream）。
func (c *Ctx) Bytes(b []byte) error {
	if !c.hasHeader("Content-Type") {
		c.Set("Content-Type", "application/octet-stream")
	}
	_, err := c.w.Write(b)
	return err
}

// String 回一段文本（没设 Content-Type 的话设成 text/plain）。
func (c *Ctx) String(s string) error {
	if !c.hasHeader("Content-Type") {
		c.Set("Content-Type", "text/plain")
	}
	_, err := c.w.Write([]byte(s))
	return err
}

// hasHeader 响应头里有没有这个名字（大小写无关，和 hasHeaderName 一个口径）。
func (c *Ctx) hasHeader(name string) bool { return hasHeaderName(c.w.Header(), name) }

// Int 回一个整数的十进制文本。
func (c *Ctx) Int(n int) error { return c.String(strconv.Itoa(n)) }

// Conn 底层连接（要拿对端地址、或者自己手写响应的时候用）。
func (c *Ctx) Conn() *engine.Conn { return c.w.Conn() }

// WriteRaw 绕过响应拼装直接写（要手写一整条响应的时候用）。
func (c *Ctx) WriteRaw(b []byte) error { return c.w.WriteRaw(b) }

// WritePrepared 写一整条**已经拼好**的响应（见 ResponseWriter.WritePrepared）。
// 静态文件那种"内容恒定、整条在缓存里"的响应走这条最省。
func (c *Ctx) WritePrepared(b []byte) error { return c.w.WritePrepared(b) }

// Defer 声明这次响应稍后再写。见 ResponseWriter.Defer。
//
// 调了它就该立刻返回，之后再写响应并调 Resume 收尾。
func (c *Ctx) Defer() { c.w.Defer() }

// Resume 收尾一个被 Defer 挂起的请求。见 Resume。
//
// **要在这条连接的事件循环的 goroutine 上调**（engine.Conn.SyncOnLoop）。
func (c *Ctx) Resume() error { return Resume(c.w.conn, c.req) }
