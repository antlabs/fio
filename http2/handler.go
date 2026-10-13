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

package http2

import (
	"errors"
	"strconv"
	"strings"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/http"
)

// 请求级 handler：把一条流上的 HEADERS/DATA 拼成一个 *http.Request，交给
// 用户的 http.Handler，再把响应编回 HEADERS/DATA 帧。
//
// **存在的理由是两个协议的 handler 要一个形状**（和 http1 对齐）：
//
//	http2.NewConnHandler(http.HandlerFunc(serveHTTP), 0)
//	http.NewConnHandler(http.HandlerFunc(serveHTTP), 0)
//
// 同一个 serveHTTP 两边都能挂，和 net/http 里"一个 handler 既能服务 h1
// 又能服务 h2"是一个意思。
//
// 要自己处理流级事件（HEADERS/DATA/RST 自己管）的话用
// NewStreamConnHandler——gRPC 那种要在帧上做文章的是那条路。

// defMaxHeaderSize 是请求头（HPACK 解出来之后）的总大小上限。
//
// 算法和 HTTP/2 的 SETTINGS_MAX_HEADER_LIST_SIZE 一致：每个字段算
// 名字长度 + 值长度 + 32 字节固定开销。超过就回 431，和 http1 那边
// （httparser 报 ErrHeaderTooLarge）的处置对齐。
const defMaxHeaderSize = 32 * 1024

// errWriterNotSupported 请求级的 h2 Writer 不支持的操作。
//
// WriteRaw/WritePrepared 是"整条响应（含状态行和头）已经拼好"那种语义，
// HTTP/2 的响应是帧、没有对应的东西；用这两个的 handler 要么别挂在 h2 上，
// 要么改成走 Ctx.Write。
var errWriterNotSupported = errors.New("http2: 请求级 Writer 不支持 WriteRaw/WritePrepared")

// NewConnHandler 建一个**请求级**的服务端 HTTP/2 engine.Handler。
//
// 形状和 http1 的 http.NewConnHandler 一样（一个 http.Handler +
// maxHeaderSize），见上面那段。
//
// maxHeaderSize 传 0 = 用默认（defMaxHeaderSize）。
func NewConnHandler(h http.Handler, maxHeaderSize int32) *ConnHandler {
	if maxHeaderSize <= 0 {
		maxHeaderSize = defMaxHeaderSize
	}
	return NewStreamConnHandler(&httpBridge{
		h:             h,
		maxHeaderSize: int(maxHeaderSize),
		streams:       make(map[uint32]*streamReq),
	})
}

// httpBridge 是 StreamHandler 的请求级实现。**每条连接一个**
// （流的表、复用的 Ctx 都是连接级的），回调都在同一条连接的
// goroutine 上跑，所以下面这些字段不用加锁。
type httpBridge struct {
	h             http.Handler
	maxHeaderSize int

	// streams 是"还没收齐的请求"
	streams map[uint32]*streamReq

	// 连接级复用：每来一个请求 reset 一次，不每请求分配
	ctx *http.Ctx
	req *http.Request
	w   *h2Writer
}

// streamReq 是一条流上收到的请求（攒到 END_STREAM 才交给 handler）。
type streamReq struct {
	method     string
	path       string
	header     map[string]string
	body       []byte
	contentLen int64
	headerSize int
}

func (b *httpBridge) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	s := &streamReq{
		header:     make(map[string]string, len(headers)),
		contentLen: -1, // 没有 content-length 头时和 http1 一样是 -1
	}
	for _, f := range headers {
		switch f.Name {
		case ":method":
			s.method = f.Value
		case ":path":
			s.path = f.Value
		case ":scheme":
			// http1 的 Request 里没有独立字段，跳过（和 net/http 的
			// r.URL.Scheme 一样只在客户端有意义）
		case ":authority":
			// 和 http1 对齐：Host 放在 Header 里
			s.header["Host"] = f.Value
		default:
			s.header[f.Name] = f.Value
		}
		s.headerSize += len(f.Name) + len(f.Value) + 32
	}
	if v, ok := s.header["Content-Length"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			s.contentLen = n
		}
	}

	b.streams[streamID] = s
	if endStream {
		b.serve(c, streamID, s)
	}
}

func (b *httpBridge) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {
	s := b.streams[streamID]
	if s == nil {
		return
	}
	// data 指向引擎的读缓冲区（只在这次回调里有效），要拷一份攒起来
	s.body = append(s.body, data...)
	if endStream {
		b.serve(c, streamID, s)
	}
}

func (b *httpBridge) OnRSTStream(c *Conn, streamID uint32, code ErrCode) {
	delete(b.streams, streamID)
}

// serve 请求收齐了：交给用户的 handler，再把响应编回去。
func (b *httpBridge) serve(c *Conn, streamID uint32, s *streamReq) {
	delete(b.streams, streamID)

	if s.headerSize > b.maxHeaderSize {
		// 头太大：431（和 http1 那边一致）
		_ = c.WriteHeaders(streamID, []HeaderField{{Name: ":status", Value: "431"}}, true)
		return
	}

	if b.ctx == nil {
		b.req = &http.Request{}
		b.w = &h2Writer{}
		b.ctx = http.NewCtx(b.w, b.req)
	}
	*b.req = http.Request{
		Method:        s.method,
		Target:        s.path,
		Proto:         "HTTP/2.0",
		Header:        s.header,
		Body:          s.body,
		ContentLength: s.contentLen,
	}
	*b.w = h2Writer{c: c, streamID: streamID}

	// 和 http1 一样：handler 跑在连接的 goroutine 上（这里是流回调，
	// 也就是这条连接的引擎 goroutine），**不能阻塞**。
	err := b.h.ServeHTTP(b.ctx)
	b.w.finish(err)
}

// h2Writer 是请求级 handler 的响应端：把 ResponseWriter 那套
// （Header/WriteHeader/Write）编成 HEADERS/DATA 帧。
type h2Writer struct {
	c        *Conn
	streamID uint32

	header map[string][]string
	status int

	// sent 头块发出去了没有；ended 流收了没有；err 写失败的错
	sent  bool
	ended bool
	err   error
}

func (w *h2Writer) Header() map[string][]string {
	if w.header == nil {
		w.header = make(map[string][]string)
	}
	return w.header
}

// WriteHeader 设状态码，重复调只认第一次（和 http1 一致）。
func (w *h2Writer) WriteHeader(code int) {
	if w.sent || w.status != 0 {
		return
	}
	w.status = code
}

// PutString 把值包成单元素切片。http1 那边会复用上一次的底层数组
// （省堆分配），h2 这边响应头不是热点，简单来。
func (w *h2Writer) PutString(value string) []string { return []string{value} }

// Defer http2 的桥暂不支持挂起响应（http1 那套 Defer/Resume 是连接级的），
// 这里什么都不做——**handler 里不要依赖它**。
func (w *h2Writer) Defer() {}

// Conn 底层 engine 连接（h2c 跑在 engine 上，所以有）。
func (w *h2Writer) Conn() *engine.Conn { return w.c.ec }

func (w *h2Writer) WriteRaw(b []byte) error      { return errWriterNotSupported }
func (w *h2Writer) WritePrepared(b []byte) error { return errWriterNotSupported }

// sendHeaders 把头块发出去（第一次 Write 或者收尾时）。
func (w *h2Writer) sendHeaders(endStream bool) error {
	if w.sent {
		return nil
	}
	w.sent = true

	code := w.status
	if code == 0 {
		code = 200
	}
	fields := make([]HeaderField, 0, len(w.header)+1)
	fields = append(fields, HeaderField{Name: ":status", Value: strconv.Itoa(code)})
	for name, values := range w.header {
		// **头名必须折成小写**（RFC 9113 8.2.1）：HTTP/1.1 那边习惯写
		// "Content-Type"，原样发出去客户端直接判 PROTOCOL_ERROR、把流
		// 重置掉（实测：标准库客户端报 invalid header field name）。
		// strings.ToLower 在本来就没有大写字母时返回原串，不分配。
		lower := strings.ToLower(name)
		for _, v := range values {
			fields = append(fields, HeaderField{Name: lower, Value: v})
		}
	}
	return w.c.WriteHeaders(w.streamID, fields, endStream)
}

// Write 写响应体。第一次写会把头一起发出去（和 http1 的语义一致）。
func (w *h2Writer) Write(body []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if err := w.sendHeaders(false); err != nil {
		w.err = err
		return 0, err
	}
	if len(body) == 0 {
		return 0, nil
	}
	if err := w.c.WriteData(w.streamID, body, false); err != nil {
		w.err = err
		return 0, err
	}
	return len(body), nil
}

// finish 收尾。handlerErr 是用户 handler 返回的错。
//
//	还没发头：handler 报错就 500，没报错就空响应（HEADERS 带 END_STREAM）
//	发过头了：补一个带 END_STREAM 的空 DATA；handler 报错的话断流
//	          （RST_STREAM）——响应已经出去一半，没法再改了
func (w *h2Writer) finish(handlerErr error) {
	if w.ended {
		return
	}
	w.ended = true

	if !w.sent {
		if handlerErr != nil {
			w.status = 500
		}
		_ = w.sendHeaders(true)
		return
	}
	if handlerErr != nil {
		w.c.writeFrame(AppendRSTStream(nil, w.streamID, uint32(ErrCodeInternal)))
		return
	}
	_ = w.c.WriteData(w.streamID, nil, true)
}
