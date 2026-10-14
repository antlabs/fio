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

package http3

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
// **三个协议一个形状**（这是这个文件存在的理由）——同一个 serveHTTP
// 三个协议都能挂，和 net/http 里"一个 handler 既能服务 h1 又能服务 h2"
// 是一个意思：
//
//	engine.ListenAndServe(m, ":8080", func() engine.Handler {
//	    return http.NewConnHandler(http.HandlerFunc(serveHTTP), 0)   // h1
//	})
//	engine.ListenAndServe(m, ":8082", func() engine.Handler {
//	    return http2.NewConnHandler(http.HandlerFunc(serveHTTP), 0)  // h2c
//	})
//	srv := &http3.NativeServer{
//	    Addr: ":8443", TLSConfig: tc,
//	    NewHandler: func() http3.StreamHandler {
//	        return http3.NewConnHandler(http.HandlerFunc(serveHTTP), 0) // h3
//	    },
//	}
//
// 要自己处理流级事件（HEADERS/DATA/RST 自己管，比如 gRPC）的话用
// NewStreamConnHandler——那条路上响应是按 streamID 写的
// （WriteHeaders/WriteData），和 http2 的流级 API 同名同形。

// defMaxHeaderSize 是请求头（QPACK 解出来之后）的总大小上限。
//
// 算法和 http1/http2 那边一致：每个字段算名字长度 + 值长度 + 32 字节
// 固定开销。超过就回 431。
const defMaxHeaderSize = 32 * 1024

// errWriterNotSupported 请求级的 h3 Writer 不支持的操作。
//
// WriteRaw/WritePrepared 是"整条响应（含状态行和头）已经拼好"那种语义，
// HTTP/3 的响应是帧、没有对应的东西（和 http2 那边一个道理）；用这两个的
// handler 要么别挂在 h3 上，要么改成走 Ctx.Write。
var errWriterNotSupported = errors.New("http3: 请求级 Writer 不支持 WriteRaw/WritePrepared")

// NewStreamConnHandler 建一个**流级**的 h3 事件接收者：h 自己处理
// HEADERS/DATA/RST（要自己管每条流的状态，响应按 streamID 发）。
//
// 形状和 http2.NewStreamConnHandler 一样。挂到 NativeServer 上：
//
//	NewHandler: func() http3.StreamHandler { return http3.NewStreamConnHandler(h) }
//
// （流级 handler 是每条连接一份的有状态对象，所以这是工厂里的一行。）
func NewStreamConnHandler(h StreamHandler) StreamHandler { return h }

// NewConnHandler 建一个**请求级**的 h3 事件接收者，形状和 http1 的
// http.NewConnHandler、http2 的 http2.NewConnHandler 一样（一个
// http.Handler + maxHeaderSize）。
//
// maxHeaderSize 传 0 = 用默认（defMaxHeaderSize）。
func NewConnHandler(h http.Handler, maxHeaderSize int32) StreamHandler {
	if maxHeaderSize <= 0 {
		maxHeaderSize = defMaxHeaderSize
	}
	return &httpBridge{
		h:             h,
		maxHeaderSize: int(maxHeaderSize),
		streams:       make(map[uint64]*streamReq),
	}
}

// httpBridge 是 StreamHandler 的请求级实现。**每条连接一个**
// （流的表、复用的 Ctx 都是连接级的），回调都在同一条连接的 goroutine
// 上跑，所以下面这些字段不用加锁。
type httpBridge struct {
	h             http.Handler
	maxHeaderSize int

	// streams 是"还没收齐的请求"
	streams map[uint64]*streamReq

	// 连接级复用：每来一个请求 reset 一次，不每请求分配
	ctx *http.Ctx
	req *http.Request
	w   *h3Writer
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

func (b *httpBridge) OnHeaders(c *Conn, streamID uint64, headers []HeaderField, endStream bool) {
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
	// 头名大小写不敏感地找 content-length（h1/h2 那边也是这个口径）
	for k, v := range s.header {
		if strings.EqualFold(k, "content-length") {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				s.contentLen = n
			}
			break
		}
	}

	b.streams[streamID] = s
	if endStream {
		b.serve(c, streamID, s)
	}
}

func (b *httpBridge) OnData(c *Conn, streamID uint64, data []byte, endStream bool) {
	s := b.streams[streamID]
	if s == nil {
		return
	}
	// data 指向流层的读缓冲（只在这次回调里有效），要拷一份攒起来
	s.body = append(s.body, data...)
	if endStream {
		b.serve(c, streamID, s)
	}
}

func (b *httpBridge) OnRSTStream(c *Conn, streamID uint64, code ErrCode) {
	delete(b.streams, streamID)
}

// serve 请求收齐了：交给用户的 handler，再把响应编回去。
func (b *httpBridge) serve(c *Conn, streamID uint64, s *streamReq) {
	delete(b.streams, streamID)

	if s.headerSize > b.maxHeaderSize {
		// 头太大：431（和 http1/http2 那边一致）
		_ = c.WriteHeaders(streamID, []HeaderField{{Name: ":status", Value: "431"}}, true)
		return
	}

	if b.ctx == nil {
		b.req = &http.Request{}
		b.w = &h3Writer{}
		b.ctx = http.NewCtx(b.w, b.req)
	}
	*b.req = http.Request{
		Method:        s.method,
		Target:        s.path,
		Proto:         "HTTP/3.0",
		Header:        s.header,
		Body:          s.body,
		ContentLength: s.contentLen,
	}
	*b.w = h3Writer{c: c, streamID: streamID}

	// 和 http1/http2 一样：handler 跑在连接的 goroutine 上（这里是 lane
	// 或者收包那条快路），**不能阻塞**。
	err := b.h.ServeHTTP(b.ctx)
	b.w.finish(err)
}

// h3Writer 是请求级 handler 的响应端：把 ResponseWriter 那套
// （Header/WriteHeader/Write）编成 HEADERS/DATA 帧。
//
// 和 http2 的 h2Writer 是同一个模子，差别只有 streamID 是 uint64、
// 写的落点是 h3 的 Conn。
type h3Writer struct {
	c        *Conn
	streamID uint64

	header map[string][]string
	status int

	// sent 头块发出去了没有；ended 流收了没有；err 写失败的错
	sent  bool
	ended bool
	err   error
}

func (w *h3Writer) Header() map[string][]string {
	if w.header == nil {
		w.header = make(map[string][]string)
	}
	return w.header
}

// WriteHeader 设状态码，重复调只认第一次（和 http1 一致）。
func (w *h3Writer) WriteHeader(code int) {
	if w.sent || w.status != 0 {
		return
	}
	w.status = code
}

// PutString 把值包成单元素切片。http1 那边会复用上一次的底层数组
// （省堆分配），h3 这边响应头不是热点，简单来。
func (w *h3Writer) PutString(value string) []string { return []string{value} }

// Defer h3 的桥暂不支持挂起响应（http1 那套 Defer/Resume 是连接级的、
// 要能碰到底层 CONN 的写缓冲），这里什么都不做——**handler 里不要依赖它**。
func (w *h3Writer) Defer() {}

// Conn 底层 engine 连接。**HTTP/3 跑在 QUIC 上，不经过 engine**，所以是
// nil（要拿 QUIC 连接用 c.QUICConn()，那是流级 API）。
func (w *h3Writer) Conn() *engine.Conn { return nil }

func (w *h3Writer) WriteRaw(b []byte) error      { return errWriterNotSupported }
func (w *h3Writer) WritePrepared(b []byte) error { return errWriterNotSupported }

// sendHeaders 把头块发出去（第一次 Write 或者收尾时）。
func (w *h3Writer) sendHeaders(endStream bool) error {
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
		// **头名必须折成小写**（RFC 9114 4.2 也要求全小写，和 h2 一样）：
		// http1 那边习惯写 "Content-Type"，原样发出去客户端会判
		// PROTOCOL_ERROR 把流重置掉。ToLower 在本来没有大写字母时
		// 返回原串，不分配。
		lower := strings.ToLower(name)
		for _, v := range values {
			fields = append(fields, HeaderField{Name: lower, Value: v})
		}
	}
	return w.c.WriteHeaders(w.streamID, fields, endStream)
}

// Write 写响应体。第一次写会把头一起发出去（和 http1 的语义一致）。
func (w *h3Writer) Write(body []byte) (int, error) {
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
//	发过头了：补一个带 END_STREAM 的空 DATA；handler 报错的话把这一侧
//	          重置掉（RESET_STREAM）——响应已经出去一半，没法再改
//
// 和 http2 的 h2Writer.finish 一个语义。
func (w *h3Writer) finish(handlerErr error) {
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
		_ = w.c.ResetStream(w.streamID, ErrCodeInternalError)
		return
	}
	_ = w.c.WriteData(w.streamID, nil, true)
}
