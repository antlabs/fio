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
	"sync"

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

// defMaxBodySize 是请求体的默认上限（8MB）。
//
// Content-Length 是对端声明的，不能拿来直接分配；真收到超限的数据时
// 直接回 413，不再往 body 里 append。这样慢速客户端没法用一条流把
// 服务端内存撑爆。0 表示不限制（SetMaxBodySize(0)）。
const defMaxBodySize = 8 << 20

// maxPreallocBodyH2 是"按 Content-Length 预分配"的上限。
//
// 和 http1 的 maxPreallocBody 一个意思：Content-Length 是声明，不能
// 直接信；1MB 覆盖常见请求，超过的走 append 慢慢长。
const maxPreallocBodyH2 = 1 << 20

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
		maxBodySize:   defMaxBodySize,
		streams:       make(map[uint32]*streamReq),
	})
}

// SetMaxBodySize 设单请求体上限（字节）。n <= 0 表示不限制。
//
// 只对 NewConnHandler 建的请求级处理器有效；流级处理器（gRPC 等）自己
// 管消息大小。
func (ch *ConnHandler) SetMaxBodySize(n int64) {
	if b, ok := ch.handler.(*httpBridge); ok {
		b.maxBodySize = n
	}
}

// httpBridge 是 StreamHandler 的请求级实现。**每条连接一个**
// （流的表、复用的 Ctx 都是连接级的），回调都在同一条连接的
// goroutine 上跑，所以下面这些字段不用加锁。
type httpBridge struct {
	h             http.Handler
	maxHeaderSize int
	maxBodySize   int64

	// streams 是"还没收齐的请求"
	streams map[uint32]*streamReq

	// reqPool 复用 streamReq（含 header map / body 底层数组）。
	//
	// 能池化的前提是 http.Handler 的约定：Request 只在 ServeHTTP 调用
	// 期间有效，handler 不能存起来。和 net/http 的约束一样。
	reqPool sync.Pool

	// 连接级复用：每来一个请求 reset 一次，不每请求分配
	ctx *http.Ctx
	req *http.Request
	w   *h2Writer
}

// rejectedStreamReq 是"这个流已经被 431/413 拒掉了"的哨兵。
//
// 用它占着 streams 表，后面的 DATA/trailer 就直接丢掉，不会因为
// b.streams[id] == nil 又被当成一个新请求。共享一个空对象，不为每个
// 被拒的流分配。
var rejectedStreamReq = &streamReq{}

// 复用上限：单个请求留下太大的 map/body 就不再留着，避免一条连接
// 处理过一次大请求后长期攥着那块内存。
const (
	maxReuseHeaderEntries = 64
	maxReuseBodyCap       = maxPreallocBodyH2
	maxReuseTrailerCap    = 64
)

// getStreamReq 从池里取一个复位好的 streamReq。
func (b *httpBridge) getStreamReq() *streamReq {
	if v := b.reqPool.Get(); v != nil {
		s := v.(*streamReq)
		if s.header == nil {
			s.header = make(map[string]string, 8)
		} else {
			clear(s.header)
		}
		s.method, s.path = "", ""
		s.trailers = s.trailers[:0]
		s.body = s.body[:0]
		s.contentLen = -1
		s.headerSize = 0
		return s
	}
	return &streamReq{
		header:     make(map[string]string, 8),
		contentLen: -1,
	}
}

// putStreamReq 把 streamReq 还回池子并清掉引用（header map/body 可以
// 复用到下一个请求）。
func (b *httpBridge) putStreamReq(s *streamReq) {
	if len(s.header) > maxReuseHeaderEntries {
		s.header = nil
	} else {
		clear(s.header)
	}
	if cap(s.body) > maxReuseBodyCap {
		s.body = nil
	} else {
		s.body = s.body[:0]
	}
	if cap(s.trailers) > maxReuseTrailerCap {
		s.trailers = nil
	} else {
		s.trailers = s.trailers[:0]
	}
	s.method, s.path = "", ""
	s.contentLen = -1
	s.headerSize = 0
	b.reqPool.Put(s)
}

// streamReq 是一条流上收到的请求（攒到 END_STREAM 才交给 handler）。
type streamReq struct {
	method     string
	path       string
	header     map[string]string
	trailers   []HeaderField
	body       []byte
	contentLen int64
	headerSize int
}

func (b *httpBridge) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	// 第二次 OnHeaders 是 trailer：请求头已经在下面那条路上收好了，
	// 这里只把 trailer 挂到同一个请求上，等 END_STREAM 一起交给 handler。
	if s := b.streams[streamID]; s != nil {
		if s == rejectedStreamReq {
			// 这个流已经被 431/413 拒了：trailer 直接丢掉，流结束就清表。
			if endStream {
				delete(b.streams, streamID)
			}
			return
		}
		s.trailers = append(s.trailers[:0], headers...)
		if endStream {
			b.serve(c, streamID, s)
		}
		return
	}

	// 先只算大小/Content-Length，不急着从池里取 streamReq：被 431/413
	// 拒掉的请求不该产生任何分配。
	var (
		headerSize int
		contentLen int64 = -1 // 没有 content-length 头时和 http1 一样是 -1
	)
	for _, f := range headers {
		headerSize += len(f.Name) + len(f.Value) + 32
		// h2 的头名必须是小写（validateHeaderSyntax 会拒大写），这里
		// 不能用 http1 那种 "Content-Length" 写法，否则永远查不到。
		if f.Name == "content-length" {
			if n, err := strconv.ParseInt(f.Value, 10, 64); err == nil {
				contentLen = n
			}
		}
	}

	// **头太大直接拒**：不要等到 END_STREAM 才回 431——那之前对端还可以
	// 灌一个很大的 body，白占内存。
	if headerSize > b.maxHeaderSize {
		if !endStream {
			b.streams[streamID] = rejectedStreamReq
		}
		_ = c.WriteHeaders(streamID, []HeaderField{{Name: ":status", Value: "431"}}, true)
		return
	}
	// Content-Length 超限也直接拒（413），不建 streamReq。
	if b.maxBodySize > 0 && contentLen > b.maxBodySize {
		if !endStream {
			b.streams[streamID] = rejectedStreamReq
		}
		_ = c.WriteHeaders(streamID, []HeaderField{{Name: ":status", Value: "413"}}, true)
		return
	}

	s := b.getStreamReq()
	s.headerSize = headerSize
	s.contentLen = contentLen
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
	}

	// 按声明的大小预分配，但只信 1MB 以内（和 http1 的 maxPreallocBody
	// 一个口径）。池里拿回来的 body 可能更大，够用就不重新分配。
	if s.contentLen > 0 && s.contentLen <= maxPreallocBodyH2 && cap(s.body) < int(s.contentLen) {
		s.body = make([]byte, 0, int(s.contentLen))
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
	if s == rejectedStreamReq {
		if endStream {
			delete(b.streams, streamID)
		}
		return
	}
	// 没有 Content-Length 的请求也要有上限：超了直接 413，并把这个
	// streamReq 丢掉，后面的 DATA 就不收了。
	if b.maxBodySize > 0 && int64(len(s.body))+int64(len(data)) > b.maxBodySize {
		delete(b.streams, streamID)
		b.putStreamReq(s)
		_ = c.WriteHeaders(streamID, []HeaderField{{Name: ":status", Value: "413"}}, true)
		return
	}
	// data 指向引擎的读缓冲区（只在这次回调里有效），要拷一份攒起来
	s.body = append(s.body, data...)
	if endStream {
		b.serve(c, streamID, s)
	}
}

func (b *httpBridge) OnRSTStream(c *Conn, streamID uint32, code ErrCode) {
	if s := b.streams[streamID]; s != nil {
		delete(b.streams, streamID)
		if s != rejectedStreamReq {
			b.putStreamReq(s)
		}
	}
}

// serve 请求收齐了：交给用户的 handler，再把响应编回去。
func (b *httpBridge) serve(c *Conn, streamID uint32, s *streamReq) {
	delete(b.streams, streamID)
	// Request 只在 ServeHTTP 期间有效（和 net/http 一样），之后就可以
	// 把 streamReq 还回池子。
	defer b.putStreamReq(s)

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
	if len(s.trailers) > 0 {
		tr := make(map[string]string, len(s.trailers))
		for _, f := range s.trailers {
			tr[f.Name] = f.Value
		}
		b.req.Trailer = tr
	}
	b.w.reset(c, streamID)

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

// reset 把 writer 复位到新请求，**保留 header map** 给下一个请求复用。
func (w *h2Writer) reset(c *Conn, streamID uint32) {
	w.c = c
	w.streamID = streamID
	w.status = 0
	w.sent = false
	w.ended = false
	w.err = nil
	clear(w.header)
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
