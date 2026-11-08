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

package grpc

import (
	"fmt"
	"strings"
	"sync"

	"github.com/antlabs/fio/http2"
)

// 一次调用的两头。把 gRPC 的那点规矩（路径格式、content-type、消息分帧、
// trailer 里的状态）和 http2 的帧操作拼起来。
//
// **为什么不是一个完整的 Client/Server**：gRPC 的编排（连接池、重试、
// 负载均衡、拦截器）是另一个量级的东西。这里做的是"一次调用在协议层面
// 长什么样"——把方法名变成一个 HTTP/2 流、把消息分帧、把状态从 trailer
// 里捞出来。上面那层交给用的人（或者以后的包）。

// MethodPath 把服务名和方法名拼成 gRPC 的路径。
//
//	MethodPath("helloworld.Greeter", "SayHello")
//	-> "/helloworld.Greeter/SayHello"
//
// 路径格式是 gRPC 规范写死的（HTTP/2 的 :path）。
func MethodPath(service, method string) string {
	var sb strings.Builder
	sb.Grow(len(service) + len(method) + 2)
	sb.WriteByte('/')
	sb.WriteString(service)
	sb.WriteByte('/')
	sb.WriteString(method)
	return sb.String()
}

// SplitMethodPath 把 "/服务/方法" 拆回两段。
func SplitMethodPath(path string) (service, method string, ok bool) {
	if len(path) < 3 || path[0] != '/' {
		return "", "", false
	}
	rest := path[1:]
	i := strings.IndexByte(rest, '/')
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// RequestHeaders 拼一次调用要发的请求头。
//
// 除了 gRPC 自己那几个，还有 HTTP/2 的 pseudo-header（:method 这些）——
// 它们是 HTTP/2 报文的一部分，在 gRPC 里也必须发。
func RequestHeaders(service, method string, extra []http2.HeaderField) []http2.HeaderField {
	headers := make([]http2.HeaderField, 0, 6+len(extra))
	headers = append(headers,
		http2.HeaderField{Name: ":method", Value: "POST"},
		http2.HeaderField{Name: ":path", Value: MethodPath(service, method)},
		http2.HeaderField{Name: ":scheme", Value: "http"},
		// content-type 用 "application/grpc"（不带 +proto）：服务端多数
		// 只认这个前缀，带具体编码反而可能被拒
		http2.HeaderField{Name: headerContentType, Value: ContentType},
		// 我们用 grpc 的默认 TE: trailers 表示会读 trailer
		http2.HeaderField{Name: "te", Value: "trailers"},
	)
	return append(headers, extra...)
}

// ResponseHeaders 拼响应的头（不含 trailer，trailer 在数据之后单独发）。
//
// **必须带 :status**：HTTP/2 的响应没有它是不合法的（官方 Framer 解出来
// 的帧里就没有状态码，客户端无从判断）。gRPC 的响应**永远是 200**——
// 调用的成败在 trailer 的 grpc-status 里，不在 HTTP 状态码里。这不是
// 省事，是规范：服务端可能已经流式发了很多数据才发现要失败，那时候
// 改 HTTP 状态码已经来不及了。
func ResponseHeaders(extra []http2.HeaderField) []http2.HeaderField {
	headers := make([]http2.HeaderField, 0, 2+len(extra))
	headers = append(headers,
		http2.HeaderField{Name: ":status", Value: "200"},
		http2.HeaderField{Name: headerContentType, Value: ContentType},
	)
	return append(headers, extra...)
}

// Call 是一次调用的状态。客户端和服务端各持一个。
//
// 它把"gRPC 消息"和"HTTP/2 流"接起来：写出去的是加了 5 字节头的消息，
// 收进来的是从 DATA 帧流里切出来的消息。
type Call struct {
	// StreamID 是这次调用用的 HTTP/2 流
	StreamID uint32

	// parser 是收消息用的（一个流一个）。只由收包 goroutine 访问
	// （OnData），Send 不碰它。
	parser *MessageParser

	// mu 保护下面这几个收包侧字段：OnHeaders 在收包 goroutine 写，
	// 用户的 Status/Done/Headers 可能在另一个 goroutine 读。
	//
	// 注意 OnData 不持这把锁调用用户回调——回调里可以安全地调
	// Status/Done（RLock 可重入读）。
	mu sync.RWMutex
	// status 是调用的结果。trailer 到了才有值。
	status *Status
	// gotStatus trailer 到了没有
	gotStatus bool

	// headers 是响应头（:status、content-type 这些）
	headers []http2.HeaderField
}

// NewCall 建一次调用。
func NewCall(streamID uint32) *Call {
	return &Call{StreamID: streamID, parser: NewMessageParser(0)}
}

// OnHeaders 收到头（可能是响应头，也可能是 trailer——gRPC 的 trailer 就是
// 一个带 END_STREAM 的 HEADERS 帧）。
func (c *Call) OnHeaders(fields []http2.HeaderField, endStream bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 有 grpc-status 的就是 trailer
	for _, f := range fields {
		if f.Name == headerStatus {
			c.status = StatusFromHeaders(fields)
			c.gotStatus = true
			return
		}
	}
	c.headers = append(c.headers[:0], fields...)
}

// OnData 收到数据：切出消息，每切出一条就调 fn。
func (c *Call) OnData(data []byte, fn func(msg []byte) error) error {
	_, err := c.parser.Parse(data, fn)
	if err != nil {
		return fmt.Errorf("grpc: stream %d: %w", c.StreamID, err)
	}
	return nil
}

// Status 返回调用结果。trailer 还没到返回 nil。
func (c *Call) Status() *Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.gotStatus {
		return nil
	}
	return c.status
}

// Done 调用结束了吗（收到 trailer）。
func (c *Call) Done() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gotStatus
}

// Headers 响应头。
//
// 返回拷贝：内部的切片会被下一帧头块复用，直接交出去会让调用方读到
// 已经被覆盖的内容。
func (c *Call) Headers() []http2.HeaderField {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.headers) == 0 {
		return nil
	}
	out := make([]http2.HeaderField, len(c.headers))
	copy(out, c.headers)
	return out
}

// ClientConn 是客户端这边的一次调用发起者。
//
// 只做"把一次调用发出去、把结果收回来"，不做连接管理。
type ClientConn struct {
	conn *http2.Conn
}

// NewClientConn 包一个 HTTP/2 连接。
func NewClientConn(c *http2.Conn) *ClientConn { return &ClientConn{conn: c} }

// Call 发一次一元调用（一个请求消息、一个响应消息）。
//
// 返回的 Call 用来收响应。
func (cc *ClientConn) Call(service, method string, reqMsg []byte) (*Call, error) {
	streamID := cc.conn.NewStreamID()

	// 顺序要紧：HEADERS 必须先出去（END_STREAM=false，因为后面还有数据），
	// 然后才是带 END_STREAM 的 DATA。
	//
	// 用 WriteHeaders/WriteData（写进 http2 的发送缓冲），不用
	// MustHeaders——后者是"直接返回拼好的字节"，要自己再塞进去，
	// 两条路径混着容易把顺序搞反（第一版就是这么写的，结果 DATA 先出）。
	hdr := RequestHeaders(service, method, nil)
	if err := cc.conn.WriteHeaders(streamID, hdr, false); err != nil {
		return nil, err
	}
	if err := cc.conn.WriteData(streamID, Encode(nil, reqMsg), true); err != nil {
		return nil, err
	}
	return NewCall(streamID), nil
}

// CallStream 发一次流式调用的请求头（数据后面用 Send 一条条发）。
func (cc *ClientConn) CallStream(service, method string) (*Call, error) {
	streamID := cc.conn.NewStreamID()
	hdr := RequestHeaders(service, method, nil)
	if err := cc.conn.WriteHeaders(streamID, hdr, false); err != nil {
		return nil, err
	}
	return NewCall(streamID), nil
}

// Send 在流式调用里发一条消息。
func (cc *ClientConn) Send(call *Call, msg []byte, last bool) error {
	return cc.conn.WriteData(call.StreamID, Encode(nil, msg), last)
}

// Finish 结束发送（发一个空的 DATA 帧带 END_STREAM）。
func (cc *ClientConn) Finish(call *Call) error {
	return cc.conn.WriteData(call.StreamID, nil, true)
}

// WriteResponse 服务端发一元调用的响应：头 + 一条消息 + trailer 里的状态。
func (cc *ClientConn) WriteResponse(streamID uint32, msg []byte, st *Status) error {
	if err := cc.conn.WriteHeaders(streamID, ResponseHeaders(nil), false); err != nil {
		return err
	}
	// 消息带上 END_STREAM=false：后面还有 trailer 那个 HEADERS 帧
	if err := cc.conn.WriteData(streamID, Encode(nil, msg), false); err != nil {
		return err
	}
	// trailer：一个带 END_STREAM 的 HEADERS 帧
	return cc.conn.WriteTrailers(streamID, AppendStatus(nil, st))
}

// WriteTrailers 只发 trailer（流式调用里数据已经发完了）。
func (cc *ClientConn) WriteTrailers(streamID uint32, st *Status) error {
	return cc.conn.WriteTrailers(streamID, AppendStatus(nil, st))
}
