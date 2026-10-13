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
	"sync"

	"github.com/antlabs/fio/http2"
)

// 服务端：把 gRPC 的规矩接到 http2 的流事件上。
//
//	engine（epoll / kqueue）
//	  ↓ OnData(字节)
//	http2.ConnHandler            解帧、管流、解 HPACK
//	  ↓ StreamHandler 回调（OnHeaders / OnData / OnRSTStream）
//	ServerHandler（这个文件）     认 :path、切消息、发 trailer
//	  ↓
//	Handler（业务）
//
// **ServerHandler 实现的是 http2.StreamHandler**，所以只要把它交给
// http2.NewStreamConnHandler 再挂到 engine 上，gRPC 就跑在事件循环里了——
// 读写全在 epoll 的线程上，没有 per-connection 的 goroutine。

// Handler 是 gRPC 服务端的业务接口。
//
// 生命周期的顺序是：OnCall（头到了）-> OnMessage（每收到一条消息）
// -> OnEnd（流的 END_STREAM 到了，该收尾了）。
//
// 一元调用（最常见）就是"一条消息 + 结束"：在 OnMessage 里回复即可；
// 想在 OnEnd 里回复也行（那时消息肯定齐了）。
type Handler interface {
	// OnCall 一次调用开始了（请求头解完）。
	//
	// 返回 non-nil 会转成 INTERNAL 状态回给对端（除非实现自己已经
	// 回复过了）。
	OnCall(c *http2.Conn, call *ServerCall) error

	// OnMessage 收到一条完整的 gRPC 消息。
	//
	// **msg 的生命周期只到这次调用返回**（它指向解析器的内部缓冲），
	// 要留着就得自己拷。
	OnMessage(c *http2.Conn, call *ServerCall, msg []byte) error

	// OnEnd 流的 END_STREAM 到了。流式调用在这里收尾。
	OnEnd(c *http2.Conn, call *ServerCall) error
}

// ServerCall 是服务端视角的一次调用（一个 HTTP/2 流）。
type ServerCall struct {
	// StreamID 是这次调用的 HTTP/2 流
	StreamID uint32
	// Service / Method 从 :path 拆出来
	Service string
	Method  string
	// Headers 请求头（含 pseudo-header）
	Headers []http2.HeaderField

	// parser 从这个流的数据里切 gRPC 消息（一条消息可能跨多个 DATA 帧）
	parser *MessageParser
	// replied 响应发过没有（trailer 发出去才算）
	replied bool
}

// Replied 这次调用回复过没有。
func (sc *ServerCall) Replied() bool { return sc.replied }

// Reply 回答一次一元调用：响应头 + 一条消息 + trailer（带状态）。
func (sc *ServerCall) Reply(c *http2.Conn, msg []byte, st *Status) error {
	if err := sc.StartReply(c); err != nil {
		return err
	}
	if msg != nil {
		if err := c.WriteData(sc.StreamID, Encode(nil, msg), false); err != nil {
			return err
		}
	}
	return sc.Finish(c, st)
}

// StartReply 只发响应头（流式调用里消息后面自己 Send）。
func (sc *ServerCall) StartReply(c *http2.Conn) error {
	return c.WriteHeaders(sc.StreamID, ResponseHeaders(nil), false)
}

// Send 流式调用里发一条消息（可以发多条）。
func (sc *ServerCall) Send(c *http2.Conn, msg []byte, last bool) error {
	return c.WriteData(sc.StreamID, Encode(nil, msg), last)
}

// Finish 收尾：trailer（带状态）。
func (sc *ServerCall) Finish(c *http2.Conn, st *Status) error {
	if st == nil {
		st = StatusOK()
	}
	if err := c.WriteTrailers(sc.StreamID, AppendStatus(nil, st)); err != nil {
		return err
	}
	sc.replied = true
	return nil
}

// ReplyError 用失败状态回一次调用（头 + trailer，没有消息体）。
func (sc *ServerCall) ReplyError(c *http2.Conn, st *Status) error {
	if st == nil {
		st = StatusInternal("unknown error")
	}
	if err := sc.StartReply(c); err != nil {
		return err
	}
	return sc.Finish(c, st)
}

// ServerHandler 把 http2 的流事件翻译成 gRPC 的调用。
//
// 一个连接一个（流的表是连接级的）。它实现 http2.StreamHandler。
type ServerHandler struct {
	handler Handler

	mu sync.Mutex
	// calls 流 ID -> 调用状态。HTTP/2 是**多路复用**的：一个连接上同时
	// 有多个流，回调交错着来，所以要按流 ID 分开存。
	calls map[uint32]*ServerCall
}

// NewServerHandler 建一个 gRPC 服务端的流处理器。
func NewServerHandler(h Handler) *ServerHandler {
	return &ServerHandler{handler: h, calls: make(map[uint32]*ServerCall)}
}

// OnHeaders 一个流的请求头到了：认一认是不是 gRPC，是就建一个调用。
//
// content-type 不对的流回 415——HTTP/2 上完全可能跑着非 gRPC 的东西，
// 这里不该瞎接（真实场景里就是"同一个端口既跑 gRPC 又跑普通 HTTP/2"）。
func (s *ServerHandler) OnHeaders(c *http2.Conn, streamID uint32, headers []http2.HeaderField, endStream bool) {
	var path, ctype string
	for _, f := range headers {
		switch f.Name {
		case ":path":
			path = f.Value
		case "content-type":
			ctype = f.Value
		}
	}

	if !IsGRPCContentType(ctype) {
		_ = c.WriteHeaders(streamID, []http2.HeaderField{
			{Name: ":status", Value: "415"},
			{Name: "content-type", Value: "text/plain"},
		}, true)
		return
	}

	call := &ServerCall{StreamID: streamID, Headers: headers, parser: NewMessageParser(0)}
	if svc, method, ok := SplitMethodPath(path); ok {
		call.Service, call.Method = svc, method
	} else {
		// 路径不是 /服务/方法：按 UNIMPLEMENTED 回掉，别让对端干等
		_ = call.ReplyError(c, StatusUnimplemented("malformed method path "+path))
		return
	}

	s.mu.Lock()
	s.calls[streamID] = call
	s.mu.Unlock()

	if err := s.handler.OnCall(c, call); err != nil && !call.replied {
		_ = call.ReplyError(c, StatusInternal(err.Error()))
	}

	if endStream {
		s.end(c, streamID, call)
	}
}

// OnData 流上的数据到了：切出消息交给业务。
func (s *ServerHandler) OnData(c *http2.Conn, streamID uint32, data []byte, endStream bool) {
	s.mu.Lock()
	call := s.calls[streamID]
	s.mu.Unlock()
	if call == nil {
		// 头还没到（或者这个流已经被 RST 了）——协议上不该发生
		return
	}

	// 切出一条交一条：一条消息可能跨好几个 DATA 帧，一个 DATA 帧里也
	// 可能有好几条消息，所以**不能**假定"一帧一条"。
	if _, err := call.parser.Parse(data, func(msg []byte) error {
		if serr := s.handler.OnMessage(c, call, msg); serr != nil && !call.replied {
			_ = call.ReplyError(c, StatusInternal(serr.Error()))
		}
		return nil
	}); err != nil && !call.replied {
		// 解析失败（消息超限、压缩标志置位……）：告诉对端，别让它干等
		_ = call.ReplyError(c, StatusInvalidArgument(err.Error()))
		s.forget(streamID)
		return
	}

	if endStream {
		s.end(c, streamID, call)
	}
}

// OnRSTStream 对端重置了流：把调用状态清掉。
func (s *ServerHandler) OnRSTStream(c *http2.Conn, streamID uint32, code http2.ErrCode) {
	s.forget(streamID)
}

// end 流的 END_STREAM 到了。
func (s *ServerHandler) end(c *http2.Conn, streamID uint32, call *ServerCall) {
	defer s.forget(streamID)
	if err := s.handler.OnEnd(c, call); err != nil && !call.replied {
		_ = call.ReplyError(c, StatusInternal(err.Error()))
	}
}

func (s *ServerHandler) forget(streamID uint32) {
	s.mu.Lock()
	delete(s.calls, streamID)
	s.mu.Unlock()
}

// Decoder 是 gRPC 那边的编解码接口（proto 生成的代码实现的）。
//
// 留在这里是给上层用：ServerHandler 收发的是字节，业务按自己的 proto
// 类型解——不要让这个包依赖具体 IDL。
type Decoder interface {
	Unmarshal([]byte) error
}

// Encoder 是编方向的。
type Encoder interface {
	Marshal() ([]byte, error)
}

// Decode 把一个 Decoder 从字节里解出来（小工具）。
func Decode(dst Decoder, b []byte) error { return dst.Unmarshal(b) }

// EncodeMsg 把一条消息编成字节（小工具）。
func EncodeMsg(e Encoder) ([]byte, error) { return e.Marshal() }
