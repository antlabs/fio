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
	"context"
	"crypto/tls"
	"errors"
	"io"
	"strconv"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
)

// 自建的 HTTP/3 服务端：**只借 quic-go 的 QUIC 传输**，HTTP/3 这一层
// （帧、QPACK、流分类、请求生命周期）全在这里，不经过 net/http。
//
// 为什么不直接用 quic-go/http3.Server：那一层把每条 QUIC 流适配成
// net/http 的 Request/ResponseWriter，而且**每个请求起一个 goroutine**。
// 实测（baseline-h3，服务端 12 核，64 连接 × 每连接 64 并发流，pprof）：
//
//	HandleRequestStream                          62.9%  ← 整个请求处理
//	├ requestFromHeaders                         10.9%  ← 构造 net/http.Request
//	├ TrackStream / parseHeaders / writeHeader   ~24%   ← quic-go 的 h3 层
//	└ main.serveStdHTTP                          6.4%  ← **业务本身只有这么多**
//	QUIC 传输（Conn.run / handlePackets）         ~14%
//	runtime 栈增长/拷贝（newstack+copystack）     ~21%
//
// 也就是说那 63% 里有约九成是"把 QUIC 流翻译成 net/http"的开销，而栈
// 拷贝那 21% 也是那套深调用链带出来的。
//
// 这里的几个取舍，都是为了把这条路压到最短：
//
//   - **不为每个请求起 goroutine**：请求流在连接的 goroutine 上就地处理。
//     h3 的流本来互相独立，但一个请求的帧读完之前不会阻塞在网络上（数据
//     已经在 QUIC 的接收缓冲里），就地做省掉一次 goroutine 创建 + 调度 +
//     （见下面的 readRequest）一次栈增长。
//   - **QPACK 只用静态表**：SETTINGS 里把 MAX_TABLE_CAPACITY 和
//     BLOCKED_STREAMS 都报 0，对端就只用静态表和字面量表示，解码器不需要
//     任何动态状态（quic-go/qpack 的 Decoder 正好只支持这一档）。代价是
//     头块比用动态表大一点，但省掉的是编解码器单向流的往返和阻塞语义。
//   - **响应一个 Write 发完**：HEADERS 帧 + DATA 帧拼在同一个缓冲里，
//     只调一次 Stream.Write。QUIC 那层会按包边界自己切。
//   - **每条连接复用四块缓冲**（读、头块、输出、头字段），一个请求里
//     不分配。
type Handler func(w *ResponseWriter, r *Request) error

// Request 是一次 HTTP/3 请求。
//
// **只在 Handler 返回之前有效**：里面的切片指向连接复用的缓冲，要留着
// 自己拷。这条和 net/http 的 Request 不一样，是刻意的——拷一份 100KB 的
// 请求体在每个请求上都发生一次，而这个包的使用者（benchmark 的服务端）
// 从来不留。
type Request struct {
	// Method 是 :method（"GET"、"POST"……）
	Method string
	// Path 是 :path 里 '?' 之前那一段
	Path string
	// Query 是 :path 里 '?' 之后那一段（不含 '?'）
	Query string
	// Proto 固定是 "HTTP/3.0"
	Proto string
	// Header 是普通的头字段（伪头已经拆到上面的字段里，不在这里）
	Header []qpack.HeaderField
	// Body 是请求体（DATA 帧拼起来的）
	Body []byte
}

// Get 按名字取一个请求头，**大小写敏感**（HTTP/3 的头名规定是小写，
// 对端不规范的话这里取不到，和 net/http 的宽松处理不同）。
func (r *Request) Get(name string) (string, bool) {
	for i := range r.Header {
		if r.Header[i].Name == name {
			return r.Header[i].Value, true
		}
	}
	return "", false
}

// StatusText 常见状态码的文本。不走 net/http 的 StatusText 是为了少一个
// 依赖，也少一次 map 查找。
func StatusText(code int) string {
	switch code {
	case 200:
		return "200"
	case 204:
		return "204"
	case 404:
		return "404"
	case 500:
		return "500"
	}
	return strconv.Itoa(code)
}

// ResponseWriter 写一次响应。
type ResponseWriter struct {
	str *quic.Stream
	// c 是它所属的连接（缓冲都从那里借）
	c *nativeConn
	// wrote 表示这次响应已经写过了
	wrote bool
}

// WriteResponse 一次把整个响应写出去。
//
// status 是状态码，headers 是普通头字段（Content-Length 由这里按
// len(body) 补，调用方不用传），body 是响应体。
//
// **只调一次 Stream.Write**：HEADERS 帧和 DATA 帧拼在同一个缓冲里。
func (w *ResponseWriter) WriteResponse(status int, headers []qpack.HeaderField, body []byte) error {
	if w.wrote {
		return errors.New("http3: response already written")
	}
	w.wrote = true

	c := w.c
	// ── 头块：QPACK 编码 ──────────────────────────────────────────
	c.block = c.block[:0]
	c.encW.p = c.block
	// 复用编码器：它只在第一个 WriteField 时写一次头块前缀（两个 0），
	// Close 之后可以接着编下一块

	// 伪头在前（RFC 9114 4.3.1 要求）
	if err := c.enc.WriteField(qpack.HeaderField{Name: ":status", Value: StatusText(status)}); err != nil {
		return err
	}
	for i := range headers {
		if err := c.enc.WriteField(headers[i]); err != nil {
			return err
		}
	}
	if err := c.enc.Close(); err != nil {
		return err
	}
	c.block = c.encW.p

	// ── 拼帧：HEADERS + DATA ─────────────────────────────────────
	out := c.wbuf[:0]
	out = AppendHeaders(out, c.block)
	if len(body) > 0 {
		out = AppendData(out, body)
	}
	c.wbuf = out

	// QUIC 的流写会把数据交给传输层（按包切、重传、流控都在那边），
	// 这里一次交完。
	if _, err := w.str.Write(out); err != nil {
		return err
	}
	// 半关：响应发完这一侧就结束了，对端据此知道没有更多数据
	return w.str.Close()
}

// WriteResponseKV 和 WriteResponse 一样，但头用 [][2]string 给。
//
// 给的是"键值成对"的切片（arena 那类 handler 内部就是这么存的），
// 这里用连接级的复用切片转成 HeaderField，省掉每请求一次分配。
func (w *ResponseWriter) WriteResponseKV(status int, headers [][2]string, body []byte) error {
	c := w.c
	c.hfc = c.hfc[:0]
	for i := range headers {
		c.hfc = append(c.hfc, qpack.HeaderField{Name: headers[i][0], Value: headers[i][1]})
	}
	return w.WriteResponse(status, c.hfc, body)
}

// NativeServer 是自建的 HTTP/3 服务端。
//
// 和 Server 的区别：Server 把请求交给 net/http 的 Handler，这个交给
// 自己的 Handler——请求/响应不经过 net/http 的任何对象。
type NativeServer struct {
	// Addr 是监听的 UDP 地址，形如 ":443"。
	Addr string
	// TLSConfig 至少要带证书。QUIC 强制 TLS 1.3。
	TLSConfig *tls.Config
	// QUICConfig 是 QUIC 那层的参数。
	QUICConfig *quic.Config
	// Handler 处理请求。
	Handler Handler
}

// ListenAndServe 起服务，阻塞到出错。
func (s *NativeServer) ListenAndServe() error {
	addr := s.Addr
	if addr == "" {
		addr = ":443"
	}
	ln, err := quic.ListenAddr(addr, s.TLSConfig, s.QUICConfig)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve 在一个 QUIC listener 上服务。
func (s *NativeServer) Serve(ln *quic.Listener) error {
	for {
		qc, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.serveConn(qc)
	}
}

// ── 连接 ────────────────────────────────────────────────────────────────

type nativeConn struct {
	s  *NativeServer
	qc *quic.Conn

	dec *qpack.Decoder
	// enc 的落点是 &encW（构造时传进去，字段地址稳定），
	// 每编一块头先把 encW.p 指到 block 上。
	enc  *qpack.Encoder
	encW sliceWriter

	// 复用缓冲。一个请求走完不分配新内存（除非请求体或响应体长过现有容量）。
	rbuf  []byte
	block []byte
	wbuf  []byte
	// hb 是请求头（复用），hfc 是响应头转成 HeaderField 后的复用切片
	hb  []qpack.HeaderField
	hfc []qpack.HeaderField

	fp  FrameParser
	req Request
	w   ResponseWriter
}

// sliceWriter 是 qpack.Encoder 的落点：直接 append 进复用的切片，
// 不走 bytes.Buffer（那个每次 Write 都可能重新分配）。
type sliceWriter struct{ p []byte }

func (w *sliceWriter) Write(b []byte) (int, error) {
	w.p = append(w.p, b...)
	return len(b), nil
}

func (s *NativeServer) serveConn(qc *quic.Conn) {
	c := &nativeConn{
		s:    s,
		qc:   qc,
		dec:  qpack.NewDecoder(),
		rbuf: make([]byte, 8*1024),
		hb:   make([]qpack.HeaderField, 0, 16),
	}
	c.enc = qpack.NewEncoder(&c.encW)
	c.w.c = c

	ctx := context.Background()
	if err := c.sendSettings(ctx); err != nil {
		qc.CloseWithError(0, "")
		return
	}
	// 对端的单向流（控制流、QPACK 编/解码器流）要收，不然 quic-go
	// 那边的流配额会被占住。单开一个 goroutine 收它们。
	go c.recvUniStreams(ctx)

	for {
		str, err := qc.AcceptStream(ctx)
		if err != nil {
			return
		}
		c.handleRequest(str)
	}
}

// sendSettings 开控制流，发 SETTINGS。
//
// **MAX_TABLE_CAPACITY 和 BLOCKED_STREAMS 都报 0**：告诉对端"别用动态表"。
// 这样头块里出现的只可能是静态表引用和字面量，解码器不需要任何跨流的
// 状态（也就不需要处理 QPACK 编解码器单向流上的指令）。
func (c *nativeConn) sendSettings(ctx context.Context) error {
	str, err := c.qc.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	var buf []byte
	buf = AppendVarint(buf, StreamControl)
	buf = AppendSettings(buf,
		Setting{ID: SettingQPACKMaxTableCapacity, Value: 0},
		Setting{ID: SettingQPACKBlockedStreams, Value: 0},
	)
	if _, err := str.Write(buf); err != nil {
		return err
	}
	// 控制流不关：它还要用来发 GOAWAY
	return nil
}

// recvUniStreams 收对端的单向流。
//
// 我们只关心控制流（对端的 SETTINGS），别的读干净丢掉——不读的话
// 对面那条流会一直挂着，占住它的单向流配额。
func (c *nativeConn) recvUniStreams(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		str, err := c.qc.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		for {
			if _, err := str.Read(buf); err != nil {
				break
			}
		}
	}
}

// handleRequest 处理一条请求流（就地，不起 goroutine）。
func (c *nativeConn) handleRequest(str *quic.Stream) {
	c.fp.Reset()
	c.req = Request{Proto: "HTTP/3.0", Body: c.req.Body[:0], Header: c.hb[:0]}
	c.w.str = str
	c.w.wrote = false

	if err := c.readRequest(str); err != nil {
		str.CancelRead(0)
		return
	}
	c.hb = c.req.Header

	if c.s.Handler != nil {
		_ = c.s.Handler(&c.w, &c.req)
		return
	}
	_ = c.w.WriteResponse(204, nil, nil)
}

// readRequest 把一条请求流上的帧读完，填进 c.req。
//
// 就地循环读：读到流结束（客户端发完请求就 END_STREAM）。GET 请求
// 上来就是"HEADERS + FIN"，一次 Read 就完事。
func (c *nativeConn) readRequest(str *quic.Stream) error {
	var cbErr error
	for {
		n, err := str.Read(c.rbuf)
		if n > 0 {
			if _, perr := c.fp.Parse(c.rbuf[:n], func(f *Frame) error {
				switch f.Type {
				case FrameHeaders:
					// 载荷指向解析器的内部缓冲，**要当场解掉**
					dec := c.dec.Decode(f.Payload)
					for {
						hf, derr := dec()
						if derr == io.EOF {
							return nil
						}
						if derr != nil {
							return derr
						}
						c.addField(hf)
					}
				case FrameData:
					c.req.Body = append(c.req.Body, f.Payload...)
				default:
					// 请求流上不该有别的帧（SETTINGS/GOAWAY 在控制流上）
				}
				return nil
			}); perr != nil {
				return perr
			}
		}
		if err != nil {
			if err == io.EOF {
				return cbErr
			}
			return err
		}
	}
}

// addField 把一个头字段收进请求里：伪头拆成字段，普通的进 Header。
func (c *nativeConn) addField(hf qpack.HeaderField) {
	switch hf.Name {
	case ":method":
		c.req.Method = hf.Value
	case ":path":
		if i := indexByte(hf.Value, '?'); i >= 0 {
			c.req.Path = hf.Value[:i]
			c.req.Query = hf.Value[i+1:]
		} else {
			c.req.Path = hf.Value
			c.req.Query = ""
		}
	case ":scheme", ":authority":
		// 回环的 benchmark 用不上；留着会让 Header 多两次遍历
	default:
		c.req.Header = append(c.req.Header, hf)
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
