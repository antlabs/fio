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
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
)

// 自建的 HTTP/3 服务端：**只借 quic-go 的 QUIC 传输**，HTTP/3 这一层
// （帧、QPACK、流分类、请求生命周期）全在这里，不经过 net/http。
//
// **对外的形状和 http2 那套一致**——一样的 StreamHandler 接口、一样的
// Conn.WriteHeaders/WriteData(streamID, ...)、一样把 HeaderField 做成
// 类型别名。协议层的实现者（比如 arena 的入口）两个协议用同一套写法。
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
// 几个取舍：
//   - **不为每个请求起 goroutine**：请求流在连接的 goroutine 上就地处理。
//   - **QPACK 只用静态表**：SETTINGS 里 MAX_TABLE_CAPACITY 和
//     BLOCKED_STREAMS 都报 0，对端就只用静态表和字面量表示，解码器不需要
//     任何跨流状态（quic-go/qpack 的 Decoder 正好只支持这一档）。
//   - **一次响应一个 Write**：HEADERS 帧 + DATA 帧拼在同一个缓冲里。
//   - **每条连接复用几块缓冲**，一个请求不分配（除非体长过现有容量）。

// HeaderField 和 http2 那边一样是个别名——两边的用法完全相同。
type HeaderField = qpack.HeaderField

// ErrCode 是 HTTP/3 的应用错误码（RFC 9114 section 8.1）。
type ErrCode uint64

const (
	// ErrCodeNoError 没有错误。
	ErrCodeNoError ErrCode = 0x100
	// ErrCodeGeneralProtocolError 通用协议错误。
	ErrCodeGeneralProtocolError ErrCode = 0x101
	// ErrCodeInternalError 内部错误。
	ErrCodeInternalError ErrCode = 0x102
	// ErrCodeStreamCreationError 流创建错误。
	ErrCodeStreamCreationError ErrCode = 0x103
)

// StreamHandler 是流上面的事件回调。
//
// **和 http2.StreamHandler 是同一套**：协议层（比如 gRPC）实现它，http3
// 把流上的请求头、数据、结束通知交给它。差别只有 streamID 是 uint64
// （QUIC 的流 ID 是 62 位变长整数）。
type StreamHandler interface {
	// OnHeaders 一个流的请求头解完了。
	OnHeaders(c *Conn, streamID uint64, headers []HeaderField, endStream bool)

	// OnData 流上的数据。末尾那次 endStream 为真。
	OnData(c *Conn, streamID uint64, data []byte, endStream bool)

	// OnRSTStream 对端重置了一个流。
	OnRSTStream(c *Conn, streamID uint64, code ErrCode)
}

// Conn 是一条 HTTP/3 连接。
//
// 和 http2.Conn 一样是"每条连接一个"，**不是并发安全的**：所有回调都
// 在这条连接的 goroutine 上跑（见 NativeServer.serveConn）。
type Conn struct {
	qc *quic.Conn
	// h 是流事件的接收者（和 http2.Conn 的 handler 一个位置）
	h StreamHandler
	// newH 是 handler 工厂：并行通道 >1 时每条通道一个实例
	newH func() StreamHandler
	// mu 保护 streams
	mu sync.Mutex
	// streams 是活着的请求流：WriteHeaders/WriteData 靠它按 streamID 拿到
	// 那条流的发送状态（缓冲在 lane 里，见 lane）
	streams map[uint64]*streamState

	// dec 是 QPACK 解码器。只用静态表，所以无状态——几条 lane 同时用
	// 也没事（qpack.Decoder 是个空结构体）。
	dec *qpack.Decoder
}

// streamState 是一条流处理中的收发状态。
//
// 它归**一条 lane**所有（见 lane）：lane 串行处理自己那些流，所以这套
// 缓冲不需要锁。把发送缓冲放进来的原因是 WriteHeaders/WriteData 是按
// streamID 调的（和 http2 一个形状），得能从连接上找到当前这条流的缓冲。
type streamState struct {
	str *quic.Stream
	// enc 的落点是 &encW（构造时传进去，字段地址稳定），
	// 每编一块头先把 encW.p 指到 block 上。
	enc  *qpack.Encoder
	encW sliceWriter
	// 复用缓冲：读、头块、发送、头字段
	rbuf  []byte
	block []byte
	wbuf  []byte
	hb    []HeaderField
	body  []byte

	fp FrameParser
}

// sliceWriter 是 qpack.Encoder 的落点：直接 append 进复用的切片，
// 不走 bytes.Buffer（那个每次 Write 都可能重新分配）。
type sliceWriter struct{ p []byte }

func (w *sliceWriter) Write(b []byte) (int, error) {
	w.p = append(w.p, b...)
	return len(b), nil
}

// WriteHeaders 把一个流的响应头发出去。
//
// 和 http2.Conn.WriteHeaders 一样：fields 里要自己带 :status，endStream
// 为真表示这次响应没有体（或者体已经在之前发出去了）。
//
// **一次响应从这里开始**：内部发送缓冲在这一刻复位。
func (c *Conn) WriteHeaders(streamID uint64, fields []HeaderField, endStream bool) error {
	st := c.streamState(streamID)
	if st == nil {
		return nil
	}
	st.wbuf = st.wbuf[:0]
	st.block = st.block[:0]
	st.encW.p = st.block
	for i := range fields {
		if err := st.enc.WriteField(fields[i]); err != nil {
			return err
		}
	}
	// Close 只是复位编码器（头块前缀下次重写），不是"关流"
	if err := st.enc.Close(); err != nil {
		return err
	}
	st.block = st.encW.p
	st.wbuf = AppendHeaders(st.wbuf, st.block)

	if endStream {
		return st.flush(true)
	}
	return nil
}

func (c *Conn) streamState(streamID uint64) *streamState {
	c.mu.Lock()
	st := c.streams[streamID]
	c.mu.Unlock()
	return st
}

// WriteData 往一个流上写体。
//
// 和 http2.Conn.WriteData 一样：这次调用会把积压的头帧一起发出去。
func (c *Conn) WriteData(streamID uint64, data []byte, endStream bool) error {
	st := c.streamState(streamID)
	if st == nil {
		return nil
	}
	st.wbuf = AppendData(st.wbuf, data)
	if endStream {
		return st.flush(true)
	}
	return nil
}

// WriteTrailers 发 trailer：一个带 END_STREAM 的 HEADERS 帧。
//
// HTTP/3 和 h2 一样有 trailer（gRPC 用它送调用状态）。
func (c *Conn) WriteTrailers(streamID uint64, fields []HeaderField) error {
	st := c.streamState(streamID)
	if st == nil {
		return nil
	}
	st.block = st.block[:0]
	st.encW.p = st.block
	for i := range fields {
		if err := st.enc.WriteField(fields[i]); err != nil {
			return err
		}
	}
	if err := st.enc.Close(); err != nil {
		return err
	}
	st.block = st.encW.p
	st.wbuf = AppendHeaders(st.wbuf, st.block)
	return st.flush(true)
}

// flush 把攒下来的帧交给 QUIC 流。
//
// QUIC 那层负责按包切、重传、流控，这里一次交完就行。
func (st *streamState) flush(close bool) error {
	_, err := st.str.Write(st.wbuf)
	st.wbuf = st.wbuf[:0]
	if err != nil {
		return err
	}
	if close {
		// 半关：响应发完这一侧就结束了，对端据此知道没有更多数据
		return st.str.Close()
	}
	return nil
}

// Conn 暴露底层的 QUIC 连接（拿对端地址这类用途）。
func (c *Conn) QUICConn() *quic.Conn { return c.qc }

// NativeServer 是自建的 HTTP/3 服务端。
//
// 和 Server 的区别：Server 把请求交给 net/http 的 Handler（那是 quic-go
// 的 http3.Server 要求的），这个把流事件交给 StreamHandler——**和 http2
// 那套入口一个形状**。
type NativeServer struct {
	// Addr 是监听的 UDP 地址，形如 ":443"。
	Addr string
	// TLSConfig 至少要带证书。QUIC 强制 TLS 1.3。
	TLSConfig *tls.Config
	// QUICConfig 是 QUIC 那层的参数。
	QUICConfig *quic.Config
	// NewHandler 每条连接建一个流事件接收者。
	//
	// **是工厂不是单个实例**：Handler 是每条连接一份的有状态对象（攒流的
	// 头、复用缓冲），共用一个就得加锁。fio 里 engine.ListenAndServe 的
	// newHandler 也是这个形状。
	NewHandler func() StreamHandler
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
		// 一条 QUIC 连接一个 goroutine（和 http2 那边"一个 engine.Conn
		// 一个协议状态"是一个量级），但**流不再各起一个**。
		go s.serveConn(qc, s.NewHandler())
	}
}

func (s *NativeServer) serveConn(qc *quic.Conn, h StreamHandler) {
	c := &Conn{
		qc:      qc,
		h:       h,
		newH:    s.NewHandler,
		streams: make(map[uint64]*streamState),
		dec:     qpack.NewDecoder(),
	}

	ctx := context.Background()
	if err := c.sendSettings(ctx); err != nil {
		qc.CloseWithError(quic.ApplicationErrorCode(ErrCodeInternalError), "")
		return
	}
	// 对端的单向流（控制流、QPACK 编/解码器流）要收，不然 quic-go
	// 那边的流配额会被占住。单开一个 goroutine 收它们。
	go c.recvUniStreams(ctx)

	// **每条连接的并行通道数**。
	//
	// 1 = 就地串行（连接的 goroutine 上一条一条来）。这是实测最快的默认：
	// baseline-h3 上它比 quic-go 的"每流一个 goroutine"快 3.7 倍。
	//
	// >1 是为了 static-h3 那种**大响应**：一条流写 16KB 时会被 QUIC 的
	// 流控挡住（str.Write 阻塞），串行的话同连接上后面 63 条流都得等。
	// 但也不能每流一个 goroutine——那条路测下来反而更慢（baseline-h3
	// 2.51M -> 1.44M），goroutine 创建加上 quic-go 发送路径的锁竞争，
	// 比省下来的并行度更贵。所以只有限的几条通道，每条自己一套缓冲和
	// handler 实例。
	//
	// 注意 lanes > 1 时**同一个 StreamHandler 实例不再被串行调用**，
	// 见 StreamHandler 的说明。
	lanes := h3Lanes
	if lanes <= 1 {
		l := &lane{h: h, st: newStreamState()}
		for {
			str, err := qc.AcceptStream(ctx)
			if err != nil {
				return
			}
			c.handleStream(l, str, uint64(str.StreamID()))
		}
	}

	type streamItem struct {
		str *quic.Stream
		id  uint64
	}
	ch := make(chan streamItem, lanes*2)
	for i := 0; i < lanes; i++ {
		go func() {
			l := &lane{h: c.newH(), st: newStreamState()}
			for it := range ch {
				c.handleStream(l, it.str, it.id)
			}
		}()
	}
	for {
		str, err := qc.AcceptStream(ctx)
		if err != nil {
			close(ch)
			return
		}
		ch <- streamItem{str, uint64(str.StreamID())}
	}
}

// h3Lanes 是每条连接的并行通道数。环境变量是为了能在 lab 上扫一遍
// （不改代码就能试 1/2/4/8），默认 4。
//
// **4 是量出来的**（lab，服务端 0-11 / 客户端 12-23 / MTU 1500）：
//
//	              1        4        8      quic-go(http3.Server)
//	baseline-h3  2.51M    2.41M    2.34M        0.67M
//	static-h3    199K     235K     233K         215K
//
// baseline-h3 是"小响应、高并发"，串行最快；static-h3 是"16KB 响应、64 条
// 并发流"，一条流写大响应时会被 QUIC 流控挡住，串行就把同连接后面几十条流
// 一起堵住——4 条通道刚好，再多（8）反而回到锁竞争上。
var h3Lanes = func() int {
	if v := os.Getenv("FIO_H3_LANES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 4
}()

// lane 是一条并行通道：自己的 handler 实例 + 自己的那套缓冲。
type lane struct {
	h  StreamHandler
	st *streamState
}

func newStreamState() *streamState {
	st := &streamState{rbuf: make([]byte, 8*1024), hb: make([]HeaderField, 0, 16)}
	st.enc = qpack.NewEncoder(&st.encW)
	return st
}

// sendSettings 开控制流，发 SETTINGS。
//
// **MAX_TABLE_CAPACITY 和 BLOCKED_STREAMS 都报 0**：告诉对端"别用动态表"。
// 这样头块里出现的只可能是静态表引用和字面量，解码器不需要任何跨流的
// 状态（也就不需要处理 QPACK 编解码器单向流上的指令）。
func (c *Conn) sendSettings(ctx context.Context) error {
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
func (c *Conn) recvUniStreams(ctx context.Context) {
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

// handleStream 处理一条请求流（在它所属的 lane 上串行执行）。
//
// 先把这条流上的帧读完（GET 一次 Read 就到底），再按 http2 那套回调
// 顺序交给 Handler：OnHeaders 一次，body 非空时再 OnData 一次收尾。
// **endStream 是这么定出来的**：HTTP/3 的"请求结束"是 QUIC 流的 FIN，
// 不是帧里的标志（这点和 h2 不同），所以要读完才知道最后那一下算谁的。
func (c *Conn) handleStream(l *lane, str *quic.Stream, streamID uint64) {
	st := l.st
	st.str = str
	st.fp.Reset()
	st.hb = st.hb[:0]
	st.body = st.body[:0]

	c.mu.Lock()
	c.streams[streamID] = st
	c.mu.Unlock()

	cbErr := st.readAndDispatch(c, l.h, streamID)

	c.mu.Lock()
	delete(c.streams, streamID)
	c.mu.Unlock()
	st.str = nil
	_ = cbErr
}

// readAndDispatch 把一条流读完并交给 Handler。
func (st *streamState) readAndDispatch(c *Conn, h StreamHandler, streamID uint64) error {
	// 头帧里攒下的头块：载荷指向解析器的内部缓冲，不能留到 Parse 返回之后
	var raw []byte

	var cbErr error
	for {
		n, err := st.str.Read(st.rbuf)
		if n > 0 {
			if _, perr := st.fp.Parse(st.rbuf[:n], func(f *Frame) error {
				switch f.Type {
				case FrameHeaders:
					raw = append(raw[:0], f.Payload...)
					dec := c.dec.Decode(raw)
					for {
						hf, derr := dec()
						if derr == io.EOF {
							return nil
						}
						if derr != nil {
							return derr
						}
						st.hb = append(st.hb, hf)
					}
				case FrameData:
					st.body = append(st.body, f.Payload...)
				default:
					// 请求流上不该有别的帧（SETTINGS/GOAWAY 在控制流上）
				}
				return nil
			}); perr != nil {
				cbErr = perr
				break
			}
		}
		if err != nil {
			if err != io.EOF {
				cbErr = err
			}
			break
		}
	}

	if cbErr != nil {
		h.OnRSTStream(c, streamID, ErrCodeGeneralProtocolError)
		st.str.CancelRead(quic.StreamErrorCode(ErrCodeGeneralProtocolError))
		return cbErr
	}

	h.OnHeaders(c, streamID, st.hb, len(st.body) == 0)
	if len(st.body) > 0 {
		h.OnData(c, streamID, st.body, true)
	}
	return nil
}
