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

//go:build linux || darwin || netbsd || freebsd || openbsd || dragonfly

package http2

import (
	"github.com/antlabs/fio/engine"
)

// engine.Handler 的适配层：把 HTTP/2 接到 fio 的事件循环上。
//
//	engine（epoll + 非阻塞 io）
//	  ↓ OnData(buf)
//	ConnHandler.OnData -> http2.Conn.Feed  解帧、管流、解 HPACK
//	  ↓ TakeOutput
//	engine.Conn.Write                       写回 fd
//
// 这一层很薄——HTTP/2 的逻辑都在 conn.go 里，这里只做"搬运"：
// 把读到的字节给 Feed，把 Feed 吐出来的字节写给连接。
//
// 有了它，HTTP/2 就和 HTTP/1.1 一样能跑在事件循环上（不再需要调用方
// 手工喂字节）。
type ConnHandler struct {
	// handler 是流事件的接收者（业务实现）
	handler StreamHandler
	// isClient 这条连接是客户端还是服务端
	isClient bool

	// conn 是协议状态，OnOpen 时建
	conn *Conn
}

// NewStreamConnHandler 建一个**流级**的服务端 HTTP/2 engine.Handler：
// h 自己处理 HEADERS/DATA/RST（要自己管每条流的状态）。gRPC 走这条。
//
// 想跟 http1 一个形状（一个 http.Handler、参数是 *http.Ctx）的话用
// NewConnHandler，见 handler.go。
//
// 每条连接一个（HPACK 的编解码器是有状态的，不能共用）。
func NewStreamConnHandler(h StreamHandler) *ConnHandler {
	return &ConnHandler{handler: h}
}

// NewClientConnHandler 建一个客户端的。
func NewClientConnHandler(h StreamHandler) *ConnHandler {
	return &ConnHandler{handler: h, isClient: true}
}

// OnOpen 连接建立：建协议状态。
func (ch *ConnHandler) OnOpen(c *engine.Conn) {
	ch.conn = NewConn(ch.isClient, ch.handler)
	if ch.isClient {
		// 客户端先发连接序言（24 字节明文）+ SETTINGS
		ch.sendPreface()
		ch.flush(c)
		return
	}

	// 服务端**也要发 SETTINGS**（RFC 9113 3.4：连接序言之后，双方
	// 各自发一个 SETTINGS，都是自己那条"我能接受什么"的声明）。
	//
	// **而且必须是服务端发的第一个帧**。这一条很容易漏——服务端看起来
	// "只需要等客户端开口"，于是什么都先不发；但客户端那边在等我们的
	// SETTINGS（它要据此设 peerMaxFrameSize、流控窗口），等不到就一直
	// 卡着。实测：h2spec 的 145 条用例里 144 条报 Timeout，就是这个——
	// 它连第一条 SETTINGS 都收不到，后面什么帧都不敢发。
	//
	// 和客户端的 SETTINGS 有一处不同：服务端还要声明
	// SETTINGS_INITIAL_WINDOW_SIZE，也就是**我们愿意为每个流收多少**。
	// 声明得大一点（1MB），这样对端发大请求体时不用频繁等我们补窗口。
	ch.sendServerSettings()
	ch.flush(c)
}

// sendPreface 客户端发连接序言（RFC 9113 3.4）。
//
// 序言是**明文的 24 字节**，不是帧，所以要单独塞进发送缓冲（writeFrame
// 只管帧）。它后面紧跟一个 SETTINGS。
func (ch *ConnHandler) sendPreface() {
	ch.conn.WriteRaw(clientPreface)
	var buf []byte
	buf = AppendSettings(buf, [2]uint32{0x5, defaultMaxFrameSize})
	ch.conn.WriteRaw(buf)
}

// sendServerSettings 服务端发自己的 SETTINGS（第一个帧）。
func (ch *ConnHandler) sendServerSettings() {
	var buf []byte
	buf = AppendSettings(buf,
		// MAX_FRAME_SIZE：我们愿意收的最大帧
		[2]uint32{0x5, defaultMaxFrameSize},
		// INITIAL_WINDOW_SIZE：**每个流**我们愿意收多少（1MB）。
		//
		// 默认是 65535，太小了：对端发完就得停下来等我们补窗口，来回
		// 一趟 RTT。开大一点能让"发大 body"少几次往返。
		// （连接级的窗口协议上没法用 SETTINGS 调，只能靠 WINDOW_UPDATE
		// 慢慢加——所以下面那句 WINDOW_UPDATE 才是真正要生效的。）
		[2]uint32{0x4, maxRecvWindow},
	)
	ch.conn.WriteRaw(buf)

	// 把连接级窗口也一次性开大（默认 65535，没法用 SETTINGS 声明）。
	//
	// RFC 9113 6.9.2 允许接收方随时发 WINDOW_UPDATE 调连接级窗口，
	// 只要别超过 2^31-1。
	ch.conn.writeFrame(AppendWindowUpdate(nil, 0, maxRecvWindow-defaultInitialWindowSize))
	ch.conn.localInitialWindow = int32(maxRecvWindow)
	ch.conn.recvWindow = int32(maxRecvWindow)
}

// OnData 有数据可读：喂给 HTTP/2 状态机。
//
// 返回值按 engine 的契约：消化了多少字节。
func (ch *ConnHandler) OnData(c *engine.Conn, buf []byte) (int, error) {
	if ch.conn == nil {
		// OnOpen 还没跑到（引擎不保证它先于 OnData），补上
		ch.OnOpen(c)
	}

	return ch.conn.FeedWrite(c, buf)
}

// FeedWrite 喂一段字节，并**在这次调用里把产生的帧写出去**，返回消化量。
//
// 和 Feed 只差输出怎么交出去，而这一点对 static 这类大响应是决定性的：
// Feed 走 TakeOutput，那把发送缓冲的数组交出去之后连接就丢了它
// （outBuf = nil），下一批帧只能重新分配——8KB 的响应就是每请求一块 8KB，
// 实测那一处占 static 全部堆分配的 90%。这里改成写完把数组复位留着，
// 下一批接着用。
//
// **写的时候持着协议锁**：那块缓冲马上要被复用，锁外写的话另一个 goroutine
// 的一次 WriteData 就能把它覆盖掉——这正是这把锁存在的理由。ec.Write 自己
// 拿引擎那把锁，而两把锁的获取顺序在别处都是"协议 → 引擎"（引擎调 OnData
// 时不持自己的锁），不会反向，所以不构成死锁。
func (c *Conn) FeedWrite(ec *engine.Conn, data []byte) (int, error) {
	// 记下底层连接：请求级的 Writer.Conn() 要用（见 handler.go）
	c.ec = ec
	consumed, err := c.feed(data)
	if werr := c.WriteOutput(ec); werr != nil && err == nil {
		err = werr
	}
	return consumed, err
}

// WriteOutput 把攒下的帧写给 ec，并保留那块缓冲给下一轮。
func (c *Conn) WriteOutput(ec *engine.Conn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.outBuf) == 0 {
		return nil
	}
	if err := ec.Write(c.outBuf); err != nil {
		return err
	}
	c.outBuf = c.outBuf[:0]
	return nil
}

// OnClose 连接关闭。
func (ch *ConnHandler) OnClose(c *engine.Conn, err error) {
	ch.conn = nil
}

// Conn 返回协议状态（要主动发请求/响应时用）。
func (ch *ConnHandler) Conn() *Conn { return ch.conn }

// flush 把内部缓冲里的东西写出去。
func (ch *ConnHandler) flush(c *engine.Conn) {
	_ = ch.conn.WriteOutput(c)
}

// WriteHeaders 发响应头（走 engine 的连接）。
//
// 这是给业务用的：收到 OnHeaders/OnData 之后，用这个发响应。
func (ch *ConnHandler) WriteHeaders(c *engine.Conn, streamID uint32, fields []HeaderField, endStream bool) error {
	if err := ch.conn.WriteHeaders(streamID, fields, endStream); err != nil {
		return err
	}
	return ch.writeOut(c)
}

// WriteData 发响应体。
func (ch *ConnHandler) WriteData(c *engine.Conn, streamID uint32, data []byte, endStream bool) error {
	if err := ch.conn.WriteData(streamID, data, endStream); err != nil {
		return err
	}
	return ch.writeOut(c)
}

// WriteTrailers 发 trailer（带 END_STREAM）。
func (ch *ConnHandler) WriteTrailers(c *engine.Conn, streamID uint32, fields []HeaderField) error {
	if err := ch.conn.WriteTrailers(streamID, fields); err != nil {
		return err
	}
	return ch.writeOut(c)
}

// writeOut 把状态机吐出来的字节写进连接。
func (ch *ConnHandler) writeOut(c *engine.Conn) error {
	return ch.conn.WriteOutput(c)
}
