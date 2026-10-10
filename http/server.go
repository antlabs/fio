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
	"errors"
	"strconv"
	"strings"

	"github.com/antlabs/fio/engine"
)

// ResponseWriter 是给回调写响应用的。
//
// 形状对齐 net/http 的 ResponseWriter（Header/Write/WriteHeader），但
// 底层不是 bufio + 阻塞写，而是**先攒头、Write 时一次发出去**——非阻塞
// 的 socket 上，分开写头和数据意味着两次系统调用，而且中间可能被可写
// 事件打断，顺序要额外维护。
type ResponseWriter struct {
	// header 是还没发出去的头（名字 -> 值）
	header map[string][]string
	// statusCode 是状态码，0 表示还没设（默认 200）
	statusCode int
	// wroteHeader 调用方设过状态码了没有（WriteHeader 被调过）
	wroteHeader bool
	// headerSent 头真的写出去电路上没有
	headerSent bool

	// conn 是底层连接
	conn *engine.Conn
	// buf 是拼响应用的缓冲区（连接级复用）
	buf *[]byte

	// proto 是当前请求的版本（"HTTP/1.1"、"HTTP/1.0"）。
	//
	// 响应的版本行要按它来写：RFC 9112 2.3 要求服务端回的版本"不高于"
	// 请求的版本。对 1.0 请求回 "HTTP/1.1" 的话，严格的老客户端会当成
	// 跟自己无关的东西——而且 1.0 的客户端不认 chunked，回 1.1 却只给
	// chunked 是自相矛盾的（见 flushHeader 里的分叉）。
	proto string

	// closeAfterWrite 这次响应写完就关连接。
	//
	// 用在"HTTP/1.0 且调用方没给 Content-Length"上：1.0 没有 chunked，
	// 唯一能给客户端划出体边界的办法就是关连接。
	closeAfterWrite bool

	// deferred 这次响应由业务稍后写（见 Defer）。
	deferred bool

	// chunked 这个响应用 chunked（调用方没设 Content-Length）
	chunked bool
	// finished chunked 的收尾块发过没有
	finished bool
}

// Header 返回可以设置的头。
func (w *ResponseWriter) Header() map[string][]string {
	if w.header == nil {
		w.header = make(map[string][]string, 8)
	}
	return w.header
}

// WriteHeader 设状态码。重复调只认第一次。
func (w *ResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.statusCode = code
	w.wroteHeader = true
}

// Write 写响应体。
//
// 第一次 Write 会先把头拼好发出去（HTTP/1.1 的规矩：头和体不能分开决定）。
func (w *ResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}

	// 第一次写：头拼好之后**和体一次发出去**。
	//
	// 分开写是两次系统调用（先头、再体），而压测里的响应就是几十字节的
	// 头加几字节的体——两次 write 的固定开销比数据本身还大。实测
	// (baseline 场景, 64 连接): 每个请求 13.4µs 的用户态 CPU，其中
	// 4.8µs 在这一对 write 上。
	//
	// Writev 在总长 ≤4KB 时拼到栈上一次 write，更大时走真正的 writev，
	// 两条路都只有一次系统调用。
	if !w.headerSent {
		w.buildHeader()
		w.headerSent = true
		if w.chunked {
			// chunked 的每段体要自带长度前缀，凑不到一次写里。
			return w.writeChunkedFirst(body)
		}
		if len(body) == 0 {
			return 0, w.conn.Write(*w.buf)
		}
		if err := w.conn.Writev(*w.buf, body); err != nil {
			return 0, err
		}
		return len(body), nil
	}

	if len(body) == 0 {
		return 0, nil
	}

	// 没设 Content-Length 的就是 chunked（见 buildHeader），每段要
	// 自己带长度前缀。
	if w.chunked {
		if err := w.writeChunk(body); err != nil {
			return 0, err
		}
		return len(body), nil
	}
	return len(body), w.conn.Write(body)
}

// writeChunkedFirst 是 chunked 响应里"头还没发、体来了"那条路：头先出去，
// 剩下的按普通 chunked 走。
func (w *ResponseWriter) writeChunkedFirst(body []byte) (int, error) {
	if err := w.conn.Write(*w.buf); err != nil {
		return 0, err
	}
	if len(body) == 0 {
		return 0, nil
	}
	if err := w.writeChunk(body); err != nil {
		return 0, err
	}
	return len(body), nil
}

// writeChunk 按 chunked 格式写一段体：`<十六进制长度>\r\n<数据>\r\n`。
func (w *ResponseWriter) writeChunk(body []byte) error {
	var head [18]byte
	n := copy(head[:], strconv.AppendInt(head[:0], int64(len(body)), 16))
	head[n] = '\r'
	head[n+1] = '\n'
	if err := w.conn.Write(head[:n+2]); err != nil {
		return err
	}
	if err := w.conn.Write(body); err != nil {
		return err
	}
	return w.conn.Write([]byte("\r\n"))
}

// finish 响应收尾：chunked 的补一个"最后一块"（长度 0 的 chunk）。
//
// **这一步不能省**：chunked 的报文靠这个 0 长度的块收尾，客户端读到它
// 才知道体结束了。漏了的话客户端会一直等——实测标准库的 http 客户端
// 报 context deadline exceeded，而数据其实早就到了。
func (w *ResponseWriter) finish() error {
	if !w.chunked || w.finished {
		return nil
	}
	w.finished = true
	return w.conn.Write([]byte("0\r\n\r\n"))
}

// flushHeader 把状态行 + 头拼出来发出去。只发一次。
//
// 业务一个字都没写（只调了 WriteHeader，或者干脆什么都没做）时走这里：
// 头必须发出去，不然客户端一直等。
func (w *ResponseWriter) flushHeader() error {
	if w.headerSent {
		return nil
	}
	w.buildHeader()
	w.headerSent = true
	return w.conn.Write(*w.buf)
}

// buildHeader 拼状态行 + 头，结果放在 w.buf 里，**不发**。
//
// 和发送分开是为了让 Write 能把头和体凑成一次写（见 Write）。
// 调用方负责置 headerSent——这函数自己被调两次的话 w.buf 里就是两份头。
func (w *ResponseWriter) buildHeader() {
	if w.statusCode == 0 {
		w.statusCode = 200
	}

	// 复用连接上的缓冲区
	if w.buf == nil || cap(*w.buf) < 256 {
		b := make([]byte, 0, 512)
		w.buf = &b
	}
	buf := (*w.buf)[:0]

	// 版本行按**请求**的版本回（RFC 9112 2.3：不高于请求的版本）。
	if w.proto == "HTTP/1.0" {
		buf = append(buf, "HTTP/1.0 "...)
	} else {
		buf = append(buf, "HTTP/1.1 "...)
	}
	buf = strconv.AppendInt(buf, int64(w.statusCode), 10)
	buf = append(buf, ' ')
	buf = append(buf, StatusText(w.statusCode)...)
	buf = append(buf, '\r', '\n')

	// **体的长度怎么界定**（RFC 9112 6.3）：有 Content-Length 就按它，
	// 没有就得用 chunked。
	//
	// 两种都不给的话客户端没法知道体到哪儿结束——它会一直等连接关闭
	// （或者超时）。这不是"可选优化"，是报文合法性的问题：标准库的
	// http 客户端会一直挂到 deadline。早先这里只有 Content-Length 的
	// 路径，body 边界靠"写完就关"，但没人真的去关，于是每个没设
	// Content-Length 的响应都会把客户端吊死。
	//
	// 状态码 204/304 和 HEAD 响应是例外：它们按定义没有体，不需要
	// 任何长度标记（也不需要 chunked）。
	if !hasContentLength(w.header) && !bodylessStatus(w.statusCode) {
		// HTTP/1.0 不认 chunked（RFC 9112 6.1：没看到请求是 1.1 就不能发
		// Transfer-Encoding 的响应）。对 1.0 的客户端，体只能靠"写完关
		// 连接"来界定。
		if w.proto == "HTTP/1.0" {
			w.closeAfterWrite = true
		} else {
			w.chunked = true
			buf = append(buf, "Transfer-Encoding: chunked\r\n"...)
		}
	}

	for name, values := range w.header {
		for _, v := range values {
			buf = append(buf, name...)
			buf = append(buf, ':', ' ')
			buf = append(buf, v...)
			buf = append(buf, '\r', '\n')
		}
	}
	buf = append(buf, '\r', '\n')

	*w.buf = buf
}

// WriteRaw 直接把一段字节写出去（给需要手写响应的地方用）。
func (w *ResponseWriter) WriteRaw(b []byte) error { return w.conn.Write(b) }

// hasContentLength 调用方设了 Content-Length 没有（大小写无关）。
func hasContentLength(header map[string][]string) bool {
	return hasHeaderName(header, "Content-Length")
}

// hasHeaderName 头 map 里有没有这个名字（大小写无关）。
func hasHeaderName(header map[string][]string, want string) bool {
	if _, ok := header[want]; ok {
		return true
	}
	for name := range header {
		if len(name) == len(want) && strings.EqualFold(name, want) {
			return true
		}
	}
	return false
}

// bodylessStatus 这个状态码按定义没有响应体（RFC 9110）。
func bodylessStatus(code int) bool {
	// 1xx 是中间响应，204 是"没有内容"，304 是"用你的缓存"
	return (code >= 100 && code < 200) || code == 204 || code == 304
}

// Conn 返回底层连接（写 trailer、拿对端地址之类的场景）。
func (w *ResponseWriter) Conn() *engine.Conn { return w.conn }

// Handler 处理 HTTP 请求。
//
// 形状和 net/http 的 Handler 一样：拿到请求和 ResponseWriter，写响应。
// 不同的是它跑在事件循环上——**不能阻塞**，要等什么东西的话得自己记住
// 状态、让出，等下一次回调。
type Handler interface {
	ServeHTTP(w *ResponseWriter, r *Request)
}

// HandlerFunc 让普通函数当 Handler。
type HandlerFunc func(w *ResponseWriter, r *Request)

func (f HandlerFunc) ServeHTTP(w *ResponseWriter, r *Request) { f(w, r) }

// ConnHandler 是每个连接一个的 engine.Handler。
//
// 一个连接上会来多个请求（keep-alive），所以解析器、ResponseWriter 都
// 挂在它上面复用。
type ConnHandler struct {
	// handler 是用户的业务处理
	handler Handler
	// maxHeaderSize 传给 httparser
	maxHeaderSize int32

	// onUpgrade 是收到 Upgrade 请求时的回调（websocket 握手）
	onUpgrade func(c *engine.Conn, r *Request)
}

// NewConnHandler 建一个连接级处理器。
func NewConnHandler(h Handler, maxHeaderSize int32) *ConnHandler {
	return &ConnHandler{
		handler:       h,
		maxHeaderSize: maxHeaderSize,
	}
}

// OnUpgrade 设置 Upgrade 请求的处理（比如交给 websocket）。
func (ch *ConnHandler) OnUpgrade(fn func(c *engine.Conn, r *Request)) {
	ch.onUpgrade = fn
}

// OnOpen 连接建立。
//
// **可能在 OnData 之后才跑到**：engine 的 Add 是 accept 循环（另一个
// goroutine）调的，它把 OnOpen 投进事件循环的任务队列；而同一个连接如果
// 立刻有数据到，事件可能先被 epoll 拿出来处理。所以状态不能只靠 OnOpen
// 建，OnData 那边要能兜住（见 state 方法）。
func (ch *ConnHandler) OnOpen(c *engine.Conn) {
	if c.UserData() == nil {
		c.SetUserData(ch.newState())
	}
}

// state 取连接状态，没有就现建。
//
// 兜住"OnData 比 OnOpen 先到"那种情况——引擎不保证两者的顺序（见 OnOpen
// 的注释）。
func (ch *ConnHandler) state(c *engine.Conn) *connState {
	if st, ok := c.UserData().(*connState); ok && st != nil {
		return st
	}
	st := ch.newState()
	c.SetUserData(st)
	return st
}

// OnData 有数据可读：喂给 httparser。
//
// **返回值语义**：按 engine.Handler 的契约，返回"消化了多少字节"——引擎
// 会把这么多字节从读缓冲区里丢掉，没丢的留着下次和新的拼一起再喂。
//
// 所以这里返回的必须是**真正处理掉的**：一个请求解完了、字节也确实
// 属于它，才算。报文没解完时返回已经解掉的部分，剩下的留给下一次。
//
// 踩过的坑：早先不管解没解完都返回 len(buf)，理由是"httparser 自己会
// 把不够的攒起来"。但引擎那边也把 buf 当作消化掉了——两边都留着，结果
// 是**同一段字节被处理两次**（症状：逐字节发的请求，服务端回一个
// broken pipe 就关，因为解析器拿到的字节是重复的、拼不出合法请求）。
//
// 规矩：**缓冲只有一处**，就是引擎的读缓冲区。解析器不攒。
func (ch *ConnHandler) OnData(c *engine.Conn, buf []byte) (int, error) {
	st := ch.state(c)
	if st.pending {
		// 上一个请求的响应还挂在那儿没写（业务调了 Defer）。**一个字节都
		// 不能消费**：返回 0 引擎就不丢这些字节，等 Resume 复位之后再喂回来。
		// 这里要是照常解析，第二个请求会盖掉第一个的状态（解析器、响应
		// 写出器都是同一个）。
		return 0, nil
	}
	consumed := 0

	for consumed < len(buf) {
		n, err := st.parser.Parse(buf[consumed:])
		if err != nil {
			// 报文坏了：回 400 然后关
			ch.writeError(c, st, 400, err)
			return len(buf), err
		}
		consumed += n

		if !st.parser.Done() {
			// 报文还没收全。已经解掉的那些字节算消化了（consumed），
			// 剩下的（buf[consumed:]）留着——引擎会保留它们，下次多读到
			// 一些再拼起来喂。
			break
		}

		// 一个请求解完了
		req := st.parser.Request()

		if st.parser.Upgrade() {
			// Upgrade 请求（websocket 握手）：交给外面处理，连接不再
			// 按 HTTP 走
			if ch.onUpgrade != nil {
				ch.onUpgrade(c, req)
				return consumed, nil
			}
			ch.writeError(c, st, 400, errNoUpgrade)
			return consumed, errNoUpgrade
		}

		// 交给业务处理
		if st.w == nil {
			st.w = &ResponseWriter{}
		}
		st.w.reset(c, req.Proto)
		ch.handler.ServeHTTP(st.w, req)

		// 业务把响应推后了（见 Defer）：不要补头、不要 Reset 解析器——那会
		// 把还没写的响应变成空响应，也会让下一个请求踩掉当前的状态。把连接
		// 挂起来，交给 Resume 收尾。
		if st.w.deferred {
			st.pending = true
			return consumed, nil
		}

		// 响应收尾。
		//
		// 业务可能一个字都没写（比如只调了 WriteHeader(204)、或者干脆
		// 什么都没做）——那**状态行和头还没发出去**（头是第一次 Write
		// 时才拼的）。这里必须补上，不然客户端收不到任何响应，一直等
		// 到超时（实测：标准库客户端报 context deadline exceeded）。
		//
		// flushHeader 里会按"有没有 Content-Length"决定要不要 chunked，
		// 没写过体的话自然一个 chunk 都不发，finish 补个终止块就到底了。
		if err := st.w.flushHeader(); err != nil {
			return consumed, err
		}
		if err := st.w.finish(); err != nil {
			return consumed, err
		}

		// keep-alive？
		//
		// HTTP/1.1 默认 keep-alive，除非请求里说 Connection: close
		// （或者版本是 1.0 且没说 keep-alive）。这一条不实现的话，客户端
		// 会一直等"响应之后服务端关连接"（很多客户端靠这个判断响应结束），
		// 等到超时。
		// closeAfterWrite 是"HTTP/1.0 且没给 Content-Length"那种——
		// 体的边界只能靠关连接划出来（见 flushHeader）。
		if wantClose(req) || st.w.closeAfterWrite {
			c.Close()
			return len(buf), nil // 连接要关了，剩下的不用管
		}

		// 准备下一个请求
		st.parser.Reset()
	}

	return consumed, nil
}

// OnClose 连接关闭。
func (ch *ConnHandler) OnClose(c *engine.Conn, err error) {}

// wantClose 判断这个请求之后连接要不要关。
//
// 规矩（RFC 9112 9.3）：
//   - HTTP/1.1 默认复用，除非显式 Connection: close
//   - HTTP/1.0 默认关，除非显式 Connection: keep-alive
func wantClose(r *Request) bool {
	conn, ok := r.Get("Connection")
	if !ok {
		// 没有这个头：1.1 复用，1.0 关
		return r.Proto != "HTTP/1.1"
	}
	// 有的话按它说的来（大小写无关，值里可能有多个 token）
	hasClose := containsFold(conn, "close")
	hasKeepAlive := containsFold(conn, "keep-alive")
	if hasClose {
		return true
	}
	if hasKeepAlive && r.Proto != "HTTP/1.1" {
		return false
	}
	return r.Proto != "HTTP/1.1"
}

// containsFold 是大小写无关的子串查找（ASCII）。
func containsFold(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func (ch *ConnHandler) newState() *connState {
	return &connState{
		parser: NewParser(ch.maxHeaderSize),
	}
}

func (ch *ConnHandler) writeError(c *engine.Conn, st *connState, code int, err error) error {
	if st.w == nil {
		st.w = &ResponseWriter{}
	}
	// 报文坏了，版本不一定解得出来；错误响应统一用 1.1 的格式（WriteRaw
	// 直接写死版本，不走 flushHeader，所以这里的 proto 只影响字段状态）。
	st.w.reset(c, "HTTP/1.1")
	st.w.WriteHeader(code)
	st.w.WriteRaw([]byte("HTTP/1.1 " + strconv.Itoa(code) + " " + StatusText(code) + "\r\n" +
		"Content-Length: 0\r\nConnection: close\r\n\r\n"))
	c.Close()
	return err
}

// connState 是一个连接的 HTTP 状态。
type connState struct {
	parser *Parser
	// w 是复用的响应写出器
	w *ResponseWriter

	// pending 有一个被 Defer 挂起的请求还没收尾（见 Resume）。
	pending bool
}

// Resume 收尾一个被 Defer 挂起的请求：补头、收 chunked、按 keep-alive 决定
// 关不关连接、复位解析器。
//
// **必须在这条连接所属的事件循环的 goroutine 上调**（engine.Conn.SyncOnLoop
// 就是干这个的）。解析器和 ResponseWriter 都是那个 goroutine 的状态，从别的
// goroutine 碰它们就是数据竞争。
//
// 调之前要把响应写完（w.Write / w.WriteHeader），这之后的收尾和同步 handler
// 那条路完全一样——所以两种 handler 写出来的报文没有区别。
//
// 连接已经关了的话什么都不做。
func Resume(c *engine.Conn, req *Request) error {
	st, ok := c.UserData().(*connState)
	if !ok || st == nil || !st.pending {
		return nil
	}
	st.pending = false

	if err := st.w.flushHeader(); err != nil {
		return err
	}
	if err := st.w.finish(); err != nil {
		return err
	}
	if wantClose(req) || st.w.closeAfterWrite {
		c.Close()
		return nil
	}
	st.parser.Reset()
	return nil
}

// reset 把 ResponseWriter 复位到"新一个响应"的状态。
//
// proto 是这一条请求的版本，响应行和对 1.0 的分叉都看它。
func (w *ResponseWriter) reset(c *engine.Conn, proto string) {
	w.conn = c
	w.proto = proto
	w.statusCode = 0
	w.wroteHeader = false
	w.headerSent = false
	w.chunked = false
	w.finished = false
	w.closeAfterWrite = false
	w.deferred = false
	for k := range w.header {
		delete(w.header, k)
	}
}

// Defer 声明这次响应稍后再写。
//
// 业务调了它就该**立刻返回**，别再往 w 上写任何东西；之后的某一刻（可以在
// 别的 goroutine 上）准备好响应，用 Resume 收尾。写本身要回到事件循环上
// 做（engine.Conn.SyncOnLoop），因为 w 和解析器都是那条连接的循环 goroutine
// 的状态。
//
// **这个接口存在的理由是不许阻塞事件循环**。handler 就跑在循环的 goroutine
// 上，在里面 time.Sleep 等于把同一个循环上所有连接一起冻住——而 event loop
// 的分片是按 fd 的，睡一次影响一批连接。这类"要等一会儿才回"的请求（定时、
// 等下游）是事件循环架构上唯一必须显式让出的地方。
//
// 挂起期间这条连接上不会处理新请求：OnData 看到 pending 就返回 0，把字节
// 留在引擎的读缓冲区里（返回 0 的语义就是"没消费"），等 Resume 复位之后再喂。
// 所以**挂起期间客户端再 pipelining 进来一条请求，要等上一条回完才会被处理**
// ——对"一问一答"的客户端没有影响，对 pipelining 的会有额外延迟。
func (w *ResponseWriter) Defer() { w.deferred = true }

// errNoUpgrade 没有 Upgrade 处理器时的错误。
var errNoUpgrade = errors.New("http: upgrade request but no handler")
