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

package quic

import (
	"errors"
	"io"
)

// Stream 是一条 QUIC 流。
//
// **只有一个结构体**——这是和 quic-go 最实质的差别：那边一条流是
// send stream + receive stream + 两份流控 + frameSorter 五个对象（profile
// 里分配的大头就在那），这里收发两侧都在同一个结构体里，回环上不需要
// 乱序重排（没有丢包就没有空洞）。
type Stream struct {
	conn *Conn
	id   uint64

	// 接收侧：还没读走的缓冲 + 结束标志。
	//
	// **recvd 是累计收到的字节数，不是缓冲长度**：Read 把读走的字节从
	// rbuf 里丢掉，按缓冲长度算的话读一次之后就归零，下一帧的偏移看着
	// 就像"跳了一大截"（有洞）——数据被拼错位。
	rbuf     []byte
	readAt   int
	recvd    uint64
	fin      bool // 对端的 FIN 到了
	readDone bool // 读侧已经消费完（Read 返回过 EOF，或被取消）
	readErr  error

	// 发送侧：下一个字节的偏移 + 结束标志
	writeOff uint64
	sentFin  bool
}

func newStream(c *Conn, id uint64) *Stream {
	return &Stream{conn: c, id: id}
}

// StreamID 流 ID（HTTP/3 用它对应请求）。
func (s *Stream) StreamID() uint64 { return s.id }

// peerInitiated 这条流是不是对端开的（低位见 RFC 9000 2.1：
// 0x00 对端双向、0x01 本端双向、0x02 对端单向、0x03 本端单向）。
func (s *Stream) peerInitiated() bool {
	if s.id&0x01 == 0 {
		return s.id&0x02 == 0 // 对端双向流：0, 4, 8…
	}
	return s.id&0x02 != 0 // 对端单向流：2, 6, 10…
}

// Read 读走已收到的数据（阻塞到有数据或流结束）。流结束返回 io.EOF。
func (s *Stream) Read(p []byte) (int, error) {
	c := s.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if s.readAt < len(s.rbuf) {
			n := copy(p, s.rbuf[s.readAt:])
			s.readAt += n
			if s.readAt == len(s.rbuf) {
				s.rbuf = s.rbuf[:0]
				s.readAt = 0
			}
			return n, nil
		}
		if s.readErr != nil {
			return 0, s.readErr
		}
		if s.fin {
			// 读到 FIN：收侧结束（这条流要是也发完了就可以整个摘掉）
			s.readDone = true
			c.finishIfDone(s)
			return 0, io.EOF
		}
		if c.closed {
			return 0, c.errOr(errors.New("quic: connection closed"))
		}
		// 还没有数据：等对端的数据到（见 Conn.cond 的说明）
		c.cond.Wait()
	}
}

// Write 往流上写（按当前偏移，带长度）。
//
// 一次调用可以很大（静态文件是 16KB）：**按 maxStreamChunk 切成多个
// STREAM 帧**放进待发队列，flush 再按帧边界切包。塞不进一个包的帧是发不
// 出去的（QUIC 的帧不跨包），所以切分点必须在这里。
func (s *Stream) Write(p []byte) (int, error) {
	c := s.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, c.errOr(errors.New("quic: connection closed"))
	}
	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > maxStreamChunk {
			n = maxStreamChunk
		}
		c.appOut = appendStream(c.appOut, s.id, s.writeOff, p[:n], false)
		c.appEnds = append(c.appEnds, len(c.appOut))
		s.writeOff += uint64(n)
		p = p[n:]
	}
	// 不在这里 sendto：交给 flusher 攒一批再发（见 runFlusher）——
	// 一个数据报里来的几条请求，响应应该并进一个包出去
	c.flushSoon()
	return total, nil
}

// Close 半关这条流的发送侧（发一个带 FIN 的空 STREAM 帧）。
func (s *Stream) Close() error {
	c := s.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || s.sentFin {
		return nil
	}
	c.appOut = appendStream(c.appOut, s.id, s.writeOff, nil, true)
	c.appEnds = append(c.appEnds, len(c.appOut))
	s.sentFin = true
	c.finishIfDone(s)
	c.flushSoon()
	return nil
}

// CancelRead 告诉对端这条流的接收侧不要了（RESET_STREAM，RFC 9000 19.4），
// 等在 Read 上的调用会拿到错误。
//
// HTTP/3 在请求流上解出协议错误时用它（见 http3 的 readAndDispatch）。
func (s *Stream) CancelRead(code uint64) {
	c := s.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.readDone || c.closed {
		return
	}
	s.readErr = errors.New("quic: stream reset")
	s.readDone = true
	if !s.sentFin {
		// final size 报我们**已经收到**的字节数（RFC 9000 19.4：对端据此
		// 判断流控账目）
		c.appOut = appendResetStream(c.appOut, s.id, code, s.received())
		c.appEnds = append(c.appEnds, len(c.appOut))
		s.sentFin = true
	}
	c.finishIfDone(s)
	c.cond.Broadcast()
	_ = c.flushLocked()
}

// onStreamData 收到一段流数据（在收包的那个 goroutine 上调）。
func (c *Conn) onStreamData(id, offset uint64, data []byte, fin bool) error {
	c.mu.Lock()
	s := c.streams[id]
	isNew := false
	if s == nil {
		if c.retired(id) {
			// 这条流早就收完关掉了：帧是重传，丢
			dbg("stream %d: 已回收，丢 %d 字节", id, len(data))
			c.mu.Unlock()
			return nil
		}
		s = newStream(c, id)
		c.streams[id] = s
		isNew = true
	}
	s.append(offset, data)
	if fin {
		s.fin = true
	}
	hook := c.hook
	c.mu.Unlock()

	// 新流才需要交给上层：装了钩子就**就地调**（HTTP/3 的快路，省掉两次
	// goroutine 切换），没装就投 accept 队列。
	//
	// 调用放在解锁之后：钩子要跑用户的 handler，不能攥着连接的锁。
	if isNew {
		switch {
		case hook != nil && s.peerInitiated() && s.id&0x02 == 0:
			hook(s)
		case s.peerInitiated() && s.id&0x02 == 0:
			c.pushAccept(s) // 对端双向流：HTTP/3 的请求流
		default:
			c.pushAcceptUni(s) // 对端单向流：控制流 / QPACK
		}
	}

	// 等在 Read 上的（可能好几条流、好几个 goroutine）都醒一下：
	// 它们起来各自看一眼自己的缓冲，没有数据的会接着睡。
	c.cond.Broadcast()
	return nil
}

// Finished 对端在这条流上发完了（FIN 到了）。
//
// 快路用它判断"这个请求已经完整了"，可以就地处理；没收完的得交给
// 会阻塞的那条路（lane/goroutine），别把收包 goroutine 堵住。
func (s *Stream) Finished() bool {
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()
	return s.fin
}

// append 把一段数据按偏移接进接收缓冲。调用方持有 c.mu。
//
// 回环上没有乱序重传，绝大多数情况就是"接着尾巴追加"。真重传（对端没收到
// 我们的 ACK）会整段重复，按偏移跳过已有部分即可，不做真正的重排。
func (s *Stream) append(offset uint64, data []byte) {
	have := s.recvd
	switch {
	case offset == have:
		s.rbuf = append(s.rbuf, data...)
		s.recvd += uint64(len(data))
	case offset > have:
		// 中间缺了：回环上不该发生（没有丢包），先把这段接在后面，
		// 不装作有洞——真出现的话上面的数据会是错的，见 doc.go 的范围说明
		dbg("stream %d: 偏移 %d 跳过了 %d 字节（有洞）", s.id, offset, offset-have)
		s.rbuf = append(s.rbuf, data...)
		s.recvd = offset + uint64(len(data))
	case offset < have:
		skip := have - offset
		if skip < uint64(len(data)) {
			s.rbuf = append(s.rbuf, data[skip:]...)
			s.recvd += uint64(len(data)) - skip
		}
	}
}

// received 已经按序收到的字节数（含已经读走的）。
func (s *Stream) received() uint64 { return s.recvd }

// finishIfDone 一条对端流收发都结束了就从连接的表里摘掉，并把回收水位
// 往前推（见 retireSet）。调用方持有 c.mu。
func (c *Conn) finishIfDone(s *Stream) {
	if !s.peerInitiated() || !s.fin || !s.readDone || !s.sentFin {
		return
	}
	delete(c.streams, s.id)
	if s.id&0x02 != 0 {
		c.retiredUni.done(s.id)
	} else {
		c.retiredBidi.done(s.id)
	}
}

// pushAccept / pushAcceptUni 往接收队列里投一条新流（满了就丢：对端
// 超过我们声明的流数上限时本来就该被流控挡住）。
func (c *Conn) pushAccept(s *Stream) {
	select {
	case c.accept <- s:
	default:
	}
}

func (c *Conn) pushAcceptUni(s *Stream) {
	select {
	case c.acceptUni <- s:
	default:
	}
}

// retireSet 跟踪"对端开的流都收完关到哪了"。
//
// 对端的流 ID 是单调的（0,4,8… 或 2,6,10…），所以一个水位就够了：
// ID < next 的流都已经收完关掉，之后落在那下面的帧一律是重传。中间有
// 没关完的（并发流里先关后面的）就先记在 pend 里，等低位补齐再一起推。
//
// 没有这个的话 streams 表只增不减——一个长连接跑几百万请求，收回来的
// 全是不再用的流对象。
type retireSet struct {
	next uint64
	pend map[uint64]struct{}
}

func (r *retireSet) done(id uint64) {
	if id < r.next {
		return
	}
	if id != r.next {
		r.pend[id] = struct{}{}
		return
	}
	r.next += 4
	for {
		if _, ok := r.pend[r.next]; !ok {
			return
		}
		delete(r.pend, r.next)
		r.next += 4
	}
}

func (r *retireSet) retired(id uint64) bool { return id < r.next }

// retired 这条流是不是已经收完关掉了。
func (c *Conn) retired(id uint64) bool {
	if id&0x02 != 0 {
		return c.retiredUni.retired(id)
	}
	return c.retiredBidi.retired(id)
}
