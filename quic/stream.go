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

import "errors"

// Stream 是一条 QUIC 流。
//
// **只有一个结构体**——这是和 quic-go 最实质的差别：那边一条流是
// send stream + receive stream + 两份流控 + frameSorter 五个对象（profile
// 里分配的大头就在那），这里收发两侧都在同一个结构体里，回环上不需要
// 乱序重排（没有丢包就没有空洞）。
type Stream struct {
	conn *Conn
	id   uint64

	// 接收侧：已按序拿到的数据 + 结束标志
	rbuf   []byte
	readAt int
	fin    bool

	// 发送侧：下一个字节的偏移 + 结束标志
	writeOff uint64
	sentFin  bool
}

func newStream(c *Conn, id uint64) *Stream {
	return &Stream{conn: c, id: id}
}

// StreamID 流 ID（HTTP/3 用它对应请求）。
func (s *Stream) StreamID() uint64 { return s.id }

// Read 读走已收到的数据（阻塞到有数据或流结束）。
func (s *Stream) Read(p []byte) (int, error) {
	c := s.conn
	for {
		c.mu.Lock()
		if s.readAt < len(s.rbuf) {
			n := copy(p, s.rbuf[s.readAt:])
			s.readAt += n
			if s.readAt == len(s.rbuf) {
				s.rbuf = s.rbuf[:0]
				s.readAt = 0
			}
			c.mu.Unlock()
			return n, nil
		}
		if s.fin {
			c.mu.Unlock()
			return 0, errors.New("EOF")
		}
		if c.closed {
			err := c.err
			c.mu.Unlock()
			if err == nil {
				err = errors.New("quic: stream closed")
			}
			return 0, err
		}
		// 还没有数据：等下一次 ReadFrom 把数据递进来（回环上很快就到）
		c.mu.Unlock()
		<-c.dataSig
	}
}

// Write 往流上写（按当前偏移，带长度）。
func (s *Stream) Write(p []byte) (int, error) {
	c := s.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("quic: connection closed")
	}
	c.appOut = appendStream(c.appOut, s.id, s.writeOff, p, false)
	s.writeOff += uint64(len(p))
	return len(p), nil
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
	s.sentFin = true
	return c.flushLocked()
}

// onStreamData 收到一段流数据。
func (c *Conn) onStreamData(id, offset uint64, data []byte, fin bool) error {
	c.mu.Lock()
	s := c.streams[id]
	if s == nil {
		s = newStream(c, id)
		c.streams[id] = s
		// 客户端发起的双向流（低位 0x00/0x01）要递出去给 h3 那层；
		// 单向流（0x02/0x03）是 h3 自己的控制流/QPACK，交给上层同一批处理。
		select {
		case c.accept <- s:
		default:
		}
	}
	// 回环上没有乱序，按偏移追加即可（真丢了包这里就不对了，见 doc.go 的范围）
	if offset == uint64(len(s.rbuf)+s.readAt) || offset == uint64(s.received()) {
		s.rbuf = append(s.rbuf, data...)
	} else if offset < uint64(s.received()) {
		// 重叠：丢掉已经有的部分
		skip := s.received() - int(offset)
		if skip < len(data) {
			s.rbuf = append(s.rbuf, data[skip:]...)
		}
	}
	if fin {
		s.fin = true
	}
	c.mu.Unlock()
	c.wakeData()
	return nil
}

// received 已经按序收到的字节数。
func (s *Stream) received() int { return s.readAt + len(s.rbuf) }

// appendStreamData 把攒下来的 1-RTT 帧挂到本包的载荷上。
func (c *Conn) appendStreamData(payload []byte) []byte {
	if len(c.appOut) == 0 {
		return payload
	}
	payload = append(payload, c.appOut...)
	c.appOut = c.appOut[:0]
	return payload
}

// flushLocked 立刻发一个包（发流数据/控制帧用）。
func (c *Conn) flushLocked() error {
	return c.flush()
}

// wakeData 收到新数据时报一下（非阻塞）。
func (c *Conn) wakeData() {
	select {
	case c.dataSig <- struct{}{}:
	default:
	}
}
