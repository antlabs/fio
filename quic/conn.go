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
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// Conn 是一条 QUIC 连接（服务端一侧）。
//
// 层次：UDP 数据报 -> 包（长短头、头保护、AEAD）-> 帧 -> 流。
// TLS 握手交给标准库的 tls.QUICConn：我们只负责把 CRYPTO 帧里的字节喂给它、
// 把它要发的字节包成 CRYPTO 帧，以及用它给出来的流量密钥做包保护。
type Conn struct {
	pc     net.PacketConn
	remote net.Addr
	tls    *tls.QUICConn

	// scid 是我们这条连接的源连接 ID（对端之后拿它当目标连接 ID）
	scid []byte
	// odcid 是客户端第一个 Initial 里的目标连接 ID。握手时只用来推 Initial
	// 密钥和填 original_destination_connection_id 参数（客户端要核对）。
	odcid []byte
	// dcid 是**对端**的连接 ID（它首个 Initial 里的 SCID）——我们发出去的包
	// 用它当目标连接 ID。注意不是它 Initial 里的 DCID：那个是它随机选的、
	// 只在它发给我们时用一次（RFC 9000 7.2，`asymmetric` 的那一步）。
	dcid []byte

	// 三个级别的收发密钥。Initial 那对由初始目标连接 ID 推，
	// 其余由 TLS 的 SetRead/WriteSecret 事件给。
	send [3]*keys
	recv [3]*keys

	// 每个级别的发送包序号、收到的最大包序号、待确认的包序号集合
	nextPN  [3]uint64
	largest [3]uint64
	gotPN   [3]bool
	// ackDue：有没收到的包要确认。recvSeen[lvl] 是那些包的包序号
	// （攒到下次 flush 一起 ACK，通常就一两个）。
	ackDue   [3]bool
	recvSeen [3][]uint64

	// 每个级别待发的 CRYPTO 数据（TLS 交出来的握手字节）
	cryptoOut [3][]byte
	// 每个级别已经发出去的 CRYPTO 偏移（重传用不到，回环不丢包）
	cryptoSent [3]uint64
	// 对端 CRYPTO 流上已经按序交给 TLS 的字节数，以及乱序到达、
	// 还没拼上的片段。客户端重传 ClientHello 是常态（回包晚了它就重传），
	// 重复的字节必须挡在 TLS 外面：QUICConn 在已经消费过的级别上再收到
	// 数据会直接报 "handshake data received at wrong level"。
	cryptoNext [3]uint64
	cryptoGaps [3]map[uint64][]byte

	// 流
	mu      sync.Mutex
	streams map[uint64]*Stream
	accept  chan *Stream

	// 收下来的对端传输参数
	peer peerParams

	// 允许发送的额度（对端给的）
	maxData       uint64
	maxStreamData uint64
	sentData      uint64

	handshakeDone     bool
	sentHandshakeDone bool
	closed            bool
	err               error

	// appOut 是 1-RTT 上待发的帧（各流的 STREAM、控制帧）。攒起来一次发。
	appOut []byte

	// dataSig 收到新数据时报一下，唤醒等在 Read 上的 goroutine。
	dataSig chan struct{}
}

// Config 是服务端的配置。
type Config struct {
	// TLSConfig 至少要带证书。ALPN 由 http3 那层设（"h3"）。
	TLSConfig *tls.Config
	// MaxStreams 一条连接上最多接受多少条对端发起的双向流。
	MaxStreams uint64
}

const (
	lvlInitial = 0
	lvlHandshake = 1
	lvlApp = 2
)

// newConn 建一条服务端连接。
//
// odcid 是客户端第一个 Initial 里的目标连接 ID（Initial 密钥从它推，跟
// 后面用的连接 ID 是两回事）；peerCID 是那个包里的源连接 ID，之后我们发给
// 客户端的每个包的目标连接 ID 都得是它。
func newConn(pc net.PacketConn, remote net.Addr, odcid, peerCID []byte, cfg Config) (*Conn, error) {
	c := &Conn{
		pc:      pc,
		remote:  remote,
		streams: make(map[uint64]*Stream),
		accept:  make(chan *Stream, 64),
		scid:    make([]byte, connIDLen),
		dataSig: make(chan struct{}, 1),
		dcid:    append([]byte(nil), peerCID...),
		odcid:   append([]byte(nil), odcid...),
		maxData: 1 << 20,
		maxStreamData: 1 << 20,
	}
	for i := range c.cryptoGaps {
		c.cryptoGaps[i] = make(map[uint64][]byte)
	}
	if _, err := rand.Read(c.scid); err != nil {
		return nil, err
	}
	client, server, err := deriveInitial(odcid)
	if err != nil {
		return nil, err
	}
	c.recv[lvlInitial] = client // 客户端发的用 client 密钥解
	c.send[lvlInitial] = server // 我们发的用 server 密钥

	tc := cfg.TLSConfig.Clone()
	if len(tc.NextProtos) == 0 {
		tc.NextProtos = []string{"h3"}
	}
	// QUIC 只跑 TLS 1.3（RFC 9001），没有版本协商这一步。tls.Config 的默认
	// MinVersion 是 1.2，标准库的 QUIC 入口会直接拒绝，所以这里钉死。
	// （quic-go 也是这么干的：它自己的 Config 默认就带这一条。）
	if tc.MinVersion < tls.VersionTLS13 {
		tc.MinVersion = tls.VersionTLS13
	}
	c.tls = tls.QUICServer(&tls.QUICConfig{TLSConfig: tc})
	c.tls.SetTransportParameters(c.ourParams(cfg).appendTo(nil))
	if err := c.tls.Start(context.Background()); err != nil {
		return nil, err
	}
	if err := c.drainEvents(); err != nil {
		return nil, err
	}
	dbg("newConn: scid=%x dcid=%x 启动完成 initialCryptoOut=%d", c.scid, c.dcid, len(c.cryptoOut[lvlInitial]))
	return c, nil
}

func (c *Conn) ourParams(cfg Config) transportParams {
	maxStreams := cfg.MaxStreams
	if maxStreams == 0 {
		maxStreams = 4096
	}
	return transportParams{
		maxUDPPayload:         1472,
		initialMaxData:        1 << 24,
		initialMaxStreamData:  1 << 22,
		initialMaxStreamsBidi: maxStreams,
		initialMaxStreamsUni:  32,
		idleTimeout:           30000,
		odcid:                 c.odcid,
		iscid:                 c.scid,
	}
}

// drainEvents 把 TLS 交出来的事件处理掉：密钥收下、握手字节攒起来、
// 对端传输参数解出来。
func (c *Conn) drainEvents() error {
	for {
		ev := c.tls.NextEvent()
		switch ev.Kind {
		case tls.QUICNoEvent:
			return nil
		case tls.QUICSetReadSecret:
			k, err := deriveKeys(ev.Data)
			if err != nil {
				return err
			}
			c.recv[levelIndex(ev.Level)] = k
			dbg("tls: SetReadSecret level=%v", ev.Level)
		case tls.QUICSetWriteSecret:
			k, err := deriveKeys(ev.Data)
			if err != nil {
				return err
			}
			c.send[levelIndex(ev.Level)] = k
			dbg("tls: SetWriteSecret level=%v", ev.Level)
		case tls.QUICWriteData:
			l := levelIndex(ev.Level)
			c.cryptoOut[l] = append(c.cryptoOut[l], ev.Data...)
			dbg("tls: WriteData level=%v %d 字节", ev.Level, len(ev.Data))
		case tls.QUICTransportParameters:
			c.peer = parseTransportParams(ev.Data)
			if c.peer.initialMaxData > 0 {
				c.maxData = c.peer.initialMaxData
			}
			if c.peer.initialMaxStreamData > 0 {
				c.maxStreamData = c.peer.initialMaxStreamData
			}
		case tls.QUICTransportParametersRequired:
			return errors.New("quic: server was asked for transport parameters")
		case tls.QUICHandshakeDone:
			c.handshakeDone = true
		case tls.QUICErrorEvent:
			if ev.Err != nil {
				return ev.Err
			}
			return errors.New("quic: tls error")
		case tls.QUICRejectedEarlyData, tls.QUICResumeSession, tls.QUICStoreSession:
			// 0-RTT / 会话恢复都不做
		}
	}
}

// levelIndex 把标准库的加密级别映射成我们的下标。
func levelIndex(l tls.QUICEncryptionLevel) int {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return lvlInitial
	case tls.QUICEncryptionLevelHandshake:
		return lvlHandshake
	default:
		return lvlApp
	}
}

// levelOf 把包类型映射成加密级别下标。
func levelOf(h *header) int {
	if !h.long {
		return lvlApp
	}
	if h.typ == pktInitial {
		return lvlInitial
	}
	return lvlHandshake
}

// handlePacket 处理一个收到的数据报（里面可能有多个包，本实现只解第一个：
// 客户端把 Initial 和 Handshake 放在同一个数据报里发的情况要支持，所以
// 循环解）。
func (c *Conn) handlePacket(b []byte) error {
	for len(b) > 0 {
		h, err := parseHeader(b, len(c.scid))
		if err != nil {
			// 剩下的不是合法包（可能是同一数据报里的下一个包没对齐）
			dbg("handlePacket: parseHeader 失败: %v", err)
			return nil
		}
		lvl := levelOf(h)
		k := c.recv[lvl]
		if k == nil {
			dbg("handlePacket: 级别 %d 还没密钥（长头=%v typ=%#x），丢", lvl, h.long, h.typ)
			return nil
		}
		if err := h.unprotect(k, c.largest[lvl]); err != nil {
			dbg("handlePacket: 头保护解不开 lvl=%d: %v", lvl, err)
			return err
		}
		dbg("handlePacket: lvl=%d pn=%d 密文 %d 字节", lvl, h.pn, len(h.payload))
		if h.pn > c.largest[lvl] || !c.gotPN[lvl] {
			c.largest[lvl] = h.pn
			c.gotPN[lvl] = true
		}
		payload, err := h.open(k)
		if err != nil {
			// AEAD 验不过：可能是同一数据报里我们解偏了，跳过这个包
			return nil
		}
		// **验过了才记 ACK**：验不过的包等于没收到（记了会让对端以为
		// 我们已经拿到、不再重传）。
		c.ackDue[lvl] = true
		c.recvSeen[lvl] = append(c.recvSeen[lvl], h.pn)
		if err := c.processFrames(lvl, payload); err != nil {
			return err
		}
		// 短头没有长度字段：后面没有包了
		if !h.long {
			break
		}
		next := h.ctEnd
		if next <= 0 || next > len(b) {
			break
		}
		b = b[next:]
	}
	return c.flush()
}

// processFrames 处理一个包里的帧。
func (c *Conn) processFrames(lvl int, payload []byte) error {
	var streamErr error
	err := parseFrames(payload, func(kind uint64, raw []byte, _ int) error {
		dbg("帧: kind=%#x lvl=%d %d 字节", kind, lvl, len(raw))
		switch {
		case kind == frCrypto:
			// CRYPTO：偏移 + 长度 + 数据
			off, n, err := readVarint(raw[1:])
			if err != nil {
				return err
			}
			l, n2, err := readVarint(raw[1+n:])
			if err != nil {
				return err
			}
			data := raw[1+n+n2 : 1+n+n2+int(l)]
			return c.cryptoDeliver(lvl, off, data)
		case kind >= frStreamBase && kind <= 0x0f:
			// STREAM：流 ID [+ 偏移] + 长度 + 数据
			off := 0
			id, n, err := readVarint(raw[1:])
			if err != nil {
				return err
			}
			off = 1 + n
			var dataOff uint64
			if kind&streamBitOff != 0 {
				dataOff, n, err = readVarint(raw[off:])
				if err != nil {
					return err
				}
				off += n
			}
			var l uint64
			if kind&streamBitLen != 0 {
				l, n, err = readVarint(raw[off:])
				if err != nil {
					return err
				}
				off += n
			} else {
				l = uint64(len(raw) - off)
			}
			data := raw[off : off+int(l)]
			streamErr = c.onStreamData(id, dataOff, data, kind&streamBitFin != 0)
			return nil
		case kind == frMaxData:
			if v, _, err := readVarint(raw[1:]); err == nil {
				c.maxData = v
			}
		case kind == frMaxStreamData:
			// 流 ID + 上限：我们只在 h3 控制流上主动发，忽略即可
		case kind == frConnClose || kind == frConnCloseApp:
			c.closeWith(errors.New("quic: peer closed"))
		case kind == frHandshakeDone:
			c.handshakeDone = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	return streamErr
}

// cryptoDeliver 把一个 CRYPTO 帧的数据按序交给 TLS：重传的整段/前半段丢掉，
// 乱序的先存着，等洞补上再连着交。
//
// QUIC 的 CRYPTO 流是"按偏移的字节流"，和 TCP 一样——帧的边界没有意义，
// 重传、乱序都得在这里抹平。
func (c *Conn) cryptoDeliver(lvl int, off uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	next := c.cryptoNext[lvl]
	if off > next {
		// 前面有洞：先记下，等洞来
		c.cryptoGaps[lvl][off] = append([]byte(nil), data...)
		dbg("crypto: lvl=%d 偏移 %d 早于 %d，先存着", lvl, off, next)
		return nil
	}
	if end := off + uint64(len(data)); end <= next {
		dbg("crypto: lvl=%d 偏移 %d 的 %d 字节是重传，丢", lvl, off, len(data))
		return nil // 整个都是重传
	} else if off < next {
		data = data[next-off:] // 前半段重传，后半段是新的
		off = next
	}
	for len(data) > 0 {
		if err := c.tls.HandleData(quicLevel(lvl), data); err != nil {
			dbg("tls.HandleData(lvl=%d, %d 字节) 失败: %v", lvl, len(data), err)
			return err
		}
		c.cryptoNext[lvl] = off + uint64(len(data))
		if err := c.drainEvents(); err != nil {
			return err
		}
		// 洞后面的要是补上了就接着送
		next, ok := c.cryptoGaps[lvl][c.cryptoNext[lvl]]
		if !ok {
			return nil
		}
		delete(c.cryptoGaps[lvl], c.cryptoNext[lvl])
		data, off = next, c.cryptoNext[lvl]
	}
	return nil
}

func quicLevel(lvl int) tls.QUICEncryptionLevel {
	switch lvl {
	case lvlInitial:
		return tls.QUICEncryptionLevelInitial
	case lvlHandshake:
		return tls.QUICEncryptionLevelHandshake
	default:
		return tls.QUICEncryptionLevelApplication
	}
}

// flush 把三个级别上待发的东西各发一个包出去。
func (c *Conn) flush() error {
	if c.closed {
		return nil
	}
	for _, lvl := range []int{lvlInitial, lvlHandshake, lvlApp} {
		var payload []byte
		if c.ackDue[lvl] {
			payload = appendAck(payload, c.recvSeen[lvl], 0)
			c.recvSeen[lvl] = c.recvSeen[lvl][:0]
			c.ackDue[lvl] = false
		}
		if lvl != lvlApp && len(c.cryptoOut[lvl]) > 0 {
			payload = appendCrypto(payload, c.cryptoSent[lvl], c.cryptoOut[lvl])
			c.cryptoSent[lvl] += uint64(len(c.cryptoOut[lvl]))
			c.cryptoOut[lvl] = nil
		}
		if lvl == lvlApp {
			payload = c.appendStreamData(payload)
			if c.handshakeDone && !c.sentHandshakeDone {
				payload = appendVarint(payload, frHandshakeDone)
				c.sentHandshakeDone = true
			}
		}
		if len(payload) == 0 {
			continue
		}
		k := c.send[lvl]
		if k == nil {
			dbg("flush: lvl=%d 有 %d 字节要发但没密钥", lvl, len(payload))
			continue
		}
		pn := c.nextPN[lvl]
		c.nextPN[lvl]++
		var pkt []byte
		if lvl == lvlApp {
			pkt = sealPacket(nil, false, 0, c.dcid, nil, nil, pn, payload, k)
		} else {
			typ := byte(pktInitial)
			if lvl == lvlHandshake {
				typ = pktHandshake
			}
			if lvl == lvlInitial {
				// RFC 9000 14.1：带 Initial 的数据报至少要 1200 字节（服务端
				// 也适用），不够就补 PADDING 帧。补在明文里，不是密文外
				// （见 sealPacket 那段注释）。长度字段本身可能跟着变长，
				// 所以循环到真的够为止。
				for {
					pkt = sealPacket(nil, true, typ, c.dcid, c.scid, nil, pn, payload, k)
					if len(pkt) >= 1200 {
						break
					}
					payload = append(payload, make([]byte, 1200-len(pkt))...)
				}
			} else {
				pkt = sealPacket(nil, true, typ, c.dcid, c.scid, nil, pn, payload, k)
			}
		}
		if _, err := c.pc.WriteTo(pkt, c.remote); err != nil {
			dbg("flush: lvl=%d 写 %d 字节失败: %v", lvl, len(pkt), err)
			return err
		}
		dbg("flush: lvl=%d pn=%d 发出 %d 字节（载荷 %d）", lvl, pn, len(pkt), len(payload))
	}
	return nil
}

// closeWith 关掉这条连接。
func (c *Conn) closeWith(err error) {
	if c.closed {
		return
	}
	c.closed = true
	c.err = err
	close(c.accept)
}

// ReadLoop 收数据报，直到连接关掉。
func (c *Conn) ReadLoop() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := c.pc.ReadFrom(buf)
		if err != nil {
			c.closeWith(err)
			return
		}
		if addr.String() != c.remote.String() {
			continue
		}
		if err := c.handlePacket(buf[:n]); err != nil {
			c.closeWith(err)
			return
		}
	}
}

// AcceptStream 取一条对端发起的双向流（阻塞）。
func (c *Conn) AcceptStream() (*Stream, error) {
	s, ok := <-c.accept
	if !ok {
		if c.err != nil {
			return nil, c.err
		}
		return nil, errors.New("quic: connection closed")
	}
	return s, nil
}

var _ = binary.BigEndian
