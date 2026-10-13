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
	"net"
	"sync"
)

// Listener 是一个 UDP 监听：收数据报、按连接 ID 分派给 Conn。
//
// 分派规则（RFC 9000 5.2 的简化版）：
//
//	长头 + 未知的目标连接 ID   新连接（客户端的第一条 Initial）
//	其余                       按目标连接 ID 查表——客户端握手之后用**我们发的
//	                           源连接 ID** 当它的目标连接 ID
type Listener struct {
	pc  net.PacketConn
	cfg Config

	mu     sync.Mutex
	byCID  map[string]*Conn
	accept chan *Conn
	err    error
}

// Listen 起一个 UDP 监听。addr 形如 ":8443"。
func Listen(addr string, cfg Config) (*Listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		pc:     pc,
		cfg:    cfg,
		byCID:  make(map[string]*Conn, 16),
		accept: make(chan *Conn, 16),
	}, nil
}

// Addr 实际监听的地址。
func (l *Listener) Addr() net.Addr { return l.pc.LocalAddr() }

// Close 关掉监听和上面所有连接。
func (l *Listener) Close() error {
	l.mu.Lock()
	l.err = errors.New("quic: listener closed")
	l.mu.Unlock()
	return l.pc.Close()
}

// Accept 取一条新连接（阻塞）。返回的连接需要调用方自己起 ReadLoop。
func (l *Listener) Accept() (*Conn, error) {
	c, ok := <-l.accept
	if !ok {
		l.mu.Lock()
		err := l.err
		l.mu.Unlock()
		if err == nil {
			err = errors.New("quic: listener closed")
		}
		return nil, err
	}
	return c, nil
}

// Serve 收数据报并分派。阻塞到监听关掉。
func (l *Listener) Serve() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			l.mu.Lock()
			if l.err == nil {
				l.err = err
			}
			close(l.accept)
			l.mu.Unlock()
			return
		}
		l.dispatch(buf[:n], addr)
	}
}

func (l *Listener) dispatch(b []byte, addr net.Addr) {
	h, err := parseHeader(b, connIDLen)
	if err != nil {
		dbg("dispatch: parseHeader 失败 (%d 字节): %v", len(b), err)
		return
	}
	dbg("dispatch: %d 字节 来自 %v long=%v typ=%#x dcid=%x pn=%d", len(b), addr, h.long, h.typ, h.dcid, h.pn)
	l.mu.Lock()
	c := l.byCID[string(h.dcid)]
	if c == nil && h.long && h.typ == pktInitial {
		// 新连接：Initial 的目标连接 ID 是推 initial 密钥用的那个（odcid），
		// 源连接 ID 是客户端自己的连接 ID（我们回包时的目标连接 ID）。
		nc, err := newConn(l.pc, addr, h.dcid, h.scid, l.cfg)
		if err != nil {
			dbg("dispatch: newConn 失败: %v", err)
			l.mu.Unlock()
			return
		}
		l.byCID[string(nc.scid)] = nc
		l.byCID[string(h.dcid)] = nc
		select {
		case l.accept <- nc:
		default:
		}
		c = nc
	}
	l.mu.Unlock()
	if c == nil {
		return
	}
	// **就地处理**（不另起 goroutine）：同一条连接的数据报必须按序处理，
	// 而且这两档的连接数很少、每个包的处理很短。
	_ = c.handlePacket(b)
}
