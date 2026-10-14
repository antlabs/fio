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

	// serveOnce 保证收包循环只起一个（见 Serve）。
	serveOnce sync.Once

	// dirty 是"这一轮收到了数据、有待发帧"的连接，由收包循环在每轮末尾
	// 统一 flush（见 flushDirty 和 loopFlush 的说明）。
	dirtyMu sync.Mutex
	dirty   []*Conn
}

// Listen 起一个 UDP 监听。addr 形如 ":8443"。
func Listen(addr string, cfg Config) (*Listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	return ListenPacket(pc, cfg), nil
}

// ListenPacket 用一个已经建好的 UDP socket 起监听。
//
// 需要自己控制 socket 的时候用（比如带 SO_REUSEPORT 的预派生，
// http3.NativeServer.ReusePort 走的就是这条路）。
func ListenPacket(pc net.PacketConn, cfg Config) *Listener {
	return &Listener{
		pc:     pc,
		cfg:    cfg,
		byCID:  make(map[string]*Conn, 16),
		accept: make(chan *Conn, 16),
	}
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

// Accept 取一条新连接（阻塞）。
//
// 它顺手把收包循环起起来（Serve 是幂等的）——忘了起的话症状是"客户端
// 一直重传、服务端一个包都不读"，不该让调用方自己记住这件事。
func (l *Listener) Accept() (*Conn, error) {
	l.Serve()
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

// Serve 起收包循环：第一次调用真的起一个 goroutine，之后是空操作。
//
// （以前它是"阻塞到监听关掉"的，调用方都写 go ln.Serve()；做成幂等的
// 起步函数之后两种写法等价。）
func (l *Listener) Serve() {
	l.serveOnce.Do(func() {
		go l.serveLoop()
	})
}

// serveLoop 收数据报并分派。跑在自己的 goroutine 上，直到监听关掉。
func (l *Listener) serveLoop() {
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
		// loopFlush 模式：这一轮处理出来的响应在这里一起发出去。
		// **收 -> 解 -> 处理 -> 发 全在这一条 goroutine 上**，不像以前那样
		// 每条连接各有一个 flusher goroutine 等着被唤醒（见 Conn.flushSoon）。
		l.flushDirty()
	}
}

// markDirty 把连接挂进"待 flush"表（loopFlush 模式）。
// 调用方**可能握着 c.mu**（Stream.Write/Close 里调 flushSoon 的路），
// 所以这里只能碰原子位和 listener 自己的锁。
func (l *Listener) markDirty(c *Conn) {
	if !c.dirtyQueued.CompareAndSwap(false, true) {
		return
	}
	l.dirtyMu.Lock()
	l.dirty = append(l.dirty, c)
	l.dirtyMu.Unlock()
}

// flushDirty 把这一轮攒下的连接都发一遍。
//
// 线上一个连接的数据报进来、它的响应也跟着就绪（请求级/快路都是就地
// 处理的），所以"每轮末尾统一发"既省掉了每连接一个 flusher goroutine
// 的唤醒，也天然攒了批（一次轮询里几条连接的帧一起走）。
func (l *Listener) flushDirty() {
	l.dirtyMu.Lock()
	if len(l.dirty) == 0 {
		l.dirtyMu.Unlock()
		return
	}
	list := l.dirty
	l.dirty = nil
	l.dirtyMu.Unlock()

	for _, c := range list {
		c.dirtyQueued.Store(false)
		_ = c.flush()
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
		// loopFlush：发送由收包循环统一做（见 Listener.flushDirty）
		nc.l = l
		nc.loopFlush = loopFlushOn
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
