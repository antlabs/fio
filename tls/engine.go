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

package tls

import (
	"github.com/antlabs/fio/engine"
)

// engine.Handler 的适配层：把 TLS 接到 fio 的事件循环上。
//
// **TLS 和别的协议不一样：它包在别人外面**。HTTP/2、HTTP/1.1 是"根"
// 协议（直接和 fd 打交道），TLS 是"中间层"——
//
//	fd（engine）
//	  ↕ 密文
//	TLS 状态机（这一层）
//	  ↕ 明文
//	内层协议（http2 / http1）
//
// 所以这个适配器是个**包装器**：它实现 engine.Handler，但把解出来的
// 明文交给内层协议的 handler，再把内层要发的东西加密写回 fd。
//
//	engine.OnData(密文)
//	  -> TLS 状态机 Feed
//	  -> 明文 -> 内层 OnData
//	  -> 内层吐出来的字节 -> TLS 状态机 Write 加密
//	  -> engine.Conn.Write(密文)
type ConnHandler struct {
	// config 是 TLS 配置（证书、SNI 这些）
	config *Config
	// isClient 是客户端还是服务端
	isClient bool
	// inner 是内层协议（握手完成之后数据都给它）
	inner engine.Handler

	// sm 是 TLS 状态机
	sm *StateMachine
	// handshakeDone 握手完成过一次（之后就纯转发）
	handshakeDone bool

	// innerPending 是内层没有消费完的明文，留到下一次拼在新解出来的前面。
	//
	// **两个边界不对齐**：TLS 记录是 16KB 一条（RFC 8446 5.1），HTTP/2 帧
	// 是 16KB 一帧（默认 SETTINGS_MAX_FRAME_SIZE），两者毫无关系。一次
	// OnData 解出来的明文里，最后一个帧往往是半截的——内层 Feed 解到那里
	// 就停，返回值小于传入长度。
	//
	// 早先这里把那个返回值丢掉了（`_, innerErr :=`），半截帧的字节就没了：
	// 症状是 h2 over TLS 在请求体 32KB 以上必断（客户端报 broken pipe），
	// 16KB 以下看着正常——因为小到不用跨记录边界。明文直接传（不走 TLS）
	// 时没有这个问题，所以只在 TLS 上现形。
	innerPending []byte
}

// NewConnHandler 建一个服务端的 TLS engine.Handler。
//
// inner 是 TLS 里面的协议（比如 http2 的 ConnHandler）。
func NewConnHandler(config *Config, inner engine.Handler) *ConnHandler {
	return &ConnHandler{config: config, inner: inner}
}

// NewClientConnHandler 建一个客户端的。
func NewClientConnHandler(config *Config, inner engine.Handler) *ConnHandler {
	return &ConnHandler{config: config, isClient: true, inner: inner}
}

// OnOpen 连接建立：建 TLS 状态机，客户端主动发 ClientHello。
//
// **同时装一个写拦截器**：内层协议（http2）后面会调 c.Write 发它的帧，
// 那些字节要**先加密**再出去。拦截器把它接到 TLS 状态机的 Write 上。
func (ch *ConnHandler) OnOpen(c *engine.Conn) {
	if ch.isClient {
		ch.sm = NewClientStateMachine(ch.config)
		if err := ch.sm.Start(); err != nil {
			c.Close()
			return
		}
		ch.flush(c)
	} else {
		ch.sm = NewServerStateMachine(ch.config)
	}

	// 内层写出来的明文 -> 加密 -> 真正发出去
	c.SetWriteHook(func(plain []byte) error {
		if ch.sm == nil || !ch.sm.Established() {
			// 握手没完成时内层不该有输出。真有了就丢掉——总比发明文好。
			return nil
		}
		ct, err := ch.sm.Write(plain)
		if err != nil {
			return err
		}
		if len(ct) > 0 {
			return c.WriteRaw(ct) // 绕过拦截器，否则递归
		}
		return nil
	})
}

// OnData 有数据可读：喂给 TLS 状态机，把解出来的明文转给内层。
//
// 返回值按 engine 的契约：消化了多少字节——**这是"成了几条记录"的字节数**，
// 不够一条记录的留在状态机的 RecordParser 里。
//
// 注意**不是** len(buf)：一次 OnData 里可能既有完整的记录、又有半条，
// 半条那部分不能算消化（虽然状态机自己攒着，但引擎那边也要留着——
// 两边都攒会重复处理，见 http 包里踩的那个坑）。
func (ch *ConnHandler) OnData(c *engine.Conn, buf []byte) (int, error) {
	if ch.sm == nil {
		ch.OnOpen(c)
	}

	// 1. 密文喂给 TLS
	consumed, err := ch.sm.Feed(buf)
	if err != nil {
		return consumed, err
	}

	// 2. 握手阶段的输出（ServerHello、Finished 这些）要发出去
	ch.flush(c)
	if ch.sm.Error() != nil {
		return consumed, ch.sm.Error()
	}

	// 3. 握手刚完成：通知内层（**要在转发明文之前**，内层可能要在
	// OnOpen 里初始化自己的状态）
	if ch.sm.Established() && !ch.handshakeDone {
		ch.handshakeDone = true
		if ch.inner != nil {
			ch.inner.OnOpen(c)
			ch.flushInner(c)
		}
	}

	// 4. 明文交给内层协议
	if plain := ch.sm.ReadPlaintext(); len(plain) > 0 && ch.inner != nil {
		// 上一轮内层没吃完的接在前面：记录边界和帧边界对不上，半截帧
		// 留着下次补齐（见 innerPending 的注释）。
		if len(ch.innerPending) > 0 {
			ch.innerPending = append(ch.innerPending, plain...)
			plain = ch.innerPending
		}

		n, innerErr := ch.inner.OnData(c, plain)

		// 内层没吃完的存下来。**这一步不能省**：丢掉的话那个半截帧的
		// 字节就永远没了，连接从那里开始错位。
		if n < 0 {
			n = 0
		}
		if n < len(plain) {
			ch.innerPending = append(ch.innerPending[:0], plain[n:]...)
		} else {
			ch.innerPending = ch.innerPending[:0]
		}

		// **内层吐出来的东西一定要发出去，出错时更要发**。
		//
		// 内层（http2）在发现协议错误时会先往自己的缓冲里写一个
		// GOAWAY，然后返回 error。那个 GOAWAY 是"最后的话"——对端要靠
		// 它知道为什么被断。这里要是因为 err != nil 就 return，GOAWAY
		// 就留在缓冲里没加密、没发出去，对端只看到连接断了（h2spec 报
		// 的是 Timeout，因为我们连 GOAWAY 都没回）。
		//
		// 顺序也要紧：**先 flush 再返回 error**——返回 error 之后引擎
		// 就 closeWith 了。
		ch.flushInner(c)

		if innerErr != nil {
			return consumed, innerErr
		}
	}

	return consumed, nil
}

// OnClose 连接关闭。
func (ch *ConnHandler) OnClose(c *engine.Conn, err error) {
	if ch.inner != nil {
		ch.inner.OnClose(c, err)
	}
	ch.sm = nil
	ch.innerPending = ch.innerPending[:0]
}

// State 返回 TLS 状态机的状态（测试和调试用）。
func (ch *ConnHandler) State() HandshakeState {
	if ch.sm == nil {
		return StateStart
	}
	return ch.sm.State()
}

// HandshakeDone 握手完了没有。
func (ch *ConnHandler) HandshakeDone() bool { return ch.sm != nil && ch.sm.Established() }

// CipherSuite 协商出来的套件。
func (ch *ConnHandler) CipherSuite() uint16 {
	if ch.sm == nil {
		return 0
	}
	return ch.sm.CipherSuite()
}

// ALPN 协商出来的应用层协议（HTTP/2 是 "h2"）。没协商出东西返回空串。
func (ch *ConnHandler) ALPN() string {
	if ch.sm == nil {
		return ""
	}
	return ch.sm.ALPN()
}

// flush 把 TLS 状态机要发的密文写进连接。
//
// **用 WriteRaw**：TakeOutput 出来的是**已经加密好的密文**（握手记录），
// 走 c.Write 会再进一次写拦截器、被当成明文再加密一遍。
func (ch *ConnHandler) flush(c *engine.Conn) {
	if out := ch.sm.TakeOutput(); len(out) > 0 {
		_ = c.WriteRaw(out)
	}
}

// flushInner 把内层协议还攒在它自己缓冲里的输出写出来。
//
// 内层（http2）调用 c.Write 的时候，写拦截器已经加密过了——这里只是
// 催它把攒着的东西吐出来。
func (ch *ConnHandler) flushInner(c *engine.Conn) {
	if taker, ok := ch.inner.(interface{ TakeOutput() []byte }); ok {
		if plain := taker.TakeOutput(); len(plain) > 0 {
			// 走 c.Write（进拦截器，会被加密）
			_ = c.Write(plain)
		}
	}
}

// WritePlain 把一段明文加密后写出去（给业务用）。
func (ch *ConnHandler) WritePlain(c *engine.Conn, plain []byte) error {
	return ch.writePlain(c, plain)
}

func (ch *ConnHandler) writePlain(c *engine.Conn, plain []byte) error {
	if ch.sm == nil || !ch.sm.Established() {
		return ErrHandshakeIncomplete
	}
	ct, err := ch.sm.Write(plain)
	if err != nil {
		return err
	}
	if len(ct) > 0 {
		// 密文，绕过拦截器
		return c.WriteRaw(ct)
	}
	return nil
}
