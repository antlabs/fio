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

package websocket

import (
	"io"
	"time"

	"github.com/antlabs/wsutil/enum"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/wsutil/deflate"
)

// 这一层把 websocket 接到 engine 的事件循环上。
//
//	engine（epoll / kqueue）
//	  ↓ OnData(字节)
//	ConnHandler（这个文件）
//	  ↓ 帧解析
//	Callback.OnMessage
//
// **和以前最大的不同**：以前 websocket 自己有一套事件循环、自己 read、
// 自己管读缓冲区；现在这些都归 engine，websocket 只负责"这些字节是什么
// 意思"。
//
// 三条要保持的性质：
//
//   - **零拷贝**：payload 直接指向 engine 的读缓冲区（needCopy 为 false
//     时），回调期间有效。回调返回后那块内存随下一次 read 复用。
//   - **攒包(cork)**：一轮 read 里解析出多个 frame 时，回包先攒着、轮末
//     一次写出去。写系统调用从 2,000,000/s 降到 200,000/s。
//   - **只消费完整帧**：引擎的契约是"返回消化了多少字节"，没凑齐一整帧
//     的字节要留在引擎的缓冲区里。所以解析到半个帧时要回退到那一帧的
//     开头再返回。

// ConnHandler 实现 engine.Handler，一条连接一个。
//
// **连接对象在 Bind 里建**，别处不再建第二个——一条连接对应一个 *Conn
// 是硬约束：Bind 由引擎在"注册 fd 之前"调，之后 OnData 拿到的 UserData
// 一定就是它。
//
// 为什么不在 OnOpen 里建：upgrade / Dial 这两条路拿到 fd 的时候，握手
// 协商出来的参数、bufio 多读的字节、用户的回调都只在调用方手上；建在
// OnOpen 里的话调用方得等事件循环跑完那个任务才拿得到对象，而**那个等待
// 会让事件循环先跑一轮 poll**——对端握手完立刻关连接时，等回来的对象
// 已经被关掉了（实测：Test_DefaultCallback 里客户端 WriteMessage 报
// closed）。Bind 跑在调用方的 goroutine 上、fd 还没注册，没有并发，也就
// 没有这个窗口。
type ConnHandler struct {
	conf     *Config
	isClient bool

	// pd 是握手协商出来的 permessage-deflate 参数。每连接一份（服务端
	// 由请求头决定、客户端由响应头决定），所以在建 handler 的时候带进来。
	pd deflate.PermessageDeflateConf

	// cb 覆盖 conf.cb。UpgradeLocalCallback 用（那条连接单独走一个回调），
	// 为 nil 时用 conf.cb。
	cb Callback

	// OnConn 在连接对象建好、UserData 装好之后、**fd 注册之前**调。
	//
	// 用途：
	//   - 服务端：把 http.Server 那边多读的字节喂进解析器，再调用户的
	//     Callback.OnOpen（握手已经完成，用户可以开始用）
	//   - 客户端：同上，外加把对象交回 Dial
	//
	// **跑在调用方的 goroutine 上**（upgrade 是 http handler 那个、Dial
	// 是用户那个、accept 路径是 accept 循环那个），不是事件循环的。这时候
	// fd 还没注册，事件循环看不见这条连接，所以喂数据、跑用户回调都安全。
	// 返回错误会让 fd 不注册（upgrade / Dial 把它当成升级失败交回去）。
	OnConn func(c *Conn) error
}

// NewConnHandler 建一个服务端的流处理器。
func NewConnHandler(conf *Config) *ConnHandler {
	return &ConnHandler{conf: conf}
}

// NewClientConnHandler 建一个客户端的。
func NewClientConnHandler(conf *Config) *ConnHandler {
	return &ConnHandler{conf: conf, isClient: true}
}

// SetPermessageDeflate 装握手协商出来的压缩参数。
func (h *ConnHandler) SetPermessageDeflate(pd deflate.PermessageDeflateConf) {
	h.pd = pd
}

// Bind 实现 engine.Binder：在 fd 注册到事件循环**之前**建 websocket 层的
// 连接对象。
//
// **跑在调用方的 goroutine 上**（upgrade 是 http handler 那个、Dial 是
// 用户那个、accept 路径是 accept 循环那个）。这时候事件循环还看不见这个
// fd，所以这里做的事（建对象、喂握手多读的字节、跑用户的 OnOpen）都不需要
// 锁，也不会有"对象被别处抢先建出来"的时序问题。
//
// 顺序对测试是有意义的：对端"握手完立刻 close"时，数据和 FIN 几乎同时到。
// 如果对象是等在 OnOpen 里建、调用方 SyncOnLoop 等回来的，事件循环在等待
// 期间就会把那轮的 poll 跑掉，对象等回来时已经关了；基线（迁移前）是先在
// 调用方建好、喂完 leftover、最后才注册，这里保持一致。
func (h *ConnHandler) Bind(ec *engine.Conn) error {
	c := newConn(ec, h.isClient, h.conf)
	c.pd = h.pd
	c.Callback = h.conf.cb
	if h.cb != nil {
		c.Callback = h.cb
	}
	ec.SetUserData(c)

	if h.OnConn != nil {
		return h.OnConn(c)
	}
	return nil
}

// OnOpen 连接就绪。
//
// **这里什么都不做**：连接对象已经在 Bind 里建好了（见上），而 Bind 一定
// 跑在 OnOpen 之前——引擎的 Add 先调 Bind 再注册，注册之后才轮到 OnOpen。
// 保留这个方法是 Handler 接口要求的。
func (h *ConnHandler) OnOpen(ec *engine.Conn) {}

// OnData 有数据可读：解析帧、交回调。
//
// 返回消化了多少字节。**只算完整帧**——半条帧的字节留在引擎的缓冲区里，
// 下次和新的数据拼起来再喂。
func (h *ConnHandler) OnData(ec *engine.Conn, buf []byte) (int, error) {
	c, _ := ec.UserData().(*Conn)
	if c == nil {
		// OnOpen 还没跑（不该发生，activate 保证了顺序）。真出现了就当
		// 没准备好，什么都不消费。
		return 0, nil
	}

	// **读超时续期**：语义是"多久没收到数据"(空闲超时), 不是"建连后
	// 多久"——所以每来一次数据就往后推。
	//
	// 迁移前这件事在 processWebsocketFrame 开头做（每次读事件一次），
	// 迁移后读归引擎了，等价的位置就是这里（引擎每读到一批数据调一次
	// OnData）。漏掉的症状很隐蔽：连接活过 readTimeout 就被关掉，哪怕
	// 数据一直在流——autobahn 的 12.3.10（1000 条 128KB 压缩消息，基线
	// 要跑 5.7s）就是这么挂的，基线的 duration 超过 5s 也判 OK。
	if c.readTimeout > 0 {
		_ = c.setReadDeadline(time.Now().Add(c.readTimeout))
	}

	n, err := c.parseBuf(ec, buf)
	return n, err
}

// OnClose 连接关闭。
//
// **走 websocket 自己的关闭流程**（closeNoLock），不是在这里直接调用户回调：
// 分片消息的缓冲、任务执行器都要在这里收尾，而那条路上本来就有这些。
//
// 错误值是迁移前的那套语义：**一律是个非 nil 的错误**。以前 socket 层的
// 关闭会把所有错误归一成 io.EOF，用户主动 Close() 也是 io.EOF（不是 nil）
// ——有测试靠这个区分"对面走了/出错了"和"我自己关的"。
func (h *ConnHandler) OnClose(ec *engine.Conn, err error) {
	c, _ := ec.UserData().(*Conn)
	if c == nil {
		return
	}
	if err == nil {
		err = io.EOF
	}
	c.closeNoLock(err)
}

// NextMessageSize 实现 engine.MessageSizeHinter。
//
// 引擎在读缓冲区装满、而这条报文还没凑齐的时候问一句"整条多大"，好一次
// 把缓冲区长到位——不然大帧要经历 16K→32K→…→N 的连续翻倍，每档都要把
// 已经读到的整块数据 memcpy 一遍。
//
// **只在这里让引擎动缓冲区**：引擎挑的时机是两次 OnData 之间，解析器手上
// 没有活的别名（rbuf 在 parseBuf 返回前就置回 nil 了）。
//
// 数字是上一次解析留下的：缓冲区满的时候解析器已经回退到这一帧的开头
// （rollbackFrame），而"整帧多大"是读完帧头那次算出来的。帧头都还没解析
// 出来（比如只到了 1 个字节）时这里是上一帧的大小——报小了只是少长一次，
// 下一轮 readHeader 之后就会报对，不影响正确性。
func (h *ConnHandler) NextMessageSize(ec *engine.Conn) int {
	c, _ := ec.UserData().(*Conn)
	if c == nil {
		return 0
	}
	return c.nextFrameSize()
}

// nextFrameSize 当前这一帧整条有多大（帧头 + payload）。不知道返回 0。
func (c *Conn) nextFrameSize() int {
	if c.rh.PayloadLen <= 0 {
		return 0
	}
	return c.headerLen() + int(c.rh.PayloadLen)
}

// InitialReadBufferSize 起始读缓冲区多大，实现 engine.ReadBufferSizer。
//
// 按配置里的 windowsMultipleTimesPayloadSize 算，**和迁移前那条公式一致**：
// PayloadLen × 倍数 + 帧头，PayloadLen 取 1024（常见的小报文），默认 2.0
// → 2062 字节。
//
// 为什么抠这 14 字节：bytespool 按 1KB 分档（1KB+14、2KB+14、…），要 2076
// 会落到 3KB 档拿回 3086 字节，而要 2062 正好是 2KB+14 那一档。**每连接一块
// 读缓冲区，档位差一格就是 10000 连接下多 10MB**，也影响它们能不能一起
// 装进 L3。基线（迁移前）用 readBufferSize() 要的就是 2062，所以数据面
// 的缓冲区大小和基线一模一样。
//
// 1KB 的 echo 一条消息（1030 字节）正好装下；报文比它大时引擎自己会长
// （growReadBuffer 一次跳到 16KB，那一跳正好够把 Pipeline 那种"一次 write
// 十条"的批次读完）。
func (h *ConnHandler) InitialReadBufferSize() int {
	n := int(float32(1024)*h.conf.windowsMultipleTimesPayloadSize) + enum.MaxFrameHeaderSize
	if n < 1024 {
		n = 1024
	}
	return n
}

// parseBuf 把一段缓冲区借给解析器，返回消费掉的字节数。
//
// **把 engine 的缓冲区"借"给解析器**：整段解析代码（readHeader /
// readPayload）本来就是按"rbuf + rr/rw 两个游标"写的，这里把游标指到
// engine 给的那段上，那些代码一行都不用改。
//
// rr/rw 只在本次调用里有效：返回之前会被回退到"最后一个完整帧之后"，
// 引擎把 rr 之前的字节丢掉，下次 OnData 又是从 0 开始。
func (c *Conn) parseBuf(ec *engine.Conn, buf []byte) (int, error) {
	b := buf
	c.rbuf = &b
	c.rr = 0
	c.rw = len(buf)

	n, err := c.parseFrames(ec)

	// 轮末把攒下的回包一次写出去。**出错的那一轮也要调**：攒下的东西
	// （比如 close 帧的回包）要在连接关掉之前出去。
	ec.EndCork()

	c.rbuf = nil
	c.rr, c.rw = 0, 0
	return n, err
}

// parseFrames 解析缓冲区里的所有完整帧，每解析出一条就交给回调。
//
// 返回消费了多少字节（**只到最后一个完整帧为止**）。
//
// 这里的循环结构和以前 processWebsocketFrame 的解析部分一样，区别只有
// 两处：
//
//  1. 不自己 read —— 数据是引擎给的
//  2. 解析不动的时候要**回退到这一帧的开头**（frameStart），把"半条帧"
//     整个留给引擎。不这么做的原因见下面。
func (c *Conn) parseFrames(ec *engine.Conn) (int, error) {
	consumed := 0
	for {
		// **记下这一帧的起点**：解析不动的时候要退回这里。
		//
		// 引擎的契约是"返回消化了多少字节，剩下的留着下次再喂"。而
		// readHeader 是个状态机——它可能已经吃掉了 2 字节的帧头才开始
		// 检查"扩展长度够不够"。这时候如果只返回"能解析的部分"，引擎
		// 会把那 2 字节丢掉，下次喂过来的数据就少了开头，帧头再也拼不
		// 出来。
		//
		// 所以退回起点 + 状态机复位：下次喂过来时从这一帧的第一个字节
		// 重新开始解析。代价是那 2 字节会被重复解析一次（罕见路径），
		// 换来的是"引擎的缓冲区位置"和"解析器的位置"始终一致。
		frameStart := c.rr

		success, err := c.readHeader()
		if err != nil {
			return consumed, err
		}
		if !success {
			c.rollbackFrame(frameStart)
			return consumed, nil
		}

		// **不在这里让引擎扩缓冲区**：OnData 期间协议手里握着读缓冲区的
		// 别名（零拷贝的 payload、以及解析器的 rbuf/rr/rw 就是照它摆的），
		// 这时候 compact 会把数据挪走、扩容会把数组换掉——解析器读到的
		// 就是错位/已释放的内存。实测症状很隐蔽：分片+压缩那条用例收到的
		// 报文前面多出两个字节（那是帧头），就是 compact 挪了位置。
		//
		// 预扩交给引擎：它在两次 OnData 之间（手上没有别名时）问
		// NextMessageSize，一次把空间要到最终大小。见
		// ConnHandler.NextMessageSize。
		success, err = c.readPayloadAndCallback(ec)
		if err != nil {
			return consumed, err
		}
		if !success {
			c.rollbackFrame(frameStart)
			return consumed, nil
		}

		consumed = c.rr
	}
}

// rollbackFrame 把解析位置退回这一帧的开头，并把帧头状态机复位。
//
// 复位是必须的：状态机可能已经推进到"等扩展长度"那一步了，而 rr 退回
// 去之后那些字节还没被消费。不回位的话下次会按"等扩展长度"去读，但它
// 其实还在帧头的前 2 个字节上。
func (c *Conn) rollbackFrame(frameStart int) {
	c.rr = frameStart
	c.setCurState(frameStateHeaderStart)
}

// headerLen 当前帧头已经占用的字节数（2 + 扩展长度 + 掩码）。
//
// 读路径用它算"整帧还需要多少"，readHeader 里也会维护它。
func (c *Conn) headerLen() int {
	return 2 + c.lenAndMaskSize
}
