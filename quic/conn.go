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
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
	// ackSince 是这一批待确认包里**最早**那个的到达时间。ACK 最多拖
	// ackMaxDelay（见 flusher 的检查）：**不能无限拖**——发送方靠 ACK 涨
	// 拥塞窗口，拖久了它 cwnd 用完就不再发，而我们要等它的数据才回包，
	// 两边双向死等（实测：16 条并发 8KB 上传时偶发挂死，客户端 5 秒后报
	// "no recent network activity"；8gbit 那种 100KB 请求体是同一类风险）。
	ackSince [3]time.Time

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

	// 流。mu 保护从 streams 到 appOut 这一整片（收包 goroutine 和各个
	// lane 上写响应的 goroutine 都会碰）。
	mu      sync.Mutex
	streams map[uint64]*Stream
	accept  chan *Stream
	// acceptUni 是对端开的单向流（HTTP/3 的控制流 / QPACK 流）。
	acceptUni chan *Stream
	// nextUni 是我们自己开的下一条单向流 ID（服务端单向流 3, 7, 11…）。
	nextUni uint64

	// cond 有新数据、或者连接关掉时广播。
	//
	// 原来是往一个 chan 里投一个信号——那个只能唤醒**一个**等待者。
	// HTTP/3 起几条并行通道（h3Lanes）之后同一时刻有好几个 goroutine
	// 等在各自的流上，投递式的信号会让其余的永远睡着（实测卡死在
	// 并发请求上）。
	cond *sync.Cond

	// 对端流回收水位，见 retireSet。
	retiredBidi retireSet
	retiredUni  retireSet

	// maxStreams 是我们允许对端开的双向流总数（和 initial_max_streams_bidi
	// 一个值）。maxStreamsSent 是最后一次报给对端的 MAX_STREAMS_BIDI。
	//
	// **对端流关掉之后必须把额度还回去**（RFC 9000 4.6）：不还的话对端开到
	// 4096 条就再也没有开流的额度，整个连接**静静地停在那里**。踩过：
	// baseline-h3 的压测端每连接 64 条并发流，跑到 4096 条全部卡死，
	// 吞吐从 5M 掉到 52k（那个 262144 = 64 连接 × 4096 就是它的指纹）。
	maxStreams     uint64
	maxStreamsSent uint64

	// 连接级接收流控（RFC 9000 4.1）：recvData 是从对端流上收到的总字节数，
	// maxDataSent 是报给对端的 MAX_DATA（初始值是传输参数里声明的那个窗口）。
	//
	// **这个额度同样必须还**：不还的话对端发满窗口就再也发不出数据。
	// 踩过：baseline-h3 的 -D 20 跑到后半段吞吐掉到五分之一，客户端
	// 0 错误 0 超时全在等——16MB ÷ 每请求约 50 字节 ≈ 33 万请求/连接，
	// 64 连接恰好 2100 万，就是那个"总请求数封顶"的指纹。
	recvData    uint64
	maxDataSent uint64

	// 1-RTT 的 Key Phase 位（RFC 9001 6）和我们当前这一代读密钥。
	//
	// **对端会主动换代**：quic-go 的客户端"握手之后不久就把第一次密钥
	// 更新做了"（updatable_aead.go 里写得很直白，就是为了把这条机制跑通），
	// 触发点是当前密钥下过了 100 个包。不跟着换的话，从那以后每个包都
	// AEAD 验不过——症状是流数据一个劲"有洞"、请求挂死。
	keyPhase uint8
	// prevRecv 是上一代读密钥：换代的瞬间还有在途的旧包，留一代给它们。
	prevRecv *keys

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

	// flushSig 有 1-RTT 帧要发时响一下（非阻塞投递），runFlusher 攒一批再发。
	// done 关掉时 flusher 退出。
	flushSig chan struct{}
	done     chan struct{}

	// hook 是"对端的新流到了"的同步钩子（可选），见 SetStreamHook。
	hook StreamHook

	// l 是收上来的那个 listener（loopFlush 模式下要往它的待发表里挂），
	// loopFlush 决定发送走哪条路（见 flushSoon），dirtyQueued 是挂表标记。
	l         *Listener
	loopFlush bool
	// dirtyQueued 是"已经挂在 listener 的待发表里"的标记。
	// **必须是原子的**：markDirty 是握着 c.mu 调的（Stream.Write/Close 里
	// 就是这么调的），再去抢 c.mu 就是自己锁自己（踩过：整个连接停住，
	// 收包那条路一直拿不到锁）。
	dirtyQueued atomic.Bool

	// 发送侧攒包用：txBuf 里是封好的若干包，txSizes 是各包长度。
	// fd/remoteSA 是 GSO 那条路要的（一次 sendmsg 发一批），见 writePackets。
	txBuf    []byte
	txSizes  []int
	fd       int
	remoteSA unix.Sockaddr

	// pktAvg 见 notePkt/padBulk：最近发出的包的平均载荷大小（判断在不在推大响应）
	pktAvg int

	// outstanding 是"已经发出去、还没被 ACK 确认"的控制帧载荷，见
	// retransmitLocked 和 outstanding 的说明。
	outstanding []outstanding

	// appOut 是 1-RTT 上待发的帧（各流的 STREAM、控制帧）。攒起来一次发；
	// appEnds 记每个帧的结束偏移——**帧不能跨包**，切包只能切在帧边界上
	// （见 flushLocked）。
	appOut  []byte
	appEnds []int
}

// outstanding 是"已经发出去、还没被确认"的控制帧载荷（重传用）。
//
// **回环上也会丢**：对端（压测端/客户端）一忙，它的收包缓冲就可能溢出——
// 而本实现不做丢包重传（见 doc.go 的范围）。流数据丢了没关系（对端会
// 重发请求），但**控制帧丢一次就是死等**：Handshake 的 CRYPTO 丢了握手
// 完不成、HANDSHAKE_DONE 丢了客户端（quic-go）一直卡在"等握手确认"
// 开不了流，5 秒后报 "no recent network activity"。CI 上那个偶发失败
// （TestConcurrentStreamsLargeWrites 挂住）就是这么来的。
//
// 所以只给控制帧做最小重传：发的时候把载荷留一份，收到对端 ACK 就丢掉，
// 超时没确认就用**新的包序号**重发一份（QUIC 的重传就是这个语义）。
type outstanding struct {
	pn    uint64
	lvl   int
	data  []byte // 载荷（不含包头），重传时重新封
	sent  time.Time
	rto   time.Duration // 下次重传的等待（每次翻倍）
	tries int
}

const (
	// ackMaxDelay 是 ACK 最多拖多久。压测端的 cwnd 只有十几 KB，ACK 拖过
	// 这个量级它就没额度继续发了。1ms 足够让同一批的响应把 ACK 捎走
	// （回环上响应就在几微秒之后），又不会卡住对端。
	ackMaxDelay = time.Millisecond

	// minRTO 是最小重传超时。回环上丢包是"对端缓冲溢出"这种瞬时情况，
	// 200ms 重发一次足够；翻倍退避到 maxRTO，试满 maxRTTries 次就放弃
	// （真等不到的连接，让对端的 idle timeout 收场）。
	minRTO     = 200 * time.Millisecond
	maxRTO     = 2 * time.Second
	maxRTTries = 6

	// 接收窗口。和 ourParams 里声明的值**必须是同一个**：这里的 maxDataSent
	// 就是"我们已经报给对端多少额度"的记账起点。
	recvConnWindow   = 1 << 24 // 连接级（initial_max_data）
	recvStreamWindow = 1 << 22 // 单流（initial_max_stream_data_*）

	// maxPacketPayload 一个 1-RTT 包载荷的上限。1500 的 MTU 减掉包头和
	// AEAD 标签还剩 1400 多，取 1200（QUIC 的最小 MTU）对什么路径都安全。
	maxPacketPayload = 1200
	// maxStreamChunk 一个 STREAM 帧最多带多少字节。留出帧头和小控制帧
	// （ACK/HANDSHAKE_DONE）的余量，让它们能和最后一个数据帧同包。
	maxStreamChunk = 1100
)

// Config 是服务端的配置。
type Config struct {
	// TLSConfig 至少要带证书。ALPN 由 http3 那层设（"h3"）。
	TLSConfig *tls.Config
	// MaxStreams 一条连接上最多接受多少条对端发起的双向流。
	MaxStreams uint64
}

const (
	lvlInitial   = 0
	lvlHandshake = 1
	lvlApp       = 2
)

// newConn 建一条服务端连接。
//
// odcid 是客户端第一个 Initial 里的目标连接 ID（Initial 密钥从它推，跟
// 后面用的连接 ID 是两回事）；peerCID 是那个包里的源连接 ID，之后我们发给
// 客户端的每个包的目标连接 ID 都得是它。
func newConn(pc net.PacketConn, remote net.Addr, odcid, peerCID []byte, cfg Config) (*Conn, error) {
	c := &Conn{
		pc:            pc,
		remote:        remote,
		streams:       make(map[uint64]*Stream),
		accept:        make(chan *Stream, 64),
		acceptUni:     make(chan *Stream, 8),
		scid:          make([]byte, connIDLen),
		dcid:          append([]byte(nil), peerCID...),
		odcid:         append([]byte(nil), odcid...),
		maxData:       1 << 20,
		maxStreamData: 1 << 20,
		// 服务端开的单向流从 3 开始（0x03：本端发起 + 单向）
		nextUni:     3,
		retiredUni:  retireSet{next: 2, pend: make(map[uint64]struct{})},
		retiredBidi: retireSet{next: 0, pend: make(map[uint64]struct{})},
		maxStreams:  maxStreamsOf(cfg),
		maxDataSent: recvConnWindow,
		flushSig:    make(chan struct{}, 1),
		done:        make(chan struct{}),
		fd:          -1,
		remoteSA:    sockaddrOf(remote),
	}
	// GSO 那条路要裸 fd（net.PacketConn -> RawConn -> fd）。拿不到就
	// fd=-1，发送退回一个个 WriteTo（功能一样，就是系统调用多）。
	if c.remoteSA != nil {
		if fd, err := syscallConnFd(pc); err == nil {
			c.fd = fd
		}
	}
	c.maxStreamsSent = c.maxStreams
	go c.runFlusher()
	for i := range c.cryptoGaps {
		c.cryptoGaps[i] = make(map[uint64][]byte)
	}
	c.cond = sync.NewCond(&c.mu)
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

var errNoGSO = errors.New("quic: gso not available")

// sockaddrOf 把 net.Addr 转成 sendmsg 要的 sockaddr（GSO 那条路用）。
// 转不了就返回 nil，调用方退回 WriteTo。
func sockaddrOf(a net.Addr) unix.Sockaddr {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return nil
	}
	if ip4 := ua.IP.To4(); ip4 != nil {
		sa := &unix.SockaddrInet4{Port: ua.Port}
		copy(sa.Addr[:], ip4)
		return sa
	}
	ip := ua.IP.To16()
	if ip == nil {
		return nil
	}
	sa := &unix.SockaddrInet6{Port: ua.Port}
	copy(sa.Addr[:], ip)
	return sa
}

// syscallConnFd 从 PacketConn 里挖出裸 fd。
func syscallConnFd(pc net.PacketConn) (int, error) {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return -1, errors.New("quic: packet conn is not a syscall conn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	if err := raw.Control(func(f uintptr) { fd = int(f) }); err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, errors.New("quic: no fd")
	}
	return fd, nil
}

// maxStreamsOf 是对端可以在一条连接上开的双向流总数。
func maxStreamsOf(cfg Config) uint64 {
	if cfg.MaxStreams > 0 {
		return cfg.MaxStreams
	}
	return 4096
}

func (c *Conn) ourParams(cfg Config) transportParams {
	maxStreams := maxStreamsOf(cfg)
	return transportParams{
		maxUDPPayload:         1472,
		initialMaxData:        recvConnWindow,
		initialMaxStreamData:  recvStreamWindow,
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
	// 整段在锁里：这里改的是密钥、待发 CRYPTO、对端参数，而 flusher 那边
	// 同时在读它们（拿锁就发一个包）。
	c.mu.Lock()
	defer c.mu.Unlock()
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
			dbg("TLS 握手完成（服务端）")
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
	// 整个数据报里有没有"交给 lane 的流数据"（决定 ACK 是单独发还是让
	// 响应捎出去，见下面的 streamData 分支）
	var streamData bool
	// 装了钩子的话请求是**就地**处理的（响应已经在 appOut 里），这一趟
	// 就该把 ACK + 响应一起发出去，不用等 flusher
	c.mu.Lock()
	inlineDone := c.hook != nil
	c.mu.Unlock()
	// FIO_QUIC_ACK_NOW=1：收到带数据的包**立刻**回 ACK（不搭响应的车）。
	// 默认关（搭车省一个 sendto），留开关是因为 ACK 的时机会影响对端的
	// RTT 估计和 pacing——扫档的时候用得上。
	ackNow := os.Getenv("FIO_QUIC_ACK_NOW") == "1"
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
		dbg("handlePacket: lvl=%d pn=%d 密文 %d 字节 首字节=%#x", lvl, h.pn, len(h.payload), h.raw[0])
		// 连接状态的操作都要在锁里：写侧（lane goroutine 上的
		// Write/Close -> flushLocked）会同时读 ackDue/recvSeen/密钥。
		c.mu.Lock()
		if h.pn > c.largest[lvl] || !c.gotPN[lvl] {
			c.largest[lvl] = h.pn
			c.gotPN[lvl] = true
		}
		c.mu.Unlock()
		payload, err := h.open(k)
		if err != nil {
			// AEAD 验不过。1-RTT 上先看看是不是对端换代了（见 keyPhase）：
			// 拿当前读密钥推下一代试试，解开了就跟着换。
			if lvl == lvlApp && !h.long {
				if h.keyPhase() != c.keyPhase {
					if ok, pt := c.updateKeys(h); ok {
						payload, err = pt, nil
					}
				}
				// 还不行就试试上一代：换代瞬间在途的旧包
				if err != nil && c.prevRecv != nil {
					if pt, e := h.open(c.prevRecv); e == nil {
						payload, err = pt, nil
					}
				}
			}
			if err != nil {
				dbg("handlePacket: AEAD 验不过 lvl=%d pn=%d kp=%d 当前kp=%d（%d 字节密文）",
					lvl, h.pn, h.keyPhase(), c.keyPhase, len(h.payload))
				return nil
			}
		}
		ackEliciting, gotStream, err := c.processFrames(lvl, payload)
		if err != nil {
			return err
		}
		streamData = streamData || gotStream
		// **验过了、而且这包要确认，才记 ACK**：验不过的等于没收到；
		// 只含 ACK/PADDING 的包按 RFC 9000 13.2.1 **不能回 ACK**——回的话
		// 就是 ACK 放大（每请求多一个包，实测占了发送量的一大半）。
		if ackEliciting {
			c.mu.Lock()
			if !c.ackDue[lvl] {
				c.ackSince[lvl] = time.Now()
			}
			c.ackDue[lvl] = true
			c.recvSeen[lvl] = append(c.recvSeen[lvl], h.pn)
			c.mu.Unlock()
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
	if streamData && !inlineDone && !ackNow {
		// 这一包的数据已经交给某条 lane 了：**ACK 不单独发**，让响应
		// 那个包捎出去（回环上响应就在几微秒之后）。单独发的话每请求
		// 多一个 sendto，profile 里光系统调用就占 45%。
		//
		// 别的路径（PING、握手、控制帧）还是立刻回，不然对端会等我们。
		return nil
	}
	return c.flushForce(true)
}

// processFrames 处理一个包里的帧。
//
// 两个回值都是给 handlePacket 决定"怎么回"用的：
//
//	ackEliciting 这包要不要确认（RFC 9000 13.2.1：只含 ACK/PADDING/
//	             CONNECTION_CLOSE 的包**不能回 ACK**）
//	streamData   这包里有交给 lane 的流数据（ACK 让响应捎出去）
func (c *Conn) processFrames(lvl int, payload []byte) (ackEliciting, streamData bool, err error) {
	var streamErr error
	err = parseFrames(payload, func(kind uint64, raw []byte, _ int) error {
		dbg("帧: kind=%#x lvl=%d %d 字节", kind, lvl, len(raw))
		switch kind {
		case frAck, frAckECN, frPadding, frConnClose, frConnCloseApp:
			// 不算"要确认的"
		default:
			ackEliciting = true
		}
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
			streamData = true
			streamErr = c.onStreamData(id, dataOff, data, kind&streamBitFin != 0)
			return nil
		case kind == frAck || kind == frAckECN:
			// 对端确认了我们哪些包：把对应的控制帧从重传表里去掉
			if largest, ranges, ok := parseAck(raw[1:]); ok {
				c.mu.Lock()
				c.ackSentLocked(largest, ranges)
				c.mu.Unlock()
			}
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
		case kind == frPathChallenge:
			// RFC 9000 8.2：必须把收到的 8 字节原样回一个 PATH_RESPONSE，
			// 不然对端的路径校验过不去（PMTUD/迁移时用）
			if len(raw) >= 9 {
				c.mu.Lock()
				c.appOut = appendVarint(c.appOut, frPathResponse)
				c.appOut = append(c.appOut, raw[1:9]...)
				c.appEnds = append(c.appEnds, len(c.appOut))
				c.mu.Unlock()
			}
		}
		return nil
	})
	if err != nil {
		// 帧解不动就把**整包**丢了（帧没有长度前缀，解偏了后面就没法接）。
		// 这里一定要出声：这种错误在收包那条路上是被调用方忽略的，
		// 不打日志就成了"客户端发了、服务端装死"。
		dbg("processFrames: 解帧失败 lvl=%d: %v", lvl, err)
		return ackEliciting, streamData, err
	}
	return ackEliciting, streamData, streamErr
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

// updateKeys 处理对端的密钥更新（RFC 9001 6）：拿当前读密钥推下一代，
// 能解开 h 就把读写两侧都换过去。
//
// **两侧一起换**：Key Phase 是双向同步的——对端换代之后，它也会用新一代
// 的密钥来读我们的包，所以我们的**写**密钥必须跟着换，而且之后发出的
// 短头要标新相位（见 sendPacketLocked 的 kp）。
//
// 旧的读密钥留一代（prevRecv）：换代的瞬间还有在途的旧包。
func (c *Conn) updateKeys(h *header) (bool, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.recv[lvlApp]
	if cur == nil || len(cur.secret) == 0 {
		return false, nil
	}
	next, err := cur.next()
	if err != nil {
		return false, nil
	}
	pt, err := h.open(next)
	if err != nil {
		return false, nil
	}
	c.prevRecv = cur
	c.recv[lvlApp] = next
	c.keyPhase = h.keyPhase()
	if w := c.send[lvlApp]; w != nil {
		if nw, err := w.next(); err == nil {
			c.send[lvlApp] = nw
		}
	}
	dbg("密钥更新：key phase -> %d", c.keyPhase)
	return true, pt
}

// flushDelay 是"攒一批再发"的等待窗口（**只对小响应生效**，见 runFlusher
// 里的 smallPending 门控）。
//
// 为什么小响应要等：压测端（h2load/ngtcp2）每请求的开销里"每包 2.4us"
// 是固定成本，包越少它越省。fib 是 0.022 包/请求、我们原来 0.054
// （18.5 个响应一包，而包预算装得下 45+ 个），那 3% 的差就在这。
//
// 大响应（static 那种 16KB）**不能等**：包本来就是满的，等只会白添延迟
// （实测 static-h3 在固定窗口下 −1.3%，加了门控之后不动）。
//
// lab 实测（baseline-h3，服务端 0-11 / 压测端 12-23 / MTU 1500，两轮）：
//
//	窗口 0us    : 5.045M / 5.023M
//	窗口 250us  : 5.175M / 5.149M   （fib 5.15M）
//
// 250us 是"等下一批响应"的量级：每连接 78k 请求/秒 ÷ 21 个一包 ≈ 270us
// 一个数据报，所以等一次就能让一包带上两个数据报的响应。
var flushDelay = func() time.Duration {
	if v := os.Getenv("FIO_QUIC_COALESCE_US"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Microsecond
		}
	}
	return 250 * time.Microsecond
}()

// runFlusher 攒一批 1-RTT 帧再发（每条连接一个 goroutine）。
//
// **为什么非攒不可**：压测端（h2load -m 64）一个 UDP 数据报里塞好几条请求，
// 而我们原来每条响应的 Write 都立刻 sendto —— 实测每请求 2 个报文，
// profile 里 47% 的 CPU 花在 sendto 上（一次系统调用 ~3.4us，比响应本身
// 还贵）。攒一个窗口再发，一个包带上同一批的几条响应，sendto 少一个
// 数量级。
//
// 握手、PING、ACK 那些不能等的不走这条路（handlePacket 里立刻 flush）。
//
// 兜底定时器 1ms：万一哪条路径忘了 signal，响应最晚 1ms 也会出去
// ——"永远发不出去"比"晚 1ms"严重得多。
func (c *Conn) runFlusher() {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	for {
		timer.Reset(time.Millisecond)
		select {
		case <-c.done:
			return
		case <-c.flushSig:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		// 攒批窗口：**只在"这一轮攒的帧还不到半个包"的时候等一等**。
		//
		// 小响应（baseline-h3 那种每个 ~20 字节）值得等下一批一起走：
		// 压测端每请求的开销里"每包 2.4us"是固定成本，包越少它越省
		// （fib 是 0.022 包/请求，我们原来 0.054 → 那 3% 的差就在这）。
		// 大响应（static 那种 16KB）包本来就是满的，等只会白添延迟。
		if flushDelay > 0 && c.smallPending() {
			time.Sleep(flushDelay)
		}
		if err := c.flush(); err != nil {
			return
		}
		// ACK 最多拖 ackMaxDelay：发送方要靠它涨拥塞窗口，无限拖会双向死等
		c.mu.Lock()
		if c.ackDue[lvlApp] && time.Since(c.ackSince[lvlApp]) >= ackMaxDelay {
			_ = c.flushLocked(true)
		}
		// 超时没被确认的控制帧（握手的 CRYPTO / HANDSHAKE_DONE）重发
		c.retransmitLocked()
		c.mu.Unlock()
	}
}

// loopFlushOn：发送交给收包循环（见 Listener.flushDirty），而不是每条
// 连接一个 flusher goroutine。
//
// **这是"把 HTTP/3 做成事件循环"那件事的核心开关**：开了之后一条 goroutine
// 走完 收 -> 解 -> 处理 -> 发，和 fib 的结构一致；关着的话每连接有一个
// flusher goroutine 等着被唤醒（64 条连接 × 4 个子进程就是几百个 goroutine
// 在抢 P，唤醒延迟随连接数堆）。
//
// 留成开关是因为要 A/B：唤醒延迟省下来 vs 攒批的机会变少。
var loopFlushOn = os.Getenv("FIO_QUIC_LOOP_FLUSH") == "1"

// smallPending 这一轮攒的帧还不到半个包（只有小响应才值得等一批再发）。
func (c *Conn) smallPending() bool {
	c.mu.Lock()
	n := len(c.appOut)
	c.mu.Unlock()
	return n > 0 && n < maxPacketPayload/2
}

// flushSoon 告诉"发送方"有帧要发了。
//
//	loopFlush 模式：把自己挂进 listener 的待发表，收包循环这一轮末尾发
//	默认模式：往 flusher 的 channel 里投一个信号（非阻塞，合并成一次）
func (c *Conn) flushSoon() {
	if c.l != nil && c.loopFlush {
		c.l.markDirty(c)
		return
	}
	select {
	case c.flushSig <- struct{}{}:
	default:
	}
}

// flush 保证互斥（收包 goroutine 用），flushLocked 要求调用方已经拿着 c.mu。
//
// 写侧（lane 上的 Write/Close）都是在持锁状态下攒帧的，所以它们直接调
// flushLocked；收包那条路是攒完 ACK 再进来。
// flush 是"攒批"那条路（flusher / loopFlush）：**只有 ACK 的时候先不发**，
// 等这一批的响应一起捎（见 flushLocked 的 ackOnly 分支）。
func (c *Conn) flush() error { return c.flushForce(false) }

// flushForce 是收包那条路用的：ACK 该走就走（PING、握手这类没有后续
// 响应的包，不能等）。
func (c *Conn) flushForce(force bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flushLocked(force)
}

// flushLocked 把三个级别上待发的东西发出去。
//
// 1-RTT 那份可能不止一个包：appOut 里攒的帧按**帧边界**切成 ≤
// maxPacketPayload 的载荷，一包一包发（QUIC 的帧不跨包，切分点只能落在
// 帧与帧之间，而帧的结束位置在 appEnds 里）。
func (c *Conn) flushLocked(force bool) error {
	if c.closed {
		return nil
	}
	for _, lvl := range []int{lvlInitial, lvlHandshake, lvlApp} {
		var payload []byte
		// 1-RTT 的 ACK/控制帧先攒着，等这个级别的数据也攒完再决定发不发
		// （见下面 ackOnly）。别的级别没有这个问题：ACK 和 CRYPTO 一起走。
		if lvl != lvlApp && c.ackDue[lvl] {
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
			// 还没有 1-RTT 的写密钥（握手没完）就先别动队列：**帧留在
			// 里面等密钥**。这里要是把 appOut 清了，握手没完就写进来的
			// 东西（HTTP/3 的 SETTINGS 就是）会静静地丢掉，对端一直等它。
			if c.send[lvlApp] == nil {
				continue
			}
			// 这个级别待发的 ACK（先攒着，见下面的 ackOnly）
			var ack []byte
			if c.ackDue[lvl] {
				ack = appendAck(ack, c.recvSeen[lvl], 0)
			}
			// 控制帧也先攒着（和 ACK 一样，发的时候才提交状态）
			var ctl []byte
			// 把用掉的流额度还回去（MAX_STREAMS，RFC 9000 4.6）。
			//
			// 水位推过了多少就还多少：报给对端的是"总共能开多少条"，
			// 对端取 max(旧值, 新值)，所以按四分之一额度分批报——每个
			// 请求报一次太浪费（响应包里多 3 字节），报晚了对面会撞上限。
			maxStreamsNew := uint64(0)
			if c.retiredBidi.next+c.maxStreams > c.maxStreamsSent+c.maxStreams/4 {
				maxStreamsNew = c.retiredBidi.next + c.maxStreams
				ctl = appendVarint(ctl, frMaxStreamsBidi)
				ctl = appendVarint(ctl, maxStreamsNew)
			}
			// 把用掉的**连接级**接收窗口还回去（MAX_DATA，RFC 9000 4.1）。
			// 见 recvData 那段说明：不还的话对端发满 16MB 就停住了。
			maxDataNew := uint64(0)
			if c.maxDataSent-c.recvData < recvConnWindow/2 {
				maxDataNew = c.recvData + recvConnWindow
				ctl = appendVarint(ctl, frMaxData)
				ctl = appendVarint(ctl, maxDataNew)
			}
			// **只有 ACK、没有数据和别的控制帧**：先不发。
			//
			// static-h3 上这是个大头：16KB 的响应在 lane 上写着，同一批请求
			// 的 ACK 会被 1ms 定时器单独发出去——每个响应配一个 37 字节的小
			// 包（实测 2 秒里 98 万次 sendto 都是这种）。ACK 拖到下一批
			// 响应一起走完全没问题（响应就在几微秒/几百微秒之后）。
			// force 那条路（收包循环里 PING、握手之类的）不等。
			if len(ack) > 0 && len(ctl) == 0 && len(c.appEnds) == 0 && !force {
				continue
			}
			// HANDSHAKE_DONE 单独一个包发，而且要能重传：它丢了客户端
			// 就一直开不了流（见 outstanding）。混进数据包的话重传会把
			// 流数据也重发一遍（合法但浪费）。
			if c.handshakeDone && !c.sentHandshakeDone {
				hp := append([]byte(nil), ack...)
				hp = appendVarint(hp, frHandshakeDone)
				if err := c.sendTrackedLocked(lvlApp, hp); err != nil {
					return err
				}
				dbg("发出 HANDSHAKE_DONE（pn=%d）", c.nextPN[lvlApp]-1)
				c.sentHandshakeDone = true
				c.ackDue[lvl] = false
				c.recvSeen[lvl] = c.recvSeen[lvl][:0]
				ack = nil
			}
			// 决定要发了，这时候才提交状态
			if len(ack) > 0 {
				c.ackDue[lvl] = false
				c.recvSeen[lvl] = c.recvSeen[lvl][:0]
				payload = append(payload, ack...)
			}
			if len(ctl) > 0 {
				if maxStreamsNew > 0 {
					c.maxStreamsSent = maxStreamsNew
				}
				if maxDataNew > 0 {
					c.maxDataSent = maxDataNew
				}
				payload = append(payload, ctl...)
			}
			// 攒下的帧按帧边界装包：装得下就装，装不下先封好这一包。
			//
			// 封好的包攒在 c.txBuf 里（c.txSizes 记长度），最后一起发：
			// 长度一致时走 GSO，一次系统调用发一把（见 gso_linux.go）。
			buf := c.txBuf[:0]
			sizes := c.txSizes[:0]
			start := 0
			for _, end := range c.appEnds {
				if len(payload) > 0 && len(payload)+end-start > maxPacketPayload {
					off := len(buf)
					buf = c.sealPacketLocked(lvl, c.padBulk(payload), buf)
					c.notePkt(len(buf) - off)
					sizes = append(sizes, len(buf)-off)
					payload = payload[:0]
				}
				payload = append(payload, c.appOut[start:end]...)
				start = end
			}
			c.appOut = c.appOut[:0]
			c.appEnds = c.appEnds[:0]
			if len(payload) > 0 {
				off := len(buf)
				buf = c.sealPacketLocked(lvl, c.padBulk(payload), buf)
				c.notePkt(len(buf) - off)
				sizes = append(sizes, len(buf)-off)
			}
			c.txBuf, c.txSizes = buf, sizes
			if len(sizes) > 0 {
				if err := c.writePackets(); err != nil {
					return err
				}
			}
			continue
		}
		if len(payload) == 0 {
			continue
		}
		if lvl != lvlApp {
			// 握手的 CRYPTO（还有捎着的 ACK）要能被重传：丢了的话
			// 握手就永远完不成，而对面不会替我们补
			if err := c.sendTrackedLocked(lvl, payload); err != nil {
				return err
			}
			continue
		}
		if err := c.sendPacketLocked(lvl, payload); err != nil {
			return err
		}
	}
	return nil
}

// sendPacketLocked 封一个包发出去。调用方持有 c.mu。
func (c *Conn) sendPacketLocked(lvl int, payload []byte) error {
	pkt := c.sealPacketLocked(lvl, payload, nil)
	if len(pkt) == 0 {
		return nil
	}
	if _, err := c.pc.WriteTo(pkt, c.remote); err != nil {
		dbg("flush: lvl=%d 写 %d 字节失败: %v", lvl, len(pkt), err)
		return err
	}
	return nil
}

// sealPacketLocked 封一个包，**追加到 dst 后面**并返回（不发送）。
//
// 追加而不是新建，是为了让 flush 能把一批包攒在一块缓冲里一次发出去
// （见 writePackets 里的 GSO）。调用方持有 c.mu。
func (c *Conn) sealPacketLocked(lvl int, payload, dst []byte) []byte {
	k := c.send[lvl]
	if k == nil {
		dbg("flush: lvl=%d 有 %d 字节要发但没密钥", lvl, len(payload))
		return dst
	}
	pn := c.nextPN[lvl]
	c.nextPN[lvl]++
	if lvl == lvlApp {
		// 短头要带当前的 Key Phase（对端换代之后我们也得标新相位，
		// 见 updateKeys）
		return sealPacket(dst, false, 0, c.dcid, nil, nil, pn, payload, k, c.keyPhase)
	}
	typ := byte(pktInitial)
	if lvl == lvlHandshake {
		typ = pktHandshake
	}
	if lvl == lvlInitial {
		// RFC 9000 14.1：带 Initial 的数据报至少要 1200 字节（服务端
		// 也适用），不够就补 PADDING 帧。补在明文里，不是密文外
		// （见 sealPacket 那段注释）。长度字段本身可能跟着变长，
		// 所以循环到真的够为止。
		base := len(dst)
		for {
			dst = sealPacket(dst, true, typ, c.dcid, c.scid, nil, pn, payload, k, 0)
			if len(dst)-base >= 1200 {
				break
			}
			payload = append(payload, make([]byte, 1200-(len(dst)-base))...)
		}
		return dst
	}
	return sealPacket(dst, true, typ, c.dcid, c.scid, nil, pn, payload, k, 0)
}

// pktAvg 是最近发出的包的平均载荷大小（指数平滑），用来判断这条连接是
// 不是在推大响应（见 padBulk）。调用方持有 c.mu。
func (c *Conn) notePkt(sealed int) {
	// sealed 里含包头和 AEAD 标签，这里只想要"载荷"的量级，减个常数就行
	load := sealed - 27
	if load < 0 {
		load = 0
	}
	c.pktAvg = (c.pktAvg*3 + load) / 4
}

// padBulk 把"大包模式"下的小包补到整包大小（补在明文里，用 PADDING 帧）。
//
// **为什么**：GSO 要求除最后一段外每段等长，而一条 16KB 响应在包里长这样：
// [HEADERS 小帧][数据帧 ×14][尾部短帧]——中间夹着的小包（几十~两百字节）
// 会把等长段切碎，一个响应要发 2~3 次（实测 static-h3 上 98 万次单发都是
// 这种小包）。补成一样长之后整批一个 sendmsg 就走完了。
//
// **小响应不能补**：baseline-h3 的包只有 200 字节，补到 1200 会把回环带宽
// 白烧 6 倍（那档已经领先，不能为了这个退）。所以用最近包的平均大小判断
// "这条连接现在在推大东西"——大响应档会稳稳落在大包模式，小响应档不会。
func (c *Conn) padBulk(payload []byte) []byte {
	if c.pktAvg < 900 || len(payload) >= maxPacketPayload {
		return payload
	}
	// 补 PADDING 帧（0x00）：和 Initial 那个"补到 1200"是一个办法，
	// 而且必须补在**明文**里（补在密文外面 AEAD 直接验不过）
	for len(payload) < maxPacketPayload {
		payload = append(payload, 0)
	}
	return payload
}

// sendTrackedLocked 和 sendPacketLocked 一样，但发出去的载荷记一份，
// 等对端 ACK 确认；超时没确认就重发（见 outstanding 的说明）。
func (c *Conn) sendTrackedLocked(lvl int, payload []byte) error {
	pn := c.nextPN[lvl]
	if err := c.sendPacketLocked(lvl, payload); err != nil {
		return err
	}
	c.outstanding = append(c.outstanding, outstanding{
		pn:   pn,
		lvl:  lvl,
		data: append([]byte(nil), payload...),
		sent: time.Now(),
		rto:  minRTO,
	})
	return nil
}

// ackSentLocked 对端 ACK 了 largest 和之后的区间，把确认掉的控制帧丢掉。
// 调用方持有 c.mu。
func (c *Conn) ackSentLocked(largest uint64, ranges []ackRange) {
	if len(c.outstanding) == 0 {
		return
	}
	acked := func(pn uint64) bool {
		if pn > largest {
			return false
		}
		for _, r := range ranges {
			if pn <= r.hi && pn >= r.lo {
				return true
			}
		}
		return false
	}
	keep := c.outstanding[:0]
	for _, o := range c.outstanding {
		if !acked(o.pn) {
			keep = append(keep, o)
		}
	}
	c.outstanding = keep
}

// retransmitLocked 看看有没有超时没确认的控制帧，有就用**新的包序号**重发。
// flusher 的 1ms 心跳里调（调用方持有 c.mu）。
func (c *Conn) retransmitLocked() {
	if len(c.outstanding) == 0 || c.closed {
		return
	}
	now := time.Now()
	keep := c.outstanding[:0]
	for _, o := range c.outstanding {
		if now.Sub(o.sent) < o.rto {
			keep = append(keep, o)
			continue
		}
		if o.tries >= maxRTTries {
			// 试够了：多半是对端已经走了（idle timeout 收场）
			continue
		}
		dbg("重传控制帧 lvl=%d 旧pn=%d（第 %d 次）", o.lvl, o.pn, o.tries+1)
		o.tries++
		o.rto *= 2
		if o.rto > maxRTO {
			o.rto = maxRTO
		}
		o.sent = now
		o.pn = c.nextPN[o.lvl]
		if err := c.sendPacketLocked(o.lvl, o.data); err == nil {
			keep = append(keep, o)
		}
	}
	c.outstanding = keep
}

// writePackets 把 c.txBuf 里攒好的包发出去（c.txSizes 是每个包的长度）。
//
// 中间**长度一致**的连续若干个包走 GSO：一次 sendmsg 交一把，内核自己切成
// 数据报（见 gso_linux.go——static-h3 那种 16KB 响应一个包一次 sendto 的话，
// 62% 的 CPU 都花在系统调用上）。头和尾长度不一样的零头（ACK 搭在第一包上
// 会大一点、最后一包会短一点）单独发。
//
// 调用方持有 c.mu。
func (c *Conn) writePackets() error {
	buf, sizes := c.txBuf, c.txSizes
	// off 和 idx 是一起走的游标：off 是 buf 里的字节偏移，idx 是第几个包。
	// （一开始写成两个独立的循环，重发/错位——包被发成垃圾，8.8 req/s。）
	off, idx := 0, 0
	sendUntil := func(end int) error {
		for ; idx < end; idx++ {
			if _, err := c.pc.WriteTo(buf[off:off+sizes[idx]], c.remote); err != nil {
				dbg("flush: 写 %d 字节失败: %v", sizes[idx], err)
				return err
			}
			off += sizes[idx]
		}
		return nil
	}

	if gsoEnabled && c.fd >= 0 && c.remoteSA != nil {
		if i, j := longestEqualRun(sizes); j-i >= 2 {
			if err := sendUntil(i); err != nil {
				return err
			}
			seg := sizes[i]
			// **一批 GSO 的段数要有上限**：整段塞给内核的话数据量会超过
			// 发送缓冲（默认两百来 KB），sendmsg 直接 ENOBUFS，然后退回
			// 一个个发——GSO 等于白做。（踩过：static-h3 上 64 条流各
			// 16KB，攒出来一批 960 个段 ≈ 1MB，profile 里 sendto 还是占 55%。）
			for k := i; k < j; {
				n := j - k
				if n > maxGSOSegments {
					n = maxGSOSegments
				}
				if err := sendBatchGSO(c.fd, c.remoteSA, buf[off:off+n*seg], seg); err != nil {
					dbg("GSO 失败（%d 段 × %d 字节）: %v", n, seg, err)
					break
				}
				off += n * seg
				k += n
				idx = k
			}
			// GSO 失败：游标没动，往下走普通路径，别把包丢了
		}
	}
	return sendUntil(len(sizes))
}

// maxGSOSegments 是一批 GSO 最多几个段（≈ 16 × 1.2KB ≈ 20KB，安全地低于
// 默认发送缓冲）。
const maxGSOSegments = 16

// longestEqualRun 找 sizes 里最长的一段"长度都一样"的连续区间 [i, j)。
func longestEqualRun(sizes []int) (int, int) {
	bi, bj := 0, 0
	for i := 0; i < len(sizes); {
		j := i + 1
		for j < len(sizes) && sizes[j] == sizes[i] {
			j++
		}
		if j-i > bj-bi {
			bi, bj = i, j
		}
		i = j
	}
	return bi, bj
}

// closeWith 关掉这条连接。
func (c *Conn) closeWith(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked(err)
}

// closeLocked 见 closeWith。调用方持有 c.mu。
func (c *Conn) closeLocked(err error) {
	if c.closed {
		return
	}
	c.closed = true
	c.err = err
	close(c.accept)
	close(c.acceptUni)
	close(c.done) // 让 flusher 退出
	// 等在 Read 上的全都醒一下：连接没了，它们各自看 c.closed 拿错误。
	c.cond.Broadcast()
}

// CloseWithError 发一个 CONNECTION_CLOSE（应用层错误码）再关掉连接。
//
// 形状和 quic-go 的一样（http3 那层直接调），code 是应用错误码。
func (c *Conn) CloseWithError(code uint64, msg string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if c.send[lvlApp] != nil {
		var payload []byte
		payload = appendVarint(payload, frConnCloseApp)
		payload = appendVarint(payload, code)
		payload = appendVarint(payload, uint64(len(msg)))
		payload = append(payload, msg...)
		// 发不出去也没关系（对端已经走了），关闭照做
		_ = c.sendPacketLocked(lvlApp, payload)
	}
	if msg == "" {
		msg = "closed"
	}
	c.closeLocked(errors.New("quic: " + msg))
	return nil
}

// errOr 连接上有错误就用它，否则用 fallback。
func (c *Conn) errOr(fallback error) error {
	if c.err != nil {
		return c.err
	}
	return fallback
}

// OpenUniStream 开一条我们自己发起的单向流（HTTP/3 的控制流就是它）。
func (c *Conn) OpenUniStream() *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := newStream(c, c.nextUni)
	c.nextUni += 4
	return s
}

// StreamHook 是"对端开的流上有数据了"的同步钩子，见 SetStreamHook。
type StreamHook func(s *Stream)

// SetStreamHook 装一个流事件的同步钩子。
//
// 装了就**不再往 accept 队列投**：收包那条 goroutine 直接调它。这是给
// HTTP/3 准备的快路——请求几乎都是"一个数据报里一条完整的流"，就地处理
// 就地回，省掉"收包 -> lane -> flusher"两次 goroutine 切换。
//
// 实测（lab，baseline-h3，压测端每连接 64 条并发流）：走 lane 那条路时
// 每连接的处理速度是 23.5us/请求（一条一条串着，latency 全堆在调度上），
// 换成就地处理之后能到 5us 级——量出来的差距就是这个。
//
// **钩子里不能阻塞**：它跑在收包 goroutine 上，一堵整条连接的收包都停。
// 所以调用方要先看 Stream.Finished()，没收完的流交回 accept 那条路。
func (c *Conn) SetStreamHook(fn StreamHook) {
	c.mu.Lock()
	c.hook = fn
	c.mu.Unlock()
}

// AcceptUniStream 取一条对端发起的单向流（阻塞）。
func (c *Conn) AcceptUniStream() (*Stream, error) {
	s, ok := <-c.acceptUni
	if !ok {
		c.mu.Lock()
		err := c.errOr(errors.New("quic: connection closed"))
		c.mu.Unlock()
		return nil, err
	}
	return s, nil
}

// ReadLoop 收数据报，直到连接关掉。
//
// **只给不挂在 Listener 上的连接用**：Listener 收上来的连接由 Serve 就地
// 处理（收包和握手在同一个 goroutine 上串起来），再起一个 ReadLoop 就是
// 两个读者抢同一个 socket，数据报会被随机分走。
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
