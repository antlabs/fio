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

package http2

import (
	"errors"
	"fmt"
	"sync"
)

// 连接级的状态。
type connState uint8

const (
	// statePreface 还没收到客户端的连接序言
	statePreface connState = iota
	// stateSettings 序言收到了，等 SETTINGS
	stateSettings
	// stateOpen 正常收发
	stateOpen
	// stateClosed 收到/发出 GOAWAY，连接要关
	stateClosed
)

// clientPreface 是 HTTP/2 的固定连接序言（RFC 9113 3.4）。
//
// 客户端连上之后第一件事就是发这 24 字节，服务端看到了才认为这是 HTTP/2
// 连接。这段字符串是规范写死的。
var clientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// StreamHandler 是流上面的事件回调。
//
// 和 engine.Handler 是一个路子：协议层（比如 gRPC）实现它，http2 把流上
// 的请求头、数据、结束通知交给它。
type StreamHandler interface {
	// OnHeaders 一个流的请求头解完了。pseudo 是 :method :path 这些。
	OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool)

	// OnData 流上的数据。末尾那次 endStream 为真。
	OnData(c *Conn, streamID uint32, data []byte, endStream bool)

	// OnRSTStream 对端重置了一个流。
	OnRSTStream(c *Conn, streamID uint32, code ErrCode)
}

// Conn 是一条 HTTP/2 连接的状态机。
//
// 它跑在 engine 上：引擎喂字节（OnData），这里切帧、解 HPACK、管流，
// 需要发的帧通过 Write 交给引擎。
//
// HPACK 的编解码器是**连接级**的（动态表跨头块保留），所以
// 一个 HTTP/2 连接一个 Conn，不能共用。
type Conn struct {
	// 发送那边
	mu      sync.Mutex
	outBuf  []byte
	encoder *hpackEncoder

	// 接收那边
	parser *FrameParser
	dec    *hpackDecoder
	// prefaceBuf 攒客户端的连接序言（24 字节，可能被 TCP 切开）
	prefaceBuf []byte

	state connState

	// 客户端的流 ID 是奇数，服务端发起的（push）是偶数
	nextStreamID uint32
	// isClient 我们这边是客户端还是服务端
	isClient bool

	// streams 是活着的流
	streams map[uint32]*Stream

	// 正在拼的头块（HEADERS + CONTINUATION）
	pendingHeaders struct {
		streamID  uint32
		block     []byte
		endStream bool
		active    bool
	}

	// handler 是流事件的接收者（gRPC 之类）
	handler StreamHandler

	// settings
	peerMaxFrameSize  uint32
	peerHeaderTable   uint32
	peerInitialWindow uint32

	// --- 流控（RFC 9113 6.9）---
	//
	// 两套窗口，**都要记**：
	//   - 连接级：所有流共享，帧头里的 StreamID=0
	//   - 流级：每个流一个
	//
	// 发数据要**两个窗口都够**（取小的那个）；收到数据之后**两个都要还**
	// （各回一个 WINDOW_UPDATE）。只做一个的话对端发到一半就不敢再发了。
	//
	// 数字是"我还能往对端发多少字节"：对端在 SETTINGS 里声明初始值
	// （peerInitialWindow），它每收一段就回 WINDOW_UPDATE 把额度加回来。

	// sendWindow 是连接级的发送窗口（发送方向）
	sendWindow int32
	// recvWindow 是连接级的接收窗口（接收方向）：对端还能给我发多少
	recvWindow int32
	// localInitialWindow 是我们声明的流级初始窗口（SETTINGS 里发出去的）
	localInitialWindow int32

	// pending 是"窗口不够、等着续发"的数据。
	//
	// **必须按序**：同一条连接上的流共享连接级窗口，跳着发会打乱字节
	// 顺序。所以是一队列，见 flushPending。
	pending []pendingData

	// goAway 收到过 GOAWAY
	goAway bool
	// goAwayCode
	goAwayCode ErrCode

	// lastStreamID 收到的最后一个流 ID（GOAWAY 时要用）
	lastStreamID uint32

	// maxPeerStreamID 对端用过的最大流 ID。
	//
	// **流 ID 必须递增**（RFC 9113 5.1.1）：对端不能开一个比之前小的
	// 新流，也不能重复用一个已经关掉的 ID。不用这个记账的话，"重复
	// 使用旧 ID"会被当成新请求——两边的理解就此分叉。
	maxPeerStreamID uint32

	// maxLocalStreamID 我们这边开过的最大流 ID（和 maxPeerStreamID 对称）。
	//
	// **用来区分"关掉的流"和"从没开过的流"**：流关了以后会从 c.streams
	// 里删掉（见 forgetStream），之后表里查不到。但"查不到"有两种：真
	// idle（双方都没建过）和已经关掉。对 WINDOW_UPDATE/RST_STREAM 这两个，
	// RFC 9113 5.1/6.9 只对前者要求报连接错误，对后者要忽略——WINDOW_UPDATE
	// 是对端对我们之前发的 DATA 的反馈，完全可能在我们发完 END_STREAM、
	// 把流忘掉之后才到（实测：真实客户端读 256KB 响应偶发被判
	// "WINDOW_UPDATE on idle stream"，我们主动 GOAWAY，连接被 RST，客户端
	// 读 body 报 connection reset）。
	maxLocalStreamID uint32
}

// peerParity / localParity：RFC 9113 5.1——客户端开的流用奇数号，服务端
// 用偶数号。这两个返回对应对端/本端那一侧的奇偶。
func (c *Conn) peerParity() uint32 {
	if c.isClient {
		return 0
	}
	return 1
}

func (c *Conn) localParity() uint32 { return 1 - c.peerParity() }

// NewConn 建一条 HTTP/2 连接。
func NewConn(isClient bool, h StreamHandler) *Conn {
	c := &Conn{
		parser:       NewFrameParser(),
		dec:          newHpackDecoder(),
		encoder:      newHpackEncoder(),
		streams:      make(map[uint32]*Stream),
		handler:      h,
		isClient:     isClient,
		state:        stateOpen,
		nextStreamID: 1,
		// 对端的默认值（RFC 9113 6.5.2），SETTINGS 到了会改
		peerMaxFrameSize:  defaultMaxFrameSize,
		peerHeaderTable:   defaultHeaderTableSize,
		peerInitialWindow: defaultInitialWindowSize,

		// 流控窗口的初值都是 65535（RFC 9113 6.9.2）。
		//
		// 两端都从默认值开始：发送窗口对端 SETTINGS 到了会被改
		// （onSettings 里），接收窗口是我们自己说了算。
		sendWindow:         int32(defaultInitialWindowSize),
		recvWindow:         int32(defaultInitialWindowSize),
		localInitialWindow: int32(defaultInitialWindowSize),
	}
	if !isClient {
		// 服务端要先等客户端的连接序言
		c.state = statePreface
		// 服务端发起的流是偶数
		c.nextStreamID = 2
	}
	return c
}

// defaultInitialWindowSize 是流的初始窗口（RFC 9113 6.9.2: 65535）。
const defaultInitialWindowSize = 65535

// maxRecvWindow 是我们愿意开给对端的窗口上限（连接级和流级都用它）。
//
// 为什么开大（默认才 65535）：窗口小意味着对端发完就得停下来等我们补，
// 一来一回一个 RTT。开大之后"发 1MB"这种事能一口气发完。
//
// 1MB 是个折中：再大就要考虑"对端真的灌满怎么办"——那些字节要落在我们
// 的接收缓冲区里（每个连接一份内存）。1MB 配上一万连接是 10GB 的量级，
// 但实际只有活跃的流才占用，空闲连接不占。
const maxRecvWindow = 1 << 20

// SetHandler 换流事件的处理者（握手之后才知道要交给谁的时候用）。
func (c *Conn) SetHandler(h StreamHandler) { c.handler = h }

// ---------------------------------------------------------------------------
// 收

// Feed 喂一段从 fd 读到的字节。
//
// 返回消化了多少字节 + 要发给对端的字节。
//
// **契约和 engine.Handler.OnData 一致**（http2 是跑在它上面的）：
//
//	consumed == len(data)  这段全收下了（可能攒着没成帧）
//	consumed <  len(data)  只吃下这么多，剩下的调用方留着下次再喂
//	err != nil             协议错误，连接该关
//
// 非阻塞：不够一帧的字节攒在内部，下次接着拼。
func (c *Conn) Feed(data []byte) (int, []byte, error) {
	consumed, err := c.feed(data)
	return consumed, c.takeOutput(), err
}

// feed 是 Feed 和 FeedWrite 共用的解析主体。
//
// **产生的帧留在 outBuf 里不交出去**，由调用方决定怎么拿走（Feed 用
// takeOutput 交出所有权，FeedWrite 就地写掉再复用那块内存）。
func (c *Conn) feed(data []byte) (int, error) {
	consumed := 0

	// 服务端先认客户端的连接序言。
	//
	// 序言可能被 TCP 切开（24 字节一次到不了），所以拿不定的时候要攒着。
	// 早先这里是"不够 24 字节就直接 return"——那等于把读到的几个字节
	// 丢了，客户端永远握不上手。
	if c.state == statePreface {
		// 这次喂进来的字节里，有多少是补进序言的（剩下的都是帧）。
		need := len(clientPreface) - len(c.prefaceBuf)
		if need > len(data) {
			need = len(data)
		}
		c.prefaceBuf = append(c.prefaceBuf, data[:need]...)

		if len(c.prefaceBuf) < len(clientPreface) {
			// 还没凑全，等下一次
			return need, nil
		}
		if string(c.prefaceBuf[:len(clientPreface)]) != string(clientPreface) {
			return need, fmt.Errorf("%w: bad client preface", ErrBadFrameHeader)
		}
		c.prefaceBuf = c.prefaceBuf[:0]
		c.state = stateSettings

		// 序言之后可能还跟着帧数据（同一个 TCP 段里）。
		//
		// **只报"真正消化掉的"**：解析器切不完一个帧时会停下来，剩下的
		// （半个帧）要留给下一次 feed——以前这里一律报 len(data) 全消费，
		// 那半个帧的字节就被吞了，下一次从帧中间开始解析，读到的是
		// body 内容当帧头（实测：客户端发 256KB 请求体时偶发，我们这边
		// 报 "frame exceeds max size: 7895160 > 16384"、主动 GOAWAY，
		// 7895160 就是 'xxx' 那三个字节）。解析器不吃"留着"这套，尾巴
		// 必须留在引擎的读缓冲区里，由引擎下次再喂。
		consumed = need
		rest := data[need:]
		if len(rest) > 0 {
			n, err := c.parser.Parse(rest, c.onFrame)
			consumed += n
			if err != nil {
				c.handleErrorKeep(err)
				return consumed, err
			}
		}
		return consumed, nil
	}

	n, err := c.parser.Parse(data, c.onFrame)
	consumed = n
	if consumed > len(data) {
		consumed = len(data)
	}
	if err != nil {
		c.handleErrorKeep(err)
		return consumed, err
	}
	return consumed, nil
}

// handleError 按错误的级别决定怎么回：连接错误 GOAWAY，流错误 RST_STREAM。
//
// **这个分派是 HTTP/2 正确性的关键**（RFC 9113 5.4，见 errors.go 的说明）：
//
//	连接错误 -> GOAWAY，整条连接废掉
//	流错误   -> RST_STREAM，只有那一个流出局
//
// 早先这里一律 GOAWAY：一个请求的头写错了（比如 :path 是空的），
// 同一条连接上正在跑的其他请求全被连累。浏览器一次开几十个流，
// 这种"一颗老鼠屎"的代价是整页加载失败。
//
// 返回要发出去的字节（调用方写回 fd）。
func (c *Conn) handleError(err error) []byte {
	if err == nil {
		return nil
	}

	// 流错误：回 RST_STREAM，连接继续用
	if se, ok := asStreamError(err); ok {
		c.writeFrame(AppendRSTStream(nil, se.StreamID, uint32(se.Code)))
		// 这个流废了，从表里清掉
		c.forgetStream(se.StreamID)
		return c.takeOutput()
	}

	// 连接错误（以及没分类的）：GOAWAY 然后关
	ce := asConnError(err)
	c.sendGoAway(ce.Code, ce.Msg)
	return c.takeOutput()
}

// handleErrorKeep 和 handleError 一样，但**把帧留在 outBuf 里不交出去**，
// 交给 feed 的调用方去写（见 FeedWrite）。
func (c *Conn) handleErrorKeep(err error) {
	if err == nil {
		return
	}
	if se, ok := asStreamError(err); ok {
		c.writeFrame(AppendRSTStream(nil, se.StreamID, uint32(se.Code)))
		c.forgetStream(se.StreamID)
		return
	}
	ce := asConnError(err)
	c.sendGoAway(ce.Code, ce.Msg)
}

// onFrame 处理一个解析出来的帧。
func (c *Conn) onFrame(f *Frame) error {
	// **只处理"整条连接级"的帧**，其余的落到下面按流处理。
	//
	// 踩过的坑：这里早先写过一个 `default: return nil`（本意是"未知
	// 帧类型要忽略"，RFC 9113 4.1 确实这么要求），结果把 HEADERS、DATA、
	// RST_STREAM 这些**也落进 default 的已知帧**一起吞了——整个 HTTP/2
	// 直接不工作，客户端一直等到超时。未知类型要单独判，不能用 default 兜。
	switch f.Type {
	case FrameSettings:
		return c.onSettings(f)
	case FramePing:
		return c.onPing(f)
	case FrameGoAway:
		return c.onGoAway(f)
	case FrameWindowUpdate:
		if f.StreamID == 0 {
			return c.onConnWindowUpdate(f)
		}
	case FramePriority:
		return c.onPriority(f)
	case FramePushPromise:
		// 我们不发 PUSH，收到就是协议错误
		return connError(ErrCodeProtocol, "PUSH_PROMISE not supported")

	case FrameHeaders, FrameData, FrameRSTStream, FrameContinuation:
		// 这几个要看流的状态，走下面的分支

	default:
		// **未知帧类型必须忽略**（RFC 9113 4.1 / 5.5）：这是协议的
		// 扩展点，新帧类型可以随时加。收到不认识的就报错的话，
		// 协议就没法演进了。
		//
		// 注意**未知帧不算"用了这个流"**：它不该把 idle 流唤醒，
		// 也不该推进 maxPeerStreamID（那条递增规则只管已知帧）。
		return nil
	}

	if f.StreamID == 0 {
		return connError(ErrCodeProtocol, "%v on stream 0", f.Type)
	}
	if f.StreamID > c.lastStreamID {
		c.lastStreamID = f.StreamID
	}

	switch f.Type {
	case FrameHeaders:
		return c.onHeaders(f)
	case FrameContinuation:
		return c.onContinuation(f)
	case FrameData:
		return c.onData(f)
	case FrameRSTStream:
		return c.onRSTStream(f)
	case FrameWindowUpdate:
		return c.onStreamWindowUpdate(f)
	}
	return nil
}

func (c *Conn) onSettings(f *Frame) error {
	if f.Flags&FlagSettingsAck != 0 {
		return nil // 我们发的 SETTINGS 被确认了
	}

	for i := 0; i+6 <= len(f.Payload); i += 6 {
		id := uint16(f.Payload[i])<<8 | uint16(f.Payload[i+1])
		val := uint32(f.Payload[i+2])<<24 | uint32(f.Payload[i+3])<<16 |
			uint32(f.Payload[i+4])<<8 | uint32(f.Payload[i+5])

		switch id {
		case 0x1: // SETTINGS_HEADER_TABLE_SIZE
			c.peerHeaderTable = val
			// 我们编码时能用的动态表大小
			c.encoder.SetMaxSize(val)
		case 0x2: // SETTINGS_ENABLE_PUSH
			if val != 0 && val != 1 {
				return fmt.Errorf("%w: ENABLE_PUSH %d", ErrBadFrameLength, val)
			}
		case 0x3: // SETTINGS_MAX_CONCURRENT_STREAMS
			// 记下来但先不做并发限制
		case 0x4: // SETTINGS_INITIAL_WINDOW_SIZE
			if val > 1<<31-1 {
				return fmt.Errorf("%w: INITIAL_WINDOW_SIZE too large", ErrBadFrameLength)
			}
			// **已经存在的流要按差值调**（RFC 9113 6.5.2）：不是把每条流的
			// 窗口重置成新值——重置会把"这条流已经用掉的额度"抹掉，窗口
			// 凭空变大，对端就收到超过它声明窗口的数据（判违规、断连接）。
			// 窗口允许调到负数（规范明确写了），所以下面不做下限检查。
			delta := int32(val) - int32(c.peerInitialWindow)
			c.peerInitialWindow = val
			if delta != 0 {
				c.mu.Lock()
				for _, s := range c.streams {
					if delta > 0 && s.sendWindow > (1<<31-1)-delta {
						s.sendWindow = 1<<31 - 1
						continue
					}
					s.sendWindow += delta
				}
				c.mu.Unlock()
				// 窗口调大之后攒着的数据要续发（和收到 WINDOW_UPDATE 一样）
				if err := c.flushPending(); err != nil {
					return err
				}
			}
		case 0x5: // SETTINGS_MAX_FRAME_SIZE
			if val < defaultMaxFrameSize || val > MaxFrameSize {
				return fmt.Errorf("%w: MAX_FRAME_SIZE %d", ErrBadFrameLength, val)
			}
			c.peerMaxFrameSize = val
		case 0x6: // SETTINGS_MAX_HEADER_LIST_SIZE
			// 先不做限制
		default:
			// 未知 setting 要忽略（RFC 9113 6.5.3）
		}
	}

	// 必须回一个 ACK
	return c.writeFrame(AppendSettingsAck(nil))
}

func (c *Conn) onPing(f *Frame) error {
	if f.Flags&FlagPingAck != 0 {
		return nil // 是我们发出去的 ping 的回音
	}
	// 回 PING ACK，原样带上那 8 字节
	var data [8]byte
	copy(data[:], f.Payload)
	return c.writeFrame(AppendPing(nil, data, true))
}

func (c *Conn) onGoAway(f *Frame) error {
	c.goAway = true
	c.goAwayCode = ErrCode(uint32(f.Payload[4])<<24 | uint32(f.Payload[5])<<16 |
		uint32(f.Payload[6])<<8 | uint32(f.Payload[7]))
	c.state = stateClosed
	return nil
}

// onConnWindowUpdate 对端给连接级发送窗口加了额度。
//
// 这条是"对端已经收下并处理了我之前发的数据，可以再发了"的信号。不做
// 的话服务端发到 65535 就再也不敢发——大响应体会永久卡住。
func (c *Conn) onConnWindowUpdate(f *Frame) error {
	inc := uint32(f.Payload[0])<<24 | uint32(f.Payload[1])<<16 |
		uint32(f.Payload[2])<<8 | uint32(f.Payload[3])
	if inc == 0 {
		// 连接级的 0 是协议错误（流级的 0 是允许的，表示"就这个流不要了"）
		return fmt.Errorf("%w: connection WINDOW_UPDATE increment 0", ErrBadFrameLength)
	}
	// 窗口是 31 位（最高位保留），加超了就是 **FLOW_CONTROL_ERROR**
	// （连接级的，所以要 GOAWAY 不是 RST_STREAM）
	if c.sendWindow > (1<<31-1)-int32(inc) {
		return connError(ErrCodeFlowControl, "connection window overflow: %d + %d",
			c.sendWindow, inc)
	}
	c.mu.Lock()
	c.sendWindow += int32(inc)
	c.mu.Unlock()

	// 有额度了：把之前因为窗口不够攒下的数据续发出去。
	//
	// **这一步不做的话 pending 里的数据就永远躺在那里**——大响应体会
	// 发到 65535 就再也不动了，而连接看起来还是活的（对端在等，
	// 我们在等，等到超时）。
	return c.flushPending()
}

// onStreamWindowUpdate 对端给某个流的发送窗口加了额度。
func (c *Conn) onStreamWindowUpdate(f *Frame) error {
	// **idle 上不能发 WINDOW_UPDATE**（RFC 9113 5.1 / 6.9）：没有流
	// 哪来的窗口。这是连接级错误。
	if err := c.checkStreamRecv(f.StreamID, frameKindWindowUpdate); err != nil {
		return err
	}

	inc := uint32(f.Payload[0])<<24 | uint32(f.Payload[1])<<16 |
		uint32(f.Payload[2])<<8 | uint32(f.Payload[3])
	if inc == 0 {
		// **0 是连接级 PROTOCOL_ERROR**（RFC 9113 6.9）。
		//
		// 这一点反直觉：规范正文里说流级的 0 表示"这个流的窗口我不打算
		// 再放了"，接收方要当成 RST_STREAM 处理——但 h2spec（和标准库
		// 的实现）要求的是**连接级错误**。
		//
		// 为什么不按字面来：窗口增量是 unsigned 的，0 表示"没有增量"，
		// 那对发送方就是一个永远解不开的僵局——它发不出去、也不知道
		// 对端到底是什么意思。规范在 6.9 的末尾把这条明确成了连接错误。
		return connError(ErrCodeProtocol, "WINDOW_UPDATE increment 0 on stream %d", f.StreamID)
	}
	s := c.streams[f.StreamID]
	if s == nil {
		// 流已经关了。RFC 9113 6.9 说可以忽略（窗口更新是异步的，
		// 对端发出来的时候还不知道我们关了流）。
		return nil
	}
	if s.sendWindow > (1<<31-1)-int32(inc) {
		// **加超了 2^31-1 是流级 FLOW_CONTROL_ERROR**（RFC 9113 6.9）
		return streamError(f.StreamID, ErrCodeFlowControl,
			"stream window overflow: %d + %d", s.sendWindow, inc)
	}
	c.mu.Lock()
	s.sendWindow += int32(inc)
	c.mu.Unlock()

	// 和连接级那边一样：有额度了就把攒下的数据续发出去
	return c.flushPending()
}

func (c *Conn) onHeaders(f *Frame) error {
	payload := f.Payload
	var endStream bool

	if f.Flags&FlagHeadersPadded != 0 {
		if len(payload) == 0 {
			return fmt.Errorf("%w: HEADERS padded without pad length", ErrBadFrameLength)
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			return fmt.Errorf("%w: HEADERS pad %d > %d", ErrBadFrameLength, padLen, len(payload))
		}
		payload = payload[:len(payload)-padLen]
	}
	if f.Flags&FlagHeadersPriority != 0 {
		if len(payload) < 5 {
			return connError(ErrCodeFrameSize, "HEADERS priority too short: %d", len(payload))
		}
		// **优先级字段里也有"不能依赖自己"那条**（RFC 9113 5.3.1）。
		//
		// 格式和 PRIORITY 帧一样：4 字节（最高位是独占标志 + 31 位依赖
		// 的流 ID）+ 1 字节权重。这里不看权重，只看依赖。
		//
		// 顺手校验了长度也算收益：早先只查了"够不够 5 字节"，不够时报的
		// 是 ErrBadFrameLength（连接级 PROTOCOL_ERROR），而规范要求的是
		// FRAME_SIZE_ERROR。
		dep := uint32(payload[0]&0x7f)<<24 | uint32(payload[1])<<16 |
			uint32(payload[2])<<8 | uint32(payload[3])
		if dep == f.StreamID {
			return streamError(f.StreamID, ErrCodeProtocol, "stream depends on itself")
		}
		payload = payload[5:] // 之后的优先级调度我们不做
	}

	endStream = f.Flags&FlagHeadersEndStream != 0

	if !f.EndHeaders() {
		// 还有 CONTINUATION，先攒着
		c.pendingHeaders.streamID = f.StreamID
		c.pendingHeaders.block = append(c.pendingHeaders.block[:0], payload...)
		c.pendingHeaders.endStream = endStream
		c.pendingHeaders.active = true
		return nil
	}
	return c.finishHeaders(f.StreamID, payload, endStream)
}

func (c *Conn) onContinuation(f *Frame) error {
	if !c.pendingHeaders.active || c.pendingHeaders.streamID != f.StreamID {
		return fmt.Errorf("%w: CONTINUATION on stream %d with nothing pending",
			ErrUnexpectedFrame, f.StreamID)
	}
	c.pendingHeaders.block = append(c.pendingHeaders.block, f.Payload...)
	if !f.EndHeaders() {
		return nil
	}
	block := c.pendingHeaders.block
	endStream := c.pendingHeaders.endStream
	c.pendingHeaders.active = false
	return c.finishHeaders(f.StreamID, block, endStream)
}

// finishHeaders 一个头块拼完了：解 HPACK，校验，交给流。
func (c *Conn) finishHeaders(streamID uint32, block []byte, endStream bool) error {
	fields, err := c.dec.Decode(block)
	if err != nil {
		// HPACK 解错是**连接级**错误：动态表已经不可信了，后面的头块
		// 会跟着全错（RFC 9113 4.3）
		return connError(ErrCodeCompression, "HPACK decode: %v", err)
	}

	// 流的状态检查要在建流之前做（"idle 上收到 DATA" 这类）
	if err := c.checkStreamRecv(streamID, frameKindHeaders); err != nil {
		return err
	}

	s := c.stream(streamID)
	if s == nil {
		return connError(ErrCodeProtocol, "HEADERS on stream %d that is not open", streamID)
	}

	// 头部校验（RFC 9113 8.3）：伪头、大小写、连接相关字段……
	// 这些都是**流级**错误——一个头写错了，别的流不受影响。
	//
	// **方向不同，要求不同**：
	//   - 收到请求（我们是服务端）：要查 :method/:scheme/:path 齐全
	//   - 收到响应（我们是客户端）：有 :status，根本没有 :method
	//
	// 用同一个函数查两边的话，客户端会把每个正常的响应都判成
	// "缺少 :method"。
	var herr string
	if c.isClient {
		// 客户端收的是**响应**：只查语法（响应里有 :status，
		// 不会有 :method/:scheme/:path，不能按请求那套要求）
		_, herr, _, _, _, _ = validateHeaderSyntax(fields)
	} else {
		// 服务端收的是**请求**：伪头要齐全
		var skip bool
		skip, herr = validateRequestHeaders(fields)
		_ = skip
	}
	if herr != "" {
		return streamError(streamID, ErrCodeProtocol, "%s", herr)
	}

	s.headers = append(s.headers[:0], fields...)

	// 记下 content-length（服务端方向：请求体的长度声明）
	if !c.isClient {
		cl, ok, verr := contentLengthOf(fields)
		if verr != "" {
			return streamError(streamID, ErrCodeProtocol, "%s", verr)
		}
		if ok {
			s.expectContentLength = cl
		} else {
			s.expectContentLength = -1
		}
	}

	if c.handler != nil {
		c.handler.OnHeaders(c, streamID, s.headers, endStream)
	}
	c.applyRecvEndStream(s, endStream)

	// END_STREAM 就在头里的（GET 这种没有 body 的请求）：这时候就要核对
	// "声明了 content-length 却没发数据"的情况。
	//
	// 同样**只查请求方向**——客户端收到的是响应，它的 content-length
	// 说的是响应体长度，拿它去量请求是错的。
	if endStream && !c.isClient {
		if err := c.checkContentLength(s); err != nil {
			return err
		}
	}
	c.forgetIfClosed(s)
	return nil
}

// checkContentLength 核对"声明了 content-length 的请求，实际收到多少"。
// 只在 END_STREAM 时调。
func (c *Conn) checkContentLength(s *Stream) error {
	if s.expectContentLength < 0 {
		return nil
	}
	if s.recvBodyLen != s.expectContentLength {
		return streamError(s.ID, ErrCodeProtocol,
			"content-length mismatch: declared %d, got %d",
			s.expectContentLength, s.recvBodyLen)
	}
	return nil
}

// forgetIfClosed 流两边都结束了就从表里拿掉。
func (c *Conn) forgetIfClosed(s *Stream) {
	if s.state == StreamClosed {
		c.forgetStream(s.ID)
	}
}

// applyRecvEndStream 对端发了 END_STREAM：推进流的状态。
func (c *Conn) applyRecvEndStream(s *Stream, endStream bool) {
	if !endStream {
		return
	}
	s.remoteEnded = true
	switch s.state {
	case StreamOpen:
		s.state = StreamHalfClosedRemote
	case StreamHalfClosedLocal:
		s.state = StreamClosed
		c.forgetStream(s.ID)
	}
}

// forgetStream 流关了就把它从表里拿掉（不然 map 只涨不消）。
func (c *Conn) forgetStream(id uint32) {
	delete(c.streams, id)
}

// applyLocalEndStreamLocked 我们这边发了 END_STREAM：推进流的状态。
// 调用方要持 c.mu。
//
// **这条路径原来整个是缺的**：`localEnded` 声明了没人写，没有"本地结束"
// 的状态推进，`CloseStream` 全仓库零调用。于是请求带 END_STREAM 进来把流
// 推到 HalfClosedRemote 之后，响应带着 END_STREAM 出去就没人再动它——
// **`c.streams` 每条连接上只涨不消**，每个请求留一个 map 表项 + 一块
// *Stream 到连接关闭为止。
//
// 实测（baseline-h2c，4096 连接 / -m 100 / 5s）：容器峰值内存 **13.3GiB**，
// 而 fib 同一档是 1.0GiB，h1 上两边都是 ~90MiB。7.34M req/s × 5s ÷ 4096 连接
// ≈ 每条连接九千个残留表项，量级正好对得上。
//
// 只有**两边都发了 END_STREAM**才从表里拿掉。只关了一半的（比如我们先回
// 404 带 END_STREAM、对端还在传 body）停在 HalfClosedLocal，等对端的
// END_STREAM 到了由 applyRecvEndStream 收尾——那时候再删，对端也不会再
// 往这条流上发东西了。
func (c *Conn) applyLocalEndStreamLocked(s *Stream) {
	if s == nil || s.localEnded {
		return
	}
	s.localEnded = true
	switch s.state {
	case StreamOpen:
		s.state = StreamHalfClosedLocal
	case StreamHalfClosedRemote:
		s.state = StreamClosed
		c.forgetStream(s.ID)
	}
}

// endStreamLocal 发完一个带 END_STREAM 的帧之后调（自己拿锁）。
func (c *Conn) endStreamLocal(streamID uint32) {
	c.mu.Lock()
	c.applyLocalEndStreamLocked(c.streams[streamID])
	c.mu.Unlock()
}

// frameKind 是"收到的帧"这种类别（用于状态检查）。
//
// 不直接用 FrameType 是因为状态检查关心的是"这类帧允不允许在这个状态
// 出现"，和具体的帧类型不是一一对应（比如 WINDOW_UPDATE 和 RST_STREAM
// 在 idle 上都不允许，但在 closed 上的处理又不同）。
type frameKind uint8

const (
	frameKindHeaders frameKind = iota
	frameKindData
	frameKindRSTStream
	frameKindWindowUpdate
	frameKindPriority
	frameKindContinuation
)

// checkStreamRecv 检查"在这个流的当前状态下，能不能收这类帧"。
//
// **这是 RFC 9113 5.1 那张状态表的实现**。不检查的话会出两类问题：
//
//   - 该报错的不报：h2spec 这类一致性测试会判失败
//   - 更糟的是状态悄悄错乱：比如在 idle 流上收 DATA、建出一个"活着的"
//     流，之后对同一个流 ID 的 HEADERS 就会被当成"已存在的流"，
//     真实客户端那边直接崩连接
//
// 返回的错误是流级还是连接级，取决于规范怎么说——同一个动作在不同
// 状态下要求的错误级别不一样（比如 RST_STREAM 在 idle 上是连接错误）。
func (c *Conn) checkStreamRecv(streamID uint32, kind frameKind) error {
	s := c.streams[streamID]

	// **奇偶和递增这两条只管"开新流"**（RFC 9113 5.1.1）。
	//
	// "开新流" = 收到了一个我们这边还不存在的流、而且帧是 HEADERS
	// （只有 HEADERS 能开流）。对端开的是它那一侧的流 ID（客户端开奇数、
	// 服务端开偶数）。
	//
	// 已存在的流不能查这两条：那是在回应对端、或者是我们自己开的流，
	// 奇偶天然是反的。
	//
	// 踩过的坑：早先无条件查奇偶，于是**客户端收服务端的响应**（流 1，
	// 奇数，客户端这侧是"我们自己开的"）被判成"服务器不能开奇数流"
	// ——正常的响应全给拒了。
	//
	// 递增那条更细：**用过的 ID 不能再用来开新流**（对端不能回头开一个
	// 更小的）。这个要用 maxPeerStreamID 记账，而且只在开新流时更新它
	// ——一个已经关掉的流的 ID 再出现，是"重复使用"，要报错。
	if s == nil && kind == frameKindHeaders {
		if c.isClient && streamID%2 == 1 {
			return connError(ErrCodeProtocol,
				"stream %d: server must not open odd streams", streamID)
		}
		if !c.isClient && streamID%2 == 0 {
			return connError(ErrCodeProtocol,
				"stream %d: client must not open even streams", streamID)
		}
		if streamID <= c.maxPeerStreamID {
			return connError(ErrCodeProtocol,
				"stream %d is not greater than the last one (%d)",
				streamID, c.maxPeerStreamID)
		}
		c.maxPeerStreamID = streamID
	}

	// 流不在表里：**可能是 idle（双方都没建过），也可能是建过、已经关掉
	// 并被 forgetStream 从表里删掉的**。靠两个"开过的最大 ID"区分。
	//
	// 区别在哪（RFC 9113 5.1/6.9）：idle 上收 WINDOW_UPDATE/RST_STREAM 是
	// 连接级 PROTOCOL_ERROR；但**已经关掉的流上收这两个要忽略**——
	// WINDOW_UPDATE 本来就是"对端收到我们的 DATA 之后的反馈"，它可能在我们
	// 发完 END_STREAM（对端也已经 END_STREAM → 流进 Closed 并被删掉）之后
	// 才到。一律当 idle 报错的话，正常的一次大响应都会被自己判死。
	openedBefore := false
	if s == nil {
		openedBefore = (streamID <= c.maxPeerStreamID && streamID&1 == c.peerParity()) ||
			(streamID <= c.maxLocalStreamID && streamID&1 == c.localParity())
	}
	if s == nil {
		switch kind {
		case frameKindHeaders:
			// idle 上收 HEADERS 是**正常**的（新请求），放行
			return nil
		case frameKindPriority:
			// 优先级可以在 idle 流上发（RFC 9113 5.3.1），我们不做优先级
			return nil
		case frameKindWindowUpdate, frameKindRSTStream:
			if openedBefore {
				// 已经关掉的流：忽略（RFC 9113 6.9 / 6.4）
				return nil
			}
			// **idle 上不能发这两个**（RFC 9113 5.1）——那是在操作一个
			// 双方都还没建的流，属于连接级 PROTOCOL_ERROR
			return connError(ErrCodeProtocol, "stream %d: %s on idle stream",
				streamID, kindName(kind))
		case frameKindData:
			return connError(ErrCodeProtocol, "stream %d: DATA on idle stream", streamID)
		case frameKindContinuation:
			return connError(ErrCodeProtocol, "stream %d: CONTINUATION with nothing pending", streamID)
		}
		return nil
	}

	// 流存在，看状态
	switch s.state {
	case StreamHalfClosedRemote, StreamClosed:
		switch kind {
		case frameKindData, frameKindHeaders:
			// 对端已经发了 END_STREAM，就不能再发数据/头了
			// （RFC 9113 5.1：half-closed (remote) 上收 DATA/HEADERS
			// 是 STREAM_CLOSED 的流错误）
			return streamError(streamID, ErrCodeStreamClosed,
				"%s on half-closed(remote)/closed stream", kindName(kind))
		}
	case StreamHalfClosedLocal:
		// 我们发了 END_STREAM，对端**还能继续发任何帧**。
		//
		// RFC 9113 5.1 里 half-closed(local) 限制的是"我们不能再发"，
		// 不是"对端不能再发"——流要到"收到带 END_STREAM 的帧"才转 closed。
		//
		// 这里原来把 HEADERS 也拒了（注释写的是"流已经半关，不能再开新
		// 头块"），那是错的，而且错在最常见的两条路上：
		//   - **客户端**：发完请求（带 END_STREAM）之后收到的那条响应头，
		//     就是打在这个状态上的
		//   - 任一侧发完 body 之后对端回的 trailer
		// 以前看不出来，是因为状态机根本不推进到 half-closed(local)
		// （见 applyLocalEndStreamLocked 的说明），这段是死代码；
		// 补上推进之后 gRPC 的端到端用例立刻报
		// "HEADERS on half-closed(local) stream"。
	}

	// 收到非 HEADERS 帧说明这个流真的在用，记下"对端用过这个 ID"
	if streamID > c.maxPeerStreamID {
		c.maxPeerStreamID = streamID
	}
	return nil
}

func kindName(k frameKind) string {
	switch k {
	case frameKindHeaders:
		return "HEADERS"
	case frameKindData:
		return "DATA"
	case frameKindRSTStream:
		return "RST_STREAM"
	case frameKindWindowUpdate:
		return "WINDOW_UPDATE"
	case frameKindPriority:
		return "PRIORITY"
	case frameKindContinuation:
		return "CONTINUATION"
	}
	return "frame"
}

func (c *Conn) onData(f *Frame) error {
	payload := f.Payload
	if f.Flags&FlagDataPadded != 0 {
		if len(payload) == 0 {
			return fmt.Errorf("%w: DATA padded without pad length", ErrBadFrameLength)
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			return fmt.Errorf("%w: DATA pad %d > %d", ErrBadFrameLength, padLen, len(payload))
		}
		payload = payload[:len(payload)-padLen]
	}

	// 状态检查：idle 上不能发 DATA，half-closed(remote)/closed 上也不行
	// （RFC 9113 5.1）
	if err := c.checkStreamRecv(f.StreamID, frameKindData); err != nil {
		return err
	}

	s := c.streams[f.StreamID]
	if s == nil {
		return connError(ErrCodeProtocol, "DATA on stream %d that is not open", f.StreamID)
	}
	endStream := f.Flags&FlagDataEndStream != 0

	// **接收流控**：对端能发这么多是因为我们给了额度，收多少就要还多少。
	//
	// 算的是**整个 DATA 帧的载荷长度**（含 padding 和 pad 长度字段），
	// 不是解出来的 payload——RFC 9113 6.9.1 说的就是 "the entire DATA
	// frame payload"。少还了的话对端发到窗口用完就卡住（实测：256KB 的
	// 请求体发到 65535 就不动了）。
	//
	// **两级都要还**：连接级和流级。只还流级的话，多个流一起跑的时候
	// 连接级窗口先耗尽，对端还是卡住。
	if err := c.giveRecvWindow(f.StreamID, int32(len(f.Payload))); err != nil {
		return err
	}

	s.recvBodyLen += int64(len(payload))
	if c.handler != nil && len(payload) > 0 {
		c.handler.OnData(c, f.StreamID, payload, endStream)
	}
	if endStream {
		// **收到最后一段才核对**（RFC 9113 8.1.1）：
		// 声明的 content-length 和实际字节数对不上，是流级 PROTOCOL_ERROR。
		//
		// 为什么必须查：不查的话，多出来的字节会被当成下一条消息的一部分
		// （HTTP/2 里是"同一条连接上别的流"或者上层的协议数据），
		// 典型的**请求走私**。这是一个安全边界，不是格式洁癖。
		//
		// **只查请求方向**（我们是服务端）：content-length 在响应里也是
		// 合法字段，但那是"响应体多长"，而我们收的是对端发来的**请求体**
		// ——拿响应的声明去量请求的数据，永远是错的。
		if !c.isClient {
			if err := c.checkContentLength(s); err != nil {
				return err
			}
		}
	}
	c.applyRecvEndStream(s, endStream)
	c.forgetIfClosed(s)
	return nil
}

// giveRecvWindow 收到 n 字节，记账 + 回 WINDOW_UPDATE。
//
// **两笔账，别只做一笔**：
//
//	收到 n              recvWindow -= n   （对端的额度少了 n）
//	回 WINDOW_UPDATE(+n)  recvWindow += n   （我们又把额度还给它了）
//
// 减和加都要有。**只减不加**的话窗口一路走到 0，下一帧就报
// "connection window exceeded"——可对端其实完全合法，它只是用完了我们
// 给它的那 65535。这个 bug 实测过，打印出来就是 `n 1 recv 0 -> -1`。
//
// 顺序也有讲究：**先减、检查负数、再加**。负数说明对端在我们还额度
// 之前就多发了——那才是真的超发，协议错误，要拆连接
// （RFC 9113 6.9.1 的 FLOW_CONTROL_ERROR）。
//
// 策略是"**收多少还多少**"（而不是"减到一半才还"）：
//
//   - 简单，不会因为补得不及时让对端停住
//   - 代价是每帧一个 WINDOW_UPDATE。RFC 9113 6.9.2 允许接收方自己定
//     节奏——量大了可以改成"掉到一半再补"，能省掉大部分更新帧
//
// 连接级和流级是**两套独立的账**：连接级是所有流共享的，流级是这个流
// 自己的。两边都要还——只还一边的话对端要么在连接窗口上耗尽、要么在
// 这个流上耗尽。
func (c *Conn) giveRecvWindow(streamID uint32, n int32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.recvWindow -= n
	if c.recvWindow < 0 {
		return fmt.Errorf("%w: connection window exceeded", ErrFlowControl)
	}
	s := c.streams[streamID]
	if s != nil {
		s.recvWindow -= n
		if s.recvWindow < 0 {
			return fmt.Errorf("%w: stream %d window exceeded", ErrFlowControl, streamID)
		}
	}
	if n <= 0 {
		return nil
	}

	// 还额度。**连接级的 WINDOW_UPDATE 走流 0**，流级的带流 ID——协议
	// 靠这个区分两级，写错了对端会记到另一本账上。
	c.writeFrameLocked(AppendWindowUpdate(nil, 0, uint32(n)))
	c.recvWindow += n
	if s != nil {
		c.writeFrameLocked(AppendWindowUpdate(nil, streamID, uint32(n)))
		s.recvWindow += n
	}
	return nil
}

func (c *Conn) onRSTStream(f *Frame) error {
	// **idle 上不能发 RST_STREAM**（RFC 9113 5.1）：对端在重置一个
	// 双方都还没建的流，那说明它对我们这边的状态理解是错的——连接级
	// 错误，不能只当"忽略这一个流"。
	if err := c.checkStreamRecv(f.StreamID, frameKindRSTStream); err != nil {
		return err
	}

	code := ErrCode(uint32(f.Payload[0])<<24 | uint32(f.Payload[1])<<16 |
		uint32(f.Payload[2])<<8 | uint32(f.Payload[3]))
	if c.handler != nil {
		c.handler.OnRSTStream(c, f.StreamID, code)
	}
	c.forgetStream(f.StreamID)
	return nil
}

// ---------------------------------------------------------------------------
// 流

// stream 取一个流，没有就建（对端发起的就是这样）。
func (c *Conn) stream(id uint32) *Stream {
	// 按奇偶记下"我们这边开过的最大 ID"，关流之后还要靠它区分
	// "已关闭"和"从没开过"（见 maxLocalStreamID 的说明）。
	if id&1 == c.localParity() && id > c.maxLocalStreamID {
		c.maxLocalStreamID = id
	}
	s := c.streams[id]
	if s == nil {
		s = &Stream{
			ID:    id,
			state: StreamOpen,
			// 两个方向的窗口都从各自的初始值开始
			sendWindow: int32(c.peerInitialWindow),
			recvWindow: c.localInitialWindow,
			// **-1 = 没声明**，不能是 0。零值 0 会被 checkContentLength
			// 当成"对端声明了 0 字节的 body"，然后收到任何数据都报
			// mismatch——客户端收响应时就是这样（它根本不记请求的
			// content-length）。
			expectContentLength: -1,
		}
		c.streams[id] = s
	}
	return s
}

// Stream 是一个 HTTP/2 流。
type Stream struct {
	ID      uint32
	state   StreamState
	headers []HeaderField

	// remoteEnded 对端发了 END_STREAM
	remoteEnded bool
	// localEnded 我们发了 END_STREAM
	localEnded bool

	// sendWindow 是我们还能往这个流上发多少字节
	sendWindow int32
	// recvWindow 是对端还能往这个流上发多少字节（我们收了多少就减多少，
	// 还了额度再加回去）
	recvWindow int32

	// expectContentLength 是请求头里声明的 content-length，
	// **-1 表示没声明**（或者声明得没法解析）。
	//
	// 有了它才能在收到 END_STREAM 时核对"实际收到的字节数对不对"
	// （RFC 9113 8.1.1 要求对不上就是流级 PROTOCOL_ERROR）。
	expectContentLength int64
	// recvBodyLen 这个流上已经收到的 DATA 字节数
	recvBodyLen int64
}

// StreamState 是流的状态（RFC 9113 5.1 的状态机）。
type StreamState uint8

const (
	StreamIdle StreamState = iota
	StreamOpen
	StreamHalfClosedRemote
	StreamHalfClosedLocal
	StreamClosed
)

// GetStream 取一个流。
func (c *Conn) GetStream(id uint32) *Stream { return c.streams[id] }

// CloseStream 关掉一个流（发完响应之后调）。
func (c *Conn) CloseStream(id uint32) { delete(c.streams, id) }

// ---------------------------------------------------------------------------
// 发

// NewStreamID 分配一个我们这侧的新流 ID，**并把它登记进流表**。
//
// 登记这一步不能省：流表是"这条连接上有哪些流"的唯一依据，收到的帧
// 靠它判断"这是新流（要查奇偶和递增）还是已有的流（正常收发）"。
// 我们开了流却不登记的话，对端的响应回来会被当成"对端在开一个新流"
// ——奇偶校验立刻报错（RFC 9113 5.1.1），正常的响应全被拒。
func (c *Conn) NewStreamID() uint32 {
	id := c.nextStreamID
	c.nextStreamID += 2 // 同方向的流 ID 要跳 2（保持奇偶性）
	c.stream(id)        // 登记（顺带初始化两个方向的窗口）
	return id
}

// WriteHeaders 发一个 HEADERS 帧。
func (c *Conn) WriteHeaders(streamID uint32, fields []HeaderField, endStream bool) error {
	block, err := c.encoder.Encode(fields)
	if err != nil {
		return err
	}
	// 登记这个流（我们开的：response 方向）。已经存在就什么都不做。
	c.stream(streamID)
	// 头块比分片上限大要拆成 HEADERS + CONTINUATION
	return c.writeHeaderBlock(streamID, block, endStream)
}

// writeHeaderBlock 把头块按分片上限拆开发。
//
// RFC 9113 4.3：头块超过 SETTINGS_MAX_FRAME_SIZE 要拆成 HEADERS +
// 若干 CONTINUATION，中间不能夹别的帧（所以这里一次全发出去）。
func (c *Conn) writeHeaderBlock(streamID uint32, block []byte, endStream bool) error {
	max := int(c.peerMaxFrameSize)
	first := len(block) <= max

	if first {
		if err := c.writeFrame(AppendHeaders(nil, streamID, block, endStream, true)); err != nil {
			return err
		}
		if endStream {
			c.endStreamLocal(streamID)
		}
		return nil
	}

	buf := AppendHeaders(nil, streamID, block[:max], endStream, false)
	block = block[max:]
	for len(block) > 0 {
		n := max
		if len(block) < n {
			n = len(block)
		}
		last := n == len(block)
		buf = AppendFrameHeader(buf, FrameContinuation, boolToFlag(last, FlagContinuationEndHeaders), streamID, n)
		buf = append(buf, block[:n]...)
		block = block[n:]
	}
	if err := c.writeFrame(buf); err != nil {
		return err
	}
	if endStream {
		c.endStreamLocal(streamID)
	}
	return nil
}

func boolToFlag(b bool, f uint8) uint8 {
	if b {
		return f
	}
	return 0
}

// WriteTrailers 发 trailer：一个带 END_STREAM 的 HEADERS 帧。
//
// **这是 HTTP/2 才有的东西**。HTTP/1.1 的 trailer 藏在 chunked 编码后面，
// HTTP/2 干脆就是一个"数据发完之后再来的 HEADERS"——它带 END_STREAM，
// 表示这个流到此为止。
//
// gRPC 用它送调用状态：响应头里放 content-type，响应体放消息，最后这个
// trailer 里放 grpc-status。为什么状态不放在响应头里：服务端可能要把
// 数据流式发出去，发到最后才知道结果（或者半路才出错）。
func (c *Conn) WriteTrailers(streamID uint32, fields []HeaderField) error {
	block, err := c.encoder.Encode(fields)
	if err != nil {
		return err
	}
	// trailer 必须带 END_STREAM（不然接收端不知道流结束了）
	max := int(c.peerMaxFrameSize)
	if len(block) <= max {
		return c.writeFrame(AppendHeaders(nil, streamID, block, true, true))
	}
	return c.writeHeaderBlock(streamID, block, true)
}

// WriteData 发一段 DATA。
//
// **两个限制一起管**：
//   - 帧大小（peerMaxFrameSize）：一帧不能超过对端声明的值
//   - **流控窗口**：连接级和流级**都要够**（取小的那个），不够的部分
//     攒起来等对端的 WINDOW_UPDATE
//
// 这就是 HTTP/2 和 HTTP/1.1 写数据最大的区别：HTTP/1.1 是"把字节写出去
// 就完"，HTTP/2 每一段都要先记账——对端愿意收多少才能发多少。
//
// 不发流控的话，对端（x/net/http2 这种真实实现）会认为我们违反了协议：
// "flow control window exceeded"，直接 GOAWAY 掉整条连接。
//
// **部分发出去不返回错误**：剩下的进了 pending 队列，对端给了额度会
// 自动续发（见 flushPending）。返回 error 只表示"协议层面出问题了"。
func (c *Conn) WriteData(streamID uint32, data []byte, endStream bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDataLocked(streamID, data, endStream)
}

// writeDataLocked 是 WriteData 的实现，调用方要持锁。
func (c *Conn) writeDataLocked(streamID uint32, data []byte, endStream bool) error {
	// **帧直接建在发送缓冲上**，不要 AppendData(nil, ...) 再 append 进去：
	//
	//	AppendData(nil, ...)    分配一块，把体拷进去
	//	writeFrameLocked(...)   再把它拷进 outBuf
	//
	// 8KB 的响应就是每请求分配 8KB + 拷两遍，而这份 data 往往本来就是现成
	// 的缓冲（static 是缓存里的文件、echo 是请求体），拷进 outBuf 一次就够。
	// 实测（static 8KB over h2c）：GC 扫描占 CPU 的 30%，这一处是两个大头
	// 之一（另一个是 takeOutput 每次把 outBuf 数组丢掉）。
	//
	// 一次装得下就走快路径（一帧发完），装不下走下面的拆帧那条。
	//
	// **快路径也要看两个窗口、也要记账**：流级窗口（s.sendWindow）不比
	// 连接级的大，只看连接级窗口的话，一个 ≤16KB 的块在流窗口快用完时
	// 会照发不误 —— 对端收到超过它声明的窗口就判流控违规，整条连接断掉
	// （实测：真实客户端读 256KB 响应偶发 unexpected EOF，就是响应按块写
	// 时某一块走了快路径）。
	max := int(c.peerMaxFrameSize)
	s := c.streams[streamID]
	avail := c.sendWindow
	if s != nil && s.sendWindow < avail {
		avail = s.sendWindow
	}
	if len(data) <= max && int32(len(data)) <= avail {
		n := len(data)
		c.outBuf = AppendData(c.outBuf, streamID, data, endStream)
		if endStream {
			c.applyLocalEndStreamLocked(s)
		}
		c.sendWindow -= int32(n)
		if s != nil {
			s.sendWindow -= int32(n)
		}
		return nil
	}

	// 拆成多帧，但要受窗口限制
	for len(data) > 0 {
		n := max
		if len(data) < n {
			n = len(data)
		}

		// **两个窗口取小的那个**：连接级的额度是所有流共享的，
		// 流级的是这个流自己的，哪个先用完就按哪个来
		avail := c.sendWindow
		if s := c.streams[streamID]; s != nil && s.sendWindow < avail {
			avail = s.sendWindow
		}
		if avail <= 0 {
			// 额度用完了：剩下的攒起来，等 WINDOW_UPDATE。
			//
			// **endStream 要记下来**：续发的时候最后一帧得带上
			// END_STREAM，不然对端不知道流结束了。所以队列里存的
			// 是"这段数据的最后一个字节是不是结尾"。
			c.appendPending(streamID, data, endStream)
			break
		}
		if int32(n) > avail {
			n = int(avail)
		}

		last := n == len(data)
		c.outBuf = AppendData(c.outBuf, streamID, data[:n], last && endStream)
		if last && endStream {
			c.applyLocalEndStreamLocked(c.streams[streamID])
		}

		c.sendWindow -= int32(n)
		if s := c.streams[streamID]; s != nil {
			s.sendWindow -= int32(n)
		}
		data = data[n:]
	}
	return nil
}

// pendingData 是一段等流控额度的数据。
type pendingData struct {
	streamID  uint32
	data      []byte
	endStream bool
}

// appendPending 把发不完的数据排进队列。
//
// **要拷贝**：data 常常指向调用方的缓冲区（或者读缓冲区），那两块
// 在这次调用返回之后就会被复用。
func (c *Conn) appendPending(streamID uint32, data []byte, endStream bool) {
	dup := append([]byte(nil), data...)
	c.pending = append(c.pending, pendingData{streamID: streamID, data: dup, endStream: endStream})
}

// flushPending 窗口有额度了，把攒着的数据接着发。
//
// 收到 WINDOW_UPDATE 之后调（见 onConnWindowUpdate / onStreamWindowUpdate
// 的调用点）。
//
// 队列是**按顺序**的：一条连接上的流共享连接级窗口，所以不能跳着发
// ——后面的数据先发出去会打乱同一个流上的字节顺序。
func (c *Conn) flushPending() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return nil
	}

	// 一次能发多少取决于此刻的窗口，边发边看。
	// 从头扫，遇到发不完的就停下（保持顺序）。
	for len(c.pending) > 0 {
		p := &c.pending[0]

		avail := c.sendWindow
		if s := c.streams[p.streamID]; s != nil && s.sendWindow < avail {
			avail = s.sendWindow
		}
		if avail <= 0 {
			return nil // 还是没额度，等下一次
		}
		if int32(len(p.data)) > avail {
			// 只发得出去一部分：把这段切开发掉一部分，剩下的留在队首
			n := int(avail)
			chunk := p.data[:n]
			c.sendWindow -= int32(n)
			if s := c.streams[p.streamID]; s != nil {
				s.sendWindow -= int32(n)
			}
			if err := c.writeFrameLocked(AppendData(nil, p.streamID, chunk, false)); err != nil {
				return err
			}
			p.data = p.data[n:]
			return nil
		}

		// 这一段能全发出去
		n := len(p.data)
		c.sendWindow -= int32(n)
		if s := c.streams[p.streamID]; s != nil {
			s.sendWindow -= int32(n)
		}
		// 只有"这一段确实是最后一段"才带 END_STREAM
		last := p.endStream && len(c.pending) == 1
		if err := c.writeFrameLocked(AppendData(nil, p.streamID, p.data, last)); err != nil {
			return err
		}
		if last {
			c.applyLocalEndStreamLocked(c.streams[p.streamID])
		}
		c.pending[0] = pendingData{}
		c.pending = c.pending[1:]
	}
	return nil
}

// sendGoAway 发 GOAWAY。
func (c *Conn) sendGoAway(code ErrCode, debug string) []byte {
	c.state = stateClosed
	c.goAway = true
	buf := AppendGoAway(nil, c.lastStreamID, uint32(code), []byte(debug))
	c.mu.Lock()
	c.outBuf = append(c.outBuf, buf...)
	c.mu.Unlock()
	return nil
}

// writeFrame 把一个帧追加到待发缓冲区。
func (c *Conn) writeFrame(b []byte) error {
	c.mu.Lock()
	c.outBuf = append(c.outBuf, b...)
	c.mu.Unlock()
	return nil
}

// writeFrameLocked 是 writeFrame 的实现，调用方要持锁。
//
// 拆出来是因为 WriteData 现在要在**同一把锁里**改窗口 + 写帧：分两次
// 拿锁的话，两次之间来了 WINDOW_UPDATE 就会把窗口算错。
func (c *Conn) writeFrameLocked(b []byte) error {
	c.outBuf = append(c.outBuf, b...)
	return nil
}

// takeOutput 取走待发的数据。
func (c *Conn) takeOutput() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.outBuf) == 0 {
		return nil
	}
	out := c.outBuf
	c.outBuf = nil
	return out
}

// TakeOutput 取走待发的数据（给事件循环用）。
func (c *Conn) TakeOutput() []byte { return c.takeOutput() }

// WriteRaw 把一段字节直接放进发送缓冲（不当作帧）。
//
// 给连接序言这种"不是帧的东西"用。
func (c *Conn) WriteRaw(b []byte) {
	c.mu.Lock()
	c.outBuf = append(c.outBuf, b...)
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// 便捷方法
//
// 这几个是"已经拼好的帧直接返回给你"的写法，给两种场景用：
//   - 一次性把请求发出去（发完就走）
//   - 测试里拼数据
//
// 事件循环那边更常用的是 WriteHeaders / WriteData（写到内部缓冲，
// 之后 TakeOutput 取走）。

// MustHeaders 拼一个 HEADERS 帧并返回字节。
//
// 名字里的 Must 是"要么成功要么 panic"：编码失败只可能是动态表满了这种
// 我们自己状态的问题，不是调用方传错了参数。
func (c *Conn) MustHeaders(streamID uint32, fields []HeaderField, endStream bool) []byte {
	block, err := c.encoder.Encode(fields)
	if err != nil {
		panic("http2: encode headers: " + err.Error())
	}
	// 和 WriteHeaders 一样：发头就意味着这个流存在了，登记上。
	// 不登记的话，对端回过来的帧会被当成"新流"而报奇偶错误。
	c.stream(streamID)
	var buf []byte
	buf = AppendHeaders(buf, streamID, block, endStream, true)
	return buf
}

// MustData 拼 DATA 帧（超过分片上限会拆成多个）。载荷全部拷贝进返回值，
// 调用方可以立刻复用原来的切片。
func (c *Conn) MustData(streamID uint32, data []byte, endStream bool) []byte {
	max := int(c.peerMaxFrameSize)
	var buf []byte
	for len(data) > 0 {
		n := max
		if len(data) < n {
			n = len(data)
		}
		last := n == len(data)
		buf = AppendData(buf, streamID, data[:n], last && endStream)
		data = data[n:]
	}
	return buf
}

// GoAway 收到过 GOAWAY 吗。
func (c *Conn) GoAway() bool { return c.goAway }

// GoAwayCode GOAWAY 的错误码。
func (c *Conn) GoAwayCode() ErrCode { return c.goAwayCode }

// PeerMaxFrameSize 对端声明的最大帧大小。
func (c *Conn) PeerMaxFrameSize() uint32 { return c.peerMaxFrameSize }

var errUnused = errors.New("unused")

// onPriority 处理 PRIORITY 帧。
//
// **我们不做优先级调度**（HTTP/2 的优先级树在实践中基本没人用，RFC 9113
// 也把它标成了 deprecated），但**帧的格式还是要校验**：
//
//	+---------------+
//	|E|   Stream ID |   4 字节：最高位是"是否独占"，低 31 位是依赖的流 ID
//	+---------------+
//	| Weight (8)    |   1 字节：权重（实际值 +1，所以 0 表示 1/256）
//	+---------------+
//
// 只有一条规则要拦：**一个流不能依赖自己**（RFC 9113 5.3.1）——那是
// 优先级树里的环，调度器会死循环。是流级 PROTOCOL_ERROR。
//
// （帧的载荷长度在 checkFrameShape 里已经查过了，这里只管语义。）
func (c *Conn) onPriority(f *Frame) error {
	if len(f.Payload) != 5 {
		// 长度不对是帧级错误（RFC 9113 6.3）——连接级 FRAME_SIZE_ERROR
		return connError(ErrCodeFrameSize, "PRIORITY payload %d != 5", len(f.Payload))
	}
	dep := uint32(f.Payload[0]&0x7f)<<24 | uint32(f.Payload[1])<<16 |
		uint32(f.Payload[2])<<8 | uint32(f.Payload[3])
	if dep == f.StreamID {
		return streamError(f.StreamID, ErrCodeProtocol, "stream depends on itself")
	}
	return nil
}
