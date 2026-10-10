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
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/wsutil/bytespool"
	"github.com/antlabs/wsutil/enum"
	"github.com/antlabs/wsutil/errs"
	"github.com/antlabs/wsutil/frame"
	"github.com/antlabs/wsutil/mask"
	"github.com/antlabs/wsutil/opcode"
)

const (
	maxControlFrameSize = 125
)

type frameState int8

func (f frameState) String() string {
	switch f {
	case frameStateHeaderStart:
		return "frameStateHeaderStart"
	case frameStateHeaderPayloadAndMask:
		return "frameStateHeaderPayloadAndMask"
	case frameStatePayload:
		return "frameStatePayload"
	}
	return ""
}

const (
	frameStateHeaderStart frameState = iota
	frameStateHeaderPayloadAndMask
	frameStatePayload
)

// packed 里只有两个状态位了:
//
//	bit 0-1  curState(帧头解析的状态机, 只有 3 个值)
//	bit 2    客户端为 1, 服务端为 0
//
// busy/pendingRead/pendingWrite/corking 那几个位以前也在这儿，现在归 engine
// ——它们是"这条连接正被谁处理、要不要攒包"的调度状态，和 websocket 协议
// 本身无关。
const (
	stateMask  uint32 = 0x3
	flagClient uint32 = 1 << 2
)

// curState 和 client 都走原子: Go 的 atomic 在 x86 上就是普通 load/store
// (带编译器屏障), 统一用原子不会变慢, 还避免了非原子读改写把别的 goroutine
// 原子置的位覆盖掉。
func (c *Conn) getCurState() frameState {
	return frameState(atomic.LoadUint32(&c.packed) & stateMask)
}

func (c *Conn) setCurState(st frameState) {
	for {
		old := atomic.LoadUint32(&c.packed)
		nv := (old &^ stateMask) | (uint32(st) & stateMask)
		if atomic.CompareAndSwapUint32(&c.packed, old, nv) {
			return
		}
	}
}

func (c *Conn) isClient() bool { return atomic.LoadUint32(&c.packed)&flagClient != 0 }

func (c *Conn) setClient(v bool) {
	if v {
		atomic.OrUint32(&c.packed, flagClient)
	} else {
		atomic.AndUint32(&c.packed, ^flagClient)
	}
}

// addTask 把回调交给连接的任务执行器。
//
// io 模式的 task 是 nil: 那个模式就是"就地执行", 而它占了这个库绝大
// 多数部署(包括默认配置)。走接口要过一次动态派发加一层函数调用, 而
// 这是每条消息至少一次的路径, 所以让它直接调。
func (c *Conn) addTask(f func() bool) {
	if c.isClosed() {
		return
	}

	if c.task == nil {
		f()
		return
	}

	err := c.task.AddTask(&c.mu, f)
	if err != nil {
		c.getLogger().Error("addTask", "err", err.Error())
	}
}

// 基于状态机解析frame
func (c *Conn) readHeader() (sucess bool, err error) {
	state := c.getCurState()
	// 开始解析frame
	if state == frameStateHeaderStart {
		// fin rsv1 rsv2 rsv3 opcode
		if c.rw-c.rr < 2 {
			return false, nil
		}
		c.rh.Head = (*c.rbuf)[c.rr]

		// h.Fin = head[0]&(1<<7) > 0
		// h.Rsv1 = head[0]&(1<<6) > 0
		// h.Rsv2 = head[0]&(1<<5) > 0
		// h.Rsv3 = head[0]&(1<<4) > 0
		c.rh.Opcode = opcode.Opcode(c.rh.Head & 0xF)

		maskAndPayloadLen := (*c.rbuf)[c.rr+1]
		have := 0
		c.rh.Mask = maskAndPayloadLen&(1<<7) > 0

		if c.rh.Mask {
			have += 4
		}

		c.rh.PayloadLen = int64(maskAndPayloadLen & 0x7F)
		switch {
		// 长度
		case c.rh.PayloadLen >= 0 && c.rh.PayloadLen <= 125:
		case c.rh.PayloadLen == 126:
			// 2字节长度
			have += 2
			// size += 2
		case c.rh.PayloadLen == 127:
			// 8字节长度
			have += 8
			// size += 8
		default:
			// 预期之外的, 直接报错
			return sucess, errs.ErrFramePayloadLength
		}
		c.setCurState(frameStateHeaderPayloadAndMask)
		state = frameStateHeaderPayloadAndMask
		c.lenAndMaskSize = have
		c.rr += 2

	}

	if state == frameStateHeaderPayloadAndMask {
		if c.rw-c.rr < c.lenAndMaskSize {
			return
		}
		have := c.lenAndMaskSize
		head := (*c.rbuf)[c.rr : c.rr+have]
		switch c.rh.PayloadLen {
		case 126:
			c.rh.PayloadLen = int64(binary.BigEndian.Uint16(head[:2]))
			head = head[2:]
		case 127:
			c.rh.PayloadLen = int64(binary.BigEndian.Uint64(head[:8]))
			head = head[8:]
		}

		if c.readMaxMessage > 0 && c.rh.PayloadLen > c.readMaxMessage {
			return false, TooBigMessage
		}

		if c.rh.Mask {
			c.rh.MaskKey = binary.LittleEndian.Uint32(head[:4])
		}
		c.setCurState(frameStatePayload)
		c.rr += c.lenAndMaskSize
		return true, nil
	}

	return state == frameStatePayload, nil
}

func (c *Conn) failRsv1(op opcode.Opcode) bool {
	// 解压缩没有开启
	if !c.pd.Decompression {
		return true
	}

	// 不是text和binary
	if op != opcode.Text && op != opcode.Binary {
		return true
	}

	return false
}

// readPayload 从借来的读缓冲区里取出一帧的 payload。
//
// needCopy 为 false 时 payload 直接指向 rbuf, 不拷也不从池里取内存。
// 调用方保证这块内存只在本次回调里用(见 WithServerZeroCopyPayload)。
//
// 读缓冲区的扩容/搬迁以前在这儿做(缓冲区不够就 realloc、够就 leftMove
// 挪一挪), 现在归 engine: 读到帧头就知道整条报文多大, 直接让引擎把空间
// 要到位(它会先 compact 收掉已消费的前缀、再按需扩容), 下次一次读够。
// 这里只管"数据够不够取"。
func (c *Conn) readPayload(needCopy bool) (f frame.Frame2, success bool, err error) {
	// 已读取未处理的数据
	readUnhandle := int64(c.rw - c.rr)
	needRead := c.rh.PayloadLen - readUnhandle

	// fmt.Printf("needRead:%d:rr(%d):rw(%d):PayloadLen(%d), %v\n", needRead, c.rr, c.rw, c.rh.PayloadLen, c.rbuf)
	if needRead > 0 {
		// 数据不够，等下一次读。
		//
		// **不在这里让引擎扩缓冲区**：OnData 期间协议手里握着读缓冲区的
		// 别名（解析器的 rbuf/rr/rw 就是照它摆的），compact 会把数据挪走、
		// 扩容会把数组换掉——解析器读到的是错位/已释放的内存。
		//
		// 预扩交给引擎，它挑的是"两次 OnData 之间"那个安全点：问
		// NextMessageSize（见 engine.go），一次要到最终大小。
		return
	}
	// 普通frame
	if !needCopy {
		// payload 就是 rbuf 里这一段, 别名过去, 不分配也不拷贝。
		//
		// 用 copy 而不是 unsafe.Slice: 同一个起点、长度和容量都取
		// 一致时 copy 不会真的搬数据(实测 0 次 memmove), 但它是普通
		// 的切片表达式, 不需要 unsafe, 也没那么多坑。
		//
		// 注意这里 rr 必须照常推进: 数据在 rbuf 里, 但所有权已经算
		// 交出去了, 后面的解析不能再看它。回调返回后这块内存随
		// rbuf 一起复用。
		payload := (*c.rbuf)[c.rr : c.rr+int(c.rh.PayloadLen) : c.rr+int(c.rh.PayloadLen)]
		f.Payload = &payload
		f.FrameHeader = c.rh
		c.rr += int(c.rh.PayloadLen)
		// 别在这里 leftMove: 那会把 rbuf 里刚别名出去的那段搬走,
		// 回调读到的东西跟着变。空间够不够下一次再说, 下一次
		// readPayload 开头会自己判断。
		return f, true, nil
	}

	newBuf := bytespool.GetBytes(int(c.rh.PayloadLen) + enum.MaxFrameHeaderSize)
	copy(*newBuf, (*c.rbuf)[c.rr:c.rr+int(c.rh.PayloadLen)])
	newBuf2 := (*newBuf)[:c.rh.PayloadLen] //修改下len
	f.Payload = &newBuf2

	f.FrameHeader = c.rh
	c.rr += int(c.rh.PayloadLen)

	return f, true, nil
}

// takePayload 把 payload 变成一块调用方可以长期持有的内存。
//
// needCopy 为 false 时 payload 只是读缓冲区的一段别名, 下一次 read 就会
// 覆盖它, 所以要拷进池里的一块新内存; 否则 payload 本来就是单独分配出来
// 的, 把所有权转过去就行, 不动数据。
//
// 分片消息用它: 第一个分片要留到最后一个分片到达, 中间隔着很多次 read。
func takePayload(p *[]byte, needCopy bool) *[]byte {
	if !needCopy {
		buf := bytespool.GetBytes(len(*p) + enum.MaxFrameHeaderSize)
		copy(*buf, *p)
		nb := (*buf)[:len(*p)]
		return &nb
	}
	return p
}

// putPayload 归还 payload; 零拷贝的那份是读缓冲区的别名, 不在池子里,
// 还回去会污染内存池, 所以按 needCopy 区分。
func putPayload(p *[]byte, needCopy bool) {
	if needCopy {
		bytespool.PutBytes(p)
	}
}

// needCopy 是 readPayload 给的: false 表示 f.Payload 是读缓冲区的一段
// 别名, 回调返回之后就不算数了, 所以后面凡是把 payload 存下来或者交给
// 别的 goroutine 的地方都必须自己拷一份(见下面分片和入池那两处)。
func (c *Conn) processCallback(f frame.Frame2, needCopy bool) (err error) {
	op := f.Opcode
	if c.fragmentFrameHeader != nil {
		op = c.fragmentFrameHeader.Opcode
	}

	rsv1 := f.GetRsv1()
	// 检查Rsv1 rsv2 Rfd, errsv3
	if rsv1 && c.failRsv1(op) || f.GetRsv2() || f.GetRsv3() {
		err = fmt.Errorf("%w:Rsv1(%t) Rsv2(%t) rsv2(%t) compression:%t", ErrRsv123, rsv1, f.GetRsv2(), f.GetRsv3(), c.pd.Compression)
		return c.writeErrAndOnClose(ProtocolError, err)
	}

	maskKey := c.rh.MaskKey
	needMask := c.rh.Mask

	fin := f.GetFin()
	// 分段的frame
	if c.fragmentFrameHeader != nil && !f.Opcode.IsControl() {
		if f.Opcode == 0 {
			// TODO 优化, 需要放到单独的业务go程, 目前为了保证时序性，先放到io go程里面
			if needMask {
				mask.Mask(*f.Payload, maskKey)
			}

			// 这里要留到最后一个分片到达, 中间隔着若干次 read, 所以
			// 零拷贝那份别名必须转成自己的一块内存, 见 takePayload。
			payloadOwn := takePayload(f.Payload, needCopy)
			if c.fragmentFramePayload == nil {
				c.fragmentFramePayload = payloadOwn
			} else {
				*c.fragmentFramePayload = append(*c.fragmentFramePayload, *payloadOwn...)
				putPayload(payloadOwn, true) // 已经是自己的内存了, 按池里的还
			}

			f.Payload = nil

			// 分段的在这返回
			if fin {
				// 解压缩
				fragmentFrameHeader := c.fragmentFrameHeader
				fragmentFramePayload := c.fragmentFramePayload
				decompression := c.pd.Decompression
				c.fragmentFrameHeader = nil
				c.fragmentFramePayload = nil

				// 进入业务协程执行
				c.addTask(func() (exit bool) {
					if fragmentFrameHeader.GetRsv1() && decompression {
						tempBuf, err := c.decode(fragmentFramePayload)
						if err != nil {
							// return err
							c.closeWithLock(err)
							return false
						}

						// 回收这块内存到pool里面
						bytespool.PutBytes(fragmentFramePayload)
						fragmentFramePayload = tempBuf
					}
					// 这里的check按道理应该放到f.Fin前面， 会更符合rfc的标准, 前提是c.utf8Check修改成流式解析
					// TODO c.utf8Check 修改成流式解析
					if fragmentFrameHeader.Opcode == opcode.Text && !c.utf8Check(*fragmentFramePayload) {
						c.onCloseOnce.Do(&c.mu2, func() {
							c.Callback.OnClose(c, ErrTextNotUTF8)
						})
						// return ErrTextNotUTF8
						c.closeWithLock(nil)
						return false
					}

					c.Callback.OnMessage(c, fragmentFrameHeader.Opcode, *fragmentFramePayload)
					bytespool.PutBytes(fragmentFramePayload)
					return false
				})
			}
			return nil
		}

		c.writeErrAndOnClose(ProtocolError, ErrFrameOpcode)
		return ErrFrameOpcode
	}

	if f.Opcode == opcode.Text || f.Opcode == opcode.Binary {
		if !fin {
			prevFrame := f.FrameHeader
			// 第一次分段

			// TODO 放到单独的业务go程, 目前为了保证时序性，先放到io go程里面
			if needMask {
				mask.Mask(*f.Payload, maskKey)
			}
			if c.fragmentFramePayload == nil {
				// 正常是单独分配出来的, 转移下变量的所有权就行; 零拷贝
				// 时它只是 rbuf 的一段, 得先拷成自己的。
				c.fragmentFramePayload = takePayload(f.Payload, needCopy)
				f.Payload = nil
			}

			// 让fragmentFrame的Payload指向readBuf, readBuf 原引用直接丢弃
			c.fragmentFrameHeader = &prevFrame
			return
		}

		// var payloadPtr atomic.Pointer[[]byte]
		decompression := c.pd.Decompression
		payload := f.Payload
		f.Payload = nil
		// payloadPtr.Store(f.Payload)

		// 回调就地执行(c.task == nil, 见 addTask)时, 数据在这个栈帧里
		// 就用完, 可以接着用读缓冲区那段别名; 投进池子的回调活到别的
		// 时候, 必须持有自己的一块内存。压缩的消息要解压, 解压本来就
		// 产出新内存, 两条路都一样, 不用在这里分。
		if c.task == nil {
			// 闭包是纯开销: 每个消息堆分配一个, 只为了马上同步调用一次。
			//
			// 这里不能只是"分支里直接调用, 底下再留一个闭包版本"——
			// 逃逸分析是按函数做的, 只要本函数里任何一处捕获了 f, f
			// 这个参数就整个进堆, 走哪条分支都躲不掉(实测: 684MB, 全记
			// 在函数入口那一行)。所以闭包版本挪到单独的 noinline 函数
			// 里去, 让逃逸发生在它自己的栈帧里。
			if !c.isClosed() {
				c.processCallbackData(f, payload, rsv1, decompression, needMask, maskKey, needCopy)
			}
			return
		}

		// 交给池: 它可能过一会才跑, 那时候 rbuf 已经换了内容。
		payloadOwn := takePayload(payload, needCopy)
		f.Payload = payloadOwn
		c.addProcessCallbackTask(f, payloadOwn, rsv1, decompression, needMask, maskKey, true)
		return
	}

	if f.Opcode == Close || f.Opcode == Ping || f.Opcode == Pong {

		// 消息体的内容比较小，直接在io go程里面处理
		if needMask {
			mask.Mask(*f.Payload, maskKey)
		}
		//  对方发的控制消息太大
		if f.PayloadLen > maxControlFrameSize {
			c.writeErrAndOnClose(ProtocolError, ErrMaxControlFrameSize)
			return ErrMaxControlFrameSize
		}
		// Close, Ping, Pong 不能分片
		if !fin {
			c.writeErrAndOnClose(ProtocolError, ErrNOTBeFragmented)
			return ErrNOTBeFragmented
		}

		if f.Opcode == Close {
			if len(*f.Payload) == 0 {
				c.writeErrAndOnClose(NormalClosure, &CloseErrMsg{Code: NormalClosure})
				return nil
			}

			if len(*f.Payload) < 2 {
				return c.writeErrAndOnClose(ProtocolError, ErrClosePayloadTooSmall)
			}

			if !c.utf8Check((*f.Payload)[2:]) {
				return c.writeErrAndOnClose(ProtocolError, ErrTextNotUTF8)
			}

			code := binary.BigEndian.Uint16(*f.Payload)
			if !validCode(code) {
				return c.writeErrAndOnClose(ProtocolError, ErrCloseValue)
			}

			// 回敬一个close包
			if err := c.WriteTimeout(Close, *f.Payload, 2*time.Second); err != nil {
				return err
			}

			err = bytesToCloseErrMsg(*f.Payload)
			c.onCloseOnce.Do(&c.mu2, func() {
				c.Callback.OnClose(c, err)
			})
			return err
		}

		if f.Opcode == Ping {
			// 回一个pong包
			if c.replyPing {
				if err := c.WriteTimeout(Pong, *f.Payload, 2*time.Second); err != nil {
					c.onCloseOnce.Do(&c.mu2, func() {
						c.Callback.OnClose(c, err)
					})
					return err
				}
				// 进入业务协程执行
				payload := f.Payload
				// here
				c.addTask(func() bool {
					return c.processPing(f, payload)
				})
				return
			}
		}

		if f.Opcode == Pong && c.ignorePong {
			return
		}

		// 进入业务协程执行
		c.addTask(func() bool {
			c.Callback.OnMessage(c, f.Opcode, nil)
			return false
		})
		return
	}
	// 检查Opcode
	c.writeErrAndOnClose(ProtocolError, ErrOpcode)
	return ErrOpcode
}

func (c *Conn) processPing(f frame.Frame2, payload *[]byte) bool {
	c.Callback.OnMessage(c, f.Opcode, *payload)
	bytespool.PutBytes(payload)
	return false
}

// addProcessCallbackTask 是"把回调交给任务池"的那条路, 单独一个函数
// 是为了把捕获 f 的闭包隔离在这里: 逃逸分析按函数做, 留在
// processCallback 里会让它的 f 参数无论走不走池都进堆。
//
// noinline 是必要的, 否则内联回去就白隔离了。
//
//go:noinline
func (c *Conn) addProcessCallbackTask(f frame.Frame2, payload *[]byte, rsv1 bool, decompression bool, needMask bool, maskKey uint32, owned bool) {
	c.addTask(func() bool {
		return c.processCallbackData(f, payload, rsv1, decompression, needMask, maskKey, owned)
	})
}

// 如果是text或者binary的消息， 在这里调用OnMessage函数
//
// owned 表示 payload 是不是我们自己的一块内存(池里来的, 或者 takePayload
// 拷出来的): 是就归还在池里, 不是就只是读缓冲区的一段别名, 碰不得。
func (c *Conn) processCallbackData(f frame.Frame2, payload *[]byte, rsv1 bool, decompression bool, needMask bool, maskKey uint32, owned bool) (ok bool) {
	var err error
	if needMask {
		mask.Mask(*payload, maskKey)
	}
	decodePayload := payload
	if rsv1 && decompression {
		// 不分段的解压缩
		decodePayload, err = c.decode(payload)
		if err != nil {
			c.closeWithLock(err)
			putPayload(payload, owned)
			return false
		}
		defer bytespool.PutBytes(decodePayload)
	}

	if f.Opcode == opcode.Text {
		if !c.utf8Check(*decodePayload) {
			c.closeWithLock(nil)
			c.onCloseOnce.Do(&c.mu2, func() {
				c.Callback.OnClose(c, ErrTextNotUTF8)
			})
			return false
		}
	}

	c.Callback.OnMessage(c, f.Opcode, *decodePayload)
	putPayload(payload, owned)
	return false
}

func (c *Conn) writeAndMaybeOnClose(err error) error {
	var sc *StatusCode
	defer func() {
		c.onCloseOnce.Do(&c.mu2, func() {
			c.Callback.OnClose(c, err)
		})
	}()

	if errors.As(err, &sc) {
		if err := c.WriteTimeout(opcode.Close, sc.toBytes(), 2*time.Second); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) writeErrAndOnClose(code StatusCode, userErr error) error {
	defer func() {
		c.onCloseOnce.Do(&c.mu2, func() {
			c.Callback.OnClose(c, userErr)
		})
	}()
	if err := c.WriteTimeout(opcode.Close, code.toBytes(), 2*time.Second); err != nil {
		return err
	}

	return userErr
}

func (c *Conn) readPayloadAndCallback(ec *engine.Conn) (sucess bool, err error) {
	if c.getCurState() == frameStatePayload {
		// 这几种情况必须拷: 压缩的要拿去解压(结果跟读缓冲区生命周期
		// 无关, 但解压本身按 payload 的长度读, 拷与不拷收益一样, 统一
		// 走拷贝省得分叉); 分段消息的下一个分片到达时这块内存已经换了
		// 内容; 已经进入分段状态时更不用说。
		//
		// 其余情况(单帧、不压缩、消息在一次 read 里拿全)对回调来说
		// 只是"回调期间有效"的字节, 正好和读缓冲区共用一块。
		needCopy := !c.zeroCopyPayload ||
			c.rh.GetRsv1() ||
			!c.rh.GetFin() ||
			c.fragmentFrameHeader != nil
		f, success, err := c.readPayload(needCopy)
		if err != nil {
			c.getLogger().Error("readPayloadAndCallback.read payload err", "err", err.Error())
			return sucess, err
		}

		// fmt.Printf("read payload, success:%t, %v\n", success, f.Payload)
		if success {
			// 这一轮里如果还有后续 frame, 现在就开攒: 回调写出去的回包
			// 先攒着, 轮末(OnData 末尾)一次写出去。剩多少字节就是给引擎
			// 的 capHint(回包和请求大小往往差不多)。
			//
			// 以前是 maybeCork, 现在攒不攒的机制在 engine, 这里只负责
			// "还有数据就告诉它开始攒"。
			if rem := c.rw - c.rr; rem > 0 {
				if ec != nil {
					ec.StartCork(rem)
				}
			}
			if err := c.processCallback(f, needCopy); err != nil {
				c.closeWithLock(err)
				return false, err
			}
			c.setCurState(frameStateHeaderStart)
			return true, err
		}
	}
	return false, nil
}

func (c *Conn) isClosed() bool {
	return atomic.LoadInt32(&c.closed) == 1
}

func (c *Conn) WriteMessage(op Opcode, writeBuf []byte) (err error) {
	if c.isClosed() {
		return ErrClosed
	}

	if op == opcode.Text {
		if !c.utf8Check(writeBuf) {
			return ErrTextNotUTF8
		}
	}

	rsv1 := c.pd.Compression && (op == opcode.Text || op == opcode.Binary)
	if rsv1 {
		writeBufPtr, err := c.encoode(&writeBuf)
		if err != nil {
			return err
		}

		defer bytespool.PutBytes(writeBufPtr)
		writeBuf = *writeBufPtr
	}

	// 这把锁必须拿着: 它不只是给"回调被投到线程池"那个模式用的——
	// Close() 可能从任意 goroutine 来(用户代码、超时定时器), 它会释放
	// 连接状态(见 conn_unix.go 的 closeWithLock), 不拿锁写就会写到已
	// 释放的内存上。
	//
	// 实测(io 模式, 1KB echo, 交替 3 轮): 去掉这把锁 TPS 差 0.3%(噪声内)、
	// TP99 好 1.8%。收益是零, 不值得拿这个风险换。
	c.mu.Lock()
	defer c.mu.Unlock()

	// 帧头在栈上拼。wsHeader 拼"FIN + opcode + 长度"，剩下的两位和掩码
	// 在这里补：
	//
	//   - rsv1：压缩过的消息必须置位，不然对端按明文收（收到的就是
	//     deflate 的原始字节）
	//   - 掩码：客户端发的帧**必须**带掩码（RFC 6455 5.3），服务端发的
	//     必须不带
	//
	// 这两件事以前是 frame.WriteFrame 干的（基线里所有快速路径都写着
	// !c.isClient() && !rsv1，剩下的全走它）。手拼之后漏过两次，所以
	// 这里一次说清楚。
	var hdr [14]byte // 10 字节最长帧头 + 4 字节掩码
	hn := wsHeader(hdr[:], uint8(op), len(writeBuf))
	if rsv1 {
		hdr[0] |= 1 << 6
	}
	if c.isClient() {
		hdr[1] |= 1 << 7
		key := rand.Uint32()
		binary.LittleEndian.PutUint32(hdr[hn:], key)
		hn += 4
		// 掩码要写在拷贝上：writeBuf 可能是用户自己的切片（改了就污染
		// 调用方的数据），也可能是压缩刚产出的池内存（下一次复用之前
		// 就会被还回去，而它还带着掩码）。
		masked := make([]byte, len(writeBuf))
		copy(masked, writeBuf)
		mask.Mask(masked, key)
		writeBuf = masked
	}

	// 攒包期间(一轮 read 里有多个 frame): 回包先攒着, 轮末一次写出去。
	// 这是 Pipeline 场景写路径 CPU 的主要来源。
	//
	// 压缩的消息(rsv1)不攒: 它的 payload 是另外分配出来的, 攒包那条路
	// 假设 payload 在攒完之前一直有效——而现在攒完之前它就解压拷贝走了,
	// 还是走 Writev 更直白。
	if c.ec != nil && c.ec.IsCorking() && !rsv1 {
		return wrapEngineErr(c.ec.CorkWrite(hdr[:hn], writeBuf))
	}

	// 引擎的 Writev: header + payload 两段, 小消息(≤4KB)在引擎里拼到栈上
	// 一次 sendto, 大消息走 iovec。部分写、EAGAIN、可写事件补写都在引擎里
	// 处理完了, 这里不用管 wbufList。
	if c.ec != nil {
		return wrapEngineErr(c.ec.Writev(hdr[:hn], writeBuf))
	}
	return ErrClosed
}

// wrapEngineErr 把 engine 的 ErrClosed 换成 websocket 自己的。
//
// 两个包各有一个 ErrClosed（一个 "engine: connection closed"，一个
// "fio: connection closed"），用户代码里比较的是 websocket 这个。
// 不翻译的话，对端刚关连接时的写会拿到 engine 那个，比较不上。
func wrapEngineErr(err error) error {
	if errors.Is(err, engine.ErrClosed) {
		return ErrClosed
	}
	return err
}

// 写分段数据, 目前主要是单元测试使用
func (c *Conn) writeFragment(op Opcode, writeBuf []byte, maxFragment int /*单个段最大size*/) (err error) {
	if len(writeBuf) < maxFragment {
		return c.WriteMessage(op, writeBuf)
	}

	if op == opcode.Text {
		if !c.utf8Check(writeBuf) {
			return ErrTextNotUTF8
		}
	}

	rsv1 := c.pd.Compression && (op == opcode.Text || op == opcode.Binary)
	if rsv1 {
		writeBufPtr, err := c.encoode(&writeBuf)
		if err != nil {
			return err
		}
		defer bytespool.PutBytes(writeBufPtr)
		writeBuf = *writeBufPtr
	}

	// 每个分片独立成帧、自己带掩码(客户端要 mask, 服务端不要), 所以这里
	// 一个个分片拼帧头再交给 engine 写。以前走 frame.WriteFrame 那条慢路径,
	// 现在统一到 wsHeader + ec.Writev, 和 WriteMessage 一致。
	//
	// 只给"这一片是 FIN"的那次置 fin, 中间的分片 op=Continuation。
	for len(writeBuf) > 0 {
		fin := true
		chunk := writeBuf
		if len(writeBuf) > maxFragment {
			fin = false
			chunk = writeBuf[:maxFragment]
		}

		head := frameHeaderBuf(fin, rsv1, op, chunk, c.isClient())
		if c.ec != nil {
			if err := wrapEngineErr(c.ec.Writev(head.hdr[:head.n], head.payload)); err != nil {
				return err
			}
		} else {
			return ErrClosed
		}

		if fin {
			return nil
		}
		writeBuf = writeBuf[maxFragment:]
		op = Continuation
	}
	return nil
}

// fragmentHeader 是分片帧的帧头 + 这是不是最后一片。
//
// writeFragment 以前靠 frame.WriteFrame 拼帧头(带掩码), 那条路删掉了;
// 这里用 wsHeader 拼, 客户端再补一段 4 字节掩码。分片只在单元测试里用,
// 不是热路径, 所以不追求零分配。
type fragmentHeader struct {
	hdr     [14]byte // 10 字节最长帧头 + 4 字节掩码
	n       int
	payload []byte
}

// frameHeaderBuf 拼一个分片帧的帧头（含客户端的掩码），顺带把 payload
// 掩上。
//
// **rsv1 必须照实置位**：压缩过的分片不置 rsv1，对端就按明文收——收到的
// 是 deflate 的原始字节（实测症状：服务端拿到的"hello"是
// "\x00\x05\x00\xfa\xffhello\x00"，那是 deflate 的 stored block 头
// 加明文）。以前走 frame.WriteFrame 那条路（它自己管 rsv1），换成这里
// 手拼之后漏了一次。
func frameHeaderBuf(fin, rsv1 bool, op Opcode, payload []byte, client bool) fragmentHeader {
	var f fragmentHeader
	b0 := byte(op) & 0x0F
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 1 << 6
	}
	f.hdr[0] = b0

	ln := len(payload)
	switch {
	case ln <= 125:
		f.hdr[1] = byte(ln)
		f.n = 2
	case ln <= 65535:
		f.hdr[1] = 126
		binary.BigEndian.PutUint16(f.hdr[2:], uint16(ln))
		f.n = 4
	default:
		f.hdr[1] = 127
		binary.BigEndian.PutUint64(f.hdr[2:], uint64(ln))
		f.n = 10
	}

	if client {
		f.hdr[1] |= 1 << 7
		key := rand.Uint32()
		binary.LittleEndian.PutUint32(f.hdr[f.n:], key)
		f.n += 4
		// 掩码写的是拷贝, 不能原地改调用方的 buf(它可能被复用)。
		payload = append([]byte(nil), payload...)
		mask.Mask(payload, key)
	}
	f.payload = payload
	return f
}

// TODO
func (c *Conn) WriteTimeout(op Opcode, data []byte, t time.Duration) (err error) {
	if err = c.setWriteDeadline(time.Now().Add(t)); err != nil {
		return
	}

	defer func() { _ = c.setWriteDeadline(time.Time{}) }()
	return c.WriteMessage(op, data)
}

func (c *Conn) WriteControl(op Opcode, data []byte) (err error) {
	if len(data) > maxControlFrameSize {
		return ErrMaxControlFrameSize
	}
	return c.WriteMessage(op, data)
}

func (c *Conn) WriteCloseTimeout(sc StatusCode, t time.Duration) (err error) {
	buf := sc.toBytes()
	return c.WriteTimeout(opcode.Close, buf, t)
}

// data 不能超过125字节
func (c *Conn) WritePing(data []byte) (err error) {
	return c.WriteControl(Ping, data[:])
}

// data 不能超过125字节
func (c *Conn) WritePong(data []byte) (err error) {
	return c.WriteControl(Pong, data[:])
}

func (c *Conn) Close() error {
	if c == nil {
		return nil
	}

	c.closeWithLock(nil)
	return nil
}
