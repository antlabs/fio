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

// Package grpc 是 fio 上的 gRPC。
//
// gRPC 是**跑在 HTTP/2 上的**，不是自己一套传输：请求是 HTTP/2 的
// HEADERS（:method=POST、:path=/包名.服务名/方法名、content-type=
// application/grpc）+ DATA，响应同理，末尾的状态放在 trailer 里。
// 所以这个包依赖 http2/，自己做的是 gRPC 那点额外规矩：
//
//   - **消息分帧**：每条 gRPC 消息前面有 5 个字节——1 字节压缩标志 +
//     4 字节大端长度。HTTP/2 的 DATA 帧边界和消息边界**没关系**，一条
//     消息可能跨好几个 DATA 帧，一个 DATA 帧里也可能有多条消息。
//   - **状态**：调用的结果（OK / NOT_FOUND / ...）不在 HTTP 状态码里，
//     在 trailer 的 grpc-status 字段里。HTTP 200 也可能是失败的调用。
//   - **trailer**：gRPC 的 trailer 是 HTTP/2 里一个带 END_STREAM 的
//     HEADERS 帧（不是 HTTP/1.1 那种 chunked 后面的 trailer）。
package grpc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// 消息头长度：1 字节压缩标志 + 4 字节长度。
const messageHeaderLen = 5

// 默认的单条消息上限（4MB，和 Go 的 grpc-go 默认一致）。
const defaultMaxMessageSize = 4 * 1024 * 1024

var (
	ErrMessageTooLarge  = errors.New("grpc: message exceeds max size")
	ErrBadMessageHeader = errors.New("grpc: malformed message header")
	ErrCompressed       = errors.New("grpc: compressed messages not supported")
)

// MessageParser 从 DATA 帧的字节流里切出 gRPC 消息。
//
// 和 http2 的帧解析器一个路子，但**边界来源不同**：HTTP/2 的帧边界在
// 帧头里写着，gRPC 的消息边界在消息自己的 5 字节头里。所以一条消息可能
// 跨好几个 DATA 帧，一个 DATA 帧里也可能有好几条消息——真实客户端不会
// 保证"一条消息一个 DATA 帧"，这个解析器不能省。
//
//	Parse(data) -> 切出几条完整消息
//	             -> 剩下不够一条的攒在内部
//	             -> 下次 Parse 时和新的数据拼起来
//
// **消化量的约定**：返回"这次传进来的 data 里有多少被处理了"。攒在
// 内部的那部分不算——调用方每次把整段给它就行，不用自己切。
type MessageParser struct {
	// maxSize 是单条消息上限
	maxSize int
	// buf 攒着还没凑完整消息的字节（可能含半条消息的头）
	buf []byte
}

// NewMessageParser 建一个消息解析器。maxSize <= 0 时用默认值。
func NewMessageParser(maxSize int) *MessageParser {
	if maxSize <= 0 {
		maxSize = defaultMaxMessageSize
	}
	return &MessageParser{maxSize: maxSize}
}

// Reset 清空（一个流一个解析器，流结束时复位）。
func (p *MessageParser) Reset() { p.buf = p.buf[:0] }

// Buffered 还有多少字节攒着没处理。
func (p *MessageParser) Buffered() int { return len(p.buf) }

// Parse 喂一段字节，每切出一条完整消息就调 fn。
//
// 返回消化了多少字节（按传进来的 data 算）。
func (p *MessageParser) Parse(data []byte, fn func(msg []byte) error) (int, error) {
	// 攒着的那部分先处理掉：把它们和这次的数据拼起来看。
	//
	// 拼的时候要记住"之前攒了多少"（oldLen），因为返回值要按这次输入的
	// 长度算：之前攒的那些字节在上一轮就算消化过了。
	oldLen := len(p.buf)
	work := data
	if oldLen > 0 {
		p.buf = append(p.buf, data...)
		work = p.buf
	}

	consumed := 0
	var err error
	for {
		if len(work)-consumed < messageHeaderLen {
			break // 头还没凑齐
		}
		head := work[consumed : consumed+messageHeaderLen]
		compressed := head[0]
		length := binary.BigEndian.Uint32(head[1:5])

		if compressed != 0 {
			// 压缩标志是 1 表示整条消息被压缩了。gRPC 允许用
			// grpc-encoding 头协商压缩，我们还没做——收到压缩的直接
			// 报错，比悄悄解出错好。
			err = ErrCompressed
			break
		}
		if length > uint32(p.maxSize) {
			err = fmt.Errorf("%w: %d > %d", ErrMessageTooLarge, length, p.maxSize)
			break
		}
		if len(work)-consumed-messageHeaderLen < int(length) {
			break // 载荷还没凑齐
		}

		msg := work[consumed+messageHeaderLen : consumed+messageHeaderLen+int(length)]
		if cbErr := fn(msg); cbErr != nil {
			err = cbErr
			break
		}
		consumed += messageHeaderLen + int(length)
	}

	// 剩下没处理的留回 p.buf。
	//
	// 如果 work 本来就是 p.buf（上一轮已经攒了数据），未消费的部分
	// **已经在正确的位置上**，再 append 一遍就是白拷：一条跨 N 个 DATA
	// 帧的大消息会因此退化成 O(n²)。这里直接把切片往前推。
	if oldLen > 0 {
		p.buf = work[consumed:]
	} else if rest := work[consumed:]; len(rest) > 0 {
		// work 是调用方的读缓冲区，必须拷一份留着。
		p.buf = append(p.buf[:0], rest...)
	} else {
		p.buf = p.buf[:0]
	}

	// 消化量：这次的 data 全部收下了。
	//
	// 为什么要全算：没切出完整消息的那些字节**已经存进 p.buf**，调用方
	// 再喂一遍它们就重复了（一条消息会被切两次）。所以"消化"的意思是
	// "进了解析器，不用再给我了"——包括攒着的那些。
	//
	// 早先按 consumed 算（只数"变成了完整消息"的字节），症状是喂 13 字节
	// 只消化 10——第二条的半截头被攒起来了却算没消化，调用方留着它，
	// 下次又喂一遍，拼出来就是重复的字节。
	_ = consumed
	return len(data), err
}

// Encode 给一条消息加上 gRPC 的 5 字节头。
//
// dst 是复用的缓冲区；返回的切片可能指向它。
func Encode(dst []byte, msg []byte) []byte {
	dst = append(dst, 0) // 压缩标志：0 = 没压
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(msg)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, msg...)
}

// EncodeAll 把多条消息拼成一段（一连串"头 + 载荷"）。
func EncodeAll(dst []byte, msgs ...[]byte) []byte {
	for _, m := range msgs {
		dst = Encode(dst, m)
	}
	return dst
}
