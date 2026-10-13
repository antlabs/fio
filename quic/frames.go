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
	"sort"
)

// QUIC 的帧（RFC 9000 section 19）。只做这套实现用得到的那些。
//
// 每个帧都可以出现在任何包里（Initial 里也有 ACK/PADDING/CRYPTO），所以
// 解析是"一包一包地走，遇到不认识的就报错"——按 RFC 必须报
// FRAME_ENCODING_ERROR，不能跳过（帧没有长度前缀，跳不了）。

const (
	frPadding        = 0x00
	frPing           = 0x01
	frAck            = 0x02
	frAckECN         = 0x03
	frResetStream    = 0x04
	frStopSending    = 0x05
	frCrypto         = 0x06
	frNewToken       = 0x07
	frStreamBase     = 0x08 // 0x08~0x0f：三个低位是 OFF/LEN/FIN
	frMaxData        = 0x10
	frMaxStreamData  = 0x11
	frMaxStreamsBidi = 0x12
	frMaxStreamsUni  = 0x13
	frDataBlocked    = 0x14
	frStreamDataBlocked = 0x15
	frStreamsBlockedBidi = 0x16
	frStreamsBlockedUni  = 0x17
	frNewConnID      = 0x18
	frRetireConnID   = 0x19
	frPathChallenge  = 0x1a
	frPathResponse   = 0x1b
	frConnClose      = 0x1c
	frConnCloseApp   = 0x1d
	frHandshakeDone  = 0x1e
)

// 流的三种状态位（STREAM 帧的低三位）
const (
	streamBitOff = 0x04
	streamBitLen = 0x02
	streamBitFin = 0x01
)

var errFrame = errors.New("quic: malformed frame")

// streamFrame 是解析出来的 STREAM 帧（载荷指向包内，不拷贝）。
type streamFrame struct {
	id     uint64
	offset uint64
	data   []byte
	fin    bool
}

// parseFrames 走一遍包载荷，把每个帧交给 fn。
//
// fn 返回非 nil 就停下（比如 CRYPTO 喂给 TLS 出错了）。
func parseFrames(payload []byte, fn func(kind uint64, b []byte, n int) error) error {
	off := 0
	for off < len(payload) {
		kind, n, err := readVarint(payload[off:])
		if err != nil {
			return err
		}
		start := off
		off += n
		switch {
		case kind == frPadding:
			// PADDING 是单字节，可能有几百个——一次跳完
			for off < len(payload) && payload[off] == 0 {
				off++
			}
			continue
		case kind == frPing:
			// 没有载荷
		case kind == frAck || kind == frAckECN:
			// 最大已确认、ACK 延迟、区间数、首个区间长 [+ ECN 计数×3]
			if _, n, err = readVarint(payload[off:]); err != nil {
				return err
			}
			off += n
			if _, n, err = readVarint(payload[off:]); err != nil {
				return err
			}
			off += n
			ranges, n, err := readVarint(payload[off:])
			if err != nil {
				return err
			}
			off += n
			if _, n, err = readVarint(payload[off:]); err != nil {
				return err
			}
			off += n
			for i := uint64(0); i < ranges; i++ {
				for j := 0; j < 2; j++ {
					if _, n, err = readVarint(payload[off:]); err != nil {
						return err
					}
					off += n
				}
			}
			if kind == frAckECN {
				for j := 0; j < 3; j++ {
					if _, n, err = readVarint(payload[off:]); err != nil {
						return err
					}
					off += n
				}
			}
		case kind == frCrypto || (kind >= frStreamBase && kind <= 0x0f):
			// 两者都是 偏移 + 长度 + 数据
			if kind == frCrypto {
				if _, n, err = readVarint(payload[off:]); err != nil {
					return err
				}
				off += n
			} else {
				if _, n, err = readVarint(payload[off:]); err != nil { // 流 ID
					return err
				}
				off += n
				if kind&streamBitOff != 0 {
					if _, n, err = readVarint(payload[off:]); err != nil {
						return err
					}
					off += n
				}
			}
			var l uint64
			if kind == frCrypto || kind&streamBitLen != 0 {
				if l, n, err = readVarint(payload[off:]); err != nil {
					return err
				}
				off += n
			} else {
				l = uint64(len(payload) - off) // 没长度就是到包尾
			}
			if off+int(l) > len(payload) {
				return errFrame
			}
			if err := fn(kind, payload[start:off+int(l)], off+int(l)-start); err != nil {
				return err
			}
			off += int(l)
			continue
		case kind == frMaxData || kind == frMaxStreamData || kind == frMaxStreamsBidi ||
			kind == frMaxStreamsUni || kind == frDataBlocked || kind == frStreamDataBlocked ||
			kind == frStreamsBlockedBidi || kind == frStreamsBlockedUni:
			// 一个或两个可变长整数
			if _, n, err = readVarint(payload[off:]); err != nil {
				return err
			}
			off += n
			if kind == frMaxStreamData || kind == frStreamDataBlocked {
				if _, n, err = readVarint(payload[off:]); err != nil {
					return err
				}
				off += n
			}
		case kind == frNewConnID:
			// 序号 + 长度 + CID + 重置令牌（16 字节）
			if _, n, err = readVarint(payload[off:]); err != nil {
				return err
			}
			off += n
			cl, n, err := readVarint(payload[off:])
			if err != nil {
				return err
			}
			off += n + int(cl) + 16
			if off > len(payload) {
				return errFrame
			}
		case kind == frRetireConnID:
			if _, n, err = readVarint(payload[off:]); err != nil {
				return err
			}
			off += n
		case kind == frPathChallenge || kind == frPathResponse:
			off += 8
			if off > len(payload) {
				return errFrame
			}
		case kind == frConnClose || kind == frConnCloseApp:
			if _, n, err = readVarint(payload[off:]); err != nil { // 错误码
				return err
			}
			off += n
			if kind == frConnClose {
				if _, n, err = readVarint(payload[off:]); err != nil { // 帧类型
					return err
				}
				off += n
			}
			rl, n, err := readVarint(payload[off:]) // 原因短语
			if err != nil {
				return err
			}
			off += n + int(rl)
			if off > len(payload) {
				return errFrame
			}
		case kind == frHandshakeDone || kind == frNewToken:
			if kind == frNewToken {
				l, n, err := readVarint(payload[off:])
				if err != nil {
					return err
				}
				off += n + int(l)
				if off > len(payload) {
					return errFrame
				}
			}
		default:
			return errFrame
		}
		if err := fn(kind, payload[start:off], off-start); err != nil {
			return err
		}
	}
	return nil
}

// appendAck 拼一个 ACK 帧。pns 是这一轮收到的包序号（乱序也行，函数自己
// 排成区间列表）。
//
// 区间按 RFC 9000 19.3.1 编码：最大包序号、延迟、区间数（减一）、首个区间
// 长度（都是相对量），之后每段是"和前一段之间空了几个 + 本段长度"。
func appendAck(dst []byte, pns []uint64, delay uint64) []byte {
	if len(pns) == 0 {
		return dst
	}
	sort.Slice(pns, func(i, j int) bool { return pns[i] > pns[j] })

	// 从大到小扫成区间（同一区间里包序号连续）。
	type ackRange struct{ hi, lo uint64 }
	ranges := make([]ackRange, 0, 2)
	hi, lo := pns[0], pns[0]
	for _, pn := range pns[1:] {
		switch {
		case pn == hi:
			// 重复收到（重传），忽略
		case pn == lo-1:
			lo = pn
		default:
			ranges = append(ranges, ackRange{hi, lo})
			hi, lo = pn, pn
		}
	}
	ranges = append(ranges, ackRange{hi, lo})

	dst = appendVarint(dst, frAck)
	dst = appendVarint(dst, ranges[0].hi)
	dst = appendVarint(dst, delay)
	dst = appendVarint(dst, uint64(len(ranges)-1))
	dst = appendVarint(dst, ranges[0].hi-ranges[0].lo)
	for i := 1; i < len(ranges); i++ {
		// 空档：前一段的最低 - 本段的最高 - 2（两个端点之间的间隔数）
		dst = appendVarint(dst, ranges[i-1].lo-ranges[i].hi-2)
		dst = appendVarint(dst, ranges[i].hi-ranges[i].lo)
	}
	return dst
}

// appendCrypto 拼一个 CRYPTO 帧。
func appendCrypto(dst []byte, offset uint64, data []byte) []byte {
	dst = appendVarint(dst, frCrypto)
	dst = appendVarint(dst, offset)
	dst = appendVarint(dst, uint64(len(data)))
	return append(dst, data...)
}

// appendStream 拼一个 STREAM 帧（带偏移和长度，fin 由调用方给）。
func appendStream(dst []byte, id uint64, offset uint64, data []byte, fin bool) []byte {
	kind := uint64(frStreamBase | streamBitLen)
	if offset > 0 {
		kind |= streamBitOff
	}
	if fin {
		kind |= streamBitFin
	}
	dst = appendVarint(dst, kind)
	dst = appendVarint(dst, id)
	if offset > 0 {
		dst = appendVarint(dst, offset)
	}
	dst = appendVarint(dst, uint64(len(data)))
	return append(dst, data...)
}
