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
	"encoding/binary"
	"errors"
)

// QUIC 的包层（RFC 9000 section 17 / RFC 9001 section 5.4）。
//
// 两种包头：
//
//	长头（Initial / Handshake，本实现只用这两种）：首字节高位 1，带版本号、
//	  目标/源连接 ID；Initial 还带 token 和长度字段。
//	短头（1-RTT）：首字节高位 0，只有目标连接 ID；**没有长度字段**——报文
//	  的边界由 UDP 数据报本身给出。
//
// 头保护：首字节的低 4 位（长头）/低 5 位（短头）和包序号的 1~4 字节被一个
// 掩码异或。掩码来自"包序号偏移 +4 起的 16 字节样本"用 AES-ECB 加密后的
// 前 16 字节（RFC 9001 5.4.1）。**必须先解保护才能知道包序号，也才知道
// nonce**——这是 QUIC 和 TLS 记录层最不一样的地方。
//
// 这里的状态约定：header.raw 指向**整个报文**，unprotect 就地把首字节和
// 包序号改成明文形态；于是 AEAD 的关联数据（AD）就是 raw[:pnOffset+pnLen]，
// 不用另外拼。

const (
	packetVersion1 = 0x00000001

	pktInitial   = 0x00
	pktZeroRTT   = 0x01
	pktHandshake = 0x02
	pktRetry     = 0x03

	// connIDLen 是我们自己发的连接 ID 长度（服务端）。短头里目标连接 ID
	// 不带长度字段，靠这个约定切。
	connIDLen = 8
)

// header 是一个解析出来的包头。raw 始终指向整个报文。
type header struct {
	long     bool
	typ      byte
	dcid     []byte
	scid     []byte
	token    []byte
	pn       uint64
	pnLen    int
	ctEnd    int    // 长头：密文结束的位置（raw 里的下标）
	pnOffset int    // 包序号在 raw 里的偏移
	raw      []byte // 整个报文；unprotect 之后头部分是明文
	payload  []byte // 密文（raw 里去掉包头和包序号的部分）
}

var (
	errShort = errors.New("quic: packet too short")
	// ErrAuth 是 AEAD 校验失败（包被篡改，或者密钥不对）。
	ErrAuth = errors.New("quic: packet authentication failed")
)

// parseHeader 解出包头的结构（首字节和包序号**还没**解保护）。
//
// dcidLen 是短头里目标连接 ID 的固定长度（我们自己发的连接 ID 长度）。
func parseHeader(b []byte, dcidLen int) (*header, error) {
	if len(b) < 1 {
		return nil, errShort
	}
	h := &header{raw: b}
	if b[0]&0x80 != 0 {
		h.long = true
		h.typ = (b[0] >> 4) & 0x03
		if len(b) < 7 {
			return nil, errShort
		}
		if binary.BigEndian.Uint32(b[1:5]) != packetVersion1 {
			return nil, errors.New("quic: unsupported version")
		}
		off := 5
		dl := int(b[off])
		off++
		if off+dl > len(b) {
			return nil, errShort
		}
		h.dcid = b[off : off+dl]
		off += dl
		if off >= len(b) {
			return nil, errShort
		}
		sl := int(b[off])
		off++
		if off+sl > len(b) {
			return nil, errShort
		}
		h.scid = b[off : off+sl]
		off += sl
		if h.typ == pktInitial {
			tl, n, err := readVarint(b[off:])
			if err != nil {
				return nil, err
			}
			off += n
			if off+int(tl) > len(b) {
				return nil, errShort
			}
			h.token = b[off : off+int(tl)]
			off += int(tl)
		}
		if h.typ == pktRetry {
			h.payload = b[off:]
			return h, nil
		}
		pl, n, err := readVarint(b[off:])
		if err != nil {
			return nil, err
		}
		off += n
		if off+int(pl) > len(b) {
			return nil, errShort
		}
		h.pnOffset = off
		h.ctEnd = off + int(pl)
	} else {
		if len(b) < 1+dcidLen {
			return nil, errShort
		}
		h.dcid = b[1 : 1+dcidLen]
		h.pnOffset = 1 + dcidLen
		h.payload = b[h.pnOffset:]
	}
	return h, nil
}

// unprotect 解掉首字节和包序号上的掩码（**就地改 raw**），定下包序号长度，
// 并把 payload 切成真正的密文。
func (h *header) unprotect(k *keys, largestPN uint64) error {
	if h.typ == pktRetry && h.long {
		return nil // Retry 不做头保护
	}
	// 样本：包序号偏移 +4 起的 16 字节。载荷不够长时按 0 补齐（RFC 9001 5.4.2）
	var sample [16]byte
	for i := 0; i < 16; i++ {
		idx := h.pnOffset + 4 + i
		if idx < len(h.raw) {
			sample[i] = h.raw[idx]
		}
	}
	mask := k.headerMask(sample[:], &[16]byte{})

	first := h.raw[0]
	if h.long {
		first ^= mask[0] & 0x0f
	} else {
		first ^= mask[0] & 0x1f
	}
	h.raw[0] = first
	h.pnLen = int(first&0x03) + 1
	if h.pnOffset+h.pnLen > len(h.raw) {
		return errShort
	}
	var pn uint64
	for i := 0; i < h.pnLen; i++ {
		b := h.raw[h.pnOffset+i] ^ mask[1+i]
		h.raw[h.pnOffset+i] = b
		pn = pn<<8 | uint64(b)
	}
	h.pn = decodePN(pn, h.pnLen, largestPN)
	// 长头有长度字段：密文按它截断（后面可能是同一数据报里的下一个包）。
	// 短头没有长度字段，报文边界由数据报给出，取到末尾。
	end := len(h.raw)
	if h.long && h.ctEnd > 0 && h.ctEnd <= end {
		end = h.ctEnd
	}
	h.payload = h.raw[h.pnOffset+h.pnLen : end]
	return nil
}

// decodePN 按"最大已收包序号"还原完整包序号（RFC 9000 A.3）。
func decodePN(truncated uint64, pnLen int, largest uint64) uint64 {
	expected := largest + 1
	win := uint64(1) << (pnLen * 8)
	half := win / 2
	if expected < half {
		return truncated
	}
	maskbits := win - 1
	candidate := (expected &^ maskbits) | truncated
	if candidate+half <= expected {
		candidate += win
	} else if candidate > expected+half && candidate >= win {
		candidate -= win
	}
	return candidate
}

// open 解开载荷。调用前先 unprotect。
func (h *header) open(k *keys) ([]byte, error) {
	if k == nil || k.aead == nil {
		return nil, errNoKeys
	}
	var nb [12]byte
	ad := h.raw[:h.pnOffset+h.pnLen]
	pt, err := k.aead.Open(nil, k.nonce(h.pn, &nb), h.payload, ad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// sealHeader 把包头写进 dst（首字节和包序号是**明文形态**），返回包序号偏移。
//
// payloadLen 只有长头用得到：长度字段在包序号**之前**（RFC 9000 17.2 的顺序
// 是 首字节|版本|DCID|SCID|Token|长度|包序号），写错位置解析就会错位。
func sealHeader(dst []byte, long bool, typ byte, dcid, scid, token []byte, payloadLen, overhead int, pn uint64, pnLen int) (out []byte, pnOffset int) {
	first := byte(0x40 | (pnLen - 1)) // 定长包序号位（0x40）
	if long {
		first |= 0x80 | (typ << 4)
	}
	out = append(dst, first)
	if long {
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], packetVersion1)
		out = append(out, v[:]...)
		out = append(out, byte(len(dcid)))
		out = append(out, dcid...)
		out = append(out, byte(len(scid)))
		out = append(out, scid...)
		if typ == pktInitial {
			out = appendVarint(out, uint64(len(token)))
			out = append(out, token...)
		}
		// 长度 = 包序号 + 密文（含标签）
		out = appendVarint(out, uint64(pnLen+payloadLen+overhead))
	} else {
		out = append(out, dcid...)
	}
	pnOffset = len(out)
	for i := pnLen - 1; i >= 0; i-- {
		out = append(out, byte(pn>>(8*i)))
	}
	return out, pnOffset
}

// sealPacket 封一个完整的报文：包头 + AEAD 载荷 + 头保护。
func sealPacket(dst []byte, long bool, typ byte, dcid, scid, token []byte, pn uint64, payload []byte, k *keys) []byte {
	const pnLen = 2
	// 取样要"包序号偏移 +4 起 16 字节"，即 密文长度 >= 20-pnLen。不够就在
	// **明文**里补 PADDING 帧（0x00，RFC 9000 19.1）——补在密文外面的话
	// 对端会把零当成密文，AEAD 验不过。
	if min := 20 - pnLen - k.aead.Overhead(); len(payload) < min {
		padded := make([]byte, min)
		copy(padded, payload)
		payload = padded
	}
	start := len(dst)
	dst, pnOffset := sealHeader(dst, long, typ, dcid, scid, token, len(payload), k.aead.Overhead(), pn, pnLen)
	// 头（明文形态）就是 AD；AEAD 从包头后面接着写
	ad := dst[start:]
	var nb [12]byte
	dst = k.aead.Seal(dst, k.nonce(pn, &nb), payload, ad)

	// **包太短就把明文补够**，别在密文外面补零：取样要的是"包序号偏移 +4 起
	// 16 字节"（RFC 9001 5.4.2），对端解保护时也按同一段取；在密文外面补
	// 零会让对端把那些零当成密文的一部分，AEAD 直接验不过（踩过）。
	_ = pnOffset
	var sample [16]byte
	copy(sample[:], dst[pnOffset+4:pnOffset+20])
	mask := k.headerMask(sample[:], &[16]byte{})
	if long {
		dst[start] ^= mask[0] & 0x0f
	} else {
		dst[start] ^= mask[0] & 0x1f
	}
	for i := 0; i < pnLen; i++ {
		dst[pnOffset+i] ^= mask[1+i]
	}
	return dst
}
