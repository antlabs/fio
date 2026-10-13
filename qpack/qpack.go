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

// Package qpack 是 HTTP/3 的头压缩（RFC 9204）。
//
// **只做静态表这一档**：动态表（跨流的编码器/解码器指令、阻塞流、容量协商）
// 一概不做——fio 的 HTTP/3 在 SETTINGS 里把 MAX_TABLE_CAPACITY 和
// BLOCKED_STREAMS 都报 0，对端就只能用静态表和字面量，解码器不需要任何
// 跨流状态（也就不需要在几条 lane 之间加锁）。这也是 h3 那一层的用法约定，
// 见 http3/native.go。
//
// Huffman（RFC 7541 附录 B）用 golang.org/x/net/http2/hpack 的表和实现：
// 那是 HPACK/QPACK 共用的同一张码表，自己抄 257 项没有意义。**编码侧可以
// 不用 Huffman**（协议里是可选的），但解码侧必须支持——客户端（quic-go）
// 发过来的字面量是压过的。
package qpack

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

// HeaderField 是一个头字段。字段名在 HTTP/3 里要求全小写。
type HeaderField struct {
	Name, Value string
}

var (
	// errDynamicTable 对端用了动态表。我们的 SETTINGS 声明容量为 0，
	// 对端还发动态表引用的话是协议错误。
	errDynamicTable = errors.New("qpack: dynamic table is not supported")
	errBadIndex     = errors.New("qpack: invalid static table index")
	errShortBlock   = errors.New("qpack: truncated field line")
)

// ---------------------------------------------------------------------------
// 整数编码（RFC 9204 4.1.1）
//
// 前缀几个 bit 存小值；存不下时前缀全 1，后面跟 128 进制的续字节。
// QPACK 里所有长度/索引字段都是这个编码。

// appendInt 把一个整数按 prefix 位前缀编码进 dst。
func appendInt(dst []byte, prefix uint8, v uint64) []byte {
	max := uint64(1)<<prefix - 1
	if v < max {
		return append(dst, byte(v))
	}
	dst = append(dst, byte(max))
	v -= max
	for v >= 128 {
		dst = append(dst, byte(v%128+128))
		v /= 128
	}
	return append(dst, byte(v))
}

// readInt 解一个前缀整数，返回值和剩下的字节。
func readInt(prefix uint8, b []byte) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, nil, errShortBlock
	}
	max := uint64(1)<<prefix - 1
	v := uint64(b[0]) & max
	b = b[1:]
	if v < max {
		return v, b, nil
	}
	// 续字节：每字节 7 位，最高位是"还有"
	var shift uint
	for {
		if len(b) == 0 {
			return 0, nil, errShortBlock
		}
		c := b[0]
		b = b[1:]
		v += uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, b, nil
		}
		shift += 7
		if shift > 56 {
			return 0, nil, errors.New("qpack: integer too large")
		}
	}
}

// ---------------------------------------------------------------------------
// 编码器

// Encoder 把头字段编成 QPACK 字段块，写进 w。
//
// 一次"字段块"的生命周期：NewEncoder（或复用）-> 若干 WriteField ->
// Close（复位，下次写新的块）。和 HPACK 的 Encoder 形状一样。
type Encoder struct {
	w           io.Writer
	buf         []byte
	wrotePrefix bool
}

// NewEncoder 建一个编码器，输出写到 w。
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// WriteField 编一个字段。第一个字段之前会先写字段块前缀
// （Required Insert Count = 0、Delta Base = 0——没有动态表）。
func (e *Encoder) WriteField(f HeaderField) error {
	if !e.wrotePrefix {
		// 前缀：Required Insert Count（8 位前缀）+ Delta Base（7 位前缀），
		// 都是 0。RFC 9204 4.5.1 说 RIC 为 0 时 Delta Base 也必须是 0，
		// 但**字段还是要在**（对端的解码器会读它）。
		e.buf = appendInt(e.buf, 8, 0)
		e.buf = appendInt(e.buf, 7, 0)
		e.wrotePrefix = true
	}

	// 1. 名字+值都在静态表里：索引字段行（1 T index，T=1 静态）
	if idx, ok := staticByField[f.Name+"\x00"+f.Value]; ok {
		e.writeIndexed(idx)
	} else if idx, ok := staticByName[f.Name]; ok {
		// 2. 名字在表里：带名引用的字面量（0 1 N T nameIdx，T=1 静态，N=0）
		e.writeLiteralWithNameRef(idx, f.Value)
	} else {
		// 3. 名字也不在：带字面量名字的字面量
		e.writeLiteralWithLiteralName(f)
	}

	_, err := e.w.Write(e.buf)
	e.buf = e.buf[:0]
	return err
}

// Close 结束一个字段块（这里只是复位，下个块重新写前缀）。
func (e *Encoder) Close() error {
	var err error
	if !e.wrotePrefix {
		// 一个字段都没有的块也要有前缀（2 个 0 字节），不然对端解不出来
		e.buf = appendInt(e.buf, 8, 0)
		e.buf = appendInt(e.buf, 7, 0)
		_, err = e.w.Write(e.buf)
		e.buf = e.buf[:0]
	}
	e.wrotePrefix = false
	return err
}

// writeIndexed 索引字段行：1 T Index(6+)，T=1 表示静态表。
func (e *Encoder) writeIndexed(idx uint64) {
	off := len(e.buf)
	e.buf = appendInt(e.buf, 6, idx)
	e.buf[off] |= 0xc0 // 1 + T=1
}

// writeLiteralWithNameRef 带名引用的字面量：0 1 N T NameIdx(4+) + 值。
func (e *Encoder) writeLiteralWithNameRef(idx uint64, value string) {
	off := len(e.buf)
	e.buf = appendInt(e.buf, 4, idx)
	e.buf[off] |= 0x50 // 01 + N=0 + T=1
	e.appendValue(value)
}

// writeLiteralWithLiteralName 带字面量名字的字面量：
// 0 0 1 N H NameLen(3+) Name + H ValueLen(7+) Value。
func (e *Encoder) writeLiteralWithLiteralName(f HeaderField) {
	off := len(e.buf)
	e.buf = appendInt(e.buf, 3, uint64(hpack.HuffmanEncodeLength(f.Name)))
	e.buf[off] |= 0x28 // 001 + N=0 + H=1（名字用 Huffman）
	e.buf = hpack.AppendHuffmanString(e.buf, f.Name)
	e.appendValue(f.Value)
}

// appendValue 写值的部分：H(1) + 长度(7+) + 字节（Huffman）。
func (e *Encoder) appendValue(value string) {
	off := len(e.buf)
	e.buf = appendInt(e.buf, 7, uint64(hpack.HuffmanEncodeLength(value)))
	e.buf[off] |= 0x80 // H=1
	e.buf = hpack.AppendHuffmanString(e.buf, value)
}

// ---------------------------------------------------------------------------
// 解码器

// Decoder 解 QPACK 字段块。
//
// 是**无状态**的（没有动态表，也就没有跨流状态）：一个实例几条 lane
// 同时用也没事，h3 那层就是这么用的。
type Decoder struct{}

// NewDecoder 建一个解码器。
func NewDecoder() *Decoder { return &Decoder{} }

// Decode 返回一个迭代器：每次调用给出一个头字段，块读完返回 io.EOF。
//
// 形状和 quic-go/qpack 的一样（http3 那层的调用方式）。字段块前缀在这里
// **只解一次**——它是整个块的头，不是一个字段。
func (d *Decoder) Decode(b []byte) func() (HeaderField, error) {
	// 字段块前缀（RFC 9204 4.5.1）：Required Insert Count(8+) + Delta Base(7+)。
	// 动态表容量为 0，所以两个都必须是 0。
	var err error
	ric, rest, rerr := readInt(8, b)
	if rerr != nil {
		err = rerr
	} else if ric != 0 {
		err = errDynamicTable
	} else if base, rest2, berr := readInt(7, rest); berr != nil {
		err = berr
	} else if base != 0 {
		err = errDynamicTable
	} else {
		b = rest2
	}
	return func() (HeaderField, error) {
		if err != nil {
			return HeaderField{}, err
		}
		if len(b) == 0 {
			return HeaderField{}, io.EOF
		}
		var hf HeaderField
		hf, b, err = d.fieldLine(b)
		return hf, err
	}
}

// fieldLine 解一条字段行（RFC 9204 4.5.2~4.5.6）。
func (d *Decoder) fieldLine(b []byte) (HeaderField, []byte, error) {
	first := b[0]
	switch {
	case first&0x80 != 0:
		// 索引字段行：1 T Index(6+)
		if first&0x40 == 0 {
			return HeaderField{}, nil, errDynamicTable
		}
		idx, rest, err := readInt(6, b)
		if err != nil {
			return HeaderField{}, nil, err
		}
		if idx >= uint64(len(staticTableEntries)) {
			return HeaderField{}, nil, errBadIndex
		}
		return staticTableEntries[idx], rest, nil

	case first&0x40 != 0:
		// 带名引用的字面量：0 1 N T NameIdx(4+) + 值
		if first&0x10 == 0 {
			return HeaderField{}, nil, errDynamicTable
		}
		idx, rest, err := readInt(4, b)
		if err != nil {
			return HeaderField{}, nil, err
		}
		if idx >= uint64(len(staticTableEntries)) {
			return HeaderField{}, nil, errBadIndex
		}
		val, rest, err := readString(rest)
		if err != nil {
			return HeaderField{}, nil, err
		}
		return HeaderField{Name: staticTableEntries[idx].Name, Value: val}, rest, nil

	case first&0x20 != 0:
		// 带字面量名字的字面量：0 0 1 N H NameLen(3+) Name + H ValueLen(7+) Value
		//
		// **名字那段的 H 位是 0x08，不是 0x80**：名字长度只占 3 位前缀，
		// H 挤在低 4 位里（0 0 1 N H），值的 H 才是最高位。看错一位的
		// 后果是把 Huffman 字节当明文名字用（解出来一串乱码）。
		name, rest, err := readStringWithPrefix(3, 0x08, b)
		if err != nil {
			return HeaderField{}, nil, err
		}
		val, rest, err := readString(rest)
		if err != nil {
			return HeaderField{}, nil, err
		}
		return HeaderField{Name: name, Value: val}, rest, nil

	default:
		// 0000xxxx / 0001xxxx：post-base 索引，都是动态表的东西
		return HeaderField{}, nil, errDynamicTable
	}
}

// readString 读一个"H(1) + 长度(7+) + 字节"的字符串。
func readString(b []byte) (string, []byte, error) {
	return readStringWithPrefix(7, 0x80, b)
}

// readStringWithPrefix 读 "长度(prefix+) + 字节"，H 置位就 Huffman 解压。
//
// hMask 是 H 位在该位置上的掩码：长度占 7 位前缀时是 0x80（值那一段），
// 占 3 位前缀时是 0x08（带字面量名字的名字那一段）。
func readStringWithPrefix(prefix uint8, hMask byte, b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", nil, errShortBlock
	}
	huff := b[0]&hMask != 0
	n, rest, err := readInt(prefix, b)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(rest)) < n {
		return "", nil, fmt.Errorf("qpack: string length %d exceeds block", n)
	}
	raw := rest[:n]
	rest = rest[n:]
	if !huff {
		return string(raw), rest, nil
	}
	s, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", nil, fmt.Errorf("qpack: huffman: %w", err)
	}
	return s, rest, nil
}
