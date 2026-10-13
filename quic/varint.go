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

import "errors"

// QUIC 的可变长整数（RFC 9000 section 16）：头两个二进制位定长度
// （1/2/4/8 字节），剩下 62 位放值。和 HTTP/3 那一份是同一种编码，
// 但这个包不依赖 http3（依赖方向是 http3 在 quic 之上）。

var errVarint = errors.New("quic: bad varint")

// varintLen 值占几个字节。
func varintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	default:
		return 8
	}
}

// appendVarint 把 v 编进去。
func appendVarint(dst []byte, v uint64) []byte {
	n := varintLen(v)
	switch n {
	case 1:
		return append(dst, byte(v))
	case 2:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case 4:
		return append(dst, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst,
			byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// readVarint 解一个可变长整数，返回值和消耗的字节数。
func readVarint(b []byte) (uint64, int, error) {
	if len(b) < 1 {
		return 0, 0, errVarint
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, errVarint
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}
