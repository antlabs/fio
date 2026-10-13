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

// QUIC 的传输参数（RFC 9000 section 18.2）：一串 TLV，
// 每项是 可变长整数 id + 可变长整数长度 + 值。放在 TLS 的
// encrypted_extensions 里（服务端）和 ClientHello 里（客户端）。

const (
	tpMaxIdleTimeout          = 0x01
	tpMaxUDPPayloadSize       = 0x03
	tpInitialMaxData          = 0x04
	tpInitialMaxStreamDataBidiLocal  = 0x05
	tpInitialMaxStreamDataBidiRemote = 0x06
	tpInitialMaxStreamDataUni        = 0x07
	tpInitialMaxStreamsBidi   = 0x08
	tpInitialMaxStreamsUni    = 0x09
	tpAckDelayExponent        = 0x0a
	tpMaxAckDelay             = 0x0b
	tpDisableActiveMigration  = 0x0c
	tpActiveConnIDLimit       = 0x0e
	tpInitialSourceConnID     = 0x0f
)

// transportParams 是我们（服务端）发出去的那一份。
//
// 窗口都给得很大：这两档跑在回环上，流控不该成为任何东西的瓶颈——
// 流控帧本身也是每请求的开销。
type transportParams struct {
	maxUDPPayload       uint64
	initialMaxData      uint64
	initialMaxStreamData uint64
	initialMaxStreamsBidi uint64
	initialMaxStreamsUni  uint64
	idleTimeout         uint64 // 毫秒
}

func (p transportParams) appendTo(dst []byte) []byte {
	dst = appendVarint(dst, tpMaxIdleTimeout)
	dst = appendVarint(dst, 1)
	dst = appendVarint(dst, p.idleTimeout)

	dst = appendVarint(dst, tpMaxUDPPayloadSize)
	dst = appendVarint(dst, 2)
	dst = appendVarint(dst, p.maxUDPPayload)

	dst = appendVarint(dst, tpInitialMaxData)
	dst = appendVarint(dst, uint64(varintLen(p.initialMaxData)))
	dst = appendVarint(dst, p.initialMaxData)

	dst = appendVarint(dst, tpInitialMaxStreamDataBidiLocal)
	dst = appendVarint(dst, uint64(varintLen(p.initialMaxStreamData)))
	dst = appendVarint(dst, p.initialMaxStreamData)
	dst = appendVarint(dst, tpInitialMaxStreamDataBidiRemote)
	dst = appendVarint(dst, uint64(varintLen(p.initialMaxStreamData)))
	dst = appendVarint(dst, p.initialMaxStreamData)
	dst = appendVarint(dst, tpInitialMaxStreamDataUni)
	dst = appendVarint(dst, uint64(varintLen(p.initialMaxStreamData)))
	dst = appendVarint(dst, p.initialMaxStreamData)

	dst = appendVarint(dst, tpInitialMaxStreamsBidi)
	dst = appendVarint(dst, uint64(varintLen(p.initialMaxStreamsBidi)))
	dst = appendVarint(dst, p.initialMaxStreamsBidi)
	dst = appendVarint(dst, tpInitialMaxStreamsUni)
	dst = appendVarint(dst, uint64(varintLen(p.initialMaxStreamsUni)))
	dst = appendVarint(dst, p.initialMaxStreamsUni)

	// 禁掉连接迁移：回环上没有"换路径"这回事，不声明的话对端会等着
	// 我们支持它。
	dst = appendVarint(dst, tpDisableActiveMigration)
	dst = appendVarint(dst, 0)
	return dst
}

// peerParams 是对端给的那一份里我们用得到的字段。
type peerParams struct {
	maxUDPPayload          uint64
	initialMaxData         uint64
	initialMaxStreamData   uint64 // 对端允许我们发的单流上限
	initialMaxStreamsBidi  uint64
	initialMaxStreamsUni   uint64
	idleTimeout            uint64
}

// parseTransportParams 解对端的传输参数。认识的记住，不认识的原样跳过
// （RFC 9000 18.1：多出来的参数要**忽略**，不能报错——将来加参数是常态）。
func parseTransportParams(b []byte) peerParams {
	p := peerParams{
		maxUDPPayload:         1252, // 缺省值（RFC 9000 18.2）
		initialMaxData:        0,
		initialMaxStreamData:  0,
		initialMaxStreamsBidi: 0,
		initialMaxStreamsUni:  0,
	}
	for len(b) > 0 {
		id, n, err := readVarint(b)
		if err != nil {
			return p
		}
		b = b[n:]
		l, n, err := readVarint(b)
		if err != nil {
			return p
		}
		b = b[n:]
		if int(l) > len(b) {
			return p
		}
		v := b[:l]
		b = b[l:]
		switch id {
		case tpMaxUDPPayloadSize:
			x, _, _ := readVarint(v)
			if x >= 1200 {
				p.maxUDPPayload = x
			}
		case tpInitialMaxData:
			p.initialMaxData, _, _ = readVarint(v)
		case tpInitialMaxStreamDataBidiRemote:
			p.initialMaxStreamData, _, _ = readVarint(v)
		case tpInitialMaxStreamsBidi:
			p.initialMaxStreamsBidi, _, _ = readVarint(v)
		case tpInitialMaxStreamsUni:
			p.initialMaxStreamsUni, _, _ = readVarint(v)
		case tpMaxIdleTimeout:
			p.idleTimeout, _, _ = readVarint(v)
		}
	}
	return p
}
