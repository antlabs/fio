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
	"bytes"
	"testing"
)

// 封一个包、再解回来，载荷要一模一样（长头和短头都过一遍）。
func TestPacketRoundTrip(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	scid := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	send, recv, err := deriveInitial(dcid)
	if err != nil {
		t.Fatal(err)
	}
	// 发送方用 client 密钥、接收方用 server 密钥解 —— 这里都拿 client 那套
	// 当"同一个方向"来验往返。
	payloads := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte("x"), 1500),
		{}, // 空载荷
	}
	for _, p := range payloads {
		for _, tc := range []struct {
			name string
			long bool
			typ  byte
		}{
			{"initial", true, pktInitial},
			{"handshake", true, pktHandshake},
			{"1rtt", false, 0},
		} {
			var token []byte
			if tc.typ == pktInitial {
				token = []byte("tok")
			}
			pkt := sealPacket(nil, tc.long, tc.typ, dcid, scid, token, 42, p, send)
			h, err := parseHeader(pkt, len(dcid))
			if err != nil {
				t.Fatalf("%s: parseHeader: %v", tc.name, err)
			}
			if err := h.unprotect(send, 0); err != nil {
				t.Fatalf("%s: unprotect: %v", tc.name, err)
			}
			if h.pn != 42 {
				t.Errorf("%s: pn = %d, want 42", tc.name, h.pn)
			}
			got, err := h.open(send)
			if err != nil {
				t.Fatalf("%s: open: %v", tc.name, err)
			}
			// 载荷太短时发送侧会补 PADDING 帧（0x00），所以解出来的是
			// "原文 + 若干 0"，只要求前缀相同。
			if !bytes.HasPrefix(got, p) {
				t.Errorf("%s: 解出来 %d 字节，前缀和原文（%d 字节）不等", tc.name, len(got), len(p))
			}
			_ = recv
		}
	}
}

// 客户端和服务端的 initial 密钥必须是两份不同的（防反射攻击）。
func TestInitialKeysDiffer(t *testing.T) {
	c, s, err := deriveInitial([]byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c.iv, s.iv) || bytes.Equal(c.hpK, s.hpK) {
		t.Fatal("客户端和服务端的 initial 密钥不该相同")
	}
	if len(c.iv) != 12 || len(c.hpK) != 16 {
		t.Fatalf("iv/hp 长度不对：%d/%d", len(c.iv), len(c.hpK))
	}
}

// 包序号还原（RFC 9000 A.3 的语义）。
func TestDecodePN(t *testing.T) {
	if got := decodePN(0xac5c02, 3, 0xabe8b3); got != 0xac5c02 {
		t.Errorf("decodePN = %#x, want 0xac5c02", got)
	}
	if got := decodePN(0xace8fe, 3, 0xabe8b3); got != 0xace8fe {
		t.Errorf("decodePN = %#x, want 0xace8fe", got)
	}
}

func TestVarint(t *testing.T) {
	for _, v := range []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1} {
		b := appendVarint(nil, v)
		got, n, err := readVarint(b)
		if err != nil || got != v || n != len(b) {
			t.Errorf("varint %d: 解出 %d（%d 字节，报错 %v）", v, got, n, err)
		}
	}
}
