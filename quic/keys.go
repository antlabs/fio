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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// QUIC 的包保护密钥派生（RFC 9001 section 5）。
//
// 两种来源：
//
//	Initial 级别  从**初始目标连接 ID** 推（下面的 initialSalt），固定值——
//	              握手还没开始，双方只能靠这个约定对上。
//	Handshake/1-RTT 从 TLS 交出来的 traffic secret 推（quic.SetReadSecret /
//	              SetWriteSecret 两个事件）——TLS 1.3 的密钥调度照旧由
//	              crypto/tls 做，这里只换标签。
//
// 每个级别三样东西：
//
//	key   AEAD 的密钥
//	iv    和包序号异或出 nonce
//	hp    头保护（AES-ECB 算掩码，只取前 16 字节）

// initialSalt 是 RFC 9001 5.2 钉死的那个盐。
var initialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// keys 是一个方向、一个加密级别的包保护材料。
type keys struct {
	aead cipher.AEAD
	// hp 是头保护用的块密码（AES-ECB），掩码取它加密 16 字节样本的结果
	hp  cipher.Block
	iv  []byte
	hpK []byte
	// secret 是推出这一代密钥的 traffic secret。只有它才能推出下一代
	// （密钥更新，RFC 9001 6.1），所以存着。
	secret []byte
}

// next 推下一代密钥（RFC 9001 6.1）：
//
//	secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
//
// **只换 AEAD 的 key/iv，头保护密钥（quic hp）不换。** RFC 9001 6 的原文：
// "同一个头保护密钥在整个连接期间使用，密钥更新之后也不变"——Key Phase
// 位本身也被头保护盖着，靠的就是这一点才能稳定地解出来。头保护跟着换的
// 话，换代之后每个包解出来的首字节都是乱的（表现成 pnLen 变成 4、包序号
// 大得离谱），对端一切正常、我们自己全崩。
//
// 只有 1-RTT 会换代（Initial/Handshake 的密钥跟着握手走，不存在更新）。
func (k *keys) next() (*keys, error) {
	if len(k.secret) == 0 {
		return nil, errors.New("quic: no secret to update from")
	}
	secret := hkdfExpandLabel(k.secret, "quic ku", len(k.secret))
	key := hkdfExpandLabel(secret, "quic key", 16)
	iv := hkdfExpandLabel(secret, "quic iv", 12)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &keys{aead: aead, hp: k.hp, iv: iv, hpK: k.hpK, secret: secret}, nil
}

var errNoKeys = errors.New("quic: no keys for this level")

// hkdfExpandLabel 是 TLS 1.3 的 HKDF-Expand-Label（RFC 8446 7.1），QUIC 也用它
// （RFC 9001 5.1）。info = "tls13 " + label 的长度前缀形式。
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // context 为空
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err) // 长度合法时不会失败
	}
	return out
}

// deriveKeys 从 traffic secret 推一个级别的 key/iv/hp（RFC 9001 5.1）。
//
// 注意标签是 "quic key"/"quic iv"/"quic hp"，**不是** TLS 记录层用的
// "key"/"iv"——同一份 secret 在 QUIC 和 TLS 记录层里导出的是不同的密钥。
func deriveKeys(secret []byte) (*keys, error) {
	key := hkdfExpandLabel(secret, "quic key", 16)
	iv := hkdfExpandLabel(secret, "quic iv", 12)
	hp := hkdfExpandLabel(secret, "quic hp", 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	return &keys{aead: aead, hp: hpBlock, iv: iv, hpK: hp, secret: append([]byte(nil), secret...)}, nil
}

// deriveInitial 推 Initial 级别的密钥（RFC 9001 5.2）。
//
//	initial_secret        = HKDF-Extract(initial_salt, client_dst_connection_id)
//	client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//	server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
func deriveInitial(dcid []byte) (client, server *keys, err error) {
	initialSecret, err := hkdf.Extract(sha256.New, dcid, initialSalt)
	if err != nil {
		return nil, nil, err
	}
	cs := hkdfExpandLabel(initialSecret, "client in", 32)
	ss := hkdfExpandLabel(initialSecret, "server in", 32)
	if client, err = deriveKeys(cs); err != nil {
		return nil, nil, err
	}
	if server, err = deriveKeys(ss); err != nil {
		return nil, nil, err
	}
	return client, server, nil
}

// nonce 由 iv 和包序号异或出来（序号右对齐，RFC 9001 5.3）。
func (k *keys) nonce(pn uint64, buf *[12]byte) []byte {
	copy(buf[:], k.iv)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], pn)
	for i := 0; i < 8; i++ {
		buf[4+i] ^= seq[i]
	}
	return buf[:]
}

// headerMask 用头保护密钥算掩码：AES-ECB 加密 16 字节样本（RFC 9001 5.4.1）。
func (k *keys) headerMask(sample []byte, buf *[16]byte) []byte {
	k.hp.Encrypt(buf[:], sample)
	return buf[:]
}
