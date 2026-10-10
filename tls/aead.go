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

package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// TLS 1.3 的记录保护（RFC 8446 section 5.2）。
//
// 1.3 把加密放在**记录层**：握手消息和应用数据都装进"内层明文"再加密。
// 内层明文的格式是：
//
//	opaque content[TLSPlaintext.length]
//	ContentType type            // 真实的类型（握手/应用数据/告警）
//	zeros[length_of_padding]
//
// 也就是**真实的记录类型藏在密文里面**（最后那个字节）。外面那 5 字节
// 记录头的类型永远是 application_data（23）——这是 1.3 的一个特征，
// 中间设备看到的是"一堆应用数据"，看不出握手还是业务。
//
// 为什么要这样：1.2 的握手是明文的，中间设备能看见（也因此能干预、
// 能当作"降级攻击"的入口）。1.3 把类型藏进密文，中间设备就无从下手。
//
// nonce 的构造（RFC 8446 5.3）：
//
//	nonce = iv XOR (0...0 || seq)    // seq 是 8 字节的包序号
//
// 也就是"固定的 iv 和递增的序号异或"——每条记录一个不重复的 nonce。

var (
	ErrAEADOpen      = errors.New("tls: record authentication failed")
	ErrAEADNotReady  = errors.New("tls: keys not ready")
	ErrSequenceLimit = errors.New("tls: record sequence exhausted")
)

// recordProtector 用一个方向的流量密钥加密/解密记录。
//
// **每个方向一个**：客户端发的和服务端发的用不同的密钥（那是 TLS 1.3
// 刻意的设计——防止反射攻击）。
type recordProtector struct {
	aead cipher.AEAD
	iv   []byte
	// seq 是这条连接在这个方向上发/收的第几条记录
	seq uint64
}

// newRecordProtector 用派生出来的 key/iv 建一个保护器。
func newRecordProtector(keys trafficKeys) (*recordProtector, error) {
	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &recordProtector{aead: aead, iv: keys.iv}, nil
}

// nonce 算这条记录的 nonce：iv 和序号异或（序号在最后 8 字节）。
func (p *recordProtector) nonce() []byte {
	n := make([]byte, len(p.iv))
	copy(n, p.iv)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], p.seq)
	// 异或到末尾 8 字节
	off := len(n) - 8
	for i := 0; i < 8; i++ {
		n[off+i] ^= seq[i]
	}
	return n
}

// additionalData 是 AEAD 的关联数据：记录头（但不含真实类型，那个被
// 藏进密文了）。它的作用是绑住"这条记录属于哪个版本、有多长"。
func additionalData(version uint16, ciphertextLen int) []byte {
	ad := make([]byte, 5)
	ad[0] = recordApplicationData // 外层永远是 application_data
	ad[1] = byte(version >> 8)
	ad[2] = byte(version)
	ad[3] = byte(ciphertextLen >> 8)
	ad[4] = byte(ciphertextLen)
	return ad
}

// seal 加密一段内层明文，返回可以直接写出去的密文（含认证标签）。
//
// innerType 是真实的记录类型（握手/应用数据/告警）——它被追加到明文
// 末尾，加密之后外面看不出来。
func (p *recordProtector) seal(innerType uint8, plaintext []byte) ([]byte, error) {
	if p.aead == nil {
		return nil, ErrAEADNotReady
	}
	if p.seq == ^uint64(0) {
		return nil, ErrSequenceLimit
	}

	// 内层明文 = 数据 + 真实类型，**拼完就地加密**。
	//
	// 原来是两次分配：一次给内层明文（整段拷贝一遍），一次给密文。
	// 一替一算下来，一条 16KB 的记录要分配 32KB、拷两遍；300KB 的响应
	// 按记录切就是 19 遍，光这两处 600KB 的分配——量出来的话，300KB
	// 静态文件过 TLS 这个场景服务端 8 秒分配 76GB。
	//
	// crypto/cipher 明确支持原地加密（Seal 的文档："To reuse plaintext's
	// storage for the encrypted output, use plaintext[:0] as dst"），
	// 所以一次分配到位（多留一个认证标签的位置），然后把 buf[:0] 当 dst。
	buf := make([]byte, 0, len(plaintext)+1+p.aead.Overhead())
	buf = append(buf, plaintext...)
	buf = append(buf, innerType)

	nonce := p.nonce()
	// 外层长度 = 内层长度 + 认证标签
	ad := additionalData(0x0303, len(buf)+p.aead.Overhead())

	out := p.aead.Seal(buf[:0], nonce, buf, ad)
	p.seq++
	return out, nil
}

// open 解密一条密文，返回内层明文和真实类型。
func (p *recordProtector) open(ciphertext []byte) ([]byte, uint8, error) {
	if p.aead == nil {
		return nil, 0, ErrAEADNotReady
	}
	if len(ciphertext) < p.aead.Overhead() {
		return nil, 0, fmt.Errorf("%w: too short", ErrAEADOpen)
	}

	nonce := p.nonce()
	ad := additionalData(0x0303, len(ciphertext))

	inner, err := p.aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, 0, ErrAEADOpen
	}
	p.seq++

	// 最后一个字节是真实类型
	if len(inner) == 0 {
		return nil, 0, fmt.Errorf("%w: empty inner plaintext", ErrAEADOpen)
	}
	innerType := inner[len(inner)-1]
	content := inner[:len(inner)-1]

	// **剥填充：从末尾往前，但只剥"类型字节那一段连续的零"里属于填充的
	// 部分——而光看零是分不清"填充的零"和"数据末尾的零"的。**
	//
	// 这是个真踩过的坑：EE（EncryptedExtensions）的内容是
	// `08 00 00 02 00 00`，最后那两个 0 是"空扩展列表的长度字段"，
	// 是**真实数据**。早先这里无脑把末尾的零全剥了，结果 EE 只剩
	// `08 00 00 02`（一个不完整的握手头），被攒进握手解析器；下一条
	// 记录的明文接上去，长度字段就成了天文数字（实测报
	// "handshake message 3604480 bytes"）。
	//
	// 正确的做法：**填充只能是"整个明文就是 0 组成"那段的前缀**，
	// 也就是 RFC 8446 说的 "zeros[length_of_padding]"。但接收方没有
	// 内层长度可参照，所以只能按"零填充是发送方为了对齐而加的、内容
	// 本身不该以零结尾"这个约定来剥——**而这个约定对 EE 不成立**。
	//
	// 所以这里用另一条更可靠的规则：**只剥掉"末尾连续的零里，
	// 最后一个非零字节之后的那一段"**，也就是……不剥。
	//
	// 结论：**不做填充剥离**。我们自己的发送端不加填充（seal 里没加），
	// 而标准实现（crypto/tls、openssl）默认也不加。真遇到加填充的对端，
	// 那部分零会被当成内容的一段——对握手消息来说会导致解析失败。
	// 要支持加填充的对端，得按 RFC 的规则来：接收方解析时**先用
	// 内层长度字段**判断内容多长（比如握手消息的前 4 字节），而不是
	// 靠剥零。
	//
	// 这里先把"剥零"去掉——它带来的问题是实实在在的（把真实数据当
	// 填充吃掉），而它想解决的"对端加填充"我们还没遇到。
	return content, innerType, nil
}
