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
	"slices"
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

	// nonceBuf / scratch 是复用的缓冲。
	//
	// 两者都是**每次调用都重新分配**的典型：nonce 12 字节、scratch 一条
	// 记录的密文（最多 16KB+），而一条连接上记录的条数是响应大小除以 16KB
	// ——300KB 的响应就是 19 遍。nonce 和 scratch 都只在函数体里用掉就丢
	// （GCM 同步读 nonce，密文由调用方当场 append 进输出），所以复用是安全的。
	nonceBuf []byte
	scratch  []byte
	// adBuf 是 additionalData 的复用缓冲（5 字节的记录头）。
	adBuf [5]byte
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
//
// 返回的切片归保护器所有，只在下一次 nonce 之前有效（GCM 是同步读它的，
// 不保留）。
func (p *recordProtector) nonce() []byte {
	if p.nonceBuf == nil {
		p.nonceBuf = make([]byte, len(p.iv))
	}
	n := p.nonceBuf
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
//
// 写进保护器自己的 adBuf 而不是自己 make：5 个字节不大，但这是**每条记录
// 每个方向各一次**的小分配，而记录数随响应大小线性增长——300KB 的响应是
// 19 条记录。返回的切片同样只在下一次调用前有效。
func (p *recordProtector) additionalData(version uint16, ciphertextLen int) []byte {
	p.adBuf[0] = recordApplicationData // 外层永远是 application_data
	p.adBuf[1] = byte(version >> 8)
	p.adBuf[2] = byte(version)
	p.adBuf[3] = byte(ciphertextLen >> 8)
	p.adBuf[4] = byte(ciphertextLen)
	return p.adBuf[:]
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
	//
	// 更进一步：这块缓冲本身也复用（p.scratch）。产物调用方都是当场就用掉
	// 的——两条调用路径（StateMachine.Write 和 sendHandshake）都是
	// AppendRecord(out, ..., ct)，那是往输出缓冲里拷一份，拷完 ct 就没人
	// 要了。所以**返回的切片只在下一次 seal 之前有效**。
	need := len(plaintext) + 1 + p.aead.Overhead()
	if cap(p.scratch) < need {
		p.scratch = make([]byte, 0, need)
	}
	buf := append(p.scratch[:0], plaintext...)
	buf = append(buf, innerType)

	nonce := p.nonce()
	// 外层长度 = 内层长度 + 认证标签
	ad := p.additionalData(0x0303, len(buf)+p.aead.Overhead())

	out := p.aead.Seal(buf[:0], nonce, buf, ad)
	p.scratch = out
	p.seq++
	return out, nil
}

// appendWindow 把"a 和 b 拼接之后、从 off 开始的 n 字节"追加到 dst。
//
// a、b 是两段连续语义的输入（HTTP 的响应头 + 响应体），窗口可能横跨两者的
// 交界，所以要分两次 append。调用方保证 off+n <= len(a)+len(b)。
func appendWindow(dst, a, b []byte, off, n int) []byte {
	if off < len(a) {
		k := len(a) - off
		if k > n {
			k = n
		}
		dst = append(dst, a[off:off+k]...)
		n -= k
		off = 0
	} else {
		off -= len(a)
	}
	if n > 0 {
		dst = append(dst, b[off:off+n]...)
	}
	return dst
}

// sealWindow 加密一段内层明文，把整条记录（5 字节头 + 密文）追加到 dst。
//
// 明文取自"a 和 b 拼接后的一段窗口"——两段是 HTTP 的响应头和响应体。
//
// **一条记录只拷一遍**：先按"记录头 + 明文 + 内层类型"的长度往 dst 里填，
// 然后把密文写回明文自己那块地方（Seal 允许的精确重叠）。对比 seal 那条路
// （明文→scratch、原地加密、密文→输出缓冲，两遍）。
//
// 为什么两条路的拷贝数不一样，是**量出来的**，不是推导出来的：
//
//	                static-tls   json-tls   static-h2 / baseline-h2
//	一遍（这个函数）   -4.9%        -1.3%      **+5.0% / +8.9%**
//	两遍（seal）        基准         基准         基准
//
// h1 的 WriteTwo 走这条路（一次调用就是一条输出缓冲，也就那一条响应），
// h2 的 Write 走 seal（一次调用的输出缓冲里装着多个流的输出，大得多）。
//
// **原因（第二次重测之后想明白了）**：这一版把明文拷进 dst 再原地加密，
// 加密得从 dst 读回来——**dst 大时读回的是冷数据**；两遍那版让明文落在
// p.scratch（一条记录的 16KB，复用、热），密文再 append 进输出缓冲。
// 所以"目标缓冲小 → 一遍好、大 → 两遍好"。
//
// 第一次的结论是在 **MTU 65536** 那个病态 regime 下量的（wrk 驱动的档会
// 掉 20 倍），本来不足为凭；2026-10-12 在 MTU 1500 下重测，h2 仍然
// **+8.9%**——两次一致，这次也解释得通了，就不再是"没解释清楚的分叉"。
func (p *recordProtector) sealWindow(dst []byte, innerType uint8, a, b []byte, off, n int) ([]byte, error) {
	if p.aead == nil {
		return dst, ErrAEADNotReady
	}
	if p.seq == ^uint64(0) {
		return dst, ErrSequenceLimit
	}

	// 外层长度 = 内层长度（窗口 + 类型 + 标签）
	ctLen := n + 1 + p.aead.Overhead()
	start := len(dst)

	// 容量先留够（记录头 + 明文 + 内层类型 + 标签）。
	//
	// **不能省**：Seal 在 dst 的容量放不下标签时不报错，它返回另分配的一块
	// 的切片——密文就落不到 dst 里，写出去的是明文（对端报 bad record MAC）。
	if cap(dst) < start+recordHeaderLen+ctLen {
		grown := make([]byte, len(dst), start+recordHeaderLen+ctLen)
		copy(grown, dst)
		dst = grown
	}

	// 预留记录头，紧接着窗口里的明文和内层类型
	dst = append(dst, 0, 0, 0, 0, 0)
	dst = appendWindow(dst, a, b, off, n)
	dst = append(dst, innerType)

	// 明文把自己那块地方让给密文：两者起点相同，是 Seal 允许的精确重叠
	ct := dst[start+recordHeaderLen:]
	p.aead.Seal(ct[:0], p.nonce(), ct, p.additionalData(0x0303, ctLen))
	// 密文比明文长一个标签，把 dst 伸到它的全长
	dst = dst[:start+recordHeaderLen+ctLen]

	h := dst[start : start+recordHeaderLen]
	h[0] = recordApplicationData
	h[1] = 0x03
	h[2] = 0x03
	h[3] = byte(ctLen >> 8)
	h[4] = byte(ctLen)

	p.seq++
	return dst, nil
}

// openInto 解密一条密文，**解到 dst 的尾巴上**，返回追加后的 dst 和真实类型。
//
// 调用方传进来的就是攒明文的那块缓冲（StateMachine.plaintext），于是解出来
// 的明文不用先落到一块临时缓冲、再 append 拷进去。原来那条路是每条记录一次
// `aead.Open(nil, ...)`（分配一块）+ 一次 append（再拷一遍）——100KB 的请求体
// 按 16KB 一条记录切就是 7 条，7 次分配、7 次多余拷贝，全在 GC 的账上。
//
// 返回的切片**末尾带着内层的真实类型字节**（TLS 1.3 把真实类型藏在密文里，
// 见文件开头那段），调用方自己剥。返回的切片**只在调用方再动 dst 之前有效**。
func (p *recordProtector) openInto(dst []byte, ciphertext []byte) ([]byte, uint8, error) {
	if p.aead == nil {
		return dst, 0, ErrAEADNotReady
	}
	if len(ciphertext) < p.aead.Overhead() {
		return dst, 0, fmt.Errorf("%w: too short", ErrAEADOpen)
	}

	base := len(dst)
	// 先把容量留够，Open 才能写在 dst 的尾巴上而不是另分配一块。
	// 用 slices.Grow 而不是自己 make：它按倍增扩，不会让这里变成 O(n^2)
	// （plaintext 是攒整条请求体的）。
	dst = slices.Grow(dst, len(ciphertext)-p.aead.Overhead())

	// dst[base:base] 的容量就是 Open 能落脚的地方
	plain, err := p.aead.Open(dst[base:base], p.nonce(), ciphertext,
		p.additionalData(0x0303, len(ciphertext)))
	if err != nil {
		return dst, 0, ErrAEADOpen
	}
	p.seq++

	out := dst[:base+len(plain)]
	if len(plain) == 0 {
		return out, 0, fmt.Errorf("%w: empty inner plaintext", ErrAEADOpen)
	}
	return out, out[len(out)-1], nil
}
