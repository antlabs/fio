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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// CertificateVerify 的签名（RFC 8446 section 4.4.3）。
//
// 服务端用证书私钥签一段特定的内容，客户端验签——证明"我确实持有这个
// 证书的私钥"，而不是"我捡到了别人的证书"（证书是公开的，谁都能拿到）。
//
// 签名的内容是：
//
//	64 个 0x20（空格）
//	"TLS 1.3, server CertificateVerify" 或 "TLS 1.3, client CertificateVerify"
//	0x00
//	Transcript-Hash（到 Certificate 为止的握手哈希）
//
// **那 64 个空格 + 那行文字是刻意的**：让待签名的字节是一段"看起来像
// 文本"的东西。如果签名内容可以任意构造，攻击者可能诱导签名者把别的
// 协议的消息签成 TLS 的（跨协议攻击）。加一段固定的、带有上下文标记的
// 前缀，让两边签的东西在语义上不可混淆。

var (
	ErrNoCertificate = errors.New("tls: no certificate configured")
	ErrBadSignature  = errors.New("tls: certificate verify signature invalid")
)

// 签名算法编号（RFC 8446 section 4.2.3）。
const (
	sigRSAPSSRSAE_SHA256 uint16 = 0x0804
	sigECDSAP256_SHA256  uint16 = 0x0403
	sigEd25519           uint16 = 0x0807
)

// certificateVerifyInput 拼待签名的内容。
func certificateVerifyInput(isClient bool, transcriptHash []byte) []byte {
	context := "TLS 1.3, server CertificateVerify"
	if isClient {
		context = "TLS 1.3, client CertificateVerify"
	}
	// 64 个空格
	const padding = "                                                                "
	if len(padding) != 64 {
		panic("tls: padding must be 64 spaces")
	}

	out := make([]byte, 0, 64+len(context)+1+len(transcriptHash))
	out = append(out, padding...)
	out = append(out, context...)
	out = append(out, 0)
	return append(out, transcriptHash...)
}

// pssOptions 是 RSA-PSS 的签名参数。
//
// **盐长必须显式给 PSSSaltLengthEqualsHash**（RFC 8446 4.2.3 对
// rsa_pss_rsae_* 的要求："The salt length MUST be Hash.length"）。
//
// 给 nil 的话 crypto/rsa 会按 PSSSaltLengthAuto 处理，也就是**用能塞下的
// 最大盐长**——签出来的东西自己验得过，但所有按标准写的验签方都拒收。
// 实测（Go 的 crypto/rsa，2048 位密钥、SHA-256）：
//
//	nil         签名 -> EqualsHash 验签: verification error
//	nil         签名 -> nil        验签: ok
//	EqualsHash  签名 -> EqualsHash 验签: ok
//
// 这个坑能藏住的原因是**两端都错**：fio 自己的客户端也拿 nil 验签，自家
// client/server 互通无碍，只有跟标准实现（crypto/tls、OpenSSL、浏览器）
// 对话时才现形——症状是握手一路走到 CertificateVerify，然后客户端报
// "invalid signature"（LibreSSL 报 "salt length check failed"）。
var pssOptions = &rsa.PSSOptions{
	SaltLength: rsa.PSSSaltLengthEqualsHash,
	Hash:       crypto.SHA256,
}

// signWithKey 用私钥签名。
func signWithKey(priv crypto.PrivateKey, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)

	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, digest[:])
	case *rsa.PrivateKey:
		return rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest[:], pssOptions)
	case ed25519.PrivateKey:
		// Ed25519 是"签原文不是签哈希"，而且它内部自己做 SHA512
		return ed25519.Sign(k, message), nil
	}
	return nil, fmt.Errorf("tls: unsupported private key type %T", priv)
}

// verifyWithKey 用公钥验签。
func verifyWithKey(pub crypto.PublicKey, message, sig []byte, algo uint16) error {
	digest := sha256.Sum256(message)

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return ErrBadSignature
		}
		return nil
	case *rsa.PublicKey:
		// 和签名那边同一套参数：标准要求盐长等于哈希长度，验签也照这个
		// 口径收（见 pssOptions 的注释）。
		if err := rsa.VerifyPSS(k, crypto.SHA256, digest[:], sig, pssOptions); err != nil {
			return ErrBadSignature
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, message, sig) {
			return ErrBadSignature
		}
		return nil
	}
	return fmt.Errorf("tls: unsupported public key type %T", pub)
}

// signatureAlgorithm 返回私钥对应的签名算法编号。
func signatureAlgorithm(priv crypto.PrivateKey) uint16 {
	switch priv.(type) {
	case *ecdsa.PrivateKey:
		return sigECDSAP256_SHA256
	case *rsa.PrivateKey:
		return sigRSAPSSRSAE_SHA256
	case ed25519.PrivateKey:
		return sigEd25519
	}
	return 0
}

// parseCertificate 从 Certificate 消息里取出证书链。
//
// 格式（RFC 8446 4.4.2）：
//
//	opaque certificate_request_context<0..2^8-1>
//	CertificateEntry certificate_list<0..2^24-1>:
//	    opaque cert_data<1..2^24-1>
//	    Extension extensions<0..2^16-1>
func parseCertificate(payload []byte) ([]*x509.Certificate, error) {
	if len(payload) == 0 {
		return nil, errors.New("tls: empty Certificate message")
	}
	ctxLen := int(payload[0])
	off := 1
	if off+ctxLen > len(payload) {
		return nil, errors.New("tls: Certificate context truncated")
	}
	off += ctxLen

	if off+3 > len(payload) {
		return nil, errors.New("tls: Certificate list truncated")
	}
	listLen := int(payload[off])<<16 | int(payload[off+1])<<8 | int(payload[off+2])
	off += 3
	if off+listLen > len(payload) {
		return nil, errors.New("tls: Certificate list truncated")
	}

	var certs []*x509.Certificate
	end := off + listLen
	for off+3 <= end {
		derLen := int(payload[off])<<16 | int(payload[off+1])<<8 | int(payload[off+2])
		off += 3
		if off+derLen > end {
			return nil, errors.New("tls: Certificate entry truncated")
		}
		cert, err := x509.ParseCertificate(payload[off : off+derLen])
		if err != nil {
			return nil, fmt.Errorf("tls: parse certificate: %w", err)
		}
		certs = append(certs, cert)
		off += derLen

		// 跳过扩展
		if off+2 > end {
			break
		}
		extLen := int(payload[off])<<8 | int(payload[off+1])
		off += 2 + extLen
	}
	if len(certs) == 0 {
		return nil, errors.New("tls: Certificate message has no certificates")
	}
	return certs, nil
}

// parseCertificateVerify 解析 CertificateVerify 消息。
func parseCertificateVerify(payload []byte) (algo uint16, sig []byte, err error) {
	if len(payload) < 4 {
		return 0, nil, errors.New("tls: CertificateVerify truncated")
	}
	algo = uint16(payload[0])<<8 | uint16(payload[1])
	sigLen := int(payload[2])<<8 | int(payload[3])
	if 4+sigLen > len(payload) {
		return 0, nil, errors.New("tls: CertificateVerify signature truncated")
	}
	return algo, payload[4 : 4+sigLen], nil
}
