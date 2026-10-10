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
	"crypto/rand"
	"errors"
	"fmt"
)

// StateMachine 是一条连接上的 TLS 1.3 状态机。
//
// **这是对 crypto/tls 那套的替代**：不启动 goroutine、不阻塞，就是
// "喂字节、推进状态、吐字节"：
//
//	var sm = tls.NewServerStateMachine(&tls.Config{...})
//	sm.Start()
//
//	// 事件循环里
//	sm.Feed(ciphertext)         // 喂对端发来的密文
//	out := sm.TakeOutput()      // 取要发出去的密文
//	conn.Write(out)
//	if sm.State() == tls.StateEstablished {
//	    plain := sm.ReadPlaintext()
//	}
//
// 为什么不用 crypto/tls 的 Conn：那个 Conn 的握手**不是分步的**——
// 内部的 handshakeErr 一旦置上，后面每次 Handshake() 都直接返回那个
// 错误，不会再尝试读。所以在非阻塞 fd 上，第一次"数据不够"就把它废了。
// 实测过（纯 crypto/tls 上就能复现）：喂完 1746 字节的 ServerHello 再调
// Handshake，它一个字节都不读，直接回 need more data。
//
// 这个状态机做的是同一件事，但**每一步都可以停**：数据不够就留在
// 缓冲区里，下次接着喂。
type StateMachine struct {
	// config 是证书这些配置
	config *Config
	// isClient 我们这边是客户端还是服务端
	isClient bool

	// state 当前握手的阶段
	state HandshakeState

	// --- 解析层（三层：记录 -> 握手消息 -> 具体消息）---
	records    *RecordParser
	handshakes *HandshakeParser

	// --- 密钥派生 ---
	keys *keySchedule
	// kx 是我们这边的 ECDHE 密钥对
	kx *keyExchange
	// peerKeyShare 是对端的 ECDHE 公钥
	peerKeyShare []byte

	// --- 记录保护（握手阶段和应用阶段各一套）---
	// 发出去的用自己方向的密钥，收到的用对端方向的
	writeKeys   *recordProtector
	readKeys    *recordProtector
	hsWriteKeys *recordProtector
	hsReadKeys  *recordProtector

	// --- 握手阶段的流量密钥（secret 本身，不只是 AEAD）---
	//
	// **必须缓存**：Finished 的校验值要用它，而它的值是在
	// **ServerHello 那一刻**的 transcript 上算出来的。
	//
	// 踩过的坑：早先在验 Finished 时重新 derive 一遍，用的是**当时**的
	// transcript（已经含了 EE/Cert/CV）——算出来的 secret 和用来加解密
	// 记录的那个不是同一个，于是 Finished 校验必然失败（实测报
	// "Finished verify data mismatch"）。
	hsWriteSecret []byte
	hsReadSecret  []byte

	// --- 应用阶段的流量密钥（secret 本身）---
	//
	// **这两个也必须在"server Finished 刚进 transcript"那一刻算好**：
	//
	//	client_application_traffic_secret_0 =
	//	    Derive-Secret(Master Secret, "c ap traffic", CH..server Finished)
	//
	// 之后 transcript 还会继续长（客户端的 Finished 也要写进去），
	// 那时再 derive 就是**另一个值**了。
	//
	// 踩过的坑：原先是在收完对端 Finished 之后才 derive，而那时候
	// transcript 已经含了对端那条 Finished。自己和自己测能过（两边错得
	// 一样，算出来还是同一个值），一接标准库就露馅——
	// 实测 "tls: record authentication failed"，而握手本身是好的。
	appWriteSecret []byte
	appReadSecret  []byte

	// --- 输出缓冲 ---
	// out 是要发给对端的密文（握手消息 + 记录头）
	out []byte

	// --- 应用数据 ---
	// plaintext 是解出来的应用数据
	plaintext []byte

	// --- 握手状态 ---
	// clientHello 是收到的 ClientHello（服务端用）
	clientHello *ClientHello
	// serverHello 是收到的 ServerHello（客户端用）
	serverHello *ServerHello
	// suite 是协商出来的密码套件
	suite uint16
	// negotiatedALPN 是协商出来的应用层协议（"h2"、"http/1.1"……）。
	// 没协商出东西就是空串。
	//
	// 服务端：从客户端的 ALPN 列表和服务端配置里挑，放在 EncryptedExtensions。
	// 客户端：从服务端回的 EncryptedExtensions 里读。
	negotiatedALPN string

	// err 是握手失败的原因
	err error
}

// NewServerStateMachine 建一个服务端的 TLS 1.3 状态机。
func NewServerStateMachine(config *Config) *StateMachine {
	sm := &StateMachine{
		config:   config,
		isClient: false,
		state:    StateWaitClientHello,
	}
	sm.init()
	return sm
}

// NewClientStateMachine 建一个客户端的 TLS 1.3 状态机。
func NewClientStateMachine(config *Config) *StateMachine {
	sm := &StateMachine{
		config:   config,
		isClient: true,
		state:    StateWaitServerHello,
	}
	sm.init()
	return sm
}

func (sm *StateMachine) init() {
	sm.records = NewRecordParser()
	sm.handshakes = NewHandshakeParser()
	sm.keys = newKeySchedule()
	sm.keys.deriveEarly(nil)
}

// State 当前的握手阶段。
func (sm *StateMachine) State() HandshakeState { return sm.state }

// Error 握手失败的原因，没失败返回 nil。
func (sm *StateMachine) Error() error { return sm.err }

// Established 握手完了没有。
func (sm *StateMachine) Established() bool { return sm.state == StateEstablished }

// CipherSuite 协商出来的密码套件（握手完成后有效）。
func (sm *StateMachine) CipherSuite() uint16 { return sm.suite }

// ALPN 返回协商出来的应用层协议（"h2"、"http/1.1"……）。
// 没协商出东西返回空串。
func (sm *StateMachine) ALPN() string { return sm.negotiatedALPN }

// ClientHello 返回收到的 ClientHello（服务端用；客户端返回 nil）。
func (sm *StateMachine) ClientHello() *ClientHello { return sm.clientHello }

// ServerHello 返回收到的 ServerHello（客户端用；服务端返回 nil）。
func (sm *StateMachine) ServerHello() *ServerHello { return sm.serverHello }

// Start 让客户端发出第一条消息（ClientHello）。
//
// 服务端不用调（它等客户端先说话）。
func (sm *StateMachine) Start() error {
	if !sm.isClient {
		return errors.New("tls: server does not start")
	}

	kx, err := newKeyExchange()
	if err != nil {
		return err
	}
	sm.kx = kx

	ch := &ClientHello{
		LegacyVersion: 0x0303,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
		},
	}
	if _, err := rand.Read(ch.Random[:]); err != nil {
		return err
	}
	// **兼容模式要求 client 发一个非空的 session_id**（32 字节随机数）。
	//
	// 为什么：TLS 1.3 沿用 1.2 的 ClientHello 结构，中间设备（防火墙、
	// 负载均衡）看到空的 session_id 会认为这是"残缺的 1.2 握手"而拒绝。
	// RFC 8446 5 的"middlebox compatibility mode"就是为这个：客户端填
	// 一个随机的 session_id，服务端原样回一个，那些设备就满意了。
	//
	// 实测：不填的话 **crypto/tls 的服务端直接回 fatal handshake_failure
	// (alert 40)**，而且是在解析 ClientHello 阶段就拒——因为标准库自己
	// 也按兼容模式实现，它期望客户端填。
	ch.SessionID = make([]byte, 32)
	if _, err := rand.Read(ch.SessionID); err != nil {
		return err
	}
	if sm.config != nil && sm.config.ServerName != "" {
		ch.ServerName = sm.config.ServerName
	}
	// ALPN：客户端声明自己想要的协议（HTTP/2 是 "h2"）。
	//
	// 服务端挑哪个由它决定，客户端要接受结果——所以这里报的是**偏好
	// 顺序**，不是一个请求。标准库的 Transport 走 h2 时这一步是必须的。
	if sm.config != nil {
		ch.ALPN = sm.config.NextProtos
	}

	msg := AppendClientHello(nil, ch, sm.kx.pub)
	// ClientHello 是明文的（握手第一条，还没有密钥）
	rec := AppendRecord(nil, recordHandshake, 0x0303, msg)
	sm.out = append(sm.out, rec...)

	// ClientHello 要进 transcript（派生密钥靠它）
	sm.keys.transcript.write(msg)
	return nil
}

// Feed 喂对端发来的密文（从 fd 读到的原始字节）。
//
// 返回消化了多少字节。**契约和 engine.Handler.OnData 一致**：
//
//	consumed == len(data)  全收下了（不够一条记录的攒着）
//	consumed <  len(data)  只吃下这么多，剩下的调用方下次再喂
//
// 不阻塞：不够一条记录的字节留在内部的 RecordParser 里，下次接着拼。
func (sm *StateMachine) Feed(data []byte) (int, error) {
	if sm.err != nil {
		return 0, sm.err
	}
	if len(data) == 0 {
		return 0, nil
	}

	n, err := sm.records.Parse(data, func(r *Record) error {
		return sm.onRecord(r)
	})
	if err != nil {
		sm.err = err
		return n, err
	}
	return n, nil
}

// Buffered 还有多少字节攒在内部没成记录。
func (sm *StateMachine) Buffered() int { return sm.records.Buffered() }

// onRecord 处理一条记录。
func (sm *StateMachine) onRecord(r *Record) error {
	switch r.Type {
	case recordHandshake:
		// 外层类型是 handshake(22)：**明文**的握手记录。
		//
		// 这一条只在握手开头出现（ClientHello / ServerHello）——那时候
		// 还没有密钥。TLS 1.3 里 ServerHello 之后的所有东西都装在
		// application_data(23) 里（加密了，真实类型藏在密文内）。
		//
		// 踩过的坑：早先这里写成"有读密钥就尝试解密"，但客户端是先
		// 收到明文 ServerHello、才派生密钥的——拿刚派生的密钥去解明文，
		// AEAD 解出来是垃圾，后面按握手消息解就报"长度 3670016"这种
		// 莫名其妙的错。
		_, err := sm.handshakes.Parse(r.Payload, func(h *Handshake) error {
			return sm.onHandshake(h)
		})
		return err

	case recordApplicationData:
		// 加密的记录（握手后期和应用数据都是这个外层类型）
		if sm.readKeys == nil || sm.readKeys.aead == nil {
			return errors.New("tls: encrypted record before keys")
		}
		content, innerType, err := sm.readKeys.open(r.Payload)
		if err != nil {
			return err
		}
		switch innerType {
		case recordHandshake:
			_, err := sm.handshakes.Parse(content, func(h *Handshake) error {
				return sm.onHandshake(h)
			})
			return err
		case recordApplicationData:
			sm.plaintext = append(sm.plaintext, content...)
			return nil
		case recordAlert:
			return sm.onAlert(content)
		}
		return nil

	case recordAlert:
		return sm.onAlert(r.Payload)

	case recordChangeCipherSpec:
		// TLS 1.3 里这个是"兼容用的空动作"（老中间设备看到它会以为
		// 是 1.2 的握手），收到就忽略
		return nil
	}
	return nil
}

// onAlert 处理告警。
func (sm *StateMachine) onAlert(b []byte) error {
	if len(b) >= 2 {
		level, desc := b[0], b[1]
		if level == 2 { // fatal
			return fmt.Errorf("tls: fatal alert %d", desc)
		}
	}
	return nil
}

// onHandshake 处理一条握手消息。**这里是状态机的核心**。
func (sm *StateMachine) onHandshake(h *Handshake) error {
	switch h.Type {
	case hsClientHello:
		return sm.onClientHello(h.Payload)

	case hsServerHello:
		return sm.onServerHello(h.Payload)

	case hsEncryptedExtensions:
		// 大部分扩展我们不看（都支持），但 **ALPN 的协商结果在这里**，
		// 得读出来（HTTP/2 靠它知道该不该说 h2）。
		//
		// 不管看不看内容，**都必须进 transcript**——Finished 的校验值
		// 依赖它，漏了就是 "Finished verify data mismatch"。
		if sm.isClient {
			sm.negotiatedALPN = parseALPNServerExtension(h.Payload)
		}
		sm.keys.transcript.write(AppendHandshake(nil, h.Type, h.Payload))
		if sm.state == StateWaitEncryptedExtensions {
			sm.state = StateWaitCertificate
		}
		return nil

	case hsCertificate:
		sm.keys.transcript.write(AppendHandshake(nil, h.Type, h.Payload))
		if sm.state == StateWaitCertificate {
			sm.state = StateWaitCertificateVerify
		}
		return nil

	case hsCertificateVerify:
		sm.keys.transcript.write(AppendHandshake(nil, h.Type, h.Payload))
		if sm.state == StateWaitCertificateVerify {
			sm.state = StateWaitServerFinished
		}
		return nil

	case hsFinished:
		return sm.onFinished(h.Payload)

	case hsNewSessionTicket:
		// 会话票据：我们不做会话恢复（每次都是完整握手），
		// 收到就忽略。但它在 transcript 里的位置要注意——它是在
		// 握手**之后**发的，不影响已完成的校验。
		return nil

	case hsKeyUpdate:
		// 密钥更新：还没做
		return errors.New("tls: KeyUpdate not implemented")
	}
	return nil
}

// onClientHello 服务端处理 ClientHello。
func (sm *StateMachine) onClientHello(payload []byte) error {
	if !sm.isClient == false {
		return errors.New("tls: ClientHello on client")
	}

	ch, err := ParseClientHello(payload)
	if err != nil {
		return err
	}
	sm.clientHello = ch

	// 选一个我们都支持的套件
	for _, cs := range ch.CipherSuites {
		if cs == TLS_AES_128_GCM_SHA256 {
			sm.suite = cs
			break
		}
	}
	if sm.suite == 0 {
		return ErrNoSharedCipher
	}

	// 从 key_share 扩展里取客户端的公钥
	// （ParseClientHello 没解析扩展数据，这里重新扫一遍）
	ks, err := clientKeyShare(payload)
	if err != nil {
		return err
	}
	sm.peerKeyShare = ks

	// ALPN：从客户端的列表和我们配置的交集里挑一个。
	//
	// 服务端的偏好顺序来自 config.NextProtos（和 crypto/tls 是同一个
	// 字段，所以配置方式对使用者是一样的）。
	if sm.config != nil {
		sm.negotiatedALPN = negotiateALPN(ch.ALPN, sm.config.NextProtos)
	}

	// ClientHello 进 transcript
	sm.keys.transcript.write(AppendHandshake(nil, hsClientHello, payload))

	// 生成本方的 ECDHE
	kx, err := newKeyExchange()
	if err != nil {
		return err
	}
	sm.kx = kx

	// 算共享密钥，派生握手密钥
	shared, err := kx.shared(ks)
	if err != nil {
		return err
	}
	if err := sm.keys.deriveHandshake(shared); err != nil {
		return err
	}

	// 发 ServerHello
	sh := &ServerHello{
		LegacyVersion: 0x0303,
		CipherSuite:   sm.suite,
	}
	if _, err := rand.Read(sh.Random[:]); err != nil {
		return err
	}
	if ch.SessionID != nil {
		// 1.3 要求服务端回一个一样的 session_id（兼容用）
		sh.SessionID = ch.SessionID
	}
	shMsg := AppendServerHello(nil, sh, kx.pub)
	sm.out = append(sm.out, AppendRecord(nil, recordHandshake, 0x0303, shMsg)...)
	sm.keys.transcript.write(shMsg)

	// ServerHello 之后的一切都加密了：建握手阶段的保护器
	// **注意方向**：服务端写用 "s hs traffic"，读用 "c hs traffic"
	//
	// 把 secret 本身也存下来（Finished 要用，见 hsWriteSecret 的说明）
	sm.hsWriteSecret = deriveSecret(sm.keys.handshakeSecret, "s hs traffic", sm.keys.transcript.sum())
	sm.hsReadSecret = deriveSecret(sm.keys.handshakeSecret, "c hs traffic", sm.keys.transcript.sum())

	sWrite, err := newRecordProtector(keysFromSecret(sm.hsWriteSecret))
	if err != nil {
		return err
	}
	cRead, err := newRecordProtector(keysFromSecret(sm.hsReadSecret))
	if err != nil {
		return err
	}
	sm.hsWriteKeys = sWrite
	sm.hsReadKeys = cRead
	sm.writeKeys = sWrite
	sm.readKeys = cRead

	// 发 ChangeCipherSpec（兼容模式的一条空动作，RFC 8446 5 的
	// "middlebox compatibility mode"）。
	//
	// 内容是单个字节 0x01，明文的。为什么要有：TLS 1.3 的规定是
	// "ServerHello 之后所有东西都加密"，中间设备看不出握手到哪一步了，
	// 有些会因此判定超时或者乱猜。发一条 1.2 时代的 CCS 让它们安心。
	// 收到的一方必须忽略它（我们客户端那边就是这么做的）。
	sm.out = append(sm.out, AppendRecord(nil, recordChangeCipherSpec, 0x0303, []byte{1})...)

	// 发 EncryptedExtensions。
	//
	// **ALPN 的协商结果放在这里，不在 ServerHello 里**。为什么：
	// ServerHello 是明文的（密钥还没派生），协商结果放那儿中间设备能看见
	// ——它就能据此干预（比如强制降级到它看得懂的协议）。TLS 1.3 把
	// "服务端要告诉客户端的一切"都挪进了加密的 EncryptedExtensions
	// （RFC 8446 4.3.1）。
	eeExts := appendALPNServerExtension(sm.negotiatedALPN)
	ee := AppendHandshake(nil, hsEncryptedExtensions, eeExts)
	sm.writeHandshake(ee)
	sm.keys.transcript.write(ee)

	// 发 Certificate
	cert, err := sm.serverCertificate()
	if err != nil {
		return err
	}
	sm.writeHandshake(cert)
	sm.keys.transcript.write(cert)

	// 发 CertificateVerify（这里先发一个空占位——真正的签名需要证书
	// 私钥，而自签证书的签名要按 TLS 1.3 的格式算，见 signCertificateVerify）
	cv, err := sm.certificateVerify()
	if err != nil {
		return err
	}
	sm.writeHandshake(cv)
	sm.keys.transcript.write(cv)

	// 发 Finished。
	//
	// **顺序**：先算校验值（用的 transcript 是 CH..CertificateVerify），
	// 再把这条 Finished 本身写进 transcript——下一阶段（客户端 Finished
	// 的校验、应用密钥的派生）要用的 transcript 是 CH..server Finished。
	//
	// 踩过的坑：这里漏了"把 Finished 写进 transcript"那一步（注释写了、
	// 代码没写），于是服务端的 transcript 停在 CH..CV，而客户端那边是
	// CH..sFin——两边差一条消息，客户端的 Finished 校验必然失败
	// （实测报 "Finished verify data mismatch"）。
	fin := sm.finishedMessage(false)
	sm.writeHandshake(fin)
	sm.keys.transcript.write(fin)

	// **应用密钥就在这一刻算**（见 cacheApplicationSecrets 的说明）：
	// transcript 此刻正好是 CH..server Finished。等服务端收完客户端的
	// Finished 再算，那条消息已经进了 transcript，算出来是另一个值。
	if err := sm.cacheApplicationSecrets(); err != nil {
		return err
	}

	sm.state = StateWaitFinished
	return nil
}

// onServerHello 客户端处理 ServerHello。
func (sm *StateMachine) onServerHello(payload []byte) error {
	if !sm.isClient {
		return errors.New("tls: ServerHello on server")
	}

	sh, err := ParseServerHello(payload)
	if err != nil {
		return err
	}
	sm.serverHello = sh
	sm.suite = sh.CipherSuite

	// 从 key_share 扩展里取服务端的公钥
	ks, err := serverKeyShare(payload)
	if err != nil {
		return err
	}

	// ServerHello 进 transcript
	sm.keys.transcript.write(AppendHandshake(nil, hsServerHello, payload))

	// 算共享密钥，派生握手密钥
	shared, err := sm.kx.shared(ks)
	if err != nil {
		return err
	}
	if err := sm.keys.deriveHandshake(shared); err != nil {
		return err
	}

	// 建握手阶段的保护器（客户端方向和服务端相反），同样把 secret 存下来
	sm.hsWriteSecret = deriveSecret(sm.keys.handshakeSecret, "c hs traffic", sm.keys.transcript.sum())
	sm.hsReadSecret = deriveSecret(sm.keys.handshakeSecret, "s hs traffic", sm.keys.transcript.sum())

	cWrite, err := newRecordProtector(keysFromSecret(sm.hsWriteSecret))
	if err != nil {
		return err
	}
	sRead, err := newRecordProtector(keysFromSecret(sm.hsReadSecret))
	if err != nil {
		return err
	}
	sm.hsWriteKeys = cWrite
	sm.hsReadKeys = sRead
	sm.writeKeys = cWrite
	sm.readKeys = sRead

	sm.state = StateWaitEncryptedExtensions
	return nil
}

// onFinished 校验对端的 Finished。
func (sm *StateMachine) onFinished(payload []byte) error {
	// 用**缓存下来的、对端方向的**握手流量 secret（在 ServerHello
	// 那一刻算的），不是现在重新 derive 一遍——现在的 transcript 已经
	// 多了 EE/Cert/CV，算出来的是另一个值（见 hsWriteSecret 的说明）。
	//
	// hsReadSecret 就是"读方向"的：对端发来的记录用它解，对端的
	// Finished 也用它校验。
	baseSecret := sm.hsReadSecret

	want := finishedVerifyData(baseSecret, sm.keys.transcript.sum())
	if len(payload) != len(want) {
		return fmt.Errorf("tls: Finished length %d, want %d", len(payload), len(want))
	}
	// 常量时间比较（防时序攻击）
	var diff byte
	for i := range want {
		diff |= want[i] ^ payload[i]
	}
	if diff != 0 {
		return errors.New("tls: Finished verify data mismatch")
	}

	if sm.isClient {
		// 客户端收到服务端 Finished：把 Finished 进 transcript，
		// 派生应用密钥，然后发自己的 Finished
		sm.keys.transcript.write(AppendHandshake(nil, hsFinished, payload))

		// **要在发自己 Finished 之前算**：此刻 transcript 是
		// CH..server Finished，正是 RFC 8446 要的上下文；再往后写一条
		// 就错位了（见 cacheApplicationSecrets 的说明）。
		if err := sm.cacheApplicationSecrets(); err != nil {
			return err
		}

		// 客户端也发一条 CCS（兼容模式，RFC 8446 5）
		sm.out = append(sm.out, AppendRecord(nil, recordChangeCipherSpec, 0x0303, []byte{1})...)

		// 客户端发 Finished 用的是握手密钥。
		//
		// 和上面服务端那处一样：**发完必须写进 transcript**——应用密钥
		// 是从 CH..client Finished 派生的，漏了这一步两边派生出不同的
		// 密钥（症状：应用数据 "record authentication failed"，而
		// 握手本身是好的）。
		fin := sm.finishedMessage(true)
		sm.writeHandshake(fin)
		sm.keys.transcript.write(fin)

		// 握手完成：切到应用密钥
		if err := sm.switchToApplicationKeys(); err != nil {
			return err
		}
		sm.state = StateEstablished
		return nil
	}

	// 服务端收到客户端 Finished：握手完成
	sm.keys.transcript.write(AppendHandshake(nil, hsFinished, payload))
	if err := sm.switchToApplicationKeys(); err != nil {
		return err
	}
	sm.state = StateEstablished
	return nil
}

// cacheApplicationSecrets 在 **server Finished 刚写进 transcript 之后**
// 调用，把两个方向的应用流量密钥算好缓存起来。
//
// **调用的时机是这件事的全部要害**（RFC 8446 7.1）：
//
//	client/server_application_traffic_secret_0 =
//	    Derive-Secret(Master Secret, "c ap traffic" / "s ap traffic",
//	                  CH..server Finished)
//
// 服务端在发完自己 Finished 时调用；客户端在收到服务端 Finished、
// 把它写进 transcript 之后、发自己 Finished 之前调用。两边看到的
// transcript 都是 CH..server Finished，算出来才是同一对密钥。
func (sm *StateMachine) cacheApplicationSecrets() error {
	if err := sm.keys.deriveMaster(); err != nil {
		return err
	}
	th := sm.keys.transcript.sum()

	// 方向：客户端写的是 "c ap traffic"，服务端写的读的是 "s ap traffic"
	if sm.isClient {
		sm.appWriteSecret = deriveSecret(sm.keys.masterSecret, "c ap traffic", th)
		sm.appReadSecret = deriveSecret(sm.keys.masterSecret, "s ap traffic", th)
	} else {
		sm.appWriteSecret = deriveSecret(sm.keys.masterSecret, "s ap traffic", th)
		sm.appReadSecret = deriveSecret(sm.keys.masterSecret, "c ap traffic", th)
	}
	return nil
}

// switchToApplicationKeys 握手完成，把读写保护器换成应用密钥。
//
// 密钥来自 cacheApplicationSecrets 缓存的 secret——**不是现场 derive**：
// 走到这里时 transcript 已经又长了几条消息了。
//
// **换密钥时序列号要归零**（RFC 8446 5.3）：nonce 是"iv 异或序号"，
// 每个密钥有自己的序号空间——握手密钥用过的序号不影响应用密钥。
// 新建 recordProtector 时 seq 默认就是 0，所以这里"换一个新的"就对了。
func (sm *StateMachine) switchToApplicationKeys() error {
	if sm.appWriteSecret == nil || sm.appReadSecret == nil {
		return errors.New("tls: application secrets not cached")
	}

	wp, err := newRecordProtector(keysFromSecret(sm.appWriteSecret))
	if err != nil {
		return err
	}
	rp, err := newRecordProtector(keysFromSecret(sm.appReadSecret))
	if err != nil {
		return err
	}
	sm.writeKeys = wp
	sm.readKeys = rp
	return nil
}

// finishedMessage 生成（并记录）一条 Finished 消息。
//
// isClient 决定用哪个方向的握手密钥（客户端发的是 "c hs traffic"）。
func (sm *StateMachine) finishedMessage(isClient bool) []byte {
	// 用缓存的 secret（见 hsWriteSecret 的说明）
	base := sm.hsWriteSecret
	verify := finishedVerifyData(base, sm.keys.transcript.sum())
	return AppendHandshake(nil, hsFinished, verify)
}

// writeHandshake 把一条握手消息加密成记录，追加到输出。
func (sm *StateMachine) writeHandshake(msg []byte) {
	if sm.hsWriteKeys == nil || sm.hsWriteKeys.aead == nil {
		// 还没密钥（ServerHello 之前），明文发
		sm.out = append(sm.out, AppendRecord(nil, recordHandshake, 0x0303, msg)...)
		return
	}
	ct, err := sm.hsWriteKeys.seal(recordHandshake, msg)
	if err != nil {
		sm.err = err
		return
	}
	sm.out = append(sm.out, AppendRecord(nil, recordApplicationData, 0x0303, ct)...)
}

// TakeOutput 取走要发给对端的密文。
func (sm *StateMachine) TakeOutput() []byte {
	if len(sm.out) == 0 {
		return nil
	}
	out := sm.out
	sm.out = nil
	return out
}

// Write 把明文加密成应用数据记录。
//
// 握手没完成时返回错误。
func (sm *StateMachine) Write(plain []byte) ([]byte, error) {
	if sm.state != StateEstablished {
		return nil, ErrHandshakeIncomplete
	}
	if sm.writeKeys == nil || sm.writeKeys.aead == nil {
		return nil, ErrAEADNotReady
	}

	// 应用数据可以很长，按 maxRecordPayload 切成多条记录。
	//
	// 输出大小是算得准的，就别让 append 翻倍长：每条记录的密文 =
	// 明文 + 1(内层类型) + 16(AEAD 标签)，外面再套 5 字节记录头。一次
	// 分配到位，省掉的是 16K→32K→64K→128K 那几次重分配和随之而来的
	// memmove——100KB 的响应走这条路时，这一处占全部堆分配的一大块。
	nrec := (len(plain) + maxRecordPayload - 1) / maxRecordPayload
	out := make([]byte, 0, len(plain)+nrec*(recordHeaderLen+1+sm.writeKeys.aead.Overhead()))
	for len(plain) > 0 {
		n := len(plain)
		if n > maxRecordPayload {
			n = maxRecordPayload
		}
		ct, err := sm.writeKeys.seal(recordApplicationData, plain[:n])
		if err != nil {
			return out, err
		}
		out = AppendRecord(out, recordApplicationData, 0x0303, ct)
		plain = plain[n:]
	}
	return out, nil
}

// ReadPlaintext 取解出来的应用数据。
//
// **返回的切片只在下一次 Feed/ReadPlaintext 之前有效**（底层数组是状态机
// 自己的，下一批明文的 append 会覆盖它），要留着就自己拷一份。
//
// 原来是"返回之后置 nil"——所有权整个交出去，听起来干净，代价是每批明文
// 都从零长一遍：100KB 的请求体按 16KB 一条记录进来，append 要把
// 16K→32K→64K→128K 重分配一遍，而每条连接上的请求体大小是稳定的，这批
// 的容量正好就是下一批需要的。调用方只有 tls.ConnHandler.OnData 一处，
// 它在同一个函数体里把明文交给内层就返回，不会留存——所以这个契约是够的。
func (sm *StateMachine) ReadPlaintext() []byte {
	if len(sm.plaintext) == 0 {
		return nil
	}
	out := sm.plaintext
	sm.plaintext = out[:0]
	return out
}

// serverCertificate 拼 Certificate 消息（TLS 1.3 格式）。
//
// 格式（RFC 8446 4.4.2）：
//
//	opaque certificate_request_context<0..2^8-1>
//	CertificateEntry certificate_list<0..2^24-1>:
//	    opaque cert_data<1..2^24-1>
//	    Extension extensions<0..2^16-1>
func (sm *StateMachine) serverCertificate() ([]byte, error) {
	if sm.config == nil || len(sm.config.Certificates) == 0 {
		return nil, errors.New("tls: no certificate configured")
	}
	cert := sm.config.Certificates[0]

	body := make([]byte, 0, len(cert.Certificate)*2+16)
	body = append(body, 0) // certificate_request_context 空

	var entries []byte
	for _, der := range cert.Certificate {
		entries = append(entries, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		entries = append(entries, der...)
		entries = append(entries, 0, 0) // 空扩展
	}
	body = append(body, byte(len(entries)>>16), byte(len(entries)>>8), byte(len(entries)))
	body = append(body, entries...)

	return AppendHandshake(nil, hsCertificate, body), nil
}

// certificateVerify 拼 CertificateVerify 消息。
//
// **这一条是签名的**：服务端用证书私钥对"到目前为止的握手"签名，客户端
// 用它证明"我确实有这个证书的私钥"（不是偷来的证书）。
//
// 签名内容（RFC 8446 4.4.3）：
//
//	64 个空格 + "TLS 1.3, server CertificateVerify" + 0x00 + Transcript-Hash
//
// 那 64 个空格是刻意的：让签名内容是一段"看起来像文本"的东西，避免
// 某些老实现把它当成别的协议的消息。
func (sm *StateMachine) certificateVerify() ([]byte, error) {
	if sm.config == nil || len(sm.config.Certificates) == 0 {
		return nil, errors.New("tls: no certificate configured")
	}
	cert := sm.config.Certificates[0]
	if cert.PrivateKey == nil {
		return nil, errors.New("tls: certificate has no private key")
	}

	// 签名上下文
	toSign := certificateVerifyInput(sm.isClient, sm.keys.transcript.sum())

	sig, err := signWithKey(cert.PrivateKey, toSign)
	if err != nil {
		return nil, err
	}

	// 签名算法：和 signWithKey 里用的保持一致
	algo := signatureAlgorithm(cert.PrivateKey)

	body := make([]byte, 0, 4+len(sig))
	body = append(body, byte(algo>>8), byte(algo))
	body = append(body, byte(len(sig)>>8), byte(len(sig)))
	body = append(body, sig...)

	return AppendHandshake(nil, hsCertificateVerify, body), nil
}
