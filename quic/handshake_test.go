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
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// 握手验收：用 quic-go 的**客户端**连我们这套自建的服务端，握手要能完成。
//
// 这是这一层最关键的验证点——包层/密钥/帧/传输参数任何一处错了，
// 客户端都会停在某个握手阶段，报的是 "handshake did not complete" 之类。
func TestHandshakeWithQuicGoClient(t *testing.T) {
	cert, err := tls.X509KeyPair(testCertPEM, testKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", Config{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ln.Serve()

	// 先拨号再 Accept：服务端的握手是在 Serve 里就地跑完的（accept 队列
	// 有缓冲），Accept 只是取结果。反过来的话两边互相等——DialAddr 要等
	// 握手完，而握手要等客户端先发包。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := quic.DialAddr(ctx, ln.Addr().String(),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		&quic.Config{})
	if err != nil {
		t.Fatalf("客户端握手失败: %v", err)
	}
	defer cc.CloseWithError(0, "")

	// Accept 只是取结果：**不能再起 ReadLoop**——Listener.Serve 已经在读
	// 同一个 socket 了，两个读者会互相抢数据报。ReadLoop 是给不挂
	// Listener 的连接用的。
	srv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	// 握手完不算完：客户端要能**开一条流并写进去**，服务端要能收出来。
	str, err := cc.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("开流失败: %v", err)
	}
	if _, err := str.Write([]byte("hello-quic")); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	str.Close()

	got := make([]byte, 64)
	done := make(chan string, 1)
	go func() {
		for {
			s, err := srv.AcceptStream()
			if err != nil {
				done <- "ERR:" + err.Error()
				return
			}
			n, _ := s.Read(got)
			done <- string(got[:n])
			return
		}
	}()
	select {
	case v := <-done:
		if v != "hello-quic" {
			t.Fatalf("服务端收到 %q，期望 hello-quic", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等服务端的流超时")
	}
}
