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

//go:build linux || darwin

package grpc

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/http2"
	fiotls "github.com/antlabs/fio/tls"
	"golang.org/x/net/http2/hpack"

	xhttp2 "golang.org/x/net/http2"
)

// 三层叠起来的端到端：**gRPC over HTTP/2 over TLS，全在一个事件循环上**。
//
//	engine（epoll / kqueue）
//	  ↕ 密文
//	tls.ConnHandler        记录层、握手、AEAD
//	  ↕ 明文
//	http2.ConnHandler      帧、流、HPACK
//	  ↕ 流事件
//	grpc.ServerHandler     :path、消息分帧、trailer
//	  ↕
//	业务
//
// **这条路径是这次改造的最终目标**：三层协议、三个适配器，全在同一个
// 事件循环的 goroutine 上跑。没有任何一层起 goroutine、没有任何一层
// 阻塞等数据——数据到了才动，数据不够就留着。
//
// 客户端用**标准库的 crypto/tls + 官方 x/net/http2.Framer**：真实现
// 认了才算数。自己写的客户端和自己写的服务端对测，两边错得一样是看不
// 出来的（TLS 的应用密钥就栽过这个跟头）。
func TestStackedGRPCOverTLSOnEngine(t *testing.T) {
	cert, err := fiotls.SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	m, err := engine.NewAndStart(engine.WithEventLoops(2), engine.WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Free()

	// **叠的顺序**：gRPC 在最里，外面包 HTTP/2，最外面包 TLS。每一层都是
	// engine.Handler；TLS 那层特殊——它把内层的 Write 拦下来加密
	// （SetWriteHook），所以三层共用一个 fd、一个读缓冲区，谁都不用自己攒。
	//
	// accept 交给 engine.Listener（非阻塞 accept + 停止标志，两个平台的
	// Close 行为一致，见那个类型的说明）。
	ln, err := engine.ListenAndServe(m, "127.0.0.1:0", func() engine.Handler {
		return fiotls.NewConnHandler(&fiotls.Config{
			Certificates: []tls.Certificate{cert},
		}, http2.NewStreamConnHandler(NewServerHandler(runHandler{})))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr()

	// ---- 客户端：标准库 TLS + 官方 Framer ----

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))

	tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "fio-test"})
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("TLS 握手: %v", err)
	}
	t.Logf("TLS 握手成功，套件=%#x 版本=%#x",
		tconn.ConnectionState().CipherSuite, tconn.ConnectionState().Version)

	var req bytes.Buffer
	req.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	fr := xhttp2.NewFramer(&req, nil)
	fr.WriteSettings()
	block := hpackBlock(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/helloworld.Greeter/SayHello"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "localhost"},
		hpack.HeaderField{Name: "content-type", Value: ContentType},
		hpack.HeaderField{Name: "te", Value: "trailers"},
	)
	fr.WriteHeaders(xhttp2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block, EndHeaders: true,
	})
	fr.WriteData(1, true, Encode(nil, []byte("hello over the stack")))

	if _, err := tconn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	// ---- 收响应 ----

	rfr := xhttp2.NewFramer(tconn, tconn)
	dec := hpack.NewDecoder(4096, nil)
	var gotMsg []byte
	var gotStatus *Status
	var httpStatus string

	for i := 0; i < 30; i++ {
		f, err := rfr.ReadFrame()
		if err != nil {
			t.Fatalf("读响应帧: %v", err)
		}
		switch v := f.(type) {
		case *xhttp2.SettingsFrame:
			if !v.IsAck() {
				var ack bytes.Buffer
				xhttp2.NewFramer(&ack, nil).WriteSettingsAck()
				tconn.Write(ack.Bytes())
			}
		case *xhttp2.HeadersFrame:
			fields, derr := dec.DecodeFull(v.HeaderBlockFragment())
			if derr != nil {
				t.Fatalf("解头块: %v", derr)
			}
			hf := make([]http2.HeaderField, 0, len(fields))
			for _, x := range fields {
				hf = append(hf, http2.HeaderField{Name: x.Name, Value: x.Value})
			}
			for _, x := range fields {
				if x.Name == ":status" {
					httpStatus = x.Value
				}
				if x.Name == "grpc-status" {
					gotStatus = StatusFromHeaders(hf)
				}
			}
			if v.StreamEnded() {
				i = 100 // 结束
			}
		case *xhttp2.DataFrame:
			data := v.Data()
			if len(data) >= 5 {
				n := int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])
				if len(data) >= 5+n {
					gotMsg = append([]byte(nil), data[5:5+n]...)
				}
			}
		}
		if gotMsg != nil && gotStatus != nil {
			break
		}
	}

	if httpStatus != "200" {
		t.Errorf(":status = %q, want 200", httpStatus)
	}
	if string(gotMsg) != "echo: hello over the stack" {
		t.Errorf("消息 = %q", gotMsg)
	}
	if gotStatus == nil {
		t.Fatal("trailer 里没有 grpc-status")
	}
	if gotStatus.Code != OK {
		t.Errorf("grpc-status = %v (%s)", gotStatus.Code, gotStatus.Message)
	}
}

// 同一条 TLS 连接上连着来几次调用（序列号、流 ID 都要持续正确）。
func TestStackedGRPCMultipleCallsOnOneTLSConn(t *testing.T) {
	cert, err := fiotls.SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	m, err := engine.NewAndStart(engine.WithEventLoops(2), engine.WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Free()

	// accept 交给 engine.Listener（非阻塞 accept + 停止标志，两个平台的
	// Close 行为一致，见那个类型的说明）。
	ln, err := engine.ListenAndServe(m, "127.0.0.1:0", func() engine.Handler {
		return fiotls.NewConnHandler(&fiotls.Config{Certificates: []tls.Certificate{cert}},
			http2.NewStreamConnHandler(NewServerHandler(runHandler{})))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(20 * time.Second))

	tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "fio-test"})
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("TLS 握手: %v", err)
	}

	rfr := xhttp2.NewFramer(tconn, tconn)
	dec := hpack.NewDecoder(4096, nil)

	// 先发序言 + SETTINGS，并把它 ACK 掉
	var pre bytes.Buffer
	pfr := xhttp2.NewFramer(&pre, nil)
	pre.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	pfr.WriteSettings()
	if _, err := tconn.Write(pre.Bytes()); err != nil {
		t.Fatal(err)
	}

	for round := 1; round <= 5; round++ {
		// **客户端发起的流 ID 必须是奇数**（RFC 9113 5.1.1）。
		// 早先这里是 round*2（偶数）——那在没做流 ID 校验的时候能跑通，
		// 但协议上非法：客户端用偶数流 ID，服务端有权当成连接级错误
		// 把整条连接拆掉（新增的校验就是这么做的）。
		streamID := uint32(round*2 - 1)

		var buf bytes.Buffer
		fr := xhttp2.NewFramer(&buf, nil)
		block := hpackBlock(t,
			hpack.HeaderField{Name: ":method", Value: "POST"},
			hpack.HeaderField{Name: ":path", Value: "/pkg.Svc/Round"},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: "content-type", Value: ContentType},
		)
		fr.WriteHeaders(xhttp2.HeadersFrameParam{
			StreamID: streamID, BlockFragment: block, EndHeaders: true,
		})
		want := fmt.Sprintf("round %d", round)
		fr.WriteData(streamID, true, Encode(nil, []byte(want)))
		if _, err := tconn.Write(buf.Bytes()); err != nil {
			t.Fatalf("第 %d 轮写: %v", round, err)
		}

		// 收这一轮的响应
		var gotMsg []byte
		var status *Status
		for i := 0; i < 30 && (gotMsg == nil || status == nil); i++ {
			f, err := rfr.ReadFrame()
			if err != nil {
				t.Fatalf("第 %d 轮读: %v", round, err)
			}
			switch v := f.(type) {
			case *xhttp2.SettingsFrame:
				if !v.IsAck() {
					var ack bytes.Buffer
					xhttp2.NewFramer(&ack, nil).WriteSettingsAck()
					tconn.Write(ack.Bytes())
				}
			case *xhttp2.HeadersFrame:
				if v.StreamID != streamID {
					continue
				}
				fields, _ := dec.DecodeFull(v.HeaderBlockFragment())
				hf := make([]http2.HeaderField, 0, len(fields))
				for _, x := range fields {
					hf = append(hf, http2.HeaderField{Name: x.Name, Value: x.Value})
				}
				for _, x := range fields {
					if x.Name == "grpc-status" {
						status = StatusFromHeaders(hf)
					}
				}
			case *xhttp2.DataFrame:
				if v.StreamID != streamID {
					continue
				}
				data := v.Data()
				if len(data) >= 5 {
					n := int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])
					if len(data) >= 5+n {
						gotMsg = append([]byte(nil), data[5:5+n]...)
					}
				}
			}
		}

		if string(gotMsg) != "echo: "+fmt.Sprintf("round %d", round) {
			t.Fatalf("第 %d 轮消息 = %q", round, gotMsg)
		}
		if status == nil || status.Code != OK {
			t.Fatalf("第 %d 轮状态 = %v", round, status)
		}
	}
	t.Logf("一条 TLS 连接上跑了 5 轮 gRPC 调用，全对")
}
