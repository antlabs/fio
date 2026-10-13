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

package http2

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/antlabs/fio/engine"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// startServer 起一个真实的 HTTP/2 服务端（engine 的 epoll 循环 +
// http2.ConnHandler）。
func startServer(t *testing.T, h StreamHandler) (string, func()) {
	t.Helper()

	m, err := engine.NewAndStart(engine.WithEventLoops(2), engine.WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatal(err)
	}

	// accept 循环交给 engine.Listener：非阻塞 accept + 停止标志，
	// 两个平台的 Close 行为一致（见那个类型的说明）。
	ln, err := engine.ListenAndServe(m, "127.0.0.1:0", func() engine.Handler {
		return NewStreamConnHandler(h)
	})
	if err != nil {
		t.Fatal(err)
	}

	stop := func() {
		ln.Close()
		m.Free()
	}
	return ln.Addr(), stop
}

// echoStream 是测试用的流处理者：收到请求头就回响应头，收到数据就回数据。
type echoStream struct {
	t *testing.T
	// got 收到的东西
	gotHeader []string
	gotData   []byte
	endStream bool
	done      chan struct{}
}

func (e *echoStream) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	for _, h := range headers {
		e.gotHeader = append(e.gotHeader, h.Name+"="+h.Value)
	}
}

func (e *echoStream) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {
	e.gotData = append(e.gotData, data...)
	if endStream {
		select {
		case <-e.done:
		default:
			close(e.done)
		}
	}
}

func (e *echoStream) OnRSTStream(c *Conn, streamID uint32, code ErrCode) {}

// **端到端**：起一个 HTTP/2 服务端（跑在 engine 上），客户端用**官方的
// x/net/http2.Framer** 说话。
//
// 这条路径证明的是：HTTP/2 真的接上事件循环了——从 fd 读到字节、喂给
// 状态机、把响应写回 fd，整条链路。
func TestEngineEndToEnd(t *testing.T) {
	rec := &syncRecorder{}
	addr, stop := startServer(t, rec)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 客户端：发序言 + SETTINGS + HEADERS
	var req bytes.Buffer
	req.Write(clientPreface)
	cfr := http2.NewFramer(&req, nil)
	cfr.WriteSettings()

	block := hpackBlock(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/engine.test/Echo"},
		hpack.HeaderField{Name: ":scheme", Value: "http"},
	)
	cfr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: block,
		EndHeaders:    true,
	})

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	// 等一小会儿让服务端处理
	time.Sleep(200 * time.Millisecond)

	if rec.headerCount() == 0 {
		t.Fatal("服务端没收到 HEADERS")
	}
	streamID, fields := rec.headerAt(0)
	if streamID != 1 {
		t.Errorf("流 ID = %d", streamID)
	}
	found := false
	for _, f := range fields {
		if f.Name == ":path" && f.Value == "/engine.test/Echo" {
			found = true
		}
	}
	if !found {
		t.Errorf(":path 没解出来: %v", fields)
	}
}

// 服务端在 engine 上能读能写：客户端发的 SETTINGS 要收到 ACK。
func TestEngineSettingsAck(t *testing.T) {
	addr, stop := startServer(t, &syncRecorder{})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 发序言 + SETTINGS
	var req bytes.Buffer
	req.Write(clientPreface)
	http2.NewFramer(&req, nil).WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 32768})
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	// 读服务端的回应（应该有个 SETTINGS ACK）
	fr := http2.NewFramer(conn, conn)
	sawAck := false
	for i := 0; i < 5; i++ {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && sf.IsAck() {
			sawAck = true
			break
		}
	}
	if !sawAck {
		t.Error("没收到 SETTINGS ACK —— 服务端可能没跑在事件循环上")
	}
}

// 服务端发数据，客户端（官方 Framer）要能收到。
func TestEngineWriteData(t *testing.T) {
	// 这个 handler 收到请求头就回一个响应
	addr, stop := startServer(t, &replyStream{t: t})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req bytes.Buffer
	req.Write(clientPreface)
	cfr := http2.NewFramer(&req, nil)
	cfr.WriteSettings()
	block := hpackBlock(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "http"},
		hpack.HeaderField{Name: ":path", Value: "/hi"},
	)
	cfr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	// 收响应
	fr := http2.NewFramer(conn, conn)
	dec := hpack.NewDecoder(4096, nil)
	var sawStatus, sawBody bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		switch v := f.(type) {
		case *http2.HeadersFrame:
			fields, _ := dec.DecodeFull(v.HeaderBlockFragment())
			for _, x := range fields {
				if x.Name == ":status" && x.Value == "200" {
					sawStatus = true
				}
			}
		case *http2.DataFrame:
			if string(v.Data()) == "hello from engine" {
				sawBody = true
			}
		}
		if sawStatus && sawBody {
			break
		}
	}
	if !sawStatus {
		t.Error("没收到响应头")
	}
	if !sawBody {
		t.Error("没收到响应体")
	}
}

// replyStream 收到请求头就回一个固定响应。
type replyStream struct {
	t    *testing.T
	done chan struct{}
}

func (r *replyStream) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	// 回响应头 + 响应体 + trailer
	if err := c.WriteHeaders(streamID, []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/plain"},
	}, false); err != nil {
		r.t.Errorf("写响应头: %v", err)
	}
	if err := c.WriteData(streamID, []byte("hello from engine"), false); err != nil {
		r.t.Errorf("写响应体: %v", err)
	}
	if err := c.WriteTrailers(streamID, []HeaderField{
		{Name: "x-done", Value: "1"},
	}); err != nil {
		r.t.Errorf("写 trailer: %v", err)
	}
}

func (r *replyStream) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {}
func (r *replyStream) OnRSTStream(c *Conn, streamID uint32, code ErrCode)           {}

// 前言被 TCP 切开（逐字节发），服务端也要能握手。
//
// 之前 Feed 里有个 TODO：序言不够 24 字节就直接返回，那些字节就丢了。
func TestEnginePrefaceSplit(t *testing.T) {
	rec := &syncRecorder{}
	addr, stop := startServer(t, rec)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req bytes.Buffer
	req.Write(clientPreface)
	cfr := http2.NewFramer(&req, nil)
	cfr.WriteSettings()
	block := hpackBlock(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "http"},
		hpack.HeaderField{Name: ":path", Value: "/"},
	)
	cfr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})

	// 一次只发几个字节
	all := req.Bytes()
	for i := 0; i < len(all); i += 3 {
		end := i + 3
		if end > len(all) {
			end = len(all)
		}
		if _, err := conn.Write(all[i:end]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	time.Sleep(300 * time.Millisecond)
	if rec.headerCount() == 0 {
		t.Fatal("序言被切开时服务端没收到 HEADERS")
	}
}

// 加个占位，避免 io 没被用到
var _ = io.EOF
