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
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/fio/http2"
	"golang.org/x/net/http2/hpack"

	xhttp2 "golang.org/x/net/http2"
)

// startGRPCServer 起一个真实的 gRPC 服务端：
//
//	engine 的事件循环（epoll/kqueue）
//	  -> http2.ConnHandler（解帧、管流、HPACK）
//	    -> grpc.ServerHandler（认 :path、切消息、发 trailer）
//	      -> 业务 Handler
//
// 这三层全在事件循环的线程上，没有 per-connection 的 goroutine。
func startGRPCServer(t *testing.T, h Handler) (string, func()) {
	t.Helper()

	m, err := engine.NewAndStart(engine.WithEventLoops(2), engine.WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatal(err)
	}

	// accept 循环交给 engine.Listener：非阻塞 accept + 停止标志，
	// 两个平台的 Close 行为一致（见那个类型的说明）。
	ln, err := engine.ListenAndServe(m, "127.0.0.1:0", func() engine.Handler {
		// 每条连接：http2 的适配层，里面套 gRPC 的流处理器
		return http2.NewStreamConnHandler(NewServerHandler(h))
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

// hpackBlock 用官方编码器编一个头块。
func hpackBlock(t *testing.T, fields ...hpack.HeaderField) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// 调用的结果（客户端侧收下来的）。
type callResult struct {
	headers    []hpack.HeaderField // 响应头
	trailers   []hpack.HeaderField // trailer（grpc-status 在这）
	msgs       [][]byte            // 消息体
	httpStatus string
}

// doCall 用**官方 Framer** 发一次一元 gRPC 调用，把结果收回来。
//
// 客户端这边刻意不用我们自己的 http2 实现——官方实现认了才说明
// 我们发出去的帧、HPACK、trailer 都是合法的。
func doCall(t *testing.T, addr, path string, reqMsg []byte, extraHdr ...hpack.HeaderField) *callResult {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req bytes.Buffer
	req.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	fr := xhttp2.NewFramer(&req, nil)
	fr.WriteSettings()

	hdr := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: path},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "localhost"},
		{Name: "content-type", Value: ContentType},
		{Name: "te", Value: "trailers"},
	}
	hdr = append(hdr, extraHdr...)
	block := hpackBlock(t, hdr...)
	fr.WriteHeaders(xhttp2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: false,
	})
	// 请求消息（带 gRPC 的 5 字节头），最后一条带 END_STREAM
	fr.WriteData(1, true, Encode(nil, reqMsg))

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	// 收响应
	res := &callResult{}
	rfr := xhttp2.NewFramer(conn, conn)
	dec := hpack.NewDecoder(4096, nil)
	for {
		f, err := rfr.ReadFrame()
		if err != nil {
			break
		}
		switch v := f.(type) {
		case *xhttp2.HeadersFrame:
			fields, derr := dec.DecodeFull(v.HeaderBlockFragment())
			if derr != nil {
				t.Fatalf("解头块: %v", derr)
			}
			isTrailer := false
			for _, x := range fields {
				if x.Name == "grpc-status" {
					isTrailer = true
				}
				if x.Name == ":status" {
					res.httpStatus = x.Value
				}
			}
			if isTrailer {
				res.trailers = fields
			} else {
				res.headers = fields
			}
			if v.StreamEnded() {
				return res
			}
		case *xhttp2.DataFrame:
			data := v.Data()
			// 切 gRPC 消息
			for len(data) >= 5 {
				n := int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])
				if len(data) < 5+n {
					break
				}
				res.msgs = append(res.msgs, append([]byte(nil), data[5:5+n]...))
				data = data[5+n:]
			}
			if v.StreamEnded() {
				return res
			}
		case *xhttp2.RSTStreamFrame:
			t.Logf("收到 RST_STREAM: %v", v.ErrCode)
			return res
		case *xhttp2.SettingsFrame:
			if !v.IsAck() {
				var ack bytes.Buffer
				xhttp2.NewFramer(&ack, nil).WriteSettingsAck()
				conn.Write(ack.Bytes())
			}
		case *xhttp2.GoAwayFrame:
			t.Logf("收到 GOAWAY: %v", v.ErrCode)
			return res
		}
	}
	return res
}

// runHandler 是测试用的业务：一元调用，把请求里的字符串前面加个 "echo: "。
type runHandler struct{}

func (runHandler) OnCall(c *http2.Conn, call *ServerCall) error { return nil }

func (runHandler) OnMessage(c *http2.Conn, call *ServerCall, msg []byte) error {
	// 一元调用：收到消息就回
	if call.Replied() {
		return nil // 流式调用里回多条由业务自己决定，这里只回第一条
	}
	return call.Reply(c, append([]byte("echo: "), msg...), StatusOK())
}

func (runHandler) OnEnd(c *http2.Conn, call *ServerCall) error {
	// 空请求体（没有消息）也要回一个，不然对端干等
	if !call.Replied() {
		return call.Reply(c, []byte("echo: "), StatusOK())
	}
	return nil
}

// **端到端**：gRPC 服务端跑在 engine 上，客户端用官方 x/net/http2。
//
// 这条路径证明 gRPC 接上事件循环了：fd 读到字节 -> http2 解帧 ->
// gRPC 切消息 -> 业务回复 -> 帧编回去 -> 写回 fd。
func TestEngineGRPCUnary(t *testing.T) {
	addr, stop := startGRPCServer(t, runHandler{})
	defer stop()

	res := doCall(t, addr, "/helloworld.Greeter/SayHello", []byte("hello"))

	if res.httpStatus != "200" {
		t.Errorf(":status = %q, want 200", res.httpStatus)
	}
	if len(res.msgs) != 1 {
		t.Fatalf("收到 %d 条消息, want 1", len(res.msgs))
	}
	if string(res.msgs[0]) != "echo: hello" {
		t.Errorf("消息 = %q, want %q", res.msgs[0], "echo: hello")
	}

	// trailer 里要有 grpc-status: 0
	st := statusFromTrailers(res.trailers)
	if st == nil {
		t.Fatal("trailer 里没有 grpc-status")
	}
	if st.Code != OK {
		t.Errorf("grpc-status = %v (%s)", st.Code, st.Message)
	}

	// 响应头里要有 content-type: application/grpc
	if !hasHeader(res.headers, "content-type", ContentType) {
		t.Errorf("响应头缺 content-type: application/grpc: %v", res.headers)
	}
}

// 业务返回错误：状态要出现在 trailer 里，消息体可以没有。
func TestEngineGRPCErrorStatus(t *testing.T) {
	addr, stop := startGRPCServer(t, errHandler{})
	defer stop()

	res := doCall(t, addr, "/pkg.Svc/Get", []byte("x"))

	st := statusFromTrailers(res.trailers)
	if st == nil {
		t.Fatal("trailer 里没有 grpc-status")
	}
	if st.Code != NotFound {
		t.Errorf("grpc-status = %v, want NotFound", st.Code)
	}
	if st.Message != "no such user" {
		t.Errorf("grpc-message = %q", st.Message)
	}
}

type errHandler struct{}

func (errHandler) OnCall(*http2.Conn, *ServerCall) error { return nil }
func (errHandler) OnMessage(c *http2.Conn, call *ServerCall, msg []byte) error {
	return call.ReplyError(c, StatusNotFound("no such user"))
}
func (errHandler) OnEnd(*http2.Conn, *ServerCall) error { return nil }

// 非 gRPC 的 content-type 要被拒（同一端口上可能跑着普通 HTTP/2）。
func TestEngineGRPCRejectsNonGRPC(t *testing.T) {
	addr, stop := startGRPCServer(t, runHandler{})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req bytes.Buffer
	req.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	fr := xhttp2.NewFramer(&req, nil)
	fr.WriteSettings()
	block := hpackBlock(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/index.html"},
		hpack.HeaderField{Name: ":scheme", Value: "http"},
		hpack.HeaderField{Name: "content-type", Value: "text/html"},
	)
	fr.WriteHeaders(xhttp2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	})
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	rfr := xhttp2.NewFramer(conn, conn)
	dec := hpack.NewDecoder(4096, nil)
	for i := 0; i < 10; i++ {
		f, err := rfr.ReadFrame()
		if err != nil {
			t.Fatalf("没等到响应: %v", err)
		}
		if hf, ok := f.(*xhttp2.HeadersFrame); ok {
			fields, _ := dec.DecodeFull(hf.HeaderBlockFragment())
			for _, x := range fields {
				if x.Name == ":status" {
					if x.Value != "415" {
						t.Errorf(":status = %q, want 415", x.Value)
					}
					return
				}
			}
		}
	}
	t.Fatal("没收到 415")
}

// 消息跨多个 DATA 帧（TCP 和 HTTP/2 都不保证边界对齐）。
func TestEngineGRPCMessageSplitAcrossFrames(t *testing.T) {
	addr, stop := startGRPCServer(t, runHandler{})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req bytes.Buffer
	req.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	fr := xhttp2.NewFramer(&req, nil)
	fr.WriteSettings()
	block := hpackBlock(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/pkg.Svc/Split"},
		hpack.HeaderField{Name: ":scheme", Value: "http"},
		hpack.HeaderField{Name: "content-type", Value: ContentType},
	)
	fr.WriteHeaders(xhttp2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block, EndHeaders: true,
	})

	// 把一条完整消息拆成两个 DATA 帧（第 3 字节处切，正好切在长度字段中间）
	full := Encode(nil, []byte("split me across frames"))
	fr.WriteData(1, false, full[:3])
	fr.WriteData(1, true, full[3:])

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	rfr := xhttp2.NewFramer(conn, conn)
	for i := 0; i < 20; i++ {
		f, err := rfr.ReadFrame()
		if err != nil {
			t.Fatalf("没等到响应: %v", err)
		}
		if d, ok := f.(*xhttp2.DataFrame); ok {
			data := d.Data()
			if len(data) < 5 {
				continue
			}
			n := int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])
			if string(data[5:5+n]) != "echo: split me across frames" {
				t.Errorf("消息 = %q", data[5:5+n])
			}
			return
		}
	}
	t.Fatal("没收到响应体")
}

// ---- 小工具 ----

func statusFromTrailers(fields []hpack.HeaderField) *Status {
	if len(fields) == 0 {
		return nil
	}
	hf := make([]http2.HeaderField, 0, len(fields))
	for _, f := range fields {
		hf = append(hf, http2.HeaderField{Name: f.Name, Value: f.Value})
	}
	for _, f := range hf {
		if f.Name == "grpc-status" {
			return StatusFromHeaders(hf)
		}
	}
	return nil
}

func hasHeader(fields []hpack.HeaderField, name, value string) bool {
	for _, f := range fields {
		if f.Name == name && f.Value == value {
			return true
		}
	}
	return false
}
