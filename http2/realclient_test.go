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

// 拿**真实的 HTTP/2 客户端**打我们的服务端。
//
// 前面 interop_test.go 用的是官方 `x/net/http2.Framer`——它只做帧的编解码，
// 上面那层（流状态、SETTINGS 协商、**流控**、连接管理）一概没有。所以它能
// 证明"帧是合法的"，证明不了"一个真的 HTTP/2 客户端能用"。
//
// 这里用的 `x/net/http2.Transport` 是**完整的实现**：它自己管 HPACK 动态表、
// 自己算流控窗口、自己决定什么时候发 WINDOW_UPDATE、流状态机也是完整的。
// 浏览器和 grpc-go 用的就是同一套逻辑。它跑通才说明我们的服务端在真实
// 客户端眼里是合法的。
package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/antlabs/fio/engine"
	fiohttp "github.com/antlabs/fio/http"
	fiotls "github.com/antlabs/fio/tls"
	xhttp2 "golang.org/x/net/http2"
)

// startH2C 起一个 h2c（明文 HTTP/2）服务端，返回它的 URL。
//
// 用 http2.Transport 的 DialTLSContext 钩子把明文连接塞给它——这是
// x/net/http2 官方推荐的 h2c 用法（Transport 只认 https 的 scheme，
// 但拨号可以自己来）。
func startH2C(t *testing.T, h StreamHandler) (string, func()) {
	t.Helper()

	m, err := engine.NewAndStart(engine.WithEventLoops(2))
	if err != nil {
		t.Fatal(err)
	}
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

// newTransport 建一个走明文的 x/net/http2 Transport。
func newTransport(addr string) *http2Transport {
	return &http2Transport{addr: addr}
}

// 这个类型只是为了让 newTransport 的签名干净点（下面用接口也行，但直接
// 用具体类型更直白）。
type http2Transport struct{ addr string }

// doRequest 用真实客户端发一个请求，返回响应。
func (tr *http2Transport) do(t *testing.T, method, path string, body io.Reader) (*http.Response, error) {
	t.Helper()

	// AllowHTTP + 自己拨号 = h2c（Transport 只认 https，但拨号可以自己来）
	x := &xhttp2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, tr.addr)
		},
	}
	cli := &http.Client{Transport: x, Timeout: 20 * time.Second}
	req, err := http.NewRequest(method, "http://"+tr.addr+path, body)
	if err != nil {
		return nil, err
	}
	return cli.Do(req)
}

// replyStream 是最简单的业务：收到请求头就回一段固定内容。
//
// body 由测试控制（用来测大响应、流控）。
type fixedStream struct {
	body []byte
	// chunk 非 0 的话分多次发（测多个 DATA 帧）
	chunk int
}

func (f *fixedStream) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	_ = c.WriteHeaders(streamID, []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "content-length", Value: itoa(len(f.body))},
	}, false)

	if f.chunk > 0 {
		for off := 0; off < len(f.body); off += f.chunk {
			end := off + f.chunk
			if end > len(f.body) {
				end = len(f.body)
			}
			_ = c.WriteData(streamID, f.body[off:end], end == len(f.body))
		}
		if len(f.body) == 0 {
			_ = c.WriteData(streamID, nil, true)
		}
		return
	}
	_ = c.WriteData(streamID, f.body, true)
}

func (f *fixedStream) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {}
func (f *fixedStream) OnRSTStream(c *Conn, streamID uint32, code ErrCode)           {}

// **真实客户端打过来**：最简单的 GET。
func TestRealClientSimpleGet(t *testing.T) {
	addr, stop := startH2C(t, &fixedStream{body: []byte("hello from the server")})
	defer stop()

	resp, err := newTransport(addr).do(t, "GET", "/hello", nil)
	if err != nil {
		t.Fatalf("真实客户端请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("状态码 = %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("协议版本 = %d（真实客户端没走 h2？）", resp.ProtoMajor)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读 body: %v", err)
	}
	if string(body) != "hello from the server" {
		t.Errorf("body = %q", body)
	}
}

// 大响应体：**这条会撞上流控**。
//
// 真实客户端声明自己的窗口是 65535（默认），我们发超过这个数就必须等它的
// WINDOW_UPDATE。不做发送流控的话，客户端会认为我们违反了协议，报
// "flow control window exceeded"（GOAWAY 或者 RST_STREAM）。
//
// 这条是 HTTP/2 和 HTTP/1.1 最大的区别所在：HTTP/1.1 是"把字节写出去就完"，
// HTTP/2 每一段数据都要**先记账**（对端的窗口够不够）。
func TestRealClientLargeResponseFlowControl(t *testing.T) {
	// 256KB：远超过默认窗口 65535，逼出流控
	body := make([]byte, 256*1024)
	for i := range body {
		body[i] = byte(i % 251)
	}

	addr, stop := startH2C(t, &fixedStream{body: body})
	defer stop()

	resp, err := newTransport(addr).do(t, "GET", "/big", nil)
	if err != nil {
		t.Fatalf("大响应请求失败: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读大 body: %v（流控没做的话这里会断）", err)
	}
	if len(got) != len(body) {
		t.Fatalf("收到 %d 字节, want %d", len(got), len(body))
	}
	for i := range body {
		if got[i] != body[i] {
			t.Fatalf("第 %d 字节不同", i)
		}
	}
}

// 客户端发大请求体：**这条撞的是接收侧的流控**。
//
// 客户端受我们声明的窗口限制（默认 65535）。我们不主动发 WINDOW_UPDATE
// 的话，客户端发到 65535 就不敢再发了——请求会卡在那里。
func TestRealClientLargeRequestBody(t *testing.T) {
	got := make(chan int, 1)
	h := &bodyRecorder{got: got}

	addr, stop := startH2C(t, h)
	defer stop()

	body := strings.Repeat("x", 256*1024)
	resp, err := newTransport(addr).do(t, "POST", "/upload", strings.NewReader(body))
	if err != nil {
		t.Fatalf("大请求体失败: %v（接收侧没发 WINDOW_UPDATE 的话会卡住）", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	select {
	case n := <-got:
		if n != len(body) {
			t.Errorf("服务端收到 %d 字节, want %d", n, len(body))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("服务端没收到完整的请求体")
	}
}

// bodyRecorder 记下收到的数据量，收完 END_STREAM 就通知。
type bodyRecorder struct {
	got  chan int
	size int
}

func (b *bodyRecorder) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	if endStream {
		select {
		case b.got <- b.size:
		default:
		}
	}
}

func (b *bodyRecorder) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {
	b.size += len(data)
	if endStream {
		_ = c.WriteHeaders(streamID, []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: "0"},
		}, false)
		_ = c.WriteData(streamID, nil, true)
		select {
		case b.got <- b.size:
		default:
		}
	}
}

func (b *bodyRecorder) OnRSTStream(c *Conn, streamID uint32, code ErrCode) {}

// 多个请求复用一条连接（真实客户端默认会复用）。
//
// HTTP/2 的连接是长命的、上面跑很多流——所以服务端必须能处理"同一个连接上
// 交错来的多个流"，不能假定"一个连接一个请求"。
func TestRealClientConnectionReuse(t *testing.T) {
	addr, stop := startH2C(t, &echoPathStream{})
	defer stop()

	tr := newTransport(addr)

	// 用一个 client 发多次，Transport 会复用连接
	x := &xhttp2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, a string, cfg *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, tr.addr)
		},
	}
	cli := &http.Client{Transport: x, Timeout: 15 * time.Second}

	for i := 0; i < 20; i++ {
		path := fmt.Sprintf("/item/%d", i)
		resp, err := cli.Get("http://" + addr + path)
		if err != nil {
			t.Fatalf("第 %d 个请求: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != path {
			t.Fatalf("第 %d 个响应 = %q, want %q", i, body, path)
		}
	}
}

// echoPathStream 把 :path 原样回给客户端。
type echoPathStream struct{}

func (echoPathStream) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	path := ""
	for _, f := range headers {
		if f.Name == ":path" {
			path = f.Value
		}
	}
	_ = c.WriteHeaders(streamID, []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-length", Value: itoa(len(path))},
	}, false)
	_ = c.WriteData(streamID, []byte(path), true)
}

func (echoPathStream) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {}
func (echoPathStream) OnRSTStream(c *Conn, streamID uint32, code ErrCode)           {}

// **HTTPS 上的真实客户端**：TLS + HTTP/2 叠起来，客户端用标准库的
// x/net/http2.Transport（它会自己走 ALPN 协商 h2）。
func TestRealClientOverTLS(t *testing.T) {
	cert, err := fiotls.SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	m, err := engine.NewAndStart(engine.WithEventLoops(2))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Free()

	ln, err := engine.ListenAndServe(m, "127.0.0.1:0", func() engine.Handler {
		// HTTP/2 包在 TLS 里面。
		//
		// **NextProtos 必须是 ["h2"]**：RFC 9113 要求 TLS 上的 HTTP/2
		// 通过 ALPN 协商出 "h2"，标准库的客户端协商不出来就直接拒绝
		// （"unexpected ALPN protocol"）。
		return fiotls.NewConnHandler(&fiotls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{fiotls.ALPNProtoH2},
		}, NewStreamConnHandler(&echoPathStream{}))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	x := &xhttp2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := &http.Client{Transport: x, Timeout: 15 * time.Second}

	resp, err := cli.Get("https://" + ln.Addr() + "/over-tls")
	if err != nil {
		t.Fatalf("https 上的 HTTP/2 请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Errorf("协议版本 = %d（ALPN 没协商成 h2？）", resp.ProtoMajor)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "/over-tls" {
		t.Errorf("body = %q", body)
	}
}

// itoa 是本文件用的小工具（http2 包里没有别的 itoa）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// 请求级 handler（http.Handler / http.HandlerFunc，和 http1 一个形状）
// 服务真实客户端：HEADERS/DATA 要拼成一个 *http.Request，响应要编回帧。
func TestRealClientHandlerLevel(t *testing.T) {
	m, err := engine.NewAndStart(engine.WithEventLoops(2))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Free()

	// 和 http1 的 http.NewConnHandler(http.HandlerFunc(serveHTTP), 0)
	// 是一个形状
	ln, err := engine.ListenAndServe(m, "127.0.0.1:0", func() engine.Handler {
		return NewConnHandler(fiohttp.HandlerFunc(func(c *fiohttp.Ctx) error {
			if c.Path() == "/echo" {
				return c.Bytes(c.Body())
			}
			return c.String("hello, " + c.Method() + " " + c.Target())
		}), 0)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	resp, err := newTransport(ln.Addr()).do(t, "GET", "/hello", nil)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "hello, GET /hello" {
		t.Errorf("GET body = %q", got)
	}

	// POST：请求体（一个 HEADERS + 若干 DATA 帧）要原样拼出来
	resp, err = newTransport(ln.Addr()).do(t, "POST", "/echo", strings.NewReader("echo-me-256k"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	got, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "echo-me-256k" {
		t.Errorf("POST body = %q", got)
	}
}
