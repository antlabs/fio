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

package http3

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	fiotls "github.com/antlabs/fio/tls"
	"github.com/quic-go/quic-go"
)

// testStream 是按 http2 那套写法拼一个请求所需的状态。
type testStream struct {
	method, path, query string
}

// testH3Handler 是一个最小的 StreamHandler：攒请求，读完了回一个响应。
//
// 写法刻意和 arena 里的 h2Handler 一样（OnHeaders 攒、OnData 收尾、
// 然后 WriteHeaders/WriteData），验证这套形状在 h3 上也顺手。
type testH3Handler struct {
	fn      func(method, path, query string, body []byte) (int, string)
	streams map[uint64]testStream
}

func newTestH3Handler(fn func(method, path, query string, body []byte) (int, string)) *testH3Handler {
	return &testH3Handler{fn: fn, streams: map[uint64]testStream{}}
}

func (h *testH3Handler) OnHeaders(c *Conn, streamID uint64, headers []HeaderField, endStream bool) {
	var s testStream
	for _, f := range headers {
		switch f.Name {
		case ":method":
			s.method = f.Value
		case ":path":
			if i := strings.IndexByte(f.Value, '?'); i >= 0 {
				s.path, s.query = f.Value[:i], f.Value[i+1:]
			} else {
				s.path = f.Value
			}
		}
	}
	h.streams[streamID] = s
	if endStream {
		h.respond(c, streamID, nil)
	}
}

func (h *testH3Handler) OnData(c *Conn, streamID uint64, data []byte, endStream bool) {
	if endStream {
		h.respond(c, streamID, data)
	}
}

func (h *testH3Handler) OnRSTStream(c *Conn, streamID uint64, code ErrCode) {
	delete(h.streams, streamID)
}

func (h *testH3Handler) respond(c *Conn, streamID uint64, body []byte) {
	s := h.streams[streamID]
	delete(h.streams, streamID)
	status, respBody := h.fn(s.method, s.path, s.query, body)
	err := c.WriteHeaders(streamID, []HeaderField{
		{Name: ":status", Value: strconv.Itoa(status)},
		{Name: "content-type", Value: "text/plain"},
	}, len(respBody) == 0)
	if err != nil {
		return
	}
	if len(respBody) > 0 {
		_ = c.WriteData(streamID, []byte(respBody), true)
	}
}

func startNativeServer(t *testing.T, h StreamHandler) string {
	t.Helper()
	cert, err := fiotls.SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	srv := &NativeServer{
		Addr:       "127.0.0.1:0",
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
		NewHandler: func() StreamHandler { return h },
	}
	ln, err := quic.ListenAddr(srv.Addr, srv.TLSConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func nativeClient() *http.Client {
	tr := &Transport{TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// 用 quic-go 的 h3 客户端（ngtcp2 之外的另一个实现）打自建服务端，
// 验证 QPACK 头块、帧拼接、流分类都对。
//
// **为什么不只用自家客户端测**：自己编自己解，两边错得一样就看不出来
// （tls 那边 RSA-PSS 的盐长就是这么藏了很久）。对端用 quic-go 的
// http3 client，它用的是完整的 QPACK + 自己的流管理。
func TestNativeServerGet(t *testing.T) {
	addr := startNativeServer(t, newTestH3Handler(
		func(method, path, query string, body []byte) (int, string) {
			return 200, fmt.Sprintf("%s %s q=%s", method, path, query)
		}))
	c := nativeClient()
	resp, err := c.Get("https://" + addr + "/hello?a=1&b=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("状态码 %d", resp.StatusCode)
	}
	if got := string(body); got != "GET /hello q=a=1&b=2" {
		t.Fatalf("体是 %q", got)
	}
	if ct := resp.Header.Get("content-type"); ct != "text/plain" {
		t.Fatalf("content-type 是 %q", ct)
	}
}

// POST 带体：走 DATA 帧，两个方向都要对。
func TestNativeServerPostBody(t *testing.T) {
	addr := startNativeServer(t, newTestH3Handler(
		func(method, path string, q string, body []byte) (int, string) {
			return 200, ":" + string(body)
		}))
	c := nativeClient()
	resp, err := c.Post("https://"+addr+"/echo", "application/octet-stream",
		strings.NewReader(strings.Repeat("abc", 5000)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	want := ":" + strings.Repeat("abc", 5000)
	if string(body) != want {
		t.Fatalf("回显长度 %d，期望 %d", len(body), len(want))
	}
}

// 同一连接上并发多条流：每个请求的/响应不能串。
func TestNativeServerConcurrentStreams(t *testing.T) {
	addr := startNativeServer(t, newTestH3Handler(
		func(method, path string, q string, body []byte) (int, string) {
			return 200, path
		}))

	c := nativeClient()
	const n = 32
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			path := fmt.Sprintf("/s%02d", i)
			resp, err := c.Get("https://" + addr + path)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != path {
				errs <- fmt.Errorf("%s 收到 %q", path, body)
				return
			}
			errs <- nil
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// 状态码不是硬编码成 200。
func TestNativeServerStatus(t *testing.T) {
	addr := startNativeServer(t, newTestH3Handler(
		func(method, path string, q string, body []byte) (int, string) {
			if path != "/ok" {
				return 404, "nope"
			}
			return 200, "ok"
		}))
	c := nativeClient()
	resp, err := c.Get("https://" + addr + "/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 404 || string(body) != "nope" {
		t.Fatalf("状态 %d 体 %q", resp.StatusCode, body)
	}
}
