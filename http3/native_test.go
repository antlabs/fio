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
	"strings"
	"testing"
	"time"

	fiotls "github.com/antlabs/fio/tls"
	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
)

// 自建服务端的端到端：用 quic-go 的 h3 客户端（ngtcp2 之外的另一个实现）
// 打它，验证 QPACK 头块、帧拼接、流分类都对。
//
// **为什么不只用自家客户端测**：自己编自己解，两边错得一样就看不出来
// （tls 那边 RSA-PSS 的盐长就是这么藏了很久）。对端用 quic-go 的
// http3 client，它用的是完整的 QPACK + 自己的流管理。
func startNativeServer(t *testing.T, h Handler) string {
	t.Helper()
	cert, err := fiotls.SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	srv := &NativeServer{
		Addr:      "127.0.0.1:0",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
		Handler:   h,
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

func TestNativeServerGet(t *testing.T) {
	addr := startNativeServer(t, func(w *ResponseWriter, r *Request) error {
		body := fmt.Sprintf("%s %s q=%s", r.Method, r.Path, r.Query)
		return w.WriteResponse(200, []qpack.HeaderField{{Name: "content-type", Value: "text/plain"}}, []byte(body))
	})
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
	addr := startNativeServer(t, func(w *ResponseWriter, r *Request) error {
		// 回显，顺便断言请求头也收到了
		n, _ := r.Get("x-probe")
		return w.WriteResponse(200, nil, append([]byte(n+":"), r.Body...))
	})
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
	addr := startNativeServer(t, func(w *ResponseWriter, r *Request) error {
		return w.WriteResponse(200, nil, []byte(r.Path))
	})

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

// 404 路径也要能走通（状态码不是硬编码成 200）。
func TestNativeServerStatus(t *testing.T) {
	addr := startNativeServer(t, func(w *ResponseWriter, r *Request) error {
		if r.Path != "/ok" {
			return w.WriteResponse(404, nil, []byte("nope"))
		}
		return w.WriteResponse(200, nil, []byte("ok"))
	})
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
