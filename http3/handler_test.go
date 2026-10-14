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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	fiohttp "github.com/antlabs/fio/http"
	fioquic "github.com/antlabs/fio/quic"
	fiotls "github.com/antlabs/fio/tls"
)

// startBridgeServer 起一个**请求级**的 h3 服务端：handler 的形状和
// http1/http2 完全一样（http.HandlerFunc(serveHTTP)），验证三套形参统一。
func startBridgeServer(t *testing.T, h fiohttp.Handler, maxHeaderSize int32) string {
	t.Helper()
	cert, err := fiotls.SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	srv := &NativeServer{
		Addr:      "127.0.0.1:0",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
		// 和 http1/http2 的入口一个写法：NewConnHandler(handler, size)
		NewHandler: func() StreamHandler {
			return NewConnHandler(h, maxHeaderSize)
		},
	}
	ln, err := fioquic.Listen(srv.Addr, fioquic.Config{TLSConfig: srv.TLSConfig})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// 请求级 handler 的 GET：方法/路径/查询串都要对上（和 h1/h2 一套写法）。
func TestConnHandlerGet(t *testing.T) {
	addr := startBridgeServer(t, fiohttp.HandlerFunc(func(c *fiohttp.Ctx) error {
		return c.String(fmt.Sprintf("%s %s q=%s", c.Method(), c.Path(), c.Query("a")))
	}), 0)

	resp, err := nativeClient().Get("https://" + addr + "/hello?a=1&b=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "GET /hello q=1" {
		t.Fatalf("状态 %d 体 %q", resp.StatusCode, body)
	}
}

// POST 带体：数据要完整送到 handler。
func TestConnHandlerPostBody(t *testing.T) {
	addr := startBridgeServer(t, fiohttp.HandlerFunc(func(c *fiohttp.Ctx) error {
		return c.String("len=" + fmt.Sprint(len(c.Body())))
	}), 0)

	body := strings.Repeat("abc", 5000)
	resp, err := nativeClient().Post("https://"+addr+"/echo", "application/octet-stream", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != fmt.Sprintf("len=%d", len(body)) {
		t.Fatalf("体 %q", got)
	}
}

// 响应头 + 非 200 状态码：头名会被折成小写发出去（RFC 9114 4.2，
// 客户端收到大写头名会判协议错、把流重置）。
func TestConnHandlerHeadersAndStatus(t *testing.T) {
	addr := startBridgeServer(t, fiohttp.HandlerFunc(func(c *fiohttp.Ctx) error {
		c.Status(404)
		c.Set("X-Custom-Header", "yes") // 大写：发出去前要折小写
		c.Set("content-type", "text/plain")
		return c.String("nope")
	}), 0)

	resp, err := nativeClient().Get("https://" + addr + "/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 404 || string(body) != "nope" {
		t.Fatalf("状态 %d 体 %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("x-custom-header"); got != "yes" {
		t.Fatalf("x-custom-header = %q", got)
	}
}

// handler 在写响应之前报错 -> 500（和 h1/h2 一个语义）。
func TestConnHandlerError(t *testing.T) {
	addr := startBridgeServer(t, fiohttp.HandlerFunc(func(c *fiohttp.Ctx) error {
		return errors.New("boom")
	}), 0)

	resp, err := nativeClient().Get("https://" + addr + "/boom")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("状态 %d，期望 500", resp.StatusCode)
	}
}

// 头太大 -> 431（和 http1 的 ErrHeaderTooLarge、h2 的
// SETTINGS_MAX_HEADER_LIST_SIZE 一个处置）。
func TestConnHandlerHeaderTooLarge(t *testing.T) {
	// 上限故意设得很小，普通请求就会超
	addr := startBridgeServer(t, fiohttp.HandlerFunc(func(c *fiohttp.Ctx) error {
		return c.String("should not reach")
	}), 32)

	req, err := http.NewRequest("GET", "https://"+addr+"/big", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-padding", strings.Repeat("p", 200))
	resp, err := nativeClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 431 {
		t.Fatalf("状态 %d，期望 431", resp.StatusCode)
	}
}

// 流级和请求级的构造函数都在，名字和 h2 对齐（编译期检查，顺带跑一下）。
func TestHandlerConstructors(t *testing.T) {
	var sh StreamHandler = NewStreamConnHandler(&testH3Handler{fn: func(m, p, q string, b []byte) (int, string) {
		return 200, "ok"
	}})
	if sh == nil {
		t.Fatal("NewStreamConnHandler 返回 nil")
	}
	var sh2 StreamHandler = NewConnHandler(fiohttp.HandlerFunc(func(c *fiohttp.Ctx) error {
		return c.String("ok")
	}), 0)
	if sh2 == nil {
		t.Fatal("NewConnHandler 返回 nil")
	}
}
