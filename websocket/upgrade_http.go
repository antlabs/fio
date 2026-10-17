// Copyright 2023-2026 antlabs. All rights reserved.
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

package websocket

import (
	"bytes"
	"net/http"
	"net/textproto"
	"strconv"

	"github.com/antlabs/fio/engine"
	fiohttp "github.com/antlabs/fio/http"
	"github.com/antlabs/wsutil/bytespool"
	"github.com/antlabs/wsutil/deflate"
)

// UpgradeConn 在 fio 自己的 HTTP/1.1 服务端上完成 WebSocket 握手。
//
// 它和 Upgrade 的区别：**不走 net/http、不 hijack、不 dup fd**。连接已经
// 由 engine 注册好了，这里只写 101 响应，然后把这条连接的 handler 从
// HTTP 换成 WebSocket：
//
//	ch := fiohttp.NewConnHandler(nil, 0)
//	ch.OnUpgrade(func(c *engine.Conn, r *fiohttp.Request) {
//		if _, err := upgrade.UpgradeConn(c, r); err != nil {
//			log.Printf("websocket upgrade failed: %v", err)
//		}
//	})
//	ln, _ := engine.ListenAndServe(m, addr, func() engine.Handler { return ch })
//
// 握手和第一帧拼在同一次 write 里也没问题：engine.SetHandler 会让读循环
// 在 HTTP handler 返回之后，继续把缓冲区里剩下的字节交给 WebSocket。
func (u *UpgradeServer) UpgradeConn(c *engine.Conn, r *fiohttp.Request) (wsCon *Conn, err error) {
	return upgradeConn(c, r, &u.config)
}

// UpgradeConn 和上边的 UpgradeServer.UpgradeConn 一样，只是每次调用现拼
// 一份配置，适合只升级一两条连接、不想先建 UpgradeServer 的场景。
func UpgradeConn(c *engine.Conn, r *fiohttp.Request, opts ...ServerOption) (wsCon *Conn, err error) {
	var conf ConnOption
	conf.defaultSetting()
	for _, o := range opts {
		o(&conf)
	}
	conf.defaultSettingAfter()
	return upgradeConn(c, r, &conf.Config)
}

func upgradeConn(c *engine.Conn, r *fiohttp.Request, conf *Config) (wsCon *Conn, err error) {
	hr := nativeHTTPRequest(r)
	if ecode, err := checkRequest(hr); err != nil {
		writeUpgradeError(c, ecode, err)
		return nil, err
	}

	var pd deflate.PermessageDeflateConf
	if conf.Decompression {
		pd, err = deflate.GetConnPermessageDeflate(hr.Header)
		if err != nil {
			writeUpgradeError(c, http.StatusBadRequest, err)
			return nil, err
		}
	}
	resetPermessageDeflate(&pd, conf)

	buf := bytespool.GetUpgradeRespBytes()
	defer bytespool.PutUpgradeRespBytes(buf)
	w := bytes.NewBuffer((*buf)[:0])
	if err = prepareWriteResponse(hr, w, conf, pd); err != nil {
		return nil, err
	}
	if err = c.Write(w.Bytes()); err != nil {
		return nil, err
	}
	// HTTP 这一轮可能开了攒包（握手后面还跟着帧时），把 101 冲出去并清掉
	// 攒包标志。否则 OnOpen 里写的消息会先攒着，和握手的顺序还要靠 HTTP
	// handler 的 defer 兜底。
	c.EndCork()

	// 连接对象在 engine.Conn 上建好、装进 UserData，然后才换 handler：
	// 换完 handler 之后缓冲区里剩下的字节就会交给它。
	h := NewConnHandler(conf)
	h.SetPermessageDeflate(pd)
	conf.engineMode = true
	if err = h.Bind(c); err != nil {
		return nil, err
	}
	wsCon, _ = c.UserData().(*Conn)
	if wsCon == nil {
		return nil, ErrClosed
	}
	c.SetHandler(h)
	if wsCon.Callback != nil {
		wsCon.Callback.OnOpen(wsCon)
	}
	return wsCon, nil
}

// nativeHTTPRequest 把 fio 的 Request 转成握手校验用的 net/http.Request。
//
// 每连接一次，这点分配比 net/http 那套(goroutine + bufio + readRequest)
// 便宜得多。头名要转成规范大小写：net/http 的 Header.Get 是按规范名查
// map 的，而 fio 的解析器保留报文里的原样。
func nativeHTTPRequest(r *fiohttp.Request) *http.Request {
	header := make(http.Header, len(r.Header))
	for k, v := range r.Header {
		header[textproto.CanonicalMIMEHeaderKey(k)] = []string{v}
	}

	host, _ := r.Get("Host")
	protoMajor, protoMinor := 1, 1
	if r.Proto == "HTTP/1.0" {
		protoMinor = 0
	}
	return &http.Request{
		Method:     r.Method,
		Proto:      r.Proto,
		ProtoMajor: protoMajor,
		ProtoMinor: protoMinor,
		Header:     header,
		Host:       host,
		RequestURI: r.Target,
	}
}

// writeUpgradeError 是原生路径上的错误响应：尽力写一个 HTTP 响应再关连接。
func writeUpgradeError(c *engine.Conn, code int, err error) {
	if code <= 0 {
		code = http.StatusBadRequest
	}
	body := err.Error()
	resp := "HTTP/1.1 " + strconv.Itoa(code) + " " + http.StatusText(code) + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_ = c.Write([]byte(resp))
	_ = c.Close()
}
