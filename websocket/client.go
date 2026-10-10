// Copyright 2023-2024 antlabs. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package websocket

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/antlabs/wsutil/deflate"
	"github.com/antlabs/wsutil/hostname"
)

var (
	defaultTimeout = time.Minute * 30
)

type DialOption struct {
	Header               http.Header
	u                    *url.URL
	tlsConfig            *tls.Config
	dialTimeout          time.Duration
	bindClientHttpHeader *http.Header // 握手成功之后, 客户端获取http.Header,
	Config
}

func ClientOptionToConf(opts ...ClientOption) *DialOption {
	var dial DialOption
	dial.dialTimeout = defaultTimeout
	dial.defaultSetting()
	for _, o := range opts {
		o(&dial)
	}
	dial.defaultSettingAfter()
	return &dial
}

func DialConf(rawUrl string, conf *DialOption) (*Conn, error) {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}

	conf.u = u
	if conf.Header == nil {
		conf.Header = make(http.Header)
	}

	return conf.Dial()
}

// https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
// 又是一顿if else, 咬文嚼字
func Dial(rawUrl string, opts ...ClientOption) (*Conn, error) {
	var dial DialOption
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}

	dial.u = u
	dial.dialTimeout = defaultTimeout
	if dial.Header == nil {
		dial.Header = make(http.Header)
	}

	dial.defaultSetting()
	for _, o := range opts {
		o(&dial)
	}

	dial.defaultSettingAfter()
	return dial.Dial()
}

// 准备握手的数据
func (d *DialOption) handshake() (*http.Request, string, error) {
	switch {
	case d.u.Scheme == "wss":
		d.u.Scheme = "https"
	case d.u.Scheme == "ws":
		d.u.Scheme = "http"
	default:
		return nil, "", fmt.Errorf("Unknown scheme, only supports ws:// or wss://: got %s", d.u.Scheme)
	}

	// 满足4.1
	// 第2点 GET约束http 1.1版本约束
	req, err := http.NewRequest("GET", d.u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	// 第5点
	d.Header.Add("Upgrade", "websocket")
	// 第6点
	d.Header.Add("Connection", "Upgrade")
	// 第7点
	secWebSocket := secWebSocketAccept()
	d.Header.Add("Sec-WebSocket-Key", secWebSocket)
	// TODO 第8点
	// 第9点
	d.Header.Add("Sec-WebSocket-Version", "13")

	if d.Decompression && d.Compression {
		d.Header.Add("Sec-WebSocket-Extensions", deflate.GenSecWebSocketExtensions(d.PermessageDeflateConf))
	}

	req.Header = d.Header
	return req, secWebSocket, nil
}

// 检查服务端响应的数据
// 4.2.2.5
func (d *DialOption) validateRsp(rsp *http.Response, secWebSocket string) error {
	if rsp.StatusCode != 101 {
		return fmt.Errorf("%w %d", ErrWrongStatusCode, rsp.StatusCode)
	}

	// 第2点
	if !strings.EqualFold(rsp.Header.Get("Upgrade"), "websocket") {
		return ErrUpgradeFieldValue
	}

	// 第3点
	if !strings.EqualFold(rsp.Header.Get("Connection"), "Upgrade") {
		return ErrConnectionFieldValue
	}

	// 第4点
	if !strings.EqualFold(rsp.Header.Get("Sec-WebSocket-Accept"), secWebSocketAcceptVal(secWebSocket)) {
		return ErrSecWebSocketAccept
	}

	// TODO 5点

	// TODO 6点
	return nil
}

// wss已经修改为https
func (d *DialOption) tlsConn(c net.Conn) net.Conn {
	if d.u.Scheme == "https" {
		cfg := d.tlsConfig
		if cfg == nil {
			cfg = &tls.Config{}
		} else {
			cfg = cfg.Clone()
		}

		if cfg.ServerName == "" {
			host := d.u.Host
			if pos := strings.Index(host, ":"); pos != -1 {
				host = host[:pos]
			}
			cfg.ServerName = host
		}
		return tls.Client(c, cfg)
	}

	return c
}

func (d *DialOption) Dial() (wsCon *Conn, err error) {
	if d.Config.multiEventLoop == nil {
		return nil, ErrEventLoopEmpty
	}

	// 默认事件循环在 defaultSettingAfter 里 Start 过了, 用户自己传的那份
	// 由用户 Start。engine 的 Start 是幂等的。
	d.Config.multiEventLoop.Start()
	req, secWebSocket, err := d.handshake()
	if err != nil {
		return nil, err
	}

	var deadline time.Time
	if d.dialTimeout != 0 {
		deadline = time.Now().Add(d.dialTimeout)
	}
	hostName := hostname.GetHostName(d.u)
	var conn net.Conn
	conn, err = net.DialTimeout("tcp", hostName, d.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.Dial:%w", err)
	}

	defer func() {
		if err != nil && conn != nil {
			conn.Close()
			conn = nil
		}
	}()

	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	conn = d.tlsConn(conn)

	if err = req.Write(conn); err != nil {
		return nil, fmt.Errorf("write req fail:%w", err)
	}

	br := bufio.NewReader(bufio.NewReader(conn))
	rsp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}

	if d.bindClientHttpHeader != nil {
		*d.bindClientHttpHeader = rsp.Header.Clone()
	}

	pd, err := deflate.GetConnPermessageDeflate(rsp.Header)
	if err != nil {
		return nil, err
	}
	if d.Decompression {
		pd.Decompression = pd.Enable && d.Decompression
	}
	if d.Compression {
		pd.Compression = pd.Enable && d.Compression
	}

	if err = d.validateRsp(rsp, secWebSocket); err != nil {
		return
	}

	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	// bufio 里可能已经多读了数据(服务端在握手响应之后紧跟了几个帧):
	// 先收下来, 挂到引擎之后再喂给解析器。
	//
	// 为什么先 peek 再 dup fd: net.Conn 的 bufio 和事件循环读的是同一个
	// socket, 两边都读就会把数据抢走。这里把 bufio 多读的字节拿出来自己
	// 处理, 事件循环只往后读, 不重不漏。
	var leftover []byte
	if br.Buffered() > 0 {
		b, perr := br.Peek(br.Buffered())
		if perr != nil {
			return nil, perr
		}
		leftover = append([]byte(nil), b...)
	}

	fd, err := getFdFromConn(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// 已经dup了一份fd，所以这里可以关闭
	if err = conn.Close(); err != nil {
		return nil, err
	}

	// 连接对象由引擎在**注册 fd 之前**、在**这个 goroutine 上**调 Bind 建
	// 出来（见 ConnHandler.Bind），所以 Dial 返回时对象一定已经是好的——
	// 不需要再去事件循环上等一圈。**这个"不等"是有意义的**：等的话事件
	// 循环会先跑一轮 poll，对端"握手完立刻 close"时对象等回来就已经关了
	// （数据 + FIN 一起到，一轮 poll 全处理完）。
	h := NewClientConnHandler(&d.Config)
	h.SetPermessageDeflate(pd)
	h.OnConn = func(c *Conn) error {
		// 握手多读的那几个字节喂给解析器。走的是和 OnData 一样的"借
		// 缓冲区"那套；比注册早，事件循环看不见这条连接，没有并发。
		if len(leftover) > 0 {
			if _, err := c.parseBuf(c.ec, leftover); err != nil {
				return err
			}
		}
		c.Callback.OnOpen(c)
		return nil
	}

	d.Config.engineMode = true
	ec, err := d.Config.multiEventLoop.Add(fd, h)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if wsCon, _ = ec.UserData().(*Conn); wsCon == nil {
		ec.Close()
		return nil, ErrClosed
	}
	return wsCon, nil
}
