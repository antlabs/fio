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
	"bytes"
	"errors"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/antlabs/wsutil/bytespool"
	"github.com/antlabs/wsutil/deflate"
)

type UpgradeServer struct {
	config Config
}

// Config 返回这个 upgrader 的配置。
//
// 给 ListenAndServeWebSocket 用: 它要的就是 Upgrade 那条路上的同一份
// 配置(事件循环、回调、压缩开关), 只是不经过 net/http。
func (u *UpgradeServer) Config() *Config { return &u.config }

func NewUpgrade(opts ...ServerOption) *UpgradeServer {
	var conf ConnOption
	conf.defaultSetting()
	for _, o := range opts {
		o(&conf)
	}
	conf.defaultSettingAfter()
	return &UpgradeServer{config: conf.Config}
}

func (u *UpgradeServer) Upgrade(w http.ResponseWriter, r *http.Request) (c *Conn, err error) {
	return upgradeInner(w, r, &u.config, nil)
}

func (u *UpgradeServer) UpgradeLocalCallback(w http.ResponseWriter, r *http.Request, cb Callback) (c *Conn, err error) {
	return upgradeInner(w, r, &u.config, cb)
}

func Upgrade(w http.ResponseWriter, r *http.Request, opts ...ServerOption) (c *Conn, err error) {
	var conf ConnOption
	conf.defaultSetting()
	for _, o := range opts {
		o(&conf)
	}

	conf.defaultSettingAfter()
	return upgradeInner(w, r, &conf.Config, nil)
}

func getFdFromConn(c net.Conn) (newFd int, err error) {
	sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return 0, errors.New("RawConn Unsupported")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, errors.New("RawConn Unsupported")
	}

	err = rc.Control(func(fd uintptr) {
		newFd = int(fd)
	})
	if err != nil {
		return 0, err
	}

	return duplicateSocket(int(newFd))
}

func upgradeInner(w http.ResponseWriter, r *http.Request, conf *Config, cb Callback) (wsCon *Conn, err error) {
	if conf.multiEventLoop == nil {
		return nil, ErrEventLoopEmpty
	}

	if ecode, err := checkRequest(r); err != nil {
		http.Error(w, err.Error(), ecode)
		return nil, err
	}

	hi, ok := w.(http.Hijacker)
	if !ok {
		return nil, ErrNotFoundHijacker
	}

	var conn net.Conn
	var rw *bufio.ReadWriter
	conn, rw, err = hi.Hijack()
	if err != nil {
		return nil, err
	}
	if !conf.disableBufioClearHack {
		// bufio2.ClearReadWriter(rw)
	}

	// 是否打开解压缩
	// 外层接收压缩, 并且客户端发送扩展过来
	var pd deflate.PermessageDeflateConf
	if conf.Decompression {
		pd, err = deflate.GetConnPermessageDeflate(r.Header)
		if err != nil {
			return nil, err
		}
	}

	buf := bytespool.GetUpgradeRespBytes()

	tmpWriter := bytes.NewBuffer((*buf)[:0])
	defer func() {
		bytespool.PutUpgradeRespBytes(buf)
		tmpWriter = nil
	}()
	resetPermessageDeflate(&pd, conf)
	if err = prepareWriteResponse(r, tmpWriter, conf, pd); err != nil {
		return
	}

	if _, err := conn.Write(tmpWriter.Bytes()); err != nil {
		return nil, err
	}

	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	// http.Server 那边的 bufio 可能已经多读了数据（客户端把第一个帧和
	// 握手拼在一次 write 里就会这样）。不带走就是丢，丢的是第一条消息。
	//
	// 要拷一份: 这段字节要到事件循环上（OnConn 里）才喂给解析器，那时候
	// rw 早就跟着 http.Server 一起消失了。
	var leftover []byte
	if n := rw.Reader.Buffered(); n > 0 {
		if b, perr := rw.Reader.Peek(n); perr == nil {
			leftover = append([]byte(nil), b...)
		}
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
	// 出来（见 ConnHandler.Bind）。多读的那几个字节也在这里喂——比注册早，
	// 事件循环还看不见这条连接，不会两边一起动 rr/rw 和回调。
	h := NewConnHandler(conf)
	h.SetPermessageDeflate(pd)
	h.cb = cb
	h.OnConn = func(c *Conn) error {
		if len(leftover) > 0 {
			if _, err := c.parseBuf(c.ec, leftover); err != nil {
				return err
			}
		}
		c.Callback.OnOpen(c)
		return nil
	}

	conf.engineMode = true
	ec, err := conf.multiEventLoop.Add(fd, h)
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

func resetPermessageDeflate(pd *deflate.PermessageDeflateConf, conf *Config) {
	pd.Decompression = pd.Enable && conf.Decompression
	pd.Compression = pd.Enable && conf.Compression
	pd.ServerContextTakeover = pd.Enable && pd.ServerContextTakeover && conf.ServerContextTakeover
	pd.ClientContextTakeover = pd.Enable && pd.ClientContextTakeover && conf.ClientContextTakeover
}
