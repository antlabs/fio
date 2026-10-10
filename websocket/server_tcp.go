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

//go:build linux

package websocket

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antlabs/wsutil/bytespool"
	"github.com/antlabs/wsutil/deflate"
	"golang.org/x/sys/unix"
)

// 自己 accept、自己解析 HTTP 握手, 不经过 net/http。
//
// 走 net/http 的那条路(Upgrade)是: http.Server 接连接 -> 它自己的
// bufio 读请求 -> Hijack 把 net.Conn 交出来 -> 库 dup 一份 fd 再关掉
// 原来那个。三处都是额外的: http.Server 的读写器、bufio、以及 dup。
//
// 这里从 accept 直接拿 fd, 在库自己的读缓冲上把握手请求解析掉, 然后
// 原样把这个 fd 交给事件循环——不 dup、不经过 net/http, 连接上也不留
// bufio。fnet 就是这么做的(它的 fhttp 自己解析请求)。
//
// 握手解析只覆盖 WebSocket 升级需要的那部分: 请求行、Sec-WebSocket-Key
// 和几个可选的头。它不是通用的 HTTP 服务器, 只服务 /ws 这一类端点。
//
// 用 ListenAndServeWebSocket 打开。

// TcpServer 是一个只做 WebSocket 升级的最小服务器。
//
// 它自己持监听 fd、自己 accept4, 不经过 net 包: net 每次 accept 都要
// 建一个 netFD 挂在 runtime poller 上, 而这条连接马上要交给自己的事件
// 循环, 那份登记纯属多余——之后还得像 Hijack 那样从 net 那边摘出来。
type TcpServer struct {
	conf    *Config
	fd      int
	wg      sync.WaitGroup
	closing chan struct{}
	once    sync.Once
	// handles 是握手之外的请求要走的地方, 给 /taskpool 这类控制路由用。
	// 为空时非升级请求一律 404。
	handles map[string]func(w *responseWriter, r *handshakeRequest)
}

// ListenAndServeWebSocket 在 addr 上接 WebSocket 连接, 不经过 net/http。
//
// conf 就是 Upgrade 用的那份; 它里面的 multiEventLoop 必须已经 Start。
// 返回的 server 用 Close 停。
func ListenAndServeWebSocket(addr string, conf *Config) (*TcpServer, error) {
	fd, err := listenTCP(addr)
	if err != nil {
		return nil, err
	}
	return ServeWebSocket(fd, addr, conf)
}

// listenBacklog 返回内核允许的监听队列长度。
//
// 读 /proc/sys/net/core/somaxconn, 和 Go 标准库的 maxListenerBacklog
// 一样。读不到就退回 4096(这个值在各发行版上很常见)。
func listenBacklog() int {
	b, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		return 4096
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return 4096
	}
	return n
}

// listenTCP 建一个非阻塞的监听 fd。
func listenTCP(addr string) (int, error) {
	sa, err := resolveAddr(addr)
	if err != nil {
		return -1, err
	}
	// 监听 fd 用阻塞模式: accept 阻塞在内核里等连接, 有连接立刻被唤醒。
	// 之前用的是非阻塞 + 轮询 sleep, 空闲时退避到 1ms——新连接最多要等
	// 1ms 才被接受, 建连测试(每秒上万次)里这个延迟直接压低速率。
	// net/http 和 fnet 都是阻塞 accept, 内核事件驱动, 没有这个浪费。
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return -1, err
	}
	// SO_REUSEPORT: 和压测项目其它框架一致(它们走 frameworks.Listen,
	// 默认开 reuseport)。多个监听 socket 共享同一个端口, 内核把新连接
	// 分到其中一个——建连密集时比单个 accept 队列更能吃下突发。
	// 失败不算错: 内核不支持就退回普通监听。
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return -1, err
	}
	// backlog 用内核允许的最大值(somaxconn)。
	//
	// 之前硬编码 128: 建连测试是 2000 并发猛灌, 队列一满内核就丢 SYN,
	// 客户端要重传, 建连速率直接掉下来。net/http 用的是
	// maxListenerBacklog()——就是读这个 /proc 值。
	if err := unix.Listen(fd, listenBacklog()); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// resolveAddr 把 host:port 变成 sockaddr。
func resolveAddr(addr string) (*unix.SockaddrInet4, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}
	sa := &unix.SockaddrInet4{Port: port}
	if v4 := ip.To4(); v4 != nil {
		copy(sa.Addr[:], v4)
	}
	return sa, nil
}

// ServeWebSocket 同上, 但接一个已经建好的监听 fd。
func ServeWebSocket(fd int, addr string, conf *Config) (*TcpServer, error) {
	if conf == nil || conf.multiEventLoop == nil {
		return nil, ErrEventLoopEmpty
	}
	s := &TcpServer{conf: conf, fd: fd, closing: make(chan struct{})}
	go s.acceptLoop()
	return s, nil
}

// acceptLoop 阻塞在 accept 里等连接, 每个 fd 起一个 goroutine 做握手。
//
// 监听 fd 是阻塞的, accept 会睡在内核里直到有连接——没有轮询、没有 sleep、
// 没有退避。连接一到就被唤醒, 这是 net/http 和 fnet 用的方式。
//
// 之前这里是非阻塞 + 轮询 sleep, 空闲时退避到 1ms, 新连接最多白等 1ms;
// 建连测试里那是实打实的损失。
//
// 每个地址一个 TcpServer, 所以 50 个端口就是 50 个这样的 goroutine 并行
// accept, 不会被彼此的握手拖住。
func (s *TcpServer) acceptLoop() {
	for {
		// accept4 出来的 fd 是 NONBLOCK + CLOEXEC(Accept4 的 flags 只作用
		// 在新建的 socket 上, 和监听 fd 阻不阻塞无关), 正好交给事件循环。
		fd, _, err := unix.Accept4(s.fd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if err != nil {
			select {
			case <-s.closing:
				return
			default:
			}
			switch err {
			case unix.EINTR, unix.ECONNABORTED:
				// 打断, 或连接已经被对端扔掉: 接着接下一个
				continue
			case unix.EMFILE, unix.ENFILE:
				// 句柄用尽, 等别人放出来
				time.Sleep(time.Millisecond)
				continue
			}
			return
		}
		s.wg.Add(1)
		go func(fd int) {
			defer s.wg.Done()
			s.serve(fd)
		}(fd)
	}
}

// Close 停掉这个 server, 已经在升级中的连接不受影响。
func (s *TcpServer) Close() error {
	s.once.Do(func() { close(s.closing) })
	return unix.Close(s.fd)
}

// serve 处理一条新连接: 读握手, 升级, 或者回一个错误。
//
// fd 已经是非阻塞的(accept4 给的), 读握手时要自己处理 EAGAIN: 一小段
// 自旋等数据到齐, 握手包就几十字节, 正常一次就到。
func (s *TcpServer) serve(fd int) {
	buf := bytespool.GetBytes(handshakeMaxSize)
	defer bytespool.PutBytes(buf)

	n, err := readHandshake(fd, *buf)
	if err != nil {
		unix.Close(fd)
		return
	}

	req, err := parseHandshake((*buf)[:n])
	if err != nil {
		writeHTTPError(fd, 400, err.Error())
		unix.Close(fd)
		return
	}

	if !req.isUpgrade {
		if h := s.handles[string(req.path)]; h != nil {
			w := &responseWriter{fd: fd}
			h(w, req)
			w.finish()
		} else {
			writeHTTPError(fd, 404, "not found")
		}
		unix.Close(fd)
		return
	}

	// 握手之后紧跟的字节（客户端把第一个帧和握手拼在一次 write 里发出来
	// 就会这样）。readHandshake 是"读到空行"就返回的，多读的部分停在 buf
	// 里，不带走就是丢——丢的可能是第一条消息。
	//
	// 要拷一份：buf 是池子里借的，serve 一返回就还了，而这段字节要到
	// 事件循环上（OnConn 里）才喂给解析器。
	var leftover []byte
	if i := bytes.Index((*buf)[:n], []byte("\r\n\r\n")); i >= 0 && i+4 < n {
		leftover = append([]byte(nil), (*buf)[i+4:n]...)
	}

	if err := s.upgrade(fd, req, leftover); err != nil {
		unix.Close(fd)
	}
}

// upgrade 完成握手并把连接交给事件循环。
//
// 这里不 dup fd, 也不经过 net: fd 是 accept4 直接给的, 只有我们持有它。
// Hijack 那条路要 dup 是因为 http.Server 还攥着 net 那一份。
func (s *TcpServer) upgrade(fd int, req *handshakeRequest, leftover []byte) error {
	if s.conf.tcpNoDelay {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1); err != nil {
			return err
		}
	}

	resp := buildUpgradeResponse(req)
	if err := writeAll(fd, resp); err != nil {
		return err
	}

	// 连接对象由引擎在注册 fd 之前、在这个 goroutine 上调 Bind 建出来
	// （见 ConnHandler.Bind），这里只把"握手才知道的东西"交给 handler:
	// 压缩参数、多读的字节、以及"建好之后调用户回调"这件事。
	h := NewConnHandler(s.conf)
	h.SetPermessageDeflate(req.deflate)
	h.OnConn = func(c *Conn) error {
		if len(leftover) > 0 {
			if _, err := c.parseBuf(c.ec, leftover); err != nil {
				return err
			}
		}
		c.Callback.OnOpen(c)
		return nil
	}

	s.conf.engineMode = true
	_, err := s.conf.multiEventLoop.Add(fd, h)
	return err
}

// writeAll 把 b 写完。
//
// EAGAIN 时不能空转(runtime.Gosched 自旋): 建连密集时成千上万个 goroutine
// 同时撞上它, 每个都在抢 CPU, 反而把系统拖垮——隔离测看不出来, 官方流程
// (10000 连接同时握手)下直接崩掉。改成等 fd 可写再重试, goroutine 睡在
// runtime 的 netpoller 上, 不烧 CPU。
func writeAll(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := unix.Write(fd, b)
		if err == unix.EAGAIN {
			if werr := waitWritable(fd); werr != nil {
				return werr
			}
			continue
		}
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// waitReadable / waitWritable 等 fd 可读/可写。
//
// 用 poll(2) 阻塞等——内核负责唤醒, 这个 goroutine 不烧 CPU。原来这里
// 是 runtime.Gosched() 自旋: 建连密集时(10000 连接同时握手)成千上万个
// goroutine 一起空转, 把 CPU 全占了, 吞吐反而比 net/http 还低。
//
// 超时给 5 秒: 握手是一来一回的短交互, 这么久还没动静的客户端按超时处理,
// 免得连接卡死在这里。
func waitReadable(fd int) error { return waitFd(fd, unix.POLLIN) }

func waitWritable(fd int) error { return waitFd(fd, unix.POLLOUT) }

func waitFd(fd int, events int16) error {
	for {
		fds := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(fds, 5000)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("fio: handshake timeout")
		}
		return nil
	}
}

// handshakeMaxSize 是握手请求的上限。真实请求不到 1KB, 留足余量。
const handshakeMaxSize = 4 << 10

// readHandshake 读到空行为止, 返回读到的字节数。
//
// 和 writeAll 一样: EAGAIN 不空转, 等 fd 可读再重试。
func readHandshake(fd int, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := unix.Read(fd, buf[n:])
		if err == unix.EAGAIN {
			if werr := waitReadable(fd); werr != nil {
				return n, werr
			}
			continue
		}
		if err != nil {
			return n, err
		}
		if m == 0 {
			return n, io.EOF
		}
		n += m
		if bytes.Contains(buf[:n], []byte("\r\n\r\n")) {
			return n, nil
		}
	}
	return n, errors.New("fio: handshake header too large")
}

// handshakeRequest 是握手请求里 we 用得上的那几项。
//
// 各字段是请求字节里的切片(串), 不是拷贝——调用方在读缓冲区还活着的时候
// 用完就丢。建连是每秒上万次的路径, 这里少一次分配就少一次 GC 压力。
type handshakeRequest struct {
	method    []byte
	path      []byte
	proto     []byte
	key       []byte
	version   []byte
	upgrade   []byte
	conn      []byte
	host      []byte
	protocol  []byte // Sec-WebSocket-Protocol 的第一个值
	isUpgrade bool
	deflate   deflate.PermessageDeflateConf
}

// equalFoldASCII 比 ASCII 大小写无关的相等, 不分配。
func equalFoldASCII(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// containsFoldASCII 在 a 里找 b(大小写无关的子串), 不分配。
func containsFoldASCII(a []byte, b string) bool {
	if len(b) == 0 {
		return true
	}
	if len(a) < len(b) {
		return false
	}
	for i := 0; i+len(b) <= len(a); i++ {
		if equalFoldASCII(a[i:i+len(b)], b) {
			return true
		}
	}
	return false
}

// trimOWS 去掉首尾的空格和制表符(HTTP 头值里允许的空白)。
func trimOWS(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// parseHandshake 解析握手请求。
//
// 零分配: 头名在这里用字节比较认, 不建 map、不 ToLower、不转 string;
// 各字段是 b 的切片, 不拷贝。之前是 Split + map + strings.ToLower 的写法,
// 实测 864ns / 1408B / 29 次分配一个连接——建连测试每秒上万次, 那点分配
// 直接把吞吐压下去了(自建这条路的第一次实现就是因此比 net/http 还慢)。
func parseHandshake(b []byte) (*handshakeRequest, error) {
	var r handshakeRequest

	// 请求行: METHOD SP TARGET SP HTTP/x.y CRLF
	line := b
	if i := bytes.Index(line, []byte("\r\n")); i >= 0 {
		line = line[:i]
	} else {
		return nil, errors.New("fio: bad request line")
	}
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return nil, errors.New("fio: bad request line")
	}
	rest := line[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if sp2 <= 0 {
		return nil, errors.New("fio: bad request line")
	}
	r.method = line[:sp1]
	r.path = rest[:sp2]
	r.proto = rest[sp2+1:]

	// 头字段
	for len(b) > 0 {
		var ln []byte
		if i := bytes.Index(b, []byte("\r\n")); i >= 0 {
			ln = b[:i]
			b = b[i+2:]
		} else {
			ln = b
			b = nil
		}
		if len(ln) == 0 {
			break // 空行, 头结束
		}
		colon := bytes.IndexByte(ln, ':')
		if colon <= 0 {
			continue
		}
		name := ln[:colon]
		val := trimOWS(ln[colon+1:])

		switch {
		case equalFoldASCII(name, "sec-websocket-key"):
			r.key = val
		case equalFoldASCII(name, "sec-websocket-version"):
			r.version = val
		case equalFoldASCII(name, "upgrade"):
			r.upgrade = val
		case equalFoldASCII(name, "connection"):
			r.conn = val
		case equalFoldASCII(name, "host"):
			r.host = val
		case equalFoldASCII(name, "sec-websocket-protocol"):
			// 只取第一个, 原样回给客户端
			if i := bytes.IndexByte(val, ','); i >= 0 {
				val = val[:i]
			}
			r.protocol = trimOWS(val)
		}
	}

	r.isUpgrade = equalFoldASCII(r.upgrade, "websocket") &&
		containsFoldASCII(r.conn, "upgrade")
	if r.isUpgrade && (len(r.key) == 0 || !bytes.Equal(r.version, []byte("13"))) {
		return nil, errors.New("fio: unsupported websocket version")
	}
	return &r, nil
}

// upgradeGUID 是 RFC 6455 规定的固定串。
const upgradeGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// buildUpgradeResponse 拼 101 响应。和 net/http 那条路给的一样。
//
// sha1 直接算在栈上的数组里, 不走 hash.Hash 接口——后者每次要分配一个
// digest 结构, 建连路径上每个连接一次。
func buildUpgradeResponse(req *handshakeRequest) []byte {
	// key + GUID 拼进一个栈上数组, 避免为了拼接分配。
	var buf [256]byte
	n := copy(buf[:], req.key)
	n += copy(buf[n:], upgradeGUID)
	sum := sha1.Sum(buf[:n])

	var accept [28]byte // base64 of 20-byte sha1
	base64.StdEncoding.Encode(accept[:], sum[:])

	// 固定部分 + 可选子协议, 一次算好容量, 不做中间 bytes.Buffer。
	respLen := len("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \r\n\r\n") + len(accept)
	if len(req.protocol) > 0 {
		respLen += len("Sec-WebSocket-Protocol: \r\n") + len(req.protocol)
	}
	out := make([]byte, 0, respLen)
	out = append(out, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "...)
	out = append(out, accept[:]...)
	out = append(out, "\r\n"...)
	if len(req.protocol) > 0 {
		out = append(out, "Sec-WebSocket-Protocol: "...)
		out = append(out, req.protocol...)
		out = append(out, "\r\n"...)
	}
	out = append(out, "\r\n"...)
	return out
}

// writeHTTPError 回一个最小的错误响应。
func writeHTTPError(fd int, code int, msg string) {
	body := msg + "\n"
	head := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		code, httpStatusText(code), len(body))
	_ = writeAll(fd, append([]byte(head), body...))
}

func httpStatusText(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 404:
		return "Not Found"
	}
	return strconv.Itoa(code)
}

// responseWriter 给控制路由用, 和 http.ResponseWriter 的最小子集一样。
type responseWriter struct {
	fd     int
	code   int
	header bytes.Buffer
	body   bytes.Buffer
}

func (w *responseWriter) Header() *bytes.Buffer { return &w.header }

func (w *responseWriter) WriteHeader(code int) { w.code = code }

func (w *responseWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

func (w *responseWriter) finish() {
	if w.code == 0 {
		w.code = 200
	}
	head := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n",
		w.code, httpStatusText(w.code), w.body.Len())
	out := append([]byte(head), w.header.Bytes()...)
	out = append(out, '\r', '\n')
	out = append(out, w.body.Bytes()...)
	_ = writeAll(w.fd, out)
}
