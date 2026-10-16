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

//go:build linux || darwin || netbsd || freebsd || openbsd || dragonfly

package engine

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Listener 是 accept 循环：接上来的 fd 交给 handlerFactory 建的 handler，
// 挂到引擎上。
//
// 用法：
//
//	ln, err := engine.ListenAndServe(m, "127.0.0.1:0", func() engine.Handler {
//	    return http.NewConnHandler(app, 0)
//	})
//	defer ln.Close()
//	fmt.Println(ln.Addr())
//
// **为什么不直接用 net.Listener + 阻塞 Accept**：
//
// net.Listener 的 Accept 是阻塞的，而"关掉监听 fd 来唤醒它"在 Linux 上
// 不成立——close() 不会唤醒另一个线程里已经阻塞在 accept() 的调用，那个
// 线程持有文件描述的引用，fd 表项被删了它照样睡着。于是 Close() 永远
// 等不到 accept 协程退出（实测：测试挂到超时；darwin 的 kqueue 会唤醒，
// 所以本机跑得通，这种平台差异只有跨平台跑才打得出来）。
//
// 这里用非阻塞 accept + 停止标志：Close() 一置标志，最多 1ms 后循环自己
// 退出，两个平台行为一致。
type Listener struct {
	lfd   int
	addr  string
	m     *MultiEventLoop
	newFn func() Handler

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// Listen 建一个监听 socket（非阻塞），但不开始 accept。
//
// addr 形如 "127.0.0.1:0"（端口 0 = 让内核挑一个，用 Addr 取回来）。
func Listen(m *MultiEventLoop, addr string, newHandler func() Handler) (*Listener, error) {
	sa, err := resolveAddr(addr)
	if err != nil {
		return nil, err
	}

	lfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	// 重启时端口可能还在 TIME_WAIT 里，允许复用
	if err := unix.SetsockoptInt(lfd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(lfd)
		return nil, err
	}
	// 预派生（见 WithReusePort）：允许多个进程绑同一个端口，内核按四元组
	// 哈希分连接。不开的话第二个进程直接 EADDRINUSE。
	if m.reusePort {
		if err := unix.SetsockoptInt(lfd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			unix.Close(lfd)
			return nil, err
		}
	}

	if err := unix.Bind(lfd, sa); err != nil {
		unix.Close(lfd)
		return nil, err
	}
	if err := unix.Listen(lfd, 4096); err != nil {
		unix.Close(lfd)
		return nil, err
	}
	// 关掉 Nagle（TCP_NODELAY），**在监听 socket 上设一次**：accept 出来的
	// 连接会继承这个选项（Linux/BSD 都是；lab 上实测：监听上设了，
	// accept 出来的连接 getsockopt 读回 1）。这样每条连接不用多一次
	// setsockopt——limited-conn 那种 18 万连接/秒的档，一次就是 18 万次
	// 系统调用/秒。
	//
	// 为什么需要：响应常在 MSS 之上（MTU 1500 时 15KB 就是 11 段），Nagle
	// 会把最后那段不足 MSS 的压着等前一段的 ACK，每个请求多一个来回。
	// HttpArena 的 static-tls 档（回环 MTU 1500，平均 15KB 响应）实测差
	// 1.3% 左右；MTU 65536 时（一个响应一段）看不出来。fib 在 accept 后
	// 逐连接设它，Go 的 net 包也是默认设的；我们走裸 syscall，之前一直
	// 没设。设不上（unix domain 之类的监听）就算了，不是错误。
	_ = unix.SetsockoptInt(lfd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	// **非阻塞**：accept 循环要能在没连接时立刻返回、去看停止标志
	// （见 Listener 的说明）。
	if err := unix.SetNonblock(lfd, true); err != nil {
		unix.Close(lfd)
		return nil, err
	}

	bound, _ := unix.Getsockname(lfd)
	boundPort := bound.(*unix.SockaddrInet4).Port

	return &Listener{
		lfd:   lfd,
		addr:  "127.0.0.1:" + strconv.Itoa(boundPort),
		m:     m,
		newFn: newHandler,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}, nil
}

// ListenAndServe 建监听器并开始 accept。
func ListenAndServe(m *MultiEventLoop, addr string, newHandler func() Handler) (*Listener, error) {
	ln, err := Listen(m, addr, newHandler)
	if err != nil {
		return nil, err
	}
	ln.Serve()
	return ln, nil
}

// Serve 开始 accept 循环（跑在自己的 goroutine 上）。
// acceptIdleSleep 是空转时的轮询间隔上限。
//
// 原来固定 1ms：每个监听器每秒 1000 次 accept4（EAGAIN）+ 1000 次定时唤醒。
// prefork 之后 6 个子进程 × 4 个监听器 = 每秒 2.4 万次系统调用加 2.4 万次
// 唤醒——**空转量出来占 20.6% 核**（latency-10k 那种几乎没流量的档里这笔
// 账是纯支出）。
//
// 退避之后空转只剩每秒 20 次；一收到连接立刻恢复 1ms，所以连接风暴
// （async 32000 连接那种）还是 1ms 的粒度。代价：空闲之后的第一条连接最多
// 多等这个间隔（50ms）——各档的连接都是开头一次性建好（reconnects = 0），
// 这一下在测量窗口里只发生一次。
const (
	acceptActiveSleep = time.Millisecond
	acceptIdleSleep   = 50 * time.Millisecond
	// 连续空转多少次之后进省电档。16 次 1ms ≈ 16ms 的"还在忙"余量，
	// 短促的连接间隙不会被当成空闲。
	acceptIdleAfter = 16
)

func (l *Listener) Serve() {
	go func() {
		defer close(l.done)
		idle := 0
		for {
			nfd, err := acceptNonblock(l.lfd)
			if err != nil {
				select {
				case <-l.stop:
					return
				default:
				}
				if err == unix.EAGAIN || err == unix.EINTR {
					idle++
					if idle > acceptIdleAfter {
						time.Sleep(acceptIdleSleep)
					} else {
						time.Sleep(acceptActiveSleep)
					}
					continue
				}
				return
			}
			idle = 0
			h := l.newFn()
			if _, err := l.m.Add(nfd, h); err != nil {
				// 引擎已经 Free 了之类的：关了走人
				unix.Close(nfd)
			}
		}
	}()
}

// Addr 返回实际监听的地址（端口 0 的时候用这个取回来）。
func (l *Listener) Addr() string { return l.addr }

// Fd 返回监听 fd。
func (l *Listener) Fd() int { return l.lfd }

// Close 停掉 accept 循环并关监听 fd。
//
// **可重复调**：第二次起是空操作。
func (l *Listener) Close() error {
	l.stopOnce.Do(func() {
		close(l.stop)
		unix.Close(l.lfd)
		<-l.done
	})
	return nil
}

// ---- 小的地址工具 ----

// resolveAddr 把 "host:port" 拆成 IPv4 地址和一个可用的 sockaddr。
//
// **只支持 IPv4**：这套东西跑在 epoll/kqueue 上，地址族换来换去没有
// 收益；需要 IPv6 的话这里是唯一要改的地方。
func resolveAddr(addr string) (*unix.SockaddrInet4, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, errors.New("engine: bad port " + portStr)
	}

	sa := &unix.SockaddrInet4{Port: port}
	if host != "" && host != "0.0.0.0" {
		ip := net.ParseIP(host).To4()
		if ip == nil {
			return nil, errors.New("engine: not an IPv4 host: " + host)
		}
		copy(sa.Addr[:], ip)
	}
	return sa, nil
}
