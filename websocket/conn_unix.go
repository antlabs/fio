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
// +build linux darwin netbsd freebsd openbsd dragonfly

package websocket

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antlabs/fio/engine"
	"github.com/antlabs/task/task/driver"
	"github.com/antlabs/wsutil/deflate"
	"github.com/antlabs/wsutil/frame"
	"github.com/antlabs/wsutil/myonce"
	"golang.org/x/sys/unix"
)

// Conn 是一条 websocket 连接。
//
// **IO 全部归 engine**（fd、读缓冲区、写缓冲区、事件注册、攒包），
// 这一层只剩"这些字节是什么帧"和"用户回调"。
//
//	engine.Conn  —— fd / 读缓冲区 / 写缓冲 / cork / 部分写
//	    ↑ OnData(字节)
//	Conn（这里） —— 帧解析 / 分片 / 压缩 / 用户回调
//
// 为什么这么分：epoll 的注册、部分写、EAGAIN 的处理和协议无关，写一遍
// 就够；一个协议的状态机也不该被别的协议看见。
type Conn struct {
	// ec 是引擎连接。**所有 IO 都走它**：Write / Writev / CorkWrite。
	ec *engine.Conn

	Callback                               // 用户回调
	pd       deflate.PermessageDeflateConf // 上下文接管的控制参数, 每个conn的配置可能不一样
	mu       sync.Mutex                    // 保护 websocket 层自己那块状态（关闭、定时器）
	*Config                                // 配置
	deCtx    *deflate.DeCompressContextTakeover
	enCtx    *deflate.CompressContextTakeover
	task     driver.TaskExecutor // 进协程池执行的任务（nil = io 模式，回调就地执行）
	rtime    *time.Timer         // 控制读超时
	wtime    *time.Timer         // 控制写超时

	// --- 帧解析状态 ---
	//
	// **只在事件循环的 goroutine 上碰**（OnData 里），不用加锁。
	//
	// rbuf/rr/rw 是**借来的视图**：OnData 进来时指向引擎给的那段缓冲区，
	// 返回前还原。解析代码原来是按"buf + 读/写两个游标"写的，保留同样的
	// 形状，那些代码就一行都不用改。
	rbuf                 *[]byte            // 借来的读缓冲区（只在 OnData 期间有效）
	rr                   int                // rbuf 读索引
	rw                   int                // rbuf 写索引
	lenAndMaskSize       int                // payload长度和掩码的长度
	rh                   frame.FrameHeader  // frame头部
	fragmentFramePayload *[]byte            // 存放分片帧的缓冲区
	fragmentFrameHeader  *frame.FrameHeader // 存放分段帧的头部
	// curState 是帧头解析状态机（普通字段，只在事件循环 goroutine 上碰，
	// 见 conn_core.go 里 getCurState/setCurState 的说明）。
	curState frameState

	// packed 只剩 client 一位（bit 0）。busy / pendingRead / pendingWrite /
	// corking 以前也在这几个位里，现在归 engine 管——那些是"这条连接正被
	// 谁处理"的调度状态，和协议无关。
	packed uint32

	// mu2 由 onCloseOnce 使用, 用新锁只是为了简化维护的难度
	// 也可以共用mu，区别 优点:节约内存，缺点:容易出现死锁和需要精心调试代码
	mu2         sync.Mutex
	onCloseOnce myonce.MyOnce // 保证只调用一次OnClose函数
	closed      int32         // 是否关闭
}

// newConn 建一条 websocket 连接，挂在引擎连接 ec 上。
//
// **ec 的生命周期归引擎**：连接关了引擎会回收它，这里只持有引用。
func newConn(ec *engine.Conn, client bool, conf *Config) *Conn {
	c := &Conn{
		ec:     ec,
		Config: conf,
	}
	if client {
		c.setClient(true)
	}

	// 协程池模式（回调不在事件循环的 goroutine 上跑）需要 executor；
	// io 模式下回调就地执行, 留着 nil 让 addTask 直接调。
	//
	// 实测(12 核 1KB echo): 多排一次队把 165 万 TPS 打到 22 万。
	if taskName := conf.runInGoTask; taskName != "" && taskName != "io" && conf.engineMode {
		c.task = newTaskExecutor(taskName)
	}
	if conf.readTimeout > 0 {
		_ = c.setReadDeadline(time.Now().Add(conf.readTimeout))
	}
	return c
}

// 这是一个空函数，兼容下quickws的接口
func (c *Conn) StartReadLoop() {}

// 这是一个空函数，兼容下quickws的接口
func (c *Conn) ReadLoop() error { return nil }

func duplicateSocket(socketFD int) (int, error) {
	return unix.Dup(socketFD)
}

// closeWithoutLockOnClose 关连接的实现。调用方保证自己没持有 c.mu。
//
// 真正关 fd、从事件循环摘掉、释放读写缓冲区都是引擎的事（ec.Close），
// 这里只负责 websocket 层：标记关闭、释放分片缓冲、跑用户的 OnClose。
func (c *Conn) closeWithoutLockOnClose(err error, onClose bool) {
	if c.isClosed() {
		return
	}

	if err != nil {
		err = io.EOF
	}
	c.getLogger().Debug("close conn", slog.Int64("fd", int64(c.getFd())))
	atomic.StoreInt32(&c.closed, 1)

	// 引擎那边关掉：摘事件、关 fd、释放读写缓冲。
	//
	// 引擎的 Close 是幂等的。它会回调 engine.Handler 的 OnClose（那会
	// 走到 ConnHandler.OnClose），但**用户回调在下面显式调**——要保证
	// 只调一次、而且在分片缓冲释放之后。
	if c.ec != nil {
		_ = c.ec.Close()
	}

	// 分片消息没等到最后一个分片连接就断了：那块内存是单独分配的
	// （takePayload 时拷出来的），要还回池子。
	if c.fragmentFramePayload != nil {
		putPayload(c.fragmentFramePayload, true)
		c.fragmentFramePayload = nil
	}

	// 这个必须要放在后面
	if onClose {
		c.onCloseOnce.Do(&c.mu2, func() {
			c.OnClose(c, err)
		})
		if c.task != nil {
			c.task.Close(nil)
		}
	}
}

func (c *Conn) closeNoLock(err error) {
	c.closeWithoutLockOnClose(err, true)
}

func (c *Conn) closeWithLock(err error) {
	if c.isClosed() {
		return
	}

	c.mu.Lock()
	if c.isClosed() {
		c.mu.Unlock()
		return
	}

	if err == nil {
		err = io.EOF
	}
	c.closeWithoutLockOnClose(err, false)

	c.mu.Unlock()

	// 这个必须要放在后面， 不然会死锁，因为Close会调用用户的OnClose
	// 用户的OnClose也有可能调用Close， 所以使用flags来判断是否已经关闭
	if atomic.LoadInt32(&c.closed) == 1 {
		c.onCloseOnce.Do(&c.mu2, func() {
			c.OnClose(c, err)
		})
	}
}

func closeFd(fd int) {
	unix.Close(int(fd))
}

// getFd 连接的 fd。连接关掉之后返回 -1（引擎那边会置）。
func (c *Conn) getFd() int {
	if c.ec == nil {
		return -1
	}
	return c.ec.Fd()
}

// getLogger 连接的日志器。
//
// 以前是问 multiEventLoop 要（它自己持有 *slog.Logger）。现在事件循环归
// engine 管，日志级别在 WithLogLevel 里转成了 engine 的选项、落在 engine
// 内部，websocket 这层拿不到——好在它本来也只用来打几条调试日志。
//
// 为什么从 Config 拿而不是包级变量：用户是每次 upgrade 传一份 Config 的，
// 日志器挂在配置上语义最自然。没配就退回默认 logger（装配完就是"什么都不
// 输出"），不要为了让测试看到日志去动全局状态。
func (c *Conn) getLogger() *slog.Logger {
	if c.Config != nil && c.Config.logger != nil {
		return c.Config.logger
	}
	return slog.Default()
}

// ---------------------------------------------------------------------------
// 超时

func (c *Conn) setDeadlineInner(t **time.Timer, tm time.Time, err error) error {
	if t == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if tm.IsZero() {
		if *t != nil {
			(*t).Stop()
			*t = nil
		}
		return nil
	}

	d := time.Until(tm)
	if d < 0 {
		return ErrInvalidDeadline
	}

	if *t == nil {
		*t = afterFunc(d, func() {
			c.closeWithLock(err)
		})
	} else {
		(*t).Reset(d)
	}
	return nil
}

func (c *Conn) setReadDeadline(t time.Time) error {
	return c.setDeadlineInner(&c.rtime, t, ErrReadTimeout)
}

func (c *Conn) setWriteDeadline(t time.Time) error {
	return c.setDeadlineInner(&c.wtime, t, ErrWriteTimeout)
}
