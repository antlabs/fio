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

package engine

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/antlabs/wsutil/bytespool"
)

// 攒包(cork)缓冲区的大小。见 cork.go。
const maxCorkBytes = 32 * 1024

// 读缓冲区的下限(自适应增长那个), 见 growReadBuffer。
const batchReadBufferSize = 16 * 1024

var (
	ErrClosed = errors.New("engine: connection closed")
	// ErrWouldBlock 表示这次没写出去, 剩下的交给可写事件。
	ErrWouldBlock = errors.New("engine: would block")

	// ErrMessageTooBig 表示一条报文大到读缓冲区装不下（到了
	// maxReadBufferSize），协议又只肯消费完整报文——这条连接没救了，
	// 报错关掉，别挂在那里（见 Read 里那段）。
	ErrMessageTooBig = errors.New("engine: message bigger than read buffer")
)

// Conn 是一条非阻塞连接。
//
// **它只有传输层的东西**: fd、读缓冲区、写缓冲、状态位。任何和协议有关的
// （帧头、状态码、解析状态机）都在协议包自己的结构里——协议实现把它的
// 状态挂在 UserData 上（见 SetUserData）。
//
// 这样分的理由：epoll 的注册、部分写、EAGAIN 的处理和协议无关，写一遍就
// 够了；反过来，一个协议的状态机不该被别的协议看见。
type Conn struct {
	fd int64

	// 读缓冲区。rbuf[rr:rw] 是已经读到、还没被协议消费的数据。
	rbuf *[]byte
	rr   int // 读索引
	rw   int // 写索引

	// 写缓冲。直接写失败(部分写/EAGAIN)的剩余数据按顺序排在这里，
	// 可写事件到了再补写。
	wbufList []*[]byte

	// userData 是协议挂自己的状态。协议包在 OnOpen 里放, 在 OnClose 里
	// 别管——连接对象本身会被复用池回收。
	//
	// 用 atomic.Value 而不是普通字段: Add 是 accept 循环（调用方
	// goroutine）调的, 而 OnOpen 里设的这个值之后被事件循环读——两个
	// goroutine 一写一读就是竞争（-race 会报）。原型里早先是普通字段,
	// 实测就是这么炸的。
	userData atomic.Value // 存 any, 用 Load/Store

	// packed 把几个状态位压进一个 uint32:
	//
	//	bit 0      client
	//	bit 1      busy(这个连接正被某个 goroutine 处理)
	//	bit 2      pendingRead(处理期间又到了可读事件)
	//	bit 3      pendingWrite
	//	bit 4      corking(这一轮 read 里还有后续数据, 回包先攒着)
	packed uint32

	// 关连接只做一次
	closeOnce sync.Once
	closed    int32

	// handler 是这个连接的协议
	handler Handler
	// parent 是它挂在哪个事件循环上
	parent *EventLoop
	// initRbSize 是起始读缓冲区大小（Init 时问了一次 ReadBufferSizer）。
	// 不实现 ReadBufferSizer 的协议是 0。
	initRbSize int

	// grewToBatch 表示这条连接的读缓冲区因为"一次读装满"长到过
	// batchReadBufferSize 那一档（见 growReadBuffer）。之后每轮 Read 直接
	// 按这一档取，省掉"先取一块起始大小的、装满、再换大的"那一步：
	// 每批少一次读系统调用、少一次 memcpy、少两次池操作。
	//
	// **只记这一档**。协议大报文翻倍长上去的那种块不记（它们可能很大，
	// 记下来就成了每连接常驻一块大的）；这一档的块每轮结束就还回池子
	// （见 ReleaseReadBuf），不常驻。
	grewToBatch bool

	// mu 保护 rbuf/wbufList: Close 可能从任意 goroutine 来, 它要在锁里
	// 释放这两块内存。
	mu sync.Mutex

	// writeHookFn 是写拦截器（TLS 用），见 SetWriteHook。
	writeHookFn func([]byte) error

	// releaseReadBuf 上一轮读缓冲区已经消费完、等着下次 Read 时释放。
	// 见 ConsumeRead 里"为什么不能马上还"的说明。
	releaseReadBuf bool
}

const (
	flagClient       uint32 = 1 << 0
	flagBusy         uint32 = 1 << 1
	flagPendingRead  uint32 = 1 << 2
	flagPendingWrite uint32 = 1 << 3
	flagCorking      uint32 = 1 << 4
	// flagActivated 表示 OnOpen 已经跑过了（在事件循环的 goroutine 上）。
	//
	// 为什么要有：Add 是调用方（accept 循环）的 goroutine 调的，而
	// OnOpen 要挪到事件循环上去跑（协议的初始化状态只该被一个 goroutine
	// 碰）。但投递和 epoll 事件之间没有先后保证——Add 返回时那个 fd
	// 可能已经有数据可读、事件已经排在 epoll 里了。这时候如果直接跑
	// OnData，就和还没跑的 OnOpen 撞上（-race 实测：http2.ConnHandler
	// 的 ch.conn 字段一边写一边读）。
	//
	// 所以事件里看到这个位没置就记成 pending，等 OnOpen 跑完自己再取走。
	flagActivated uint32 = 1 << 5

	// flagFreePending 表示"连接已经关了, 但缓冲区还没释放"——关的时候
	// 事件循环正在处理这条连接, 它手上还捏着读缓冲区里的一段(零拷贝的
	// payload 就是它的一段)。释放交给这一轮结束时的 unbusy, 见 closeWith。
	flagFreePending uint32 = 1 << 6
)

// Init 初始化一条连接。fd 必须是已经设成非阻塞的 socket。
func (c *Conn) Init(fd int, h Handler, parent *EventLoop) {
	c.fd = int64(fd)
	c.handler = h
	c.parent = parent
	c.closed = 0
	c.packed = 0
	c.rbuf = nil
	c.rr, c.rw = 0, 0
	c.wbufList = c.wbufList[:0]
	c.grewToBatch = false
	// 起始读缓冲区大小问一次协议就够，之后不再变——热路径上（ConsumeRead）
	// 要拿它判断"这块是不是起始大小那块、能不能留"，每消息一次接口断言不划算。
	c.initRbSize = 0
	if s, ok := h.(ReadBufferSizer); ok && s != nil {
		c.initRbSize = s.InitialReadBufferSize()
	}
	// userData 是 atomic.Value，清成"没设过"（存一个 nil 指针）
	c.userData.Store((*any)(nil))
}

// Fd 返回文件描述符。连接关掉之后返回 -1。
func (c *Conn) Fd() int { return int(atomic.LoadInt64(&c.fd)) }

// SetUserData 让协议挂自己的状态(解析器、握手上下文...)。
//
// 可以在任意 goroutine 上调（内部用 atomic.Value）。协议通常在 OnOpen
// 里设、在 OnData 里读，而这两者可能在不同的 goroutine 上。
func (c *Conn) SetUserData(v any) {
	if v == nil {
		// atomic.Value 不允许存 nil
		c.userData.Store((*any)(nil))
		return
	}
	c.userData.Store(&v)
}

// SyncOnLoop 把 f 投到这条连接所属的事件循环的 goroutine 上跑，等它跑完
// 再返回。
//
// **返回时，之前投过去的任务都已经跑完了**——任务队列是 FIFO，所以 Add 时
// 投的那个 OnOpen 保证在 f 之前执行。websocket 的客户端靠它同步拿回 OnOpen
// 里建好的连接对象（握手才知道的 pd、用户的 Callback 都得在拿到对象之后
// 才能装上去，而 Add 本身只保证"投递了"）。
//
// **不能在事件循环自己的 goroutine 上调**——那是自己等自己，直接死锁。
// 只在 Dial 这种连接刚建好、还没开始跑数据的路径上用。
func (c *Conn) SyncOnLoop(f func()) {
	if c.parent == nil {
		f()
		return
	}
	done := make(chan struct{})
	c.parent.runOnLoop(func() {
		f()
		close(done)
	})
	<-done
}

// UserData 取协议挂的状态。没设过返回 nil。
func (c *Conn) UserData() any {
	p := c.userData.Load()
	if p == nil {
		return nil
	}
	// 存的是 *any。Load 返回的接口里包着这个指针；没 Store 过的话
	// p 是 nil（不是 (*any)(nil)，是接口本身为 nil），上面那行拦住了。
	pp, ok := p.(*any)
	if !ok || pp == nil {
		return nil
	}
	return *pp
}

// IsClosed 连接关了没有。
func (c *Conn) IsClosed() bool { return atomic.LoadInt32(&c.closed) == 1 }

// SetWriteHook 装一个写拦截器。
//
// **给 TLS 那层用的**：TLS 包在内层协议（http2、http1）外面，内层调
// c.Write 是想发它自己的字节，但那要**先加密**再出去。装个拦截器之后，
// 内层的 Write 会走这里，由拦截器加密再调用 conn.Write 发到 fd。
//
// hook 传 nil 就摘掉（握手完成、或者不用 TLS 的连接）。
//
// **不要在里面调 c.Write** —— 会无限递归。拦截器应该调
// c.WriteRaw 发真正要出去的字节。
func (c *Conn) SetWriteHook(h func([]byte) error) {
	c.mu.Lock()
	c.writeHookFn = h
	c.mu.Unlock()
}

func (c *Conn) writeHook() func([]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeHookFn
}

// WriteRaw 绕过写拦截器，直接写 fd。
//
// 拦截器自己发数据用它（否则递归）。普通业务代码用 Write。
func (c *Conn) WriteRaw(data []byte) error {
	if c.IsClosed() {
		return ErrClosed
	}
	if len(data) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.wbufList) > 0 {
		c.appendToWbufList(data, len(data))
		c.flushLocked()
		return nil
	}
	n, err := c.writeToSocket(data)
	if err == nil && n == len(data) {
		return nil
	}
	if err == nil || err == syscall.EAGAIN || err == syscall.EINTR {
		if n < len(data) {
			c.appendToWbufList(data[n:], len(data)-n)
		}
		c.parent.addWrite(c)
		return nil
	}
	return err
}

// ---------------------------------------------------------------------------
// 读

// Read 把 fd 上现成的数据读到读缓冲区, 返回这次读到多少。
//
// 返回 0 且 err == nil 表示这次没数据了(EAGAIN)。返回 io.EOF 表示对端
// 关了。读到的东西在 ReadBuffer() 里, 协议自己消费。
//
// 这个方法由引擎在读事件里调, 协议不直接调它——协议实现 OnData 拿到的
// 就是这里读进来的数据。
func (c *Conn) Read() (int, error) {
	if c.IsClosed() {
		return 0, ErrClosed
	}

	// 上一轮消费完、但当时还没法安全释放的读缓冲区，在这里还掉。
	//
	// 时机是安全的：调用方（事件循环）跑完上一轮 OnData 才回到这里，
	// 上一轮指向那块内存的 buf 已经没人用了。
	c.mu.Lock()
	if c.releaseReadBuf && c.rbuf != nil {
		bytespool.PutBytes(c.rbuf)
		c.rbuf = nil
		c.rr, c.rw = 0, 0
	}
	c.releaseReadBuf = false
	// 上一轮全消费完、缓冲区又留着复用（ConsumeRead 里没还的那种）：
	// 把索引复位到开头，这块就接着用。不复位的话 buf := (*rbuf)[rw:] 是
	// 空的，会走"缓冲区满"那条路去 compact——白绕一圈。
	if c.rbuf != nil && c.rr == c.rw && c.rr > 0 {
		c.rr, c.rw = 0, 0
	}
	c.mu.Unlock()

	if c.rbuf == nil {
		// 长到过一批大小的连接（grewToBatch）直接按那一档取：不然每批
		// 都要"取 2KB -> 装满 -> 换 15KB"走一遍，白多一次读系统调用和
		// 一次 memcpy。取到之后轮末还回池子（见 ReleaseReadBuf）。
		size := c.initialReadBufSize()
		if c.grewToBatch {
			size = batchReadBufferSize
		}
		c.rbuf = bytespool.GetBytes(size)
	}

	total := 0
	for {
		buf := (*c.rbuf)[c.rw:]
		if len(buf) == 0 {
			// 缓冲区满了, 协议还没消费完。**先试着把前面消费掉的那段
			// 收回来**(compact), 收不动再扩容。
			//
			// 为什么先 compact: 协议处理半个大报文时(比如 1MB 的分片),
			// rr 停在报文开头、rw 一路往后推。不回收 rr 前面那段的话,
			// 缓冲区每次填满就翻倍, 最后为一条报文吃到 4MB(上限)——
			// 而实际上"还没解析的数据"可能只有几十 KB。
			//
			// 实测(websocket 大分片场景): 加了这一步之后, 内存占用从
			// "报文大小 × 2" 降到 "报文大小 + 一个读批次"。
			if !c.compactReadBuffer() {
				// 缓冲区满了、协议还没凑齐一条报文：**先问协议整条
				// 多大**，一次长到最终大小。不问就只能翻倍——1MB 的
				// 报文要经历 16K→32K→…→1MB 六次翻倍，每次都要把已经
				// 读到的整块数据 memcpy 一遍。
				//
				// 只有这个点能问：在两次 OnData 之间，协议手上没有活
				// 的缓冲区别名（见 MessageSizeHinter）。协议在 OnData
				// 里让引擎搬家就会把正在读的数据挪走/换掉。
				if !c.growToNextMessage() && !c.growReadBuffer() {
					// 长不动了（到 maxReadBufferSize，协议又还差着
					// 数据）。**只能关连接**：再待着就是永久卡死——
					// ET 下"缓冲区还是满的"不会再给边缘，这条连接不会
					// 再有任何进展，白白占着 fd 和内存（4MB 上限那版
					// 就是这么卡住的）。
					//
					// 协议那边的表现是收到一个关闭（websocket 报
					// OnClose），比静默挂死好诊断。
					return total, ErrMessageTooBig
				}
			}
			continue
		}

		// 这把锁要拿着: Close 可能从任意 goroutine 来, 它会在锁里关掉
		// fd、释放读缓冲区。不拿锁读就会读到已关闭的 fd。
		c.mu.Lock()
		fd := int(atomic.LoadInt64(&c.fd))
		n, err := socketRead(fd, buf)
		c.mu.Unlock()
		if c.parent != nil {
			c.parent.addReadSyscall()
		}

		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == syscall.EINTR {
					continue
				}
				if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
					return total, nil
				}
				return total, err
			}
			return total, err
		}
		if n == 0 {
			// 对端关了(FIN)。缓冲区里还有没消费的数据的话, 先让协议
			// 消费完再报 EOF——协议那边可能还有半条报文要处理。全消费
			// 完了就直接报 io.EOF, 让引擎关连接。
			if c.rw > c.rr {
				return total, nil
			}
			return total, io.EOF
		}

		c.rw += n
		total += n

		// 一次读满了说明后面还有, 换块大的, 免得下一条报文只读到一半。
		if c.rw == len(*c.rbuf) && len(*c.rbuf) < batchReadBufferSize {
			c.growReadBuffer()
		}

		// **短读就返回**：这次已经把可读的读干了，再读一次必然 EAGAIN。
		// 省掉的正是"每消息多一次系统调用"——strace 实测 recvfrom 从
		// 2.02 次/消息降到 1.02 次/消息（基线 1.0 次），CPU 跟着降。
		//
		// **FIN 不会因此丢**：pulse 注册的 epoll 事件带 EPOLLRDHUP，对端
		// 关闭会单独回调一次（api_epoll.go 里 rev&(EPOLLHUP|EPOLLRDHUP) 时
		// 直接 cb(fd, READ|WRITE, io.EOF)），不靠"读到 0"来发现。拿"发几个
		// 字节立刻 close"的用例在 Linux 上反复验过（50 轮）。
		//
		// 只有"刚好读满一整块、后面可能还有"才接着循环（上面会先把块换大）。
		if n < len(buf) {
			return total, nil
		}
	}
}

// ReadBuffer 返回已经读到、还没被消费的数据。
//
// 返回的切片只在协议处理这一轮里有效——下一次 Read 会追加/覆盖它。
func (c *Conn) ReadBuffer() []byte {
	if c.rbuf == nil {
		return nil
	}
	return (*c.rbuf)[c.rr:c.rw]
}

// ConsumeRead 告诉引擎协议消费了多少字节。
//
// 协议在 OnData 里返回消化量时引擎会自己调, 手写的协议循环里也能自己调。
func (c *Conn) ConsumeRead(n int) {
	if n <= 0 {
		return
	}
	c.rr += n
	if c.rr > c.rw {
		c.rr = c.rw
	}
	if c.rr != c.rw {
		return
	}

	// 全消费完了：**不在这里马上把缓冲区还回池子**。
	//
	// 为什么不能马上还：协议在 OnData 里拿到的 buf 就指向这块内存，
	// 而 OnData 可能还在一层层往下传（TLS 解密 -> 内层 http2 解析 ->
	// 业务回调）。调用方调 ConsumeRead 的时候那一层可能还没走完——
	// 这时候把缓冲区还给池子，**同一个事件循环上的另一条连接下一次
	// Read 就会拿到同一块内存**，正在被读的数据当场被覆盖。
	//
	// 症状：随机性极强、只在连接多的时候出现——TLS 握手偶尔莫名其妙
	// 卡住（h2spec 复现过：同一个用例十次里挂一两次，而明文模式
	// 100% 通过）。
	//
	// 所以这里只把索引推到底、记个"该还了"；真正的释放放在轮末
	// （ReleaseReadBuf，OnData 已经返回、栈退干净了）兜底在下一次 Read。
	c.releaseReadBuf = true
}

// ReleaseReadBuf 把读缓冲区当场还回池子。**每一轮 OnData 全部跑完之后
// 调**（事件循环的轮末，见 readAndDispatch）。
//
// 为什么不留在连接上、等下一次 Read 再还：留着的话，"这一批读完"到
// "下一批到来"之间的整段空闲里，每条连接都攥着一块。Pipeline 压测
// （10000 连接，每 5ms 一批 10KB，缓冲区长到 15KB 那一档）实测堆上
// **180MB** 全是这个（`Read -> growReadBuffer` 一条路径），RSS 从基线的
// 55MB 涨到 375MB；echo 那种"每连接一块 2KB 起始块"也值 20MB 堆、约
// 35MB RSS——每一档都不划算，统一还回池子。常驻涨上去之后 GC 目标跟着
// 涨，连池子里那些都没人清，滚雪球。
//
// 时机是安全的：OnData 已经返回，协议手上没有这块内存的别名了（零拷贝
// payload 只在 OnData 调用期间有效，这是引擎和协议的约定）。
func (c *Conn) ReleaseReadBuf() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rbuf == nil || c.rr != c.rw {
		// 还没开始读，或者还有没消费的数据（半条帧），留着。
		return
	}
	bytespool.PutBytes(c.rbuf)
	c.rbuf = nil
	c.rr, c.rw = 0, 0
	c.releaseReadBuf = false
}

// maxReadBufferSize 是读缓冲区能长到多大。
//
// **这个数必须大于"协议支持的最大单条报文"**，否则那条连接会永远收不完
// 一条报文——缓冲区长不下了，协议又只能消费完整报文，两边都动不了。
// 实测：定 4MB 时 autobahn 的 9.1.5(8MB)/9.1.6(16MB) 直接超时（报文读不
// 进来，5 秒读超时把连接关了）。迁移前的实现没有上限（按帧头声明的
// PayloadLen × 倍数分配），所以那两条是过的。
//
// 64MB：autobahn 最大的用例是 16MB，留 4 倍余量；常见的"一条大消息"
// （上传、大 JSON、gRPC 消息）都在里面。
//
// **它不等于"每连接常驻 64MB"**：只有对端真的发了那么大的报文、缓冲区
// 才会长上去，而且连接空下来就把缓冲区还回池子（见 Read 开头那段）。
// 10000 连接跑 1KB echo 的时候每连接还是起始的那 2KB。
//
// **它不是安全边界**：对端用一个 14 字节的帧头就能声明 64MB，这里的上限
// 挡不住这种"声明式"内存放大——那属于协议层的策略（报文大小上限），
// 引擎这层只兜底，挡住"无中生有地分配一个天文数字"。
const maxReadBufferSize = 64 * 1024 * 1024

// compactReadBuffer 把"还没被消费的那段"挪到缓冲区开头, 收回 rr 前面
// 被消费掉的空洞。返回是否挪动了(挪了就有空间读新数据)。
//
// 只在 Read 里调, 而且只在"缓冲区写满了"那一刻——那时候协议刚处理完
// 上一批数据, 没有任何 payload 别名还指着这块内存(零拷贝的 payload 只在
// OnData 调用期间有效, 这是引擎和协议的约定)。
func (c *Conn) compactReadBuffer() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rbuf == nil || c.rr == 0 {
		return false
	}
	// 把 [rr:rw] 挪到开头
	n := copy(*c.rbuf, (*c.rbuf)[c.rr:c.rw])
	c.rw = n
	c.rr = 0
	if c.parent != nil {
		c.parent.addMoveBytes(n)
	}
	return n < len(*c.rbuf) // 腾出空间了才算成功
}

// EnsureReadSpace 确保读缓冲区尾部至少有 n 字节的空闲空间。
//
// **给"读完帧头就知道整条报文多大"的协议用**：WebSocket 读到帧头就知道
// payload 长度，HTTP/2 读到帧头就知道帧长，gRPC 读到消息头就知道消息多长。
// 提前把空间要到位的收益是**省掉连续翻倍带来的多次拷贝**——不预留下来的
// 话，1MB 的报文要经历 16K→32K→…→1MB 七次 memcpy，而每次都是把整块已读
// 数据搬一遍。
//
// 返回值表示"空间够了"（false 表示到上限了也腾不出来，调用方按"暂时放
// 不下"处理：报文留在缓冲区里，等下一轮读事件——但注意 ET 下不会有新的
// 边缘，所以正常情况下这个 false 不该出现）。
//
// 空闲空间只在**尾部**：会先 compact 把已消费的前缀收回来，再考虑扩容。
func (c *Conn) EnsureReadSpace(n int) bool {
	if n <= 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rbuf == nil {
		// 还没开始读：按需要的大小起一块（下限 8KB，避免小报文反复申请）
		want := n
		if want < 8*1024 {
			want = 8 * 1024
		}
		if want > maxReadBufferSize {
			want = maxReadBufferSize
		}
		c.rbuf = bytespool.GetBytes(want)
		return cap(*c.rbuf)-c.rw >= n
	}

	// 尾部空间够就直接返回
	if len(*c.rbuf)-c.rw >= n {
		return true
	}

	// 先 compact：把 [rr:rw] 挪到开头，前面那段空洞就收回来了
	if c.rr > 0 {
		used := copy(*c.rbuf, (*c.rbuf)[c.rr:c.rw])
		c.rw = used
		c.rr = 0
		if len(*c.rbuf)-c.rw >= n {
			return true
		}
	}

	// 还不够就扩容：一次到位（不翻倍，直接按"已读 + 需要"要）
	need := c.rw + n
	if need <= len(*c.rbuf) {
		return true
	}
	if need > maxReadBufferSize {
		need = maxReadBufferSize
	}
	if need <= len(*c.rbuf) {
		return false // 已经在上限了
	}
	old := c.rbuf
	nb := bytespool.GetBytes(need)
	copy(*nb, (*old)[:c.rw])
	c.rbuf = nb
	bytespool.PutBytes(old)
	return len(*c.rbuf)-c.rw >= n
}

// 读缓冲区起始大小的默认值：8KB 够把常见的报文一次读完。
const defReadBufferSize = 8 * 1024

// initialReadBufSize 起始读缓冲区多大：Init 时问过一次，缓存起来了
// （见 Conn.initRbSize）。
func (c *Conn) initialReadBufSize() int {
	if c.initRbSize > 0 {
		return c.initRbSize
	}
	return defReadBufferSize
}

// growToNextMessage 问协议"下一条报文整条多大"，一次把缓冲区要到位。
//
// 返回 false 表示协议没实现 MessageSizeHinter、或者不知道、或者问了也长
// 不动——调用方按翻倍那条路走。
func (c *Conn) growToNextMessage() bool {
	h, ok := c.handler.(MessageSizeHinter)
	if !ok || h == nil {
		return false
	}
	need := h.NextMessageSize(c)
	// 缓冲区里现有的这些就装得下（不用长），或者压根不知道多大
	if need <= c.rw-c.rr {
		return false
	}
	return c.EnsureReadSpace(need - (c.rw - c.rr))
}

// growReadBuffer 把读缓冲区换大。返回是否换成了。
//
// 生长分两段:
//
//	< 16KB(batchReadBufferSize)  一次跳到 16KB。目的不是"装更多数据",
//	                             是"一次读能把一个批次读完"(见
//	                             batchReadBufferSize 的注释)
//	>= 16KB                      翻倍。这是"协议还没消费完、缓冲区就满了"
//	                             那条路, 必须长——不然会卡死(见下)
//
// **翻倍这段是必须的, 而且曾经漏掉过**: 早先这里写的是"到了 16KB 就
// 不再长", 结果是——一个 32KB 的 HTTP body, 缓冲区被填满、解析器还在
// 等剩下的数据、又没有空间读新的 → Read 每次都返回 0 字节, 连接永久
// 卡住。自己写的测试撞不到(那些 body 都在一次 read 里能装下), 是拿
// 标准库的 http.Client 打 64KB POST 才打出来的。
func (c *Conn) growReadBuffer() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rbuf == nil {
		return false
	}
	cur := len(*c.rbuf)
	if cur >= maxReadBufferSize {
		return false
	}

	var want int
	if cur < batchReadBufferSize {
		want = batchReadBufferSize
	} else {
		want = cur * 2 // 翻倍
		if want > maxReadBufferSize {
			want = maxReadBufferSize
		}
	}

	old := c.rbuf
	// **这块一定得比现在的大**。池按 1KB 分档给货：要 16KB 拿回来的是
	// 15374，而 cur 可能已经就是 15374 了（上一跳从池里拿的这一档），
	// "换了等于没换"——调用方（Read）看到长成功会再走一轮，缓冲区还是
	// 满的，就是死循环。对端一次发来 ≥15KB、把这一档读满时 100% 复现
	// （-rbs 16384 的压测客户端两个批次并到一起就是 20KB）。
	nb := bytespool.GetBytes(want)
	for len(*nb) <= cur {
		bytespool.PutBytes(nb)
		if want >= maxReadBufferSize {
			return false
		}
		want *= 2
		if want > maxReadBufferSize {
			want = maxReadBufferSize
		}
		nb = bytespool.GetBytes(want)
	}

	if want == batchReadBufferSize {
		// 长到的就是"一批大小"那一档：记下来，后面每轮直接按它取，
		// 省掉"取一块小的、装满、再换大的"（见 grewToBatch）。
		c.grewToBatch = true
	}
	copy(*nb, (*old)[:c.rw])
	c.rbuf = nb
	// 长过之后的块一律不常驻：每轮结束当场还回池子，见 ReleaseReadBuf。
	// （试过"长到一批大小(16KB)就留着"：echo 省一次池往返，但 Pipeline
	// 每条连接都长到那一档并留着，**10000 连接 160MB 常驻**。）
	bytespool.PutBytes(old)
	if c.parent != nil {
		c.parent.addRealloc()
	}
	return true
}

// ---------------------------------------------------------------------------
// 写

// Write 把 data 写出去。写不完的部分自动进写缓冲, 可写事件到了补写。
//
// 返回 error 只有两种情况: 连接已关, 或者写出了一个真错误。
func (c *Conn) Write(data []byte) error {
	if c.IsClosed() {
		return ErrClosed
	}
	if len(data) == 0 {
		return nil
	}

	// 有写拦截器就先给它：TLS 那层用它把内层协议写出来的明文加密，
	// 而不是直接发到 fd 上（见 SetWriteHook）。
	if h := c.writeHook(); h != nil {
		return h(data)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 有积压: 先拼到后面去, 保证顺序
	if len(c.wbufList) > 0 {
		c.appendToWbufList(data, len(data))
		c.flushLocked()
		return nil
	}

	n, err := c.writeToSocket(data)
	if err == nil && n == len(data) {
		return nil
	}
	if err == nil || err == syscall.EAGAIN || err == syscall.EINTR {
		// 部分写: 剩下的攒起来, 等可写事件
		if n < len(data) {
			c.appendToWbufList(data[n:], len(data)-n)
		}
		c.parent.addWrite(c)
		return nil
	}
	return err
}

// Writev 写多段(header + payload 这类), 不拷成一个块。
//
// 段数上限是 2: 内核的 iovec 支持更多, 但攒包路径只用得到两段; 需要更多
// 的时候调用方自己拼。
func (c *Conn) Writev(a, b []byte) error {
	if c.IsClosed() {
		return ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.wbufList) > 0 {
		// 有积压, 拼起来走普通那条
		all := make([]byte, 0, len(a)+len(b))
		all = append(all, a...)
		all = append(all, b...)
		c.appendToWbufList(all, len(all))
		c.flushLocked()
		return nil
	}

	total := len(a) + len(b)

	// **小消息(≤4KB)拼到栈上一次 sendto**。
	//
	// sendmsg 要读 iovec 数组、sendto 只要一个指针, 小消息下后者更便宜;
	// 大消息才值得用 iovec 省那次拷贝。之前无线程池的 websocket 在小消息
	// 上也用 sendmsg, 测下来多花 CPU。
	//
	// 4KB 是这么定的: maxCopiedPayload, 和 fnet 的一致——超过这个长度,
	// 拼一次的 memcpy 就比多一个 iovec 贵了。
	const maxStackWrite = 4096
	if total <= maxStackWrite {
		var stack [maxStackWrite]byte
		n := copy(stack[:], a)
		copy(stack[n:], b)
		all := stack[:total]

		wn, werr := c.writeToSocket(all)
		if werr == nil && wn == total {
			return nil
		}
		if werr == nil || werr == syscall.EAGAIN || werr == syscall.EINTR {
			if wn < 0 {
				wn = 0
			}
			c.appendToWbufList(all[wn:], total-wn)
			c.parent.addWrite(c)
			return nil
		}
		return werr
	}

	n, err := c.socketWritev(a, b)
	if err == nil && n == total {
		return nil
	}
	if err == nil || err == syscall.EAGAIN || err == syscall.EINTR {
		if n < 0 {
			n = 0
		}
		rest := make([]byte, 0, total-n)
		if n < len(a) {
			rest = append(rest, a[n:]...)
			rest = append(rest, b...)
		} else {
			rest = append(rest, b[n-len(a):]...)
		}
		c.appendToWbufList(rest, total)
		c.parent.addWrite(c)
		return nil
	}
	return err
}

// Flush 把写缓冲里的东西尽量写出去。可写事件到了由引擎调。
func (c *Conn) Flush() error {
	if c.IsClosed() {
		return ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flushLocked()
}

// FlushIfNeeded 写缓冲里非空才 flush，**只拿一次锁**。
//
// 可写事件那条路（processConn）本来是 NeedFlush() 拿一次锁 + Flush()
// 再拿一次，两次加锁都是为了问同一个问题（wbufList 空不空）。合并成一次。
//
// 这里有写缓冲的概率很低（echo 的写都是当场写完的），所以热路径基本就是
// "拿锁 -> 看一眼是空的 -> 放锁"，比两次少一半。
func (c *Conn) FlushIfNeeded() error {
	if c.IsClosed() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.wbufList) == 0 {
		return nil
	}
	return c.flushLocked()
}

// NeedFlush 写缓冲里有没有东西。
func (c *Conn) NeedFlush() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.wbufList) > 0
}

func (c *Conn) flushLocked() error {
	i := 0
	for i < len(c.wbufList) {
		wbuf := c.wbufList[i]
		n, err := c.writeToSocket(*wbuf)
		if err == nil && n == len(*wbuf) {
			bytespool.PutBytes(wbuf)
			c.wbufList[i] = nil
			i++
			continue
		}
		if err == nil || err == syscall.EAGAIN || err == syscall.EINTR {
			if n > 0 {
				copy(*wbuf, (*wbuf)[n:])
				*wbuf = (*wbuf)[:len(*wbuf)-n]
			}
			// 没写完, 剩下的留在列表里
			copy(c.wbufList, c.wbufList[i:])
			c.wbufList = c.wbufList[:len(c.wbufList)-i]
			c.parent.addWrite(c)
			return nil
		}
		return err
	}
	c.wbufList = c.wbufList[:0]
	return nil
}

// writeToSocket 直接写。**调用方必须持有 c.mu**——这个方法在 Write、
// Writev、flushLocked 里被调，它们都在锁里。
//
// 早先这里自己 Lock 了一次，而 Write 已经持锁，直接死锁（实测：
// 一条连接收到第一个字节就卡住，测试 90 秒超时）。fd 用原子读，不用锁。
func (c *Conn) writeToSocket(data []byte) (int, error) {
	fd := int(atomic.LoadInt64(&c.fd))
	// fd 已经被 closeWith 置成 -1：**不要再系统调用**。不拦的话内核
	// 回 EBADF，而这个错会一路传回用户（实测：websocket 的客户端在
	// 对端刚关连接时写一笔，拿到的是 "bad file descriptor" 而不是
	// "连接已关"）。closeWith 是先置 closed、后置 fd=-1，所以
	// IsClosed() 那个检查和这里之间有窗口。
	if fd < 0 {
		return 0, ErrClosed
	}
	n, err := socketWrite(fd, data)
	if c.parent != nil {
		c.parent.addWriteSyscall()
	}
	return n, err
}

// socketWritev 同上, 两段写。计数算一次系统调用。
// **调用方必须持有 c.mu**（和 writeToSocket 一样）。
func (c *Conn) socketWritev(a, b []byte) (int, error) {
	fd := int(atomic.LoadInt64(&c.fd))
	if fd < 0 {
		return 0, ErrClosed
	}
	n, err := socketWritev(fd, a, b)
	if c.parent != nil {
		c.parent.addWriteSyscall()
	}
	return n, err
}

// appendToWbufList 把 data 追加到写缓冲。调用方持有 mu。
func (c *Conn) appendToWbufList(data []byte, oldLen int) {
	if len(data) == 0 {
		return
	}
	if len(c.wbufList) == 0 {
		nb := bytespool.GetBytes(len(data) + oldLen)
		copy(*nb, data)
		*nb = (*nb)[:len(data)]
		c.wbufList = append(c.wbufList, nb)
		return
	}
	last := c.wbufList[len(c.wbufList)-1]
	if cap(*last)-len(*last) >= len(data) {
		*last = append(*last, data...)
		return
	}
	nb := bytespool.GetBytes(len(data) + oldLen)
	copy(*nb, data)
	*nb = (*nb)[:len(data)]
	c.wbufList = append(c.wbufList, nb)
}

// ---------------------------------------------------------------------------
// 关

// Close 关连接。幂等。
func (c *Conn) Close() error {
	c.closeWith(nil)
	return nil
}

func (c *Conn) closeWith(err error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return
	}
	c.closeOnce.Do(func() {
		// **先把攒着的写出去，再关**。
		//
		// 为什么：协议在出错时要发一个"最后的话"再走——HTTP/2 是
		// GOAWAY、WebSocket 是 close 帧。那些字节是刚写进写缓冲的
		// （Write 没写全是常态：socket 缓冲满了、刚才那次是 EAGAIN），
		// 直接 close 就把它们丢了。
		//
		// 实测：h2spec 的"帧格式错要回 GOAWAY"那几条，h2c（明文）全过、
		// 过了 TLS 就全挂——因为 TLS 那边多了一层，字节先要经过
		// 状态机加密再进写缓冲，等 OnData 返回 error 时缓冲里还压着
		// 加密后的 GOAWAY，而 close 把它们连同 wbufList 一起丢了。
		//
		// 尽力而为：不保证送到（对端可能已经关了、socket 缓冲可能还是
		// 满的），但"刚才还能写、只是没写全"这种最常见的情况能救回来。
		c.mu.Lock()
		_ = c.flushLocked()
		c.mu.Unlock()

		atomic.StoreInt32(&c.closed, 1)

		c.mu.Lock()
		fd := int(atomic.LoadInt64(&c.fd))
		atomic.StoreInt64(&c.fd, -1)

		// **缓冲区不一定能在这里释放**：事件循环可能正在处理这条连接
		// （busy 位），它手上捏着读缓冲区里的一段——零拷贝的 payload 就是
		// 它的别名。这时候还回去，同一个循环上的另一条连接下一次读就会
		// 拿到这块内存，正在读的数据当场被覆盖。
		//
		// 实测（-race）：用户 goroutine 里 con.Close() 和事件循环的
		// ReadBuffer() 抢 c.rbuf/c.rr/c.rw。
		//
		// 顺序很重要：**先置位再看 busy**。反过来的话，置位之前对方已经
		// 跑完 unbusy（它没看到标志位、不会释放），置位之后又没人再来
		// 释放——那块内存就漏了。
		atomic.OrUint32(&c.packed, flagFreePending)
		if atomic.LoadUint32(&c.packed)&flagBusy == 0 {
			atomic.AndUint32(&c.packed, ^flagFreePending)
			c.releaseBuffersLocked()
		}
		c.mu.Unlock()

		if c.parent != nil {
			c.parent.del(fd)
		}
		if fd >= 0 {
			closeFd(fd)
		}
		if c.handler != nil {
			c.handler.OnClose(c, err)
		}
	})
}

// releaseBuffersLocked 释放读写缓冲区。调用方持有 c.mu。
//
// **只能在"没有人在处理这条连接"的时候调**：处理中的那一轮手上捏着读
// 缓冲区里的一段（OnData 的 buf）。
func (c *Conn) releaseBuffersLocked() {
	if c.rbuf != nil {
		bytespool.PutBytes(c.rbuf)
		c.rbuf = nil
	}
	for i := range c.wbufList {
		if c.wbufList[i] != nil {
			bytespool.PutBytes(c.wbufList[i])
			c.wbufList[i] = nil
		}
	}
	c.wbufList = c.wbufList[:0]
	c.rr, c.rw = 0, 0
	c.releaseReadBuf = false
}

// ---------------------------------------------------------------------------
// 状态位(引擎内部用)

func (c *Conn) setClient(v bool) {
	if v {
		atomic.OrUint32(&c.packed, flagClient)
	} else {
		atomic.AndUint32(&c.packed, ^flagClient)
	}
}

func (c *Conn) isClient() bool { return atomic.LoadUint32(&c.packed)&flagClient != 0 }

// tryBusy 抢 busy 位（"这条连接归我处理了"）。
//
// **先做一次普通读再决定要不要写**：x86 上 OrUint32 是 lock 前缀的读改写，
// 比一次普通 load 贵一个数量级，而它在每条消息的事件路径上。绝大部分时候
// busy 位是 0（同一条连接的调用者都在同一个事件循环 goroutine 上，串行），
// 那次 lock 前缀纯属白花——先 load 看一眼就能跳过。
//
// 读到的 0 一定是真的（没人持有）；读到 1 也许对方刚放掉，那就走下面那条
// 慢路径老实抢。
func (c *Conn) tryBusy() bool {
	if atomic.LoadUint32(&c.packed)&flagBusy != 0 {
		return false
	}
	return atomic.OrUint32(&c.packed, flagBusy)&flagBusy == 0
}

func (c *Conn) unbusy() {
	// 热路径: 大部分时候没有 flagFreePending, 清掉 busy 就完事。
	// 用 atomic.And 的返回值判断, 不额外多一次原子读。
	if old := atomic.AndUint32(&c.packed, ^flagBusy); old&flagFreePending != 0 {
		c.mu.Lock()
		if atomic.LoadUint32(&c.packed)&flagFreePending != 0 {
			atomic.AndUint32(&c.packed, ^flagFreePending)
			c.releaseBuffersLocked()
		}
		c.mu.Unlock()
	}
}

func (c *Conn) setPendingRead()  { atomic.OrUint32(&c.packed, flagPendingRead) }
func (c *Conn) setPendingWrite() { atomic.OrUint32(&c.packed, flagPendingWrite) }

func (c *Conn) takePendingRead() bool {
	return atomic.AndUint32(&c.packed, ^flagPendingRead)&flagPendingRead != 0
}

func (c *Conn) takePendingWrite() bool {
	return atomic.AndUint32(&c.packed, ^flagPendingWrite)&flagPendingWrite != 0
}

// isActivated OnOpen 跑过了没有。
func (c *Conn) isActivated() bool { return atomic.LoadUint32(&c.packed)&flagActivated != 0 }

// setActivated 标记 OnOpen 跑完了。返回"之前有没有待处理的事件"
// ——有的话调用方要接着处理（见 eventloop 里 activate 的用法）。
func (c *Conn) setActivated() (pendingRead, pendingWrite bool) {
	old := atomic.OrUint32(&c.packed, flagActivated)
	return old&flagPendingRead != 0, old&flagPendingWrite != 0
}

// cork 相关的 isCorking/setCorking 在 cork.go 里（那边有完整说明）。
