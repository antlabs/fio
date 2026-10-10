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

// Package engine 是 fio 的协议无关网络引擎：epoll/kqueue 事件循环、非阻塞
// 连接的读写、缓冲区、定时器。协议（websocket、http、http2、tls...）实现
// Handler，引擎把数据喂进来、把要写的东西交回去。
//
// 只有这个包碰系统调用和事件循环。协议包不直接调 epoll，也不自己管 socket——
// 那些和协议无关，写一遍就够；反过来，帧头、状态码、握手这些只该被它自己的
// 包看见。
//
// 事件循环用 github.com/antlabs/pulse：它把 epoll/kqueue 的差异、ET/LT、
// park 还是阻塞等待都封好了，websocket/ 也用它。这个包建在它上面，不重复
// 造那部分。
package engine

// Handler 是协议实现的接口。引擎按事件调它。
//
// 形状对齐 http-parser 那一系的解析器（httparser 也是这个形状）：
// "给你一段字节，告诉你我消化了多少"。这样协议不用自己管缓冲——半条报文
// 没凑齐就返回 0，引擎把它留在缓冲区里，下一次读到了接着喂。
type Handler interface {
	// OnOpen 连接就绪。accept 之后、任何数据到达之前调一次。
	OnOpen(c *Conn)

	// OnData 有数据可读。buf 是读缓冲区里还没被消费的那一段。
	//
	// 返回消化了多少字节。返回 0 表示"这段还不够凑出一条报文"，引擎会
	// 把它留着，下次读到了再喂——**不是错误**。
	//
	// 返回 error 会让引擎关掉连接。
	OnData(c *Conn, buf []byte) (int, error)

	// OnClose 连接关闭，只会调一次。err 是关闭原因。
	OnClose(c *Conn, err error)
}

// ReadBufferSizer 是协议可以额外实现的可选接口：告诉引擎读缓冲区的
// **起始**大小（不够时引擎自己会扩，见 growReadBuffer）。
//
// 为什么要协议来定：读缓冲区是**每连接一块**，连接多了就是实打实的内存
// ——10000 连接 × 8KB = 80MB。而且工作集一大，每次读都在碰冷内存，吞吐
// 也跟着掉（实测 1KB echo：起始 8KB 改成 2KB，内存少 60MB、TPS 还涨）。
//
// 引擎的默认（8KB）是"什么协议都可能伺候"的值；协议自己知道报文多大，
// 报一个贴合的就行。
type ReadBufferSizer interface {
	InitialReadBufferSize() int
}

// MessageSizeHinter 是协议可以额外实现的可选接口。
//
// 引擎在**读缓冲区装满、而协议还没凑齐一条报文**的时候会问一句"整条报文
// 多大"，然后一次把缓冲区要到位。
//
// 不问的话引擎只能翻倍长：1MB 的报文要经历 16K→32K→…→1MB 六次翻倍，每次
// 都把已经读到的整块数据 memcpy 一遍。问一句就只拷一次——大报文场景下
// 省掉的是几倍于报文大小的内存带宽。
//
// **调用时机**：在两次 OnData 之间（协议手上没有活的缓冲区别名）。引擎的
// 约定是"OnData 里拿到的 buf 只在这次调用期间有效"，所以这个点动缓冲区
// 是安全的。协议**不能**在 OnData 里让引擎搬家——那会把协议正在读的数据
// 挪走或者换掉（实测：分片+压缩那条用例收到的报文头部多出两个字节）。
type MessageSizeHinter interface {
	// NextMessageSize 返回"当前这条还没收齐的报文整条有多大"。
	// 返回 0 表示不知道，引擎就按翻倍那条路走。
	NextMessageSize(c *Conn) int
}

// Binder 是 Handler 可以额外实现的可选接口：在 fd **注册到事件循环之前**
// 建协议层的连接对象。
//
// 为什么要这一步：有些协议（websocket 的 upgrade / Dial）拿到 fd 的时候
// 手上已经有全部上下文（握手协商出来的参数、bufio 多读的那几个字节、
// 调用方的回调），这些东西**只有调用方有**，而事件循环看不到。放在
// OnOpen 里建的话，调用方就得等事件循环跑完那个任务才能拿到对象——等一等
// 本身没问题，问题是那个等待会**让事件循环先跑一轮 poll**：对端握手完立刻
// 关连接（FIN 和数据一起到）时，等回来的对象已经被关掉了。
//
// 基线（迁移前）的做法就是在调用方的 goroutine 上 newConn、喂 leftover，
// 最后才注册；这个接口把那个顺序固定下来。
//
// **调用时机**：Add 里、AddRead 注册之前，跑在调用方的 goroutine 上。
// 这时候事件循环还看不见这个 fd，没有任何并发，所以建对象、喂数据都安全。
// 返回错误就不注册（fd 归调用方关）。
type Binder interface {
	Bind(c *Conn) error
}

// HandlerFunc 让 Handler 可以只用函数实现（测试、简单场景）。
type HandlerFunc struct {
	OpenFunc  func(c *Conn)
	DataFunc  func(c *Conn, buf []byte) (int, error)
	CloseFunc func(c *Conn, err error)
}

func (h *HandlerFunc) OnOpen(c *Conn) {
	if h.OpenFunc != nil {
		h.OpenFunc(c)
	}
}

func (h *HandlerFunc) OnData(c *Conn, buf []byte) (int, error) {
	if h.DataFunc != nil {
		return h.DataFunc(c, buf)
	}
	// 默认全部消费掉：不给回调就等于把数据丢掉
	return len(buf), nil
}

func (h *HandlerFunc) OnClose(c *Conn, err error) {
	if h.CloseFunc != nil {
		h.CloseFunc(c, err)
	}
}
