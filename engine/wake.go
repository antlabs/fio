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

import "golang.org/x/sys/unix"

// 自唤醒管道。
//
// **为什么需要**：runOnLoop 是"投到事件循环的 goroutine 上跑"，而事件循环
// 大部分时间阻塞在 epoll_wait / kevent 里。没有这个管道的话，投过去的任务
// 要等 Poll 超时（100ms）才轮到——因为"通道里有任务"这件事，内核不知道。
//
// 症状：一个连上但不发数据的客户端，服务端的 OnOpen 要 100ms 之后才调；
// 客户端 Dial 想同步拿回连接对象更是要卡满 100ms（websocket 的客户端要用
// 它——握手时才知道的 pd、用户的 Callback 得在拿到对象之后装上去）。
//
// 做法是最经典的那个：一根管道，读端注册进事件循环，投任务时往写端写一个
// 字节。epoll_wait 立刻返回，循环醒来先把任务跑掉。
//
// 开销：每次投递多一次 write 系统调用。**这条路上只有"注册连接"**（OnOpen
// 那类），数据路径一次都不走，所以可以忽略。

// initWake 建一根唤醒管道，把读端挂到事件循环上。
//
// 两端都设非阻塞：写端满了（64KB，等于积压了 6 万多次没处理的唤醒）就
// 直接放弃这一次写——管道里已经有字节、循环醒来一定会 drain，丢一次不
// 影响正确性。读端非阻塞是为了 drain 时能读到 EAGAIN 为止。
func (el *EventLoop) initWake() error {
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		return err
	}
	if err := unix.SetNonblock(p[0], true); err != nil {
		unix.Close(p[0])
		unix.Close(p[1])
		return err
	}
	if err := unix.SetNonblock(p[1], true); err != nil {
		unix.Close(p[0])
		unix.Close(p[1])
		return err
	}
	el.wakeR, el.wakeW = p[0], p[1]
	return el.PollingApi.AddRead(el.wakeR)
}

// closeWake 关掉唤醒管道。在 PollingApi.Free 之后调。
func (el *EventLoop) closeWake() {
	if el.wakeR > 0 {
		unix.Close(el.wakeR)
		el.wakeR = 0
	}
	if el.wakeW > 0 {
		unix.Close(el.wakeW)
		el.wakeW = 0
	}
}

// wake 叫醒事件循环。
func (el *EventLoop) wake() {
	if el.wakeW <= 0 {
		return
	}
	// 写不进去（管道满了）说明里面还有没被 drain 的字节，循环本来就会醒
	_, _ = unix.Write(el.wakeW, []byte{0})
}

// drainWake 把管道里攒的唤醒字节读干净。
//
// 必须读干净：ET 模式下"管道可读"这个边缘只报一次，留着字节不读，后面的
// 唤醒就再也触发不了（和连接上"数据读完"是同一个道理）。
func (el *EventLoop) drainWake() {
	if el.wakeR <= 0 {
		return
	}
	var buf [64]byte
	for {
		n, err := unix.Read(el.wakeR, buf[:])
		if n <= 0 || err != nil {
			return
		}
	}
}
