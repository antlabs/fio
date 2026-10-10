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
	"sync/atomic"
	"syscall"

	"github.com/antlabs/wsutil/bytespool"
)

// 攒包(cork): 一次 read 里到的多个请求, 它们的回包合成一次写。
//
// 为什么需要: 一条连接的每条消息一次 write, 而客户端一次写就可能带 10
// 条消息(压测里的 pipeline: 一次 10320 字节)。服务端每条回一条, 10 次
// write 系统调用, 每次内核都要把 1KB 从用户态搬过去。攒起来就一次 write
// 搬 10KB, 系统调用数和内核里的每次固定开销都除 10。
//
// 实测(Pipeline 场景, 10000 连接 1KB 消息 -rpl 10): 写系统调用从
// 2,000,000/s 降到 200,000/s, CPU 从 674% 降到 271%。
//
// 用法(协议侧):
//
//	if c.StartCork(remaining) {   // 这一轮还有后续数据, 值得攒
//	    // 回调里写出去的东西
//	    c.CorkWrite(header, payload)
//	}
//	...
//	c.EndCork()                   // 轮末一次写出去
//
// **不放在 Read 里自动做**：攒不攒取决于"协议这一轮还有没有后续报文"，
// 只有协议自己知道。引擎只提供攒的机制。

// corkGrowBytes 是"装不下时换多大": 一次换到位, 之后这个批次基本不会再
// 换。选 16KB 是因为常见的批次是 10 × 1KB 左右, 而 bytespool 按 1KB
// 分档, 16KB 的请求拿到的是 15KB 那档, 装得下批次还留了余量。
//
// 比它更大的批次装不下时会走 writev 那条路, 每 15KB 一次写——也比每条
// 一次好得多。
const corkGrowBytes = 16 * 1024

// StartCork 开始攒包, 返回是否真的开始了。
//
// capHint 是预计这一批回包多大(通常是"读缓冲区里还没解析的字节数", 因为
// 回包和请求大小往往差不多), 用来取一块合适的缓冲区。
//
// 这些情况不会开攒(返回 false, 调用方照常走普通写路径):
//   - 已经在攒了
//   - 装了写拦截器(TLS): 它自己有一套记录层的分帧, 攒起来会把边界搞乱
//   - 写缓冲里有积压: 攒包的批次和积压抢写事件会乱序
func (c *Conn) StartCork(capHint int) bool {
	if c.isCorking() || c.IsClosed() {
		return false
	}
	if c.writeHook() != nil {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.wbufList) != 0 {
		return false
	}
	c.corkStartLocked(capHint)
	return true
}

// IsCorking 正在攒包吗。
//
// **协议的写路径要查它**：攒着的时候不能直接往 socket 写，不然这条消息会
// 跑到"已经攒下的那批"前面去。
func (c *Conn) IsCorking() bool { return c.isCorking() }

func (c *Conn) isCorking() bool { return atomic.LoadUint32(&c.packed)&flagCorking != 0 }

func (c *Conn) setCorking(v bool) {
	if v {
		atomic.OrUint32(&c.packed, flagCorking)
	} else {
		atomic.AndUint32(&c.packed, ^flagCorking)
	}
}

// corkStartLocked 取一块攒包缓冲区。调用方持有 c.mu。
func (c *Conn) corkStartLocked(capHint int) {
	if capHint <= 0 {
		capHint = 1024
	}
	if capHint > maxCorkBytes {
		capHint = maxCorkBytes
	}
	// 回包总长和请求总长差不多(echo), 留 1/4 余量, 这样一批回包通常一个
	// 缓冲区就装下, 不用中途 writev 一次。
	capHint += capHint / 4

	b := bytespool.GetBytes(capHint)
	*b = (*b)[:0]
	c.wbufList = append(c.wbufList[:0], b)
	c.setCorking(true)
}

// CorkWrite 把一条消息(头 + 载荷)写进攒包缓冲区。
//
// 装不下时先是换一块大的, 还装不下就把"攒下的这批 + 新消息"一次 writev
// 出去(payload 不拷, 直接进 iovec)。
//
// 语义上等价于 Write(header+payload), 只是攒着晚点发。
func (c *Conn) CorkWrite(header, payload []byte) error {
	if c.IsClosed() {
		return ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.wbufList) == 0 {
		// 攒包缓冲区被写事件那条路消费掉了(部分写之后 flush 成功),
		// 重新取一块接着攒。
		c.corkStartLocked(len(payload))
	}
	b := c.wbufList[len(c.wbufList)-1]

	if len(*b)+len(header)+len(payload) <= cap(*b) {
		*b = append(*b, header...)
		*b = append(*b, payload...)
		return nil
	}

	// 装不下: 先换一块大的再来。跳一次到位, 只多拷一次"已经攒下的这些";
	// 不然就会退回"每两条一次 writev", 攒包就没意义了。
	if nb := c.growCork(b, len(*b)+len(header)+len(payload)); nb != nil {
		b = nb
		*b = append(*b, header...)
		*b = append(*b, payload...)
		return nil
	}

	// 装不下也换不动(已经很大了, 或者这批比上限还长): 攒的这批和新消息
	// 一次发出去, 三段时间接进 iovec, 都不拷。
	seg := *b
	n, err := socketWritev3(int(atomic.LoadInt64(&c.fd)), seg, header, payload)
	if n < 0 {
		// 兜底: 下面要拿 n 切 slices, 负数就是"从一个负下标切", 直接
		// panic。socketWritev3 保证出错时返回 0, 但这条路径不该因为一个
		// 返回值约定被破坏就崩掉整个进程。
		n = 0
	}
	total := len(seg) + len(header) + len(payload)
	if err == nil && n == total {
		*b = (*b)[:0]
		return nil
	}
	if err == nil || err == syscall.EAGAIN || err == syscall.EINTR {
		// 部分写: 没写出去的那部分留在写缓冲里, 剩下的交给可写事件。
		//
		// **攒包到此为止**：这个批次剩下的消息要走普通写路径了, 不然它们
		// 会插到这批没写完的数据前面去(顺序就乱了)。
		//
		// 注意这里**不能**走 appendToWbufList 的合并逻辑去拼 header 和
		// payload——它是分段写的, 拼起来要多一次拷贝。三段分别追加,
		// 顺序天然是对的。
		c.setCorking(false)
		*b = (*b)[:0]
		switch {
		case n < len(seg):
			c.appendToWbufList(seg[n:], total-n)
			c.appendToWbufList(header, len(header)+len(payload))
			c.appendToWbufList(payload, len(payload))
		case n < len(seg)+len(header):
			c.appendToWbufList(header[n-len(seg):], len(header)+len(payload)-n+len(seg))
			c.appendToWbufList(payload, len(payload))
		default:
			c.appendToWbufList(payload[n-len(seg)-len(header):], total-n)
		}
		c.parent.addWrite(c)
		return nil
	}
	*b = (*b)[:0]
	return err
}

// growCork 把攒包缓冲区换成一块够大的, 换不动(已经不小于 corkGrowBytes,
// 或者要装的东西比它还长)时返回 nil。
func (c *Conn) growCork(old *[]byte, need int) *[]byte {
	if cap(*old) >= corkGrowBytes || need > corkGrowBytes {
		return nil
	}
	nb := bytespool.GetBytes(corkGrowBytes)
	if cap(*nb) < need {
		// 池里这一档不够(它的档位是按请求大小分桶的), 不折腾了。
		bytespool.PutBytes(nb)
		return nil
	}
	*nb = append((*nb)[:0], (*old)...)
	bytespool.PutBytes(old)
	c.wbufList[len(c.wbufList)-1] = nb
	return nb
}

// EndCork 结束攒包, 把攒下的回包一次写出去。
//
// **每一轮都要调**, 包括出错的那一轮：攒下的回包要在连接关掉之前出去
// (HTTP/2 的 GOAWAY、WebSocket 的 close 帧都是这么发的)。
func (c *Conn) EndCork() {
	if !c.isCorking() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// 清位要在锁里: 别的 goroutine 的写路径拿着锁读这个位, 读到的要么是
	// "还在攒"(它写进缓冲区, 由这里一起写出去), 要么是"攒完了"(它走普通
	// 写路径)。锁外清位的话, 它可能读到过期的"还在攒", 把数据塞进一个
	// 不会再有人来写的缓冲区。
	c.setCorking(false)
	if len(c.wbufList) == 0 {
		return
	}
	// 攒包缓冲区可能是空的: 整批被 writev 溢出那条路写出去之后缓冲区就
	// 清空了(见 CorkWrite)。空的直接还回去, 不要走 flush——它会为 0 字节
	// 也记一次写系统调用。
	if len(c.wbufList) == 1 && len(*c.wbufList[0]) == 0 {
		bytespool.PutBytes(c.wbufList[0])
		c.wbufList[0] = nil
		c.wbufList = c.wbufList[:0]
		return
	}
	// flush 自己负责把写完的缓冲区还回池子。别在这里再动 wbufList——
	// flush 可能是提前返回的(连接已关), 那时列表还在, 逐个置 nil 会留下
	// 一个"非空但全是 nil"的列表, 下一个 appendToWbufList 就会解引用 nil。
	_ = c.flushLocked()
}
