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

import "sync/atomic"

// cacheLinePad 把不同核写的计数分开放, 免得一个消费者取 head 的时候
// 把生产者正在写的 tail 那一行也失效掉。
type cacheLinePad [128]byte

type ringCell struct {
	// seq 是这一格到第几圈了。空闲时等于它下次要被写入的位置, 放进了
	// 任务之后是那个位置加一, 被消费者取走并交回之后是位置加环长。
	seq  atomic.Uint64
	task task
}

// taskRing 是一个有界的多生产者多消费者队列, 装单个连接的任务。
//
// 装单个而不是一批: 一批要等这一轮 epoll 走完才投出去, 而一轮可能有
// 几千个事件、走完要几毫秒, 轮尾那些连接就白等那几毫秒——那直接进
// TP95/TP99。收到一个就投一个, 和 fnet 的做法一样。
//
// 出自 Dmitry Vyukov 的 bounded MPMC queue。(迁移前那套 websocket 里
// 是同一份实现, 见 task_ring.go; 这里跟着搬进 engine。)
//
// 生产者用 tail 上的 compare and swap 抢位置, 消费者用 head 上的抢,
// 所以投递的一方和处理的一方都不用排在锁后面。用环而不是 channel:
// channel 每投一个就要唤醒一次接收方, 一次唤醒就是一次调度。
type taskRing struct {
	cells []ringCell
	mask  uint64
	// limit 是环能装多少个任务, 可以小于格子数: 格子数是 2 的幂,
	// 好让位置用掩码映射到格子。
	limit uint64
	_     cacheLinePad
	head  atomic.Uint64
	_     cacheLinePad
	tail  atomic.Uint64
}

func newTaskRing(limit int) *taskRing {
	limit = max(limit, 1)
	// 至少两格: 只有一格时, 位置 n 上放着任务的那格和等着位置 n+1 的
	// 空格 seq 相同, 生产者会覆盖掉消费者已经认领但还没读的任务。
	size := 2
	for size < limit {
		size <<= 1
	}
	r := &taskRing{cells: make([]ringCell, size), mask: uint64(size - 1), limit: uint64(limit)}
	for i := range r.cells {
		r.cells[i].seq.Store(uint64(i))
	}
	return r
}

// push 发布一个任务, 并报告有没有位置。生产者先把位置认下来再把任务
// 写进去, 所以有一瞬间 tail 会越过一个还没落到格子里的任务; 见 pop。
func (r *taskRing) push(task task) bool {
	for {
		tail := r.tail.Load()
		head := r.head.Load()
		if head > tail {
			// tail 在读它之后又被别人推过了
			continue
		}
		if tail-head >= r.limit {
			return false
		}
		cell := &r.cells[tail&r.mask]
		seq := cell.seq.Load()
		if seq != tail {
			if seq < tail {
				// 上一圈的消费者还没把格子交回来
				return false
			}
			// 另一个生产者先抢到了这个位置
			continue
		}
		if !r.tail.CompareAndSwap(tail, tail+1) {
			continue
		}
		cell.task = task
		cell.seq.Store(tail + 1)
		return true
	}
}

// pop 取最早的一个任务, 没有就报告没有。生产者认了位置但还没写完的
// 那些算没有: 那个生产者写完之后会去叫醒一个消费者, 和每个生产者
// 都会做的一样。
func (r *taskRing) pop() (task, bool) {
	for {
		head := r.head.Load()
		cell := &r.cells[head&r.mask]
		seq := cell.seq.Load()
		if seq != head+1 {
			if seq == head {
				// 空的, 或者它的生产者还在写
				return task{}, false
			}
			// 另一个消费者先取走了这个位置
			continue
		}
		if !r.head.CompareAndSwap(head, head+1) {
			continue
		}
		t := cell.task
		cell.task = task{}
		cell.seq.Store(head + r.mask + 1)
		return t, true
	}
}

// len 是认领了但还没被取走的位置数, 含正在写的那些。只有什么都不动
// 的时候它是准的, 而调用它的地方都只要一个大概, 之后再确认。
func (r *taskRing) len() int {
	tail := r.tail.Load()
	head := r.head.Load()
	if head > tail {
		return 0
	}
	return int(tail - head)
}
