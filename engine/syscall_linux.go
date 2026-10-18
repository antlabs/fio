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

//go:build linux && !fio_rwsyscall && !fio_slowsyscall

package engine

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// 默认实现: recvfrom(2)/sendto(2), 直进 socket 层。
//
// 与 read(2)/write(2) 的区别是后者要先过 VFS(vfs_read / vfs_write),
// 再由 socket 的文件操作转到 socket 层的收发。多出来的只有 fd 到 file
// 的转换和几个模式检查, 但它在每条消息至少一次的路径上。
//
// 实测(12 核 / 10000 连接 / 1024B / C++ 客户端 echo, 2 个 event loop +
// 10 个解析 goroutine): recvfrom/sendto 1,689,307 TPS, read/write
// 1,642,562, 差 2.8%, 尾延迟 8.0ms 对 8.2ms。所以默认用这一版。
// 想量 read/write 的, 用 -tags fio_rwsyscall。
//
// 想量 RawSyscall 本身值多少(对比标准库那层 entersyscall/exitsyscall),
// 用 -tags fio_slowsyscall, 见 conn_syscall_linux_slow.go。
//
// 不是 socket 的 fd 退回 read/write: 库的 fd 正常都来自 accept, 但
// 用户可能拿别的 fd 来用, 那种情况下 recvfrom 返回 ENOTSOCK, 这里让
// 它退回 VFS, 和没有任何优化时一样。

// socketRead 从 fd 读取数据。
//
// 这里是自己发 syscall, 而不是用 x/sys/unix 的 Recvfrom: 后者会把对端
// 地址填进一个 RawSockaddrAny 并检查 family, 每次调用都要付这份开销,
// 而我们只关心数据本身。
func socketRead(fd int, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// recvfrom(fd, buf, len, flags=0, src_addr=NULL, addrlen=NULL)
	var n uintptr
	var errno unix.Errno
	if enterSyscall.Load() {
		n, _, errno = unix.Syscall6(unix.SYS_RECVFROM,
			uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)),
			0, 0, 0)
	} else {
		n, _, errno = unix.RawSyscall6(unix.SYS_RECVFROM,
			uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)),
			0, 0, 0)
	}
	if errno == unix.ENOTSOCK {
		// 不是 socket, 退回 VFS
		return rawRead(fd, p)
	}
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// socketWrite 向 fd 写入数据。
//
// 不使用 x/sys/unix 的 Sendto: 它的生成代码是
//
//	_, _, e1 := Syscall6(SYS_SENDTO, ...)
//
// 把内核返回的实际写入字节数丢掉了。非阻塞 socket 上 sendto 可能只写出去
// 一部分, 调用方要靠这个 n 判断部分写(writeToSocket 的上层就是靠
// n != len(data) 决定剩余数据进缓冲区的), 丢掉它会直接丢数据。
func socketWrite(fd int, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// MSG_NOSIGNAL: 对端已经 reset 的连接, 写会返回 EPIPE 而不是抛
	// SIGPIPE。不带这个标志时内核要生成并投递那个信号(Go runtime 还得
	// 接住它), 在长连接被对端关掉的场景里是实打实的开销。
	var n uintptr
	var errno unix.Errno
	if enterSyscall.Load() {
		n, _, errno = unix.Syscall6(unix.SYS_SENDTO,
			uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)),
			unix.MSG_NOSIGNAL, 0, 0)
	} else {
		n, _, errno = unix.RawSyscall6(unix.SYS_SENDTO,
			uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)),
			unix.MSG_NOSIGNAL, 0, 0)
	}
	if errno == unix.ENOTSOCK {
		// 不是 socket, 退回 VFS
		return rawWrite(fd, p)
	}
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// rawRead / rawWrite 是 VFS 那条路, 兜底用。
func rawRead(fd int, p []byte) (int, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_READ,
		uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)))
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func rawWrite(fd int, p []byte) (int, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_WRITE,
		uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)))
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// socketWritev 把 header 和 payload 作为两段交给内核, 由内核拼起来。
//
// 为什么不用 frame.WriteFrame: 它是"从池里取一块 buf, 把头写进去、把
// payload 拷进去、再把整块交给 w.Write"——每条消息一次完整 memcpy。
// 用 writev 就没有这次拷贝: header 在栈上构造, payload 直接用调用方的
// 那块内存, 内核自己拼。
//
// fnet 用的就是这个(sendmsg + iovec)。1KB 消息下那次 memcpy 约
// 30-50ns, 而一条消息的往返是 ~600ns。
func socketWritev(fd int, header, payload []byte) (int, error) {
	var iov [2]unix.Iovec
	iov[0].Base = unsafe.SliceData(header)
	iov[0].SetLen(len(header))
	iov[1].Base = unsafe.SliceData(payload)
	iov[1].SetLen(len(payload))
	return writevIovec(fd, &iov[0], 2)
}

// socketWritev3 是三段: 攒包缓冲区、一个新 frame 的头、它的 payload。
// 攒包装不下时走这条, payload 和攒下的那批都不用拷。
func socketWritev3(fd int, first, header, payload []byte) (int, error) {
	var iov [3]unix.Iovec
	iov[0].Base = unsafe.SliceData(first)
	iov[0].SetLen(len(first))
	iov[1].Base = unsafe.SliceData(header)
	iov[1].SetLen(len(header))
	iov[2].Base = unsafe.SliceData(payload)
	iov[2].SetLen(len(payload))
	return writevIovec(fd, &iov[0], 3)
}

func writevIovec(fd int, iov *unix.Iovec, count int) (int, error) {
	msg := unix.Msghdr{Iov: iov}
	msg.SetIovlen(count)

	var n uintptr
	var errno unix.Errno
	if enterSyscall.Load() {
		n, _, errno = unix.Syscall6(unix.SYS_SENDMSG,
			uintptr(fd), uintptr(unsafe.Pointer(&msg)), unix.MSG_NOSIGNAL, 0, 0, 0)
	} else {
		n, _, errno = unix.RawSyscall6(unix.SYS_SENDMSG,
			uintptr(fd), uintptr(unsafe.Pointer(&msg)), unix.MSG_NOSIGNAL, 0, 0, 0)
	}
	if errno == unix.ENOTSOCK {
		// 不是 socket 的 fd 退回 VFS(sendmsg 对它也是 ENOTSOCK)。把
		// iovec 描述的各段拼成一块再写。
		segs := unsafe.Slice(iov, count)
		total := 0
		for i := range segs {
			total += int(segs[i].Len)
		}
		all := make([]byte, 0, total)
		for i := range segs {
			all = append(all, unsafe.Slice((*byte)(segs[i].Base), segs[i].Len)...)
		}
		return rawWrite(fd, all)
	}
	if errno != 0 {
		// 出错时内核在返回值里放的是 -errno(无符号读出来是个很大的数,
		// 转成 int 就是负的), 不是"写了多少字节"。丢给调用方会让它拿
		// 这个负数去切 slices。和 socketWrite 一样返回 0: 出错就是
		// 一个字节都没写进去(EAGAIN/EINTR 也是)。
		return 0, errno
	}
	return int(n), nil
}
