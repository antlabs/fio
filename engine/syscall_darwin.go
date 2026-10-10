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

//go:build darwin

package engine

import "golang.org/x/sys/unix"

// Darwin 上 read(2)/write(2) 和 recvfrom/sendto 走同一套 soreceive/sosend，
// 没有可供省掉的间接层，所以单段的读沿用 read/write（见
// syscall_unix_other.go 里那段说明）。
//
// **但多段写要真的用 writev**。原先这里是"拼成一块再 write"：一次
// make + 一次整段 memcpy，响应多大就分配多大。static 这类 profile 每个响应
// 8KB~200KB，等于每请求白拷一遍整个响应体外加一次等长的堆分配。writev 让
// 内核直接按 iovec 抄，省掉用户态的这一次。
//
// （Linux 一直走的是真 writev，见 syscall_linux.go；这条只在 Darwin 上不一样，
// 而且它只影响本机调优的数字——榜单跑在 Linux 上。）

func socketRead(fd int, p []byte) (int, error) {
	return unix.Read(fd, p)
}

func socketWrite(fd int, p []byte) (int, error) {
	return unix.Write(fd, p)
}

// socketWritev 两段写。空段直接退化成单段，省一次 iovec 组装。
func socketWritev(fd int, header, payload []byte) (int, error) {
	switch {
	case len(header) == 0:
		return socketWrite(fd, payload)
	case len(payload) == 0:
		return socketWrite(fd, header)
	}
	return unix.Writev(fd, [][]byte{header, payload})
}

// socketWritev3 三段写（攒包(cork)溢出那条路用）。
func socketWritev3(fd int, first, header, payload []byte) (int, error) {
	iov := make([][]byte, 0, 3)
	if len(first) > 0 {
		iov = append(iov, first)
	}
	if len(header) > 0 {
		iov = append(iov, header)
	}
	if len(payload) > 0 {
		iov = append(iov, payload)
	}
	switch len(iov) {
	case 0:
		return 0, nil
	case 1:
		return socketWrite(fd, iov[0])
	}
	return unix.Writev(fd, iov)
}
