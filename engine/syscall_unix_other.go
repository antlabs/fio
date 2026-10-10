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

//go:build netbsd || freebsd || openbsd || dragonfly

package engine

import "golang.org/x/sys/unix"

// 非 Linux 的 unix 平台上沿用 read(2)/write(2)。
//
// 换 recvfrom/sendto 的收益是 Linux 特有的: Linux 上 read/write 要先过
// VFS 层(__sys_read -> vfs_read -> sock_read_iter), 而 BSD/Darwin 上
// read/write 与 recvfrom/sendto 走的是同一套 soreceive/sosend 逻辑,
// 没有可供省掉的间接层。既然没有收益, 就不动它, 少一处行为差异。
//
// 这里不受 fio_recvsend 标签影响: 该标签只用来在 Linux 上切换
// 两套实现, 这些平台上两套本来就是同一套。
//
// **darwin 已经从这个文件里分出去了**（见 syscall_darwin.go）：它的
// socketWritev 换成了真的 writev，所以要多一份只在那个平台上编译的实现。

func socketRead(fd int, p []byte) (int, error) {
	return unix.Read(fd, p)
}

func socketWrite(fd int, p []byte) (int, error) {
	return unix.Write(fd, p)
}

// socketWritev / socketWritev3 / wsHeader 的兜底: 这些构建组合下没有
// sendmsg 快路径, 退回"拼成一块再写"。
func socketWritev(fd int, header, payload []byte) (int, error) {
	all := make([]byte, 0, len(header)+len(payload))
	all = append(all, header...)
	all = append(all, payload...)
	return socketWrite(fd, all)
}

func socketWritev3(fd int, first, header, payload []byte) (int, error) {
	all := make([]byte, 0, len(first)+len(header)+len(payload))
	all = append(all, first...)
	all = append(all, header...)
	all = append(all, payload...)
	return socketWrite(fd, all)
}
