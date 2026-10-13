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

//go:build linux

package quic

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// UDP_SEGMENT（GSO）：一次 sendmsg 交一整块，内核按固定的段长切成一个个
// 数据报。**static-h3 那条档的命门**：16KB 的响应 = 15 个包，每个包一次
// sendto 的话，5 秒钟 1300 万个系统调用，光这一项就吃掉 5 个核（profile
// 里 sendto 占 CPU 的 45%）。切成 GSO 之后 15 个包一次系统调用。
//
// 约束（内核的规矩）：**除最后一段，每段必须正好是 segSize**。所以只能把
// 长度一致的包攒在一起发；长度不齐的走普通路径（writePackets 里判断）。
const gsoEnabled = true

// sendBatchGSO 把 buf 按 segSize 切成数据报发出去。
func sendBatchGSO(fd int, sa unix.Sockaddr, buf []byte, segSize int) error {
	if segSize <= 0 || segSize > 65535 || len(buf) < segSize {
		return errNoGSO
	}
	oob := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&oob[unix.CmsgLen(0)])) = uint16(segSize)
	_, err := unix.SendmsgN(fd, buf, oob, sa, 0)
	return err
}
