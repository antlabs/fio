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

//go:build !linux

package quic

import "golang.org/x/sys/unix"

// 非 Linux 没有 UDP_SEGMENT（darwin 的等价物是 sendmsg 的 UDP_SEGMENT
// cmsg，行为不一样），统一走不到这里：gsoEnabled=false 时 writePackets
// 直接一个个发。
const gsoEnabled = false

func sendBatchGSO(fd int, sa unix.Sockaddr, buf []byte, segSize int) error {
	return errNoGSO
}
