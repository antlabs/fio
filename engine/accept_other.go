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

//go:build !linux && !netbsd && !freebsd && !openbsd && !dragonfly

package engine

import "golang.org/x/sys/unix"

// acceptNonblock 是 accept4 不可用时的退路（macOS 就没有 accept4）：
// 先 accept，再单独设一次非阻塞。多一次 fcntl，只在 darwin/Windows 上付。
func acceptNonblock(lfd int) (int, error) {
	nfd, _, err := unix.Accept(lfd)
	if err != nil {
		return nfd, err
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return -1, err
	}
	return nfd, nil
}
