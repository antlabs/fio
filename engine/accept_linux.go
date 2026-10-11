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

//go:build linux || netbsd || freebsd || openbsd || dragonfly

package engine

import "golang.org/x/sys/unix"

// acceptNonblock 收一条连接并**顺便把它设成非阻塞**。
//
// 用 accept4(2) 而不是 accept(2) + fcntl(F_SETFL, O_NONBLOCK)：后者是两次
// 系统调用，而每建一条连接多一次，在连接 churn 型的负载上直接摊进每请求的
// 成本里。实测（limited-conn，18 万连接/秒）strace -c 里 fio 有 75K 次
// fcntl（和 accept 次数一样多），fib 一次都没有——它就是 accept4。
func acceptNonblock(lfd int) (int, error) {
	nfd, _, err := unix.Accept4(lfd, unix.SOCK_NONBLOCK)
	return nfd, err
}
