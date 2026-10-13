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

package quic

import (
	"fmt"
	"os"
)

// 调试开关：FIO_QUIC_DEBUG=1 时把包层/帧层的关键一步打成一行到 stderr。
//
// 回环上排查"握手卡住了"全靠它：客户端只会说 "no recent network activity"，
// 服务端这边得自己讲清楚是没收着、解不开、还是没回。
var debugOn = os.Getenv("FIO_QUIC_DEBUG") != ""

func dbg(format string, args ...any) {
	if debugOn {
		fmt.Fprintf(os.Stderr, "[quic] "+format+"\n", args...)
	}
}
