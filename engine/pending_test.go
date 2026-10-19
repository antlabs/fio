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

import "testing"

// unbusyAndPending 只允许“抢到 busy”，不能把 pending 位消费掉：
// 调用方的下一步是 processConn(c, false, false)，由它自己去取 pending。
// 早先这里 take 了 pending，processConn 进去时已经没事件，丢边缘——
// 表现为多 worker/shard 下升级连接偶发卡满 5s（对端 FIN 才重新触发）。
func TestUnbusyAndPendingKeepsPending(t *testing.T) {
	var c Conn
	if !c.tryBusy() {
		t.Fatal("tryBusy failed on a fresh conn")
	}
	c.setPendingRead()

	if !c.unbusyAndPending() {
		t.Fatal("unbusyAndPending should claim busy when pending is set")
	}
	if !c.hasPending() {
		t.Fatal("pending must stay set for processConn to consume")
	}
	// 返回 true 时 busy 已经归调用方了，再抢应该失败。
	if c.tryBusy() {
		t.Fatal("busy should already be held after unbusyAndPending")
	}
	c.unbusy()
}
