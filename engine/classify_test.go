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

// ≤4 核的默认布局：共享组 n/2 个 shard×2 worker，固定组 n 个 shard×1。
func TestClassifyLayout(t *testing.T) {
	p := newBatchPool(2, false)
	if !p.classify || p.sharedShards != 1 || p.fixedShards != 2 {
		t.Fatalf("2-core layout: classify=%v shared=%d fixed=%d", p.classify, p.sharedShards, p.fixedShards)
	}
	if len(p.workers) != 3 || p.perShard[0] != 2 || p.perShard[1] != 1 || p.perShard[2] != 1 {
		t.Fatalf("2-core workers=%d perShard=%v", len(p.workers), p.perShard)
	}
	if p.workerForClass(0, false) != p.workers[0] || p.workerForClass(1, false) != p.workers[0] {
		t.Fatal("echo batch should go to the shared shard")
	}
	if p.workerForClass(0, true) != p.workers[1] || p.workerForClass(1, true) != p.workers[2] {
		t.Fatal("pipeline batch should go to the fixed shard by loop")
	}

	p4 := newBatchPool(4, false)
	if !p4.classify || p4.sharedShards != 2 || p4.fixedShards != 4 || len(p4.workers) != 6 {
		t.Fatalf("4-core layout: classify=%v shared=%d fixed=%d workers=%d", p4.classify, p4.sharedShards, p4.fixedShards, len(p4.workers))
	}
	if p4.workerForClass(3, false) != p4.workers[3%2] {
		t.Fatal("4-core echo shard mapping wrong")
	}
	if p4.workerForClass(3, true) != p4.workers[2+3%4] {
		t.Fatal("4-core pipeline shard mapping wrong")
	}

	p8 := newBatchPool(8, false)
	if p8.classify || len(p8.workers) != 4 {
		t.Fatalf("8-core should keep the plain shared layout: classify=%v workers=%d", p8.classify, len(p8.workers))
	}
}

// 分类阈值：平均每个 read 任务 >=4KB 才算 pipeline；样本不足先走 echo。
func TestPipelineLoop(t *testing.T) {
	p := &batchPool{classify: true}
	var el EventLoop
	el.readStatTasks.Store(7)
	el.readStatBytes.Store(7 * 15000)
	if p.pipelineLoop(&el) {
		t.Fatal("7 samples should not classify yet")
	}
	el.readStatTasks.Store(8)
	el.readStatBytes.Store(8 * 1024)
	if p.pipelineLoop(&el) {
		t.Fatal("1KB/task should stay echo")
	}
	el.readStatBytes.Store(8 * classifyBytesPerTask)
	if !p.pipelineLoop(&el) {
		t.Fatal("4KB/task should be pipeline")
	}
	p.classify = false
	if p.pipelineLoop(&el) {
		t.Fatal("classify off must always return false")
	}
}
