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

import (
	"testing"
	"time"
)

// 队列满且 worker 已经到 max：submit 不能再起 goroutine，应该在当前
// goroutine 上把这一批处理掉（背压），并且不增加 running。
func TestSubmitOverflowAtCap(t *testing.T) {
	p := &batchPool{}
	p.free.New = func() any { return &taskBatch{} }

	w := &batchWorker{
		ch:  make(chan *taskBatch, 1),
		max: 1,
		p:   p,
	}
	w.running.Store(1)

	// 先把 channel 占满，逼 submit 走兜底路径。
	w.ch <- &taskBatch{}

	b := &taskBatch{el: &EventLoop{}}
	w.submit(b)

	if got := w.running.Load(); got != 1 {
		t.Fatalf("running = %d, want 1（到顶不能扩容）", got)
	}
	w.mu.Lock()
	n := len(w.states)
	w.mu.Unlock()
	if n != 0 {
		t.Fatalf("到顶后不该注册新 workerState: %d", n)
	}
}

// 队列满但还有扩容额度：起一次性 worker，处理完 running 要回落。
func TestSubmitOverflowSpawnsOneShot(t *testing.T) {
	p := &batchPool{}
	p.free.New = func() any { return &taskBatch{} }

	w := &batchWorker{
		ch:  make(chan *taskBatch, 1),
		max: 2,
		p:   p,
	}
	w.ch <- &taskBatch{}

	w.submit(&taskBatch{el: &EventLoop{}})

	// processBatch 是 void；等 running 回落。
	deadline := time.Now().Add(time.Second)
	for w.running.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if got := w.running.Load(); got != 0 {
		t.Fatalf("running = %d, want 0（一次性 worker 应该退出）", got)
	}
	w.mu.Lock()
	n := len(w.states)
	w.mu.Unlock()
	if n != 0 {
		t.Fatalf("一次性 worker 退出后 states 没清干净: %d", n)
	}
}
