//go:build linux || darwin || netbsd || freebsd || openbsd || dragonfly

package websocket

import (
	"runtime"
	"testing"
)

// 默认是 Worker 模式：每核 32 个 event loop、worker 总数按核数算。
// 显式 WithEventLoops 仍然优先。
func TestDefaultEventLoopsAdaptive(t *testing.T) {
	n := runtime.NumCPU()
	want, _, _ := workerTopology(n)
	want = capEventLoopsForFD(want)

	m := NewMultiEventLoopAndStartMust()
	defer m.Free()
	if got := m.NumLoops(); got != want {
		t.Fatalf("NumLoops() = %d, want %d", got, want)
	}
}

// Event 模式（内联）仍然保留，loop 数走 384/56 那套。
func TestEventModeLoops(t *testing.T) {
	n := runtime.NumCPU()
	want := defaultEventLoops
	if n == 1 {
		want = defaultEventLoopsSingleCPU
	}
	want = capEventLoopsForFD(want)

	m := NewMultiEventLoopAndStartMust(WithEventMode())
	defer m.Free()
	if got := m.NumLoops(); got != want {
		t.Fatalf("EventMode NumLoops() = %d, want %d", got, want)
	}
}

func TestExplicitEventLoopsWins(t *testing.T) {
	m := NewMultiEventLoopAndStartMust(WithEventLoops(3))
	defer m.Free()
	if got := m.NumLoops(); got != 3 {
		t.Fatalf("NumLoops() = %d, want 3", got)
	}
}
