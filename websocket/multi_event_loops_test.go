//go:build linux || darwin || netbsd || freebsd || openbsd || dragonfly

package websocket

import (
	"runtime"
	"testing"
)

// 默认事件循环是 4/3 个 CPU（WebSocket 的 syscall 等待要靠轻微超订盖住），
// 不是 engine 的"每 CPU 一个"。显式 WithEventLoops 仍然优先。
func TestDefaultEventLoopsAdaptive(t *testing.T) {
	n := runtime.NumCPU()
	want := 2
	if n > 4 {
		want = n + n/3
	}

	m := NewMultiEventLoopAndStartMust()
	defer m.Free()
	if got := m.NumLoops(); got != want {
		t.Fatalf("NumLoops() = %d, want %d", got, want)
	}
}

func TestExplicitEventLoopsWins(t *testing.T) {
	m := NewMultiEventLoopAndStartMust(WithEventLoops(3))
	defer m.Free()
	if got := m.NumLoops(); got != 3 {
		t.Fatalf("NumLoops() = %d, want 3", got)
	}
}
