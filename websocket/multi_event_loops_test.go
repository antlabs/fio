//go:build linux || darwin || netbsd || freebsd || openbsd || dragonfly

package websocket

import (
	"runtime"
	"testing"
)

// 默认事件循环：2 核以上 192，单核 64（每个循环负责的连接越少，
// cache 命中越好）。显式 WithEventLoops 仍然优先。
func TestDefaultEventLoopsAdaptive(t *testing.T) {
	n := runtime.NumCPU()
	want := defaultEventLoops
	if n == 1 {
		want = defaultEventLoopsSingleCPU
	}
	want = capEventLoopsForFD(want)

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
