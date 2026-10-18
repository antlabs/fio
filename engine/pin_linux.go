//go:build linux

package engine

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// per-core Worker 调度：event loop 和它的 worker 绑到同一个 CPU。
//
// FIO_PIN_PAIRS 只是实验开关；正式入口是 WithPerCoreWorkers。
var (
	pinEnabled bool
	pinCPUs    []int
)

func enablePinning() {
	if pinEnabled {
		return
	}
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return
	}
	for i := 0; i < 1024; i++ {
		if set.IsSet(i) {
			pinCPUs = append(pinCPUs, i)
		}
	}
	pinEnabled = len(pinCPUs) > 0
}

func init() {
	if os.Getenv("FIO_PIN_PAIRS") != "" {
		enablePinning()
	}
}

func pinLoop(idx int) {
	if !pinEnabled || len(pinCPUs) == 0 {
		return
	}
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Zero()
	set.Set(pinCPUs[idx%len(pinCPUs)])
	_ = unix.SchedSetaffinity(0, &set)
}
