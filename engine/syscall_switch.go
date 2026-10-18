package engine

import (
	"os"
	"sync/atomic"
)

// enterSyscall 决定 Linux 上的 recvfrom/sendto/sendmsg 走 RawSyscall 还是
// Syscall6（entersyscall）。默认由 websocket 层按任务模式设置：
//
//   - worker 池模式：Syscall6。syscall 期间把 P 让出去，别的 worker/event
//     loop 能继续跑；4 核 Pipeline 实测 +5%，12 核 Echo 从 ~1.78M 到 1.91M。
//   - inline 模式：RawSyscall。没有别的 goroutine 抢 P，省掉 enter/exit。
//
// FIO_ENTER_SYSCALL 环境变量可显式覆盖，用于对照实验。
var enterSyscall atomic.Bool

func init() {
	enterSyscall.Store(os.Getenv("FIO_ENTER_SYSCALL") != "")
}

// SetEnterSyscall 由 engine 选项调用（WithEnterSyscall）。
func setEnterSyscall(v bool) {
	if v {
		enterSyscall.Store(true)
	}
}
