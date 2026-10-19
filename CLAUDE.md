# fio 项目约束

## WebSocket 调度模式（2026-10-18 起）

- **默认：Worker 模式。** Event loop 只负责 epoll/kqueue 的等待、唤醒和事件分发；
  socket 读取、WebSocket 帧解析、用户回调、回包写出在 worker goroutine 池里执行。
- **Event 模式（内联模式）**：读/解析/回调/写都在 event loop 自己的 goroutine 上执行。
  保留 `WithParseInEventLoop()`（别名 `WithEventMode()`），但不再是默认。
- 两种模式都必须可用、有回归测试；默认 Worker 模式要在 2/4/8/16 核的
  Echo / Pipeline / Connections 上全面领先 fnet/fib，内存和 CPU EER 不能明显回退。
- 调整默认 loop 数、worker 数或调度路径时，先在 lab 上做同场交替 A/B
  （10k 连接、1KB，C++ 客户端），再提交；Echo 和 Pipeline 都要看，
  不能只看一个指标。
- 默认 Worker 模式的性能目标是接近/达到内联模式：event loop 按连接分片
  （小的 per-loop 连接集合保证 cache 局部性），worker 按批处理同一分片的事件，
  避免每消息一次跨 goroutine 唤醒。
- 默认 Worker 拓扑：worker 数 = 核数；event loop 数 = 32×worker，封顶 384；
  batch pool 每 shard 2 个 worker 共享一个队列（shard 数 = worker/2），**不绑核**。
  每轮 epoll_wait 默认最多取 64 条事件，批次上限 64。
  实测（10k×1KB、同场 A/B fnet）：2+2 530k/4.8M、4+4 863-889k/8.7-8.9M、
  8+8 1.26-1.29M/12.4-12.5M、12+12 1.90M/15.3M（Echo/Pipeline，环境波动 10%+）。
  改这些值要重跑 2/4/8/12 核 A/B。
- `WithPerCoreWorkers`（loop/worker 1:1 绑核）保留但**不再是默认**：低核实测
  2+2 只有 ~377k Echo，比上面的共享队列拓扑（~530k）慢；一条连接的状态在
  两个 pinned 线程/核之间搬，cache 反而更差。
- GOMAXPROCS 是进程级副作用：默认拓扑下 ≤4 核抬到 4×核数，≥5 核用核数。
  只在默认拓扑（没显式 WithEventLoops/WithParseGoroutines）下发生；调用方
  显式设了 GOMAXPROCS 环境变量也不动。8 核抬到 16/32 会把 Echo 从 1.26M
  打到 1.11M/1.04M。
- **多 worker 并发协议**：一个 shard 的多个 worker 可能并发处理同一条连接。
  busy 被占时先记 pending 再重抢 busy（`markPendingAndRetry`），清 busy 后再
  取一次 pending（`unbusyAndPending`）；OnOpen 必须在 busy 保护下跑。少任何
  一半都会丢 epoll 边缘（表现为高核/多 worker 时连接卡死、TPS 掉到 60k）。

## Worker 池动态扩容（2026-10-19）

- 每个 worker goroutine 记录任务进度；watchdog 每 1ms 检查，单条任务连续
  10ms（显式 per-core）/100ms（默认批量池）没有进展，判定业务回调卡住。
- 慢回调：置慢标志，把当前批次剩余任务拆成 8 条小批重新入队，并按 shard
  上限加**不绑核**扩容 worker（per-core 16/shard，批量池 256/shard）。
- `submit` 不允许阻塞 event loop：队列满时用临时 goroutine 处理该批。
- 正常快业务不会扩容（按“单条任务进度”判断，不按批次时长/队列长度，
  否则低核会被误扩容把 cache 打掉）。
- 内存：batchTask 池归还时清 `*Conn`；批次上限 64；event loop 数封顶 384；
  Worker 默认 epoll 事件数 64。改这些值要重新跑 2/4/8/12 核的
  TPS+MEM A/B（同场交替，环境波动可达 10%+）。
