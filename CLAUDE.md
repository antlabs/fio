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
- 默认 Worker 拓扑（Linux）：≤4 核用 per-core（一个 event loop 对一个 worker，
  loop i/worker i 绑同一个 CPU，GOMAXPROCS 抬到 4×核数）；≥5 核用批量池
  （min(32×核数, 192) 个 loop、核数 个 worker）。改这个拓扑要重跑 2/4/8/12 核 A/B。
- per-core 的 `runtime.GOMAXPROCS(4×核数)` 是进程级副作用；只在默认拓扑
  （没显式 WithEventLoops/WithParseGoroutines）下发生，调用方显式设置则不动。

## Worker 池动态扩容（2026-10-19）

- 每个 worker goroutine 记录任务进度；watchdog 每 1ms 检查，单条任务连续
  10ms（per-core）/100ms（批量池）没有进展，判定业务回调卡住。
- 慢回调：置慢标志，把当前批次剩余任务拆成 8 条小批重新入队，并按 shard
  上限加**不绑核**扩容 worker（per-core 16/shard，批量池 256/shard）。
- `submit` 不允许阻塞 event loop：队列满时用临时 goroutine 处理该批。
- 正常快业务不会扩容（按“单条任务进度”判断，不按批次时长/队列长度，
  否则 2 核 per-core 会被误扩容把 cache 打掉）。
- 内存：batchTask 池归还时清 `*Conn`；批次上限 64；batch Worker 的 loop
  数封顶 192（8/12/16 核都是 192）。改这些值要重新跑 2/4/8/12 核的
  TPS+MEM A/B（同场交替，环境波动可达 10%+）。
