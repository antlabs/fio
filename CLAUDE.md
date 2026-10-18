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
  loop i/worker i 绑同一个 CPU，GOMAXPROCS 抬到 4×核数）；≥8 核用批量池
  （32×核数 个 loop、核数 个 worker）。改这个拓扑要重跑 2/4/8/12 核 A/B。
- per-core 的 `runtime.GOMAXPROCS(4×核数)` 是进程级副作用；只在默认拓扑
  （没显式 WithEventLoops/WithParseGoroutines）下发生，调用方显式设置则不动。
