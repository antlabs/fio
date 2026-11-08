# 一致性测试

功能正确性**以协议测试套件为准**——自己写的测试只能验证"我以为要对的东西"，
套件验证的是"规范要求的东西"。这份文档记录跑什么、怎么跑、当前什么结果。

## HTTP/2：h2spec

[h2spec](https://github.com/summerwind/h2spec) 是 HTTP/2 的一致性测试套件，
按 RFC 9113 的章节组织（帧格式、流状态、流控、HPACK……）。

```bash
# 装
go install github.com/summerwind/h2spec/cmd/h2spec@latest

# 起被测服务端（明文 h2c）
go run ./conformance/server -proto=h2c -addr=127.0.0.1:8080
h2spec -h 127.0.0.1 -p 8080

# TLS 上的 h2（ALPN 协商）
go run ./conformance/server -proto=h2 -addr=127.0.0.1:8443
h2spec -h 127.0.0.1 -p 8443 -t -k
```

### 当前结果

| 平台 | 模式 | 结果 |
|---|---|---|
| macOS | **h2c（明文）** | **145 tests, 145 passed, 0 skipped, 0 failed**（h2spec module v2.2.1+incompatible，2026-11-08） |
| **Linux（lab）** | **h2c（明文）** | **145 tests, 145 passed, 0 skipped, 0 failed**（同版本 h2spec，2026-11-08） |
| macOS / Linux | h2 走 TLS | 约 132~137 passed，剩余 3~8 failed（偶发，见下） |

旧版 h2spec 有 5 条 skipped：它判定"不适用"或者拿不到服务端响应体长度。
新版在服务端声明了 `SETTINGS_MAX_CONCURRENT_STREAMS` 之后会实际执行并发流
用例，当前全部通过，所以记录是 0 skipped。

### 已经修掉的

套件从 **1 passed / 144 failed** 一路修到全过，中间修的是这些真问题：

| 问题 | 症状 | 根因 |
|---|---|---|
| 服务端不发 SETTINGS | 144 条全 Timeout | RFC 9113 3.4 要求 SETTINGS 是服务端的**第一个帧**，缺了客户端一直等 |
| 错误级别不分 | 该 RST_STREAM 的回了 GOAWAY（反之亦然） | 流级/连接级错误混用。一个坏请求把整条连接上所有流都杀了 |
| 流状态机没实现 | 一大片流状态用例失败 | idle/half-closed/closed 上收什么帧没检查 |
| 流 ID 奇偶和递增没查 | "even-numbered stream" 用例失败 | 客户端必须用奇数 ID、ID 必须递增 |
| 请求头不校验 | 8.1 那一整节失败 | 伪头齐全性、大小写、connection-specific 头、content-length 一致性 |
| CONTINUATION 可以被打断 | 4.3/6.10 失败 | 头块中间夹别的帧必须报 PROTOCOL_ERROR |
| HPACK 截断没查出 | "Huffman 含 EOS 符号"失败 | x/net 的解码器是流式的，写完后必须 `Close()` 才会报"截断了" |
| 帧格式错回错错误码 | 6.3/6.5/6.7/6.9 失败 | 该回 FRAME_SIZE_ERROR 的回成了 PROTOCOL_ERROR |
| 窗口记账错 | 大 body 卡在 65535 | 收了数据只减窗口不还，一路减到 0 |
| 不主动发 WINDOW_UPDATE | 256KB 请求体卡住 | 收多少要还多少，连接级和流级都要还 |
| 发送侧不做流控 | 大响应对端 GOAWAY | 两个窗口取小的那个，不够的部分要排队 |
| **请求 trailer 没处理** | 4.4 "POST with trailers" Connection closed | 第二个 HEADERS 被当成新请求头校验（缺 :method）；现在按 trailer 处理，只做语法校验、不覆盖 `Stream.headers` |
| **流级错误往上抛** | 一个坏请求杀掉整条连接 | `feed` 把 stream error 返回给 engine，engine 关连接；现在回 RST_STREAM 后继续用连接 |
| **收尾空帧抢跑** | 6.9.2 窗口用例 Timeout/顺序错 | 窗口为 0 时 `WriteData(nil, true)` 绕过 pending body 先发 END_STREAM；现在收尾帧排在 pending 之后 |
| **SETTINGS ACK 顺序** | 6.9.2 "Changes INITIAL_WINDOW_SIZE" Timeout | 窗口变化产生的 DATA 抢在 ACK 前面，客户端等 ACK 时丢弃；现在先 ACK 再续发 |
| **GOAWAY 被 RST 冲掉** | 4.2 超大帧 "connection reset by peer" | 连接级错误后立即 close 会把未读字节变成 RST；现在 GOAWAY 之后延迟 100ms 再关 |
| **并发流不限** | 5.1.2 并发流用例（旧版跳过） | 不声明 `MAX_CONCURRENT_STREAMS`；现在声明 128 并在 `finishHeaders` 强制执行 |

### 还没解决的：TLS 模式的偶发失败

**现象**：同一个用例（比如 `http2/4.1`），十次里挂一两次；换成 h2c 跑
100% 通过。跑十次连同一台服务端，失败数是 0~2 之间随机的。

**已经排除的**：

- 不是 HTTP/2 逻辑——h2c 用同一份代码，全过
- 不是 TLS 状态机——`-race` 下没有数据竞争，握手本身没报错
- 不是 handler 复用——`OnOpen`/`OnClose` 的配对是对的（打过日志验证）
- 不是 fd 复用——fd 被关闭之前内核不会把它分给新连接

**已经修掉的四个真 bug**（都真实存在，肉眼看过、修完有效果）：

| bug | 症状 | 修法 |
|---|---|---|
| `Add` 在 accept 线程同步调 `OnOpen` | 和事件循环抢协议状态，`-race` 必报 | 投到事件循环上跑，加 `activated` 位 |
| `activate` 重入时清掉别人的 busy 位 | 两条 goroutine 同时处理一条连接 | 用 `tryBusy` 的返回值判断"是不是我占的" |
| `ConsumeRead` 立刻把读缓冲区还给池子 | 协议那边还在用那块内存，被别的连接覆盖 | 延迟到下一次 `Read` 再还 |
| **`addWrite` 是空操作** | ET 模式下"早就可写"的 socket 不会有新边缘，缓冲的数据永远发不出去 | 用 `EPOLL_CTL_MOD` 重新注册，强制再触发一次 |

最后一个影响最大、也最隐蔽：它解释了为什么**明文模式几乎全过、TLS 模式
偶发失败**——TLS 多一层加密，写入的时机不同，撞上"缓冲里有数据但
socket 一直可写"这个组合的概率高得多。修完之后 TLS 模式的失败数从
4~7 降到 3~8（有改善但没消除）。

**还没定位的**：剩下的仍然是"服务端该发 GOAWAY 然后关连接"那一类用例，
每次挂的都不一样（说明是竞态不是逻辑错）。

**下一步的查法**：给 `activate` / `processConn` / `Feed` / `closeWith`
四个点加上**带原子序号的日志**，跑一次失败的和一次成功的，对比事件
顺序差异。重点是 `closeWith` 里那次 `flushLocked` 是不是又撞上
EAGAIN（那就还是回到"等可写事件"的老问题，而连接马上就要关了）。

## WebSocket：Autobahn

`autobahn/` 下面是套件的服务端和客户端。跑法见那个目录里的说明。

## gRPC：没有官方套件

gRPC 没有像 h2spec 那样的独立一致性套件。这里的验证靠两层：

- **HTTP/2 层**由 h2spec 保证（gRPC 就是跑在 HTTP/2 上的）
- **gRPC 层**用真实的 `x/net/http2.Transport` 做端到端（见
  `grpc/realclient_test.go`），验证消息分帧、trailer 里的状态、
  流复用

要更强的保证就得引 grpc-go 做客户端——那会带进来一大票依赖，暂时没做。

## TLS：没有独立套件

TLS 1.3 的验证靠**跨实现互操作**：我们的服务端和标准库的 `crypto/tls`
互通、我们的客户端和标准库的服务端互通（`tls/engine_test.go`）。这比
自己测自己强得多——应用密钥派生那个 bug 就是这么发现的（两边错得一样
的时候自测全绿）。

要更严格的话可以用 `openssl s_client` 或者 tlsfuzzer，还没接。
