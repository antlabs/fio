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

// Package quic 是自建的 QUIC 传输层（RFC 9000/9001），给 http3 用。
//
// **为什么不用 quic-go**：量出来的。baseline-h3 那档，同样 64 连接 × 64 并发流，
// 两边每请求的 CPU：
//
//	fio（quic-go 做传输）  2.66us/请求，10.9/12 核
//	fib（自研 QUIC 栈）    1.67us/请求， 8.5/12 核
//
// 差 37%，而且我们是"跑满核才 4.1M"、fib 是"没跑满就 5.1M"。profile 是平的
// （277 个节点、最大项 12%），成本散在 quic-go 内部：分配里 59% 是
// `quic-go.newStream`（**每个请求建一条流** = send stream + receive stream +
// 两份流控 + frameSorter），再加互斥、framer 记账、QPACK 解头。
// quic-go 的 Config 里没有对应的口子（GSO 是自动探测的，已经在用）。
//
// fib 的路子（它的 http3/quic 也是自研的，go.mod 里没有任何 quic 依赖）值得抄：
// **TLS 握手交给标准库的 crypto/tls.QUICConn**（Go 1.21+ 的 QUIC API，直接给
// 每个加密层的流量密钥），自己只写包层/帧层/流。
//
// 范围（按 HttpArena 的基线-h3/静态-h3 两档压）：
//
//	做：  Initial / Handshake / 1-RTT 三种包、短包头、头保护、AEAD、
//	      CRYPTO / ACK / STREAM / RESET_STREAM / MAX_* / HANDSHAKE_DONE /
//	      CONNECTION_CLOSE、传输参数、**密钥更新**（RFC 9001 6）
//	不做：0-RTT、Retry、连接迁移、拥塞控制（回环上没意义）、
//	      丢包重传（回环不丢；真丢了靠时间兜底，README 里记着）、
//	      发送侧的流控（窗口报得很大，回环上到不了）
//
// 进度（全部完成，验收测试在 handshake_test.go / stream_test.go）：
//
//	[x] keys.go     Initial/Handshake/1-RTT 的密钥派生 + 密钥更新（"quic ku"）
//	[x] packet.go   长短包头、包序号编解码、头保护、AEAD、Key Phase
//	[x] params.go   传输参数的编解码
//	[x] frames.go   帧的编解码（含 ACK 的区间编码）
//	[x] conn.go     连接状态机 + tls.QUICConn 集成（握手、密钥更新、切包）
//	[x] listener.go UDP 监听 + 按连接 ID 分派
//	[x] stream.go   流（收发一个结构体、按 MTU 切块、对端流回收水位）
//	[x] http3 绑定  native.go 整条路都跑在这套传输上（http3/native_test.go
//	                用 quic-go 的 http3 **客户端**打的，是外部验收）
//
// 验收口径：**用 quic-go 当对端**。自己的客户端配自己的服务端，两边错得
// 一样是看不出来的（tls 那边 RSA-PSS 的盐长就这么藏过很久）；quic-go 的
// 客户端是完整的另一份实现，握手/密钥更新/流控/ACK 任何一处对不上都过不去。
//
// 踩过的坑都写在各自的函数注释里，最坑的三个：
//   - 服务端回包的目标连接 ID 必须是客户端的 **SCID**（不是它 Initial 里的 DCID）
//   - **头保护密钥在密钥更新时不换代**（RFC 9001 6），换了之后每个包的首字节
//     都解成乱的
//   - 握手没完就写的 1-RTT 帧**要留在队列里**等密钥，不能丢
package quic
