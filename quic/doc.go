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
//	      CRYPTO / ACK / STREAM / MAX_* / HANDSHAKE_DONE / CONNECTION_CLOSE、
//	      传输参数、基本流控
//	不做：0-RTT、Retry、连接迁移、密钥更新、拥塞控制（回环上没意义）、
//	      丢包重传（回环不丢；真丢了靠时间兜底，README 里记着）
//
// 当前进度：
//
//	[x] keys.go     Initial/Handshake/1-RTT 的密钥派生（RFC 9001 5.1/5.2）
//	[x] packet.go   长短包头、包序号编解码、头保护、AEAD（packet_test.go 往返）
//	[x] params.go   传输参数的编解码
//	[ ] frames.go   帧的编解码
//	[ ] conn.go     连接状态机 + tls.QUICConn 集成（握手）
//	[ ] listener.go UDP 监听 + 按连接 ID 分派
//	[ ] stream.go   流（含发送缓冲/流控/ACK 后的清理）
//	[ ] http3 绑定  让 native.go 能跑在这套传输上（现在收 *quic-go* 的 Listener）
package quic
