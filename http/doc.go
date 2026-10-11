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

// Package http 是 fio 上的 HTTP/1.1 实现。
//
// 事件循环、连接 io、缓冲区、任务池复用 websocket/ 里的引擎，这个包只负责
// "这些字节是一个 HTTP 请求/响应"。
//
// 报文解析是**自己写的**（见 parse.go）：
//
//   - 增量：数据分几次到就喂几次，头块没读完时一个字节都不消费（那半个
//     方法名不能丢），不用攒够一个完整报文再解
//   - 解完一条就停：keep-alive 的下一个请求留在调用方的缓冲区里，等
//     Reset 之后再喂
//   - 直接填 Request，不走回调——回调式那套（每个 token 一次闭包调用，
//     再在闭包里验收）在 profile 里占了一半以上
//   - 头的上限（maxHeaderSize）自己判，ErrHeaderTooLarge / ErrBadMessage
//     两种错误分开
//   - Upgrade 头自己认（websocket 握手就是升到这个：Parser.Upgrade()）
//
// 规划中的内容：
//
//   - 响应写出：复用引擎的部分写和积攒（写不出去的部分交给可写事件）
//   - keep-alive：一个连接上顺序处理多个请求
//   - 升级：Upgrade() 为真时把连接交给 websocket 包
//
// 还没开始。
package http
