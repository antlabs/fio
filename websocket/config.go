// Copyright 2023-2024 antlabs. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package websocket

import (
	"log/slog"
	"time"

	"github.com/antlabs/wsutil/deflate"
)

// Config 配置
// 有两种方式可以配置相关值
// 1. NewUpgrade, 这通常在只初始化一次的时候使用
// 2. fio.Upgrade(), 这通常在每次请求的时候使用，每个语法的配置参数不一样
// 这样可以方便的在两种方式中使用, 不需要担心配置参数会有并发修改的情况
type Config struct {
	cb                              Callback          // 静态配置
	deflate.PermessageDeflateConf                     // 静态配置, 从WithXXX函数中获取
	tcpNoDelay                      bool              // TODO: 加下这个功能
	replyPing                       bool              // 开启自动回复
	ignorePong                      bool              // 忽略pong消息
	disableBufioClearHack           bool              // 关闭bufio的clear hack优化
	utf8Check                       func([]byte) bool // utf8检查
	readTimeout                     time.Duration     // 加下这个功能
	windowsMultipleTimesPayloadSize float32           // 设置几倍(1024+14)的payload大小
	maxDelayWriteNum                int32             // 最大延迟包的个数, 默认值为10
	delayWriteInitBufferSize        int32             // 延迟写入的初始缓冲区大小, 默认值是8k
	maxDelayWriteDuration           time.Duration     // 最大延迟时间, 默认值是10ms
	subProtocols                    []string          // 设置支持的子协议
	multiEventLoop                  *MultiEventLoop   // 事件循环(engine 的 + websocket 的诊断接口)
	runInGoTask                     string            // 运行业务OnMessage的策略, 现在fio集成三种OnMessage运行模式，分别是io, task
	readMaxMessage                  int64             // 最大消息大小
	flowBackPressureRemoveRead      bool              // 流控背压机制，移除读事件
	zeroCopyPayload                 bool              // payload 直接指向读缓冲区, 见 WithServerZeroCopyPayload
	// engineMode 表示这条连接挂在 engine 的事件循环上。
	//
	// engine 的事件循环一次只有一个 goroutine 碰这条连接, 回调就地执行
	// 就够, 不用再往协程池投一层。所以 engineMode 下 runInGoTask 默认是
	// "io"(就地执行)。
	engineMode bool         // 是否使用 engine 事件循环
	logger     *slog.Logger // 连接日志器, 没配用 slog.Default()
}

// func (c *Config) useIoUring() bool {
// 	return c.multiEventLoop.flag == EVENT_IOURING
// }

// 默认设置
func (c *Config) defaultSetting() {
	c.cb = &DefCallback{}
	c.maxDelayWriteNum = 10
	// 2.0 而不是 1.0: 读缓冲区按上一条消息的 payload 长度算, 1.0 时
	// 正好贴着消息大小, 帧头一多就要扩容; 2.0 留出一倍余量。
	// 多出来的内存只在每个连接的一块缓冲区上, 不随消息数增长。
	c.windowsMultipleTimesPayloadSize = 2.0
	c.delayWriteInitBufferSize = 8 * 1024
	c.maxDelayWriteDuration = 10 * time.Millisecond
	// c.runInGoStrategy = taskStrategyBind
	c.tcpNoDelay = true
	// 对于text消息，默认不检查text是utf8字符
	c.utf8Check = func(b []byte) bool { return true }
	// 回调默认就地执行: engine 的事件循环一次只有一个 goroutine 碰这条
	// 连接, 解析和回调都在它上面跑就够了, 不用再往协程池投一层。多投一次
	// 就是白排一次队, 实测(12 核 1KB echo)从 165 万掉到 22 万 TPS。
	c.runInGoTask = "io"
}

func (c *Config) defaultSettingAfter() {
	if c.multiEventLoop == nil {
		c.multiEventLoop = getDefaultMultiEventLoop()
	}
	c.multiEventLoop.Start()
}
