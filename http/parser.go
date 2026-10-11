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

package http

import "errors"

// Parser 是一条连接上的 HTTP/1.x 请求解析状态。
//
// 解析实现是自己写的（见 parse.go），不再依赖 github.com/antlabs/httparser。
// 对外契约和以前一样：
//
//	var p = NewParser(0)
//	for {
//	    n, err := p.Parse(buf)   // buf 是"上次没消化的 + 这次新读的"
//	    if err != nil { ... }
//	    if p.Done() { req := p.Request(); break }
//	    buf = buf[n:]            // 没消化的留下来，下次接着喂
//	}
//
// **关键**：没消化的字节要留着，不能丢。头块没读完时一个字节都不消费
// （那半个方法名后面没了分隔符就再也拼不起来），调用方每次 buf = buf[n:]，
// 再把新读到的 append 在后面。
//
// 这个包不自己缓冲：攒的活留给调用方（它本来就有那个读缓冲区），这里
// 只推进状态。缓冲整条报文是阻塞式实现的做法，会把事件循环卡住。
//
// 一次 Parse 里最多只出一条报文：Done 之后调用方先取走请求，Reset 再
// 接着喂剩下的（keep-alive 的下一个）。
type Parser struct {
	req Request

	// state 是解析阶段（stHeader / stBody）
	state int

	// bodyLeft 是 Content-Length 还差多少字节
	bodyLeft int64

	// chunked 体：chunked 表示走这条路，chunkState/chunkLeft 是它的进度
	chunked    bool
	chunkState int
	chunkLeft  int64

	// done 是"这条报文解完了"
	done bool

	// upgrade 是报文里有 Upgrade 头（websocket 握手就是这条）
	upgrade bool

	maxHeaderSize int32
}

// DefaultMaxHeaderSize 是没显式设置时的头上限。
//
// 8KB。真实请求头一般不到 4KB，8KB 够用。
const DefaultMaxHeaderSize = 8 * 1024

var (
	// ErrHeaderTooLarge 头超过 maxHeaderSize。调用方该回 431。
	ErrHeaderTooLarge = errors.New("http: header too large")
	// ErrBadMessage 报文不是合法 HTTP/1.x。调用方该回 400。
	ErrBadMessage = errors.New("http: malformed message")
)

// NewParser 建一个请求解析器。maxHeaderSize <= 0 时用 DefaultMaxHeaderSize。
func NewParser(maxHeaderSize int32) *Parser {
	if maxHeaderSize <= 0 {
		maxHeaderSize = DefaultMaxHeaderSize
	}
	p := &Parser{maxHeaderSize: maxHeaderSize}
	p.req.Header = make(map[string]string, 8)
	p.req.ContentLength = -1
	return p
}

// Parse 喂一段字节，返回第一条报文消化了多少。
//
// 返回的 n < len(buf) 说明一条报文已经解完，剩下的字节属于下一个请求
// （keep-alive），调用方自己留着，Reset 之后接着喂。
func (p *Parser) Parse(buf []byte) (int, error) {
	if p.done {
		// 上一条还没被取走，不该继续喂
		return 0, ErrBadMessage
	}
	return p.parse(buf)
}

// Done 这条报文解完了没有。
func (p *Parser) Done() bool { return p.done }

// Upgrade 报文是不是一个 Upgrade 请求（websocket 握手）。
func (p *Parser) Upgrade() bool { return p.upgrade }

// Request 返回解好的请求。没解完时返回 nil。
//
// 返回的 Request 在下一次 Reset 之前一直有效；Body 是攒出来的副本，
// 调用方可以一直拿着。
func (p *Parser) Request() *Request {
	if !p.done {
		return nil
	}
	return &p.req
}

// Reset 准备解析下一个请求（keep-alive）。
func (p *Parser) Reset() {
	r := &p.req
	// clear 是 runtime 内建，比遍历 delete 快（baseline 上实测过）。
	// Header 和 Body 的容量都留着复用。
	header := r.Header
	body := r.Body[:0]
	clear(header)
	*r = Request{
		Header:        header,
		Body:          body,
		ContentLength: -1,
	}
	p.state = stHeader
	p.bodyLeft = 0
	p.chunked = false
	p.chunkState = ckSize
	p.chunkLeft = 0
	p.done = false
	p.upgrade = false
}
