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

import (
	"strconv"

	"github.com/antlabs/httparser"
)

// Request 是一个解析好的 HTTP/1.1 请求。
//
// 字段是从 httparser 的回调里攒出来的。Method、Target、Proto 这些在
// MessageComplete 之后就不再变，可以直接持有；Body 是攒出来的副本。
type Request struct {
	Method string // "GET"、"POST" ... 原样
	Target string // 请求目标，原样（/path?query、绝对 URI、* 都可能）
	Proto  string // "HTTP/1.1"

	// Header 是头字段，名字保持原样（httparser 回调给什么就是什么）。
	// 查的时候用 Get。
	Header map[string]string

	// Body 是请求体。Content-Length 的和 chunked 的都在这里，已经拼成
	// 完整一块。
	Body []byte

	// ContentLength 是 Content-Length 的值，没有这个头时为 -1。
	ContentLength int64
}

// maxPreallocBody 是"按 Content-Length 预分配"的上限。
//
// Content-Length 是**对端说的**，不能拿来直接当分配依据：声明 1TB 就
// 分配 1TB，是一句话打垮服务端的办法。这个上限之下的才预分配，之上的
// 仍旧走 append 慢慢长（真收到那么多数据时本来也得长，但那需要真的发
// 那么多字节过来）。1MB 覆盖了压测里所有真实场景（8gbit 是 100KB）。
const maxPreallocBody = 1 << 20

// Get 按名字取一个头，大小写无关。
//
// httparser 回调里给的头名是原样的，所以查的时候要逐个比。头一般不到
// 20 个，线性扫比建一个大小写无关的 map 便宜。
func (r *Request) Get(name string) (string, bool) {
	for k, v := range r.Header {
		if equalFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// equalFold 是 ASCII 大小写无关的比较。
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// requestBuilder 把 httparser 的回调攒成一个 Request。
//
// httparser 的回调是按字节流切的（URL 可能回调多次、头名和头值分开回调），
// 所以这里要自己拼。拼的目标是一个 Request，不是把回调原样转出去——
// 调用方拿到的应该是"一个请求"，不是"一串解析事件"。
type requestBuilder struct {
	req *Request

	// 当前正在拼的头。HeaderField 给名字，HeaderValue 给值，中间可能
	// 隔着多次回调。
	curField []byte

	// 解析器的状态由这里回写：MessageComplete 和 ReadyUpgradeData 是
	// "报文结束"的信号，只有回调里才知道。
	owner *Parser
}

func newRequestBuilder(owner *Parser) *requestBuilder {
	return &requestBuilder{
		req: &Request{
			Header:        make(map[string]string, 8),
			ContentLength: -1,
		},
		owner: owner,
	}
}

// reset 复用 builder（keep-alive 的下一个请求）。
func (b *requestBuilder) reset() {
	*b.req = Request{
		Header:        b.req.Header,   // map 留着复用
		Body:          b.req.Body[:0], // 容量留着，和 Header 一个道理
		ContentLength: -1,
	}
	for k := range b.req.Header {
		delete(b.req.Header, k)
	}
	b.curField = b.curField[:0]
}

// setting 返回 httparser 的 Setting，闭包捕获这个 builder。
//
// 每个连接一个 builder，回调里不分配。
func (b *requestBuilder) setting(p *Parser) *httparser.Setting {
	return &httparser.Setting{
		// 注意：**不要**在 MessageBegin 里读 p.Major/p.Minor——那时候还是
		// 0（版本号要等请求行解完才填），写出来是 "HTTP/0.0"。踩过一次：
		// wantClose 按版本判断 keep-alive，proto 永远是 0.0 导致每个请求
		// 都被当成 HTTP/1.0 关连接，pipelining 的响应全丢。
		//
		// 版本在 HeadersComplete 里读（见下面）。

		URL: func(_ *httparser.Parser, buf []byte, _ int) {
			// URL 可能回调多次（分段到的），累加。
			//
			// 但第一条报文完成之后不能再累加：httparser 的 Execute 会把
			// 整个 buf 里的报文一次解完，一个 buf 里有两个请求时，第二个
			// 请求的 URL 回调也会来。不收的话 Target 会变成 "/a/b"
			// （实测）。
			if b.owner.done {
				return
			}
			b.req.Target += string(buf)
		},
		HeaderField: func(_ *httparser.Parser, buf []byte, _ int) {
			if b.owner.done {
				return
			}
			// 头名可能分段，攒着
			b.curField = append(b.curField[:0], buf...)
		},
		HeaderValue: func(_ *httparser.Parser, buf []byte, _ int) {
			if b.owner.done {
				return
			}
			name := string(b.curField)
			if name == "" {
				return
			}
			if last, ok := b.req.Header[name]; ok {
				// 同名头重复出现，用逗号合并（RFC 9110 的规矩）
				b.req.Header[name] = last + ", " + string(buf)
				return
			}
			b.req.Header[name] = string(buf)
		},
		HeadersComplete: func(p *httparser.Parser, _ int) {
			if b.owner.done {
				return
			}
			// 版本到这儿才准（请求行解完才有）
			b.req.Proto = "HTTP/" + strconv.Itoa(int(p.Major)) + "." + strconv.Itoa(int(p.Minor))
			b.req.Method = p.Method.String()
			if cl, ok := b.req.Get("Content-Length"); ok {
				if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
					b.req.ContentLength = n
					// 体的大小这里就知道，别让它一路 append 长过去：
					// 100KB 的请求体会把 16K→32K→64K→128K 重分配一遍，
					// 每步都带一次整段 memcpy。一次到位。
					//
					// 只在比自己现在这块大的时候才动——上限也得有，
					// Content-Length 是对端说的，一个 1TB 的声明不该
					// 变成一次 1TB 的分配。
					if n > int64(len(b.req.Body)) && n <= maxPreallocBody {
						b.req.Body = make([]byte, 0, n)
					}
				}
			}
		},
		Body: func(_ *httparser.Parser, buf []byte, _ int) {
			if b.owner.done {
				return
			}
			b.req.Body = append(b.req.Body, buf...)
		},
		MessageComplete: func(hp *httparser.Parser, offset int) {
			// 报文结束。Upgrade 的报文(websocket 握手)是"请求结束之后
			// 连接上还有别的协议的数据", 所以 upgrade 和 done 分开记。
			//
			// offset 是报文在 buf 里的结束位置——keep-alive 的一个 buf
			// 里可能有多个请求, Execute 会把它们全解完, 所以这个边界
			// 才是调用方要的消化量, 见 Parser.endOffset。
			//
			// 只在第一条上记: 后面那些报文的 offset 会把它覆盖掉, 那样
			// 返回的消化量就成了"整个 buf 解完的位置"。
			if b.owner.done {
				return
			}
			b.owner.done = true
			b.owner.endOffset = offset
			if hp.Upgrade {
				b.owner.upgrade = true
			}
		},
	}
}
