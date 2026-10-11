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

// Request 是一个解析好的 HTTP/1.1 请求。
//
// 字段由 Parser（见 parse.go）直接填好，不是从回调里攒的。Request 在
// 下一次 Reset 之前一直有效；Body 是攒出来的副本。
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
// 报文里的头名是原样的，所以查的时候要逐个比。头一般不到 20 个，线性扫
// 比建一个大小写无关的 map 便宜。
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

// proto11 / proto10 是常见的两个版本号，**常量**——每次拼字符串的话
// 每个请求要两次 strconv.Itoa 加一次拼接。响应行那边（buildHeader）也是
// 拿这两个常量比的，两边是同一份值。
const (
	proto11 = "HTTP/1.1"
	proto10 = "HTTP/1.0"
)
