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

// 自己写的 HTTP/1.x 请求解析（RFC 9112）。
//
// **为什么不用 github.com/antlabs/httparser**（原来用的就是它）：
//
//  1. 它是**回调式**的——每切出一个 token 回调一次，fio 那边再用闭包把
//     回调攒成一个 Request。profile 里 `Execute` 的 57% 其实花在 fio 自己
//     的回调上（`HeaderValue` 2.3%、`HeadersComplete` 1.9%、`URL` 1.1%），
//     这些在"直接填 Request"的写法里全都不存在。
//  2. 它**把整个 buf 里所有流水线请求都解完**（没有"解一条就停"的开关），
//     fio 只能靠 MessageComplete 给的 offset 反推第一条在哪——第二条白解，
//     而且那条路要求每个回调都先判 `if b.owner.done { return }`。
//  3. 每条连接要建一个 `httparser.Setting`（6 个闭包）——实测占
//     limited-conn 堆分配的 5.2%。
//
// profile 的结果：baseline（最"干净"的 h1 档）和 fib 的差距只剩 4.4%，而
// 其中 **3.7% 就是这个解析器自己**（`bytes.IndexAny` 那种逐字符扫集合）。
//
// 这里的做法是**直填 + 解完一条就停**：扫一遍字节把 Request 填好就返回。
//
// 增量契约和以前一样：返回"第一条报文消化了多少"，不够一条就返回已经安全
// 消化的部分（头部没读完时是 0——那半个方法名不能丢）。

// 解析阶段
const (
	stHeader = iota // 还在找头块结束（\r\n\r\n）
	stBody          // 头好了，在收体
)

// chunked 体的子状态
const (
	ckSize     = iota // 读 chunk-size 那一行
	ckData            // 读 chunk-data
	ckDataCRLF        // 读 chunk-data 后面的 CRLF
	ckTrailer         // 读 trailer 段（最后那个 CRLF 之前）
)

// isToken 是不是 RFC 9110 的 tchar。方法名和头名都用它。
func isToken(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// findCRLF 从 b[off:] 里找 CRLF，返回 CR 的位置；没有返回 -1。
//
// 手写扫描而不是 bytes.IndexAny（那是逐字符查集合，实测占 baseline 的
// 0.9%）。这里两个字节一比就能跳过一个 cache line。
func findCRLF(b []byte, off int) int {
	for i := off; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// skipOWS 跳过 OWS（RFC 9110：SP / HTAB）。
func skipOWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	return i
}

// parseRequestLine 解 `方法 SP 目标 SP HTTP/x.y`。
func (p *Parser) parseRequestLine(line []byte) error {
	// 方法
	i := 0
	for i < len(line) && isToken(line[i]) {
		i++
	}
	if i == 0 || i >= len(line) || line[i] != ' ' {
		return ErrBadMessage
	}
	method := string(line[:i])

	i++ // 跳过空格；请求目标里可以有连续空格吗？RFC 9112 3.1 是一段 SP 后跟
	// 目标，多出来的算目标的一部分——但那样目标以空格开头，是畸形。
	start := i
	for i < len(line) && line[i] != ' ' {
		i++
	}
	if i == start || i >= len(line) {
		return ErrBadMessage
	}
	target := string(line[start:i])

	i++
	ver := line[i:]
	if len(ver) != len("HTTP/1.1") || string(ver[:5]) != "HTTP/" {
		return ErrBadMessage
	}
	switch {
	case ver[5] == '1' && ver[6] == '.' && ver[7] == '1':
		p.req.Proto = proto11
	case ver[5] == '1' && ver[6] == '.' && ver[7] == '0':
		p.req.Proto = proto10
	default:
		// 别的版本照收，原样报出去（往下 wantClose 按 1.1 以外关连接处理）
		p.req.Proto = string(ver)
	}
	p.req.Method = method
	p.req.Target = target
	return nil
}

// parseHeaderLine 解一条 `名字: 值`。返回 (名字, 值, 是否合法)。
func parseHeaderLine(line []byte) ([]byte, []byte, bool) {
	i := 0
	for i < len(line) && isToken(line[i]) {
		i++
	}
	if i == 0 || i >= len(line) || line[i] != ':' {
		return nil, nil, false
	}
	name := line[:i]
	v := skipOWS(line, i+1)
	// 值尾部的 OWS 要去掉（RFC 9110 5.5）
	end := len(line)
	for end > v && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	return name, line[v:end], true
}

// parseHeaderBlock 解头块（请求行 + 若干头），填进 p.req。
func (p *Parser) parseHeaderBlock(block []byte) error {
	// 请求行
	cr := indexCRLF(block, 0)
	if cr < 0 {
		return ErrBadMessage
	}
	if err := p.parseRequestLine(block[:cr]); err != nil {
		return err
	}

	seenCL := false
	for off := cr + 2; off < len(block); {
		cr = indexCRLF(block, off)
		if cr < 0 {
			return ErrBadMessage
		}
		if cr == off {
			break // 空行：头块结束
		}
		name, value, ok := parseHeaderLine(block[off:cr])
		if !ok {
			return ErrBadMessage
		}
		// **obsolete line folding 不收**（RFC 9112 5.2：以 SP/HTAB 开头的
		// 行只能出现在被废弃的折行里，服务端遇到要当 400）。parseHeaderLine
		// 已经保证名字是 token，所以这里不用再判。
		if string(name) == "Transfer-Encoding" {
			// chunked 是唯一要求支持的传输编码；带别的（gzip 之类）当 400
			if !equalFoldString(value, "chunked") {
				return ErrBadMessage
			}
			p.chunked = true
			p.chunkState = ckSize
		}
		if string(name) == "Content-Length" {
			// RFC 9112 6.3：有 Transfer-Encoding 就忽略 Content-Length
			if !p.chunked {
				n, err := parseContentLength(value)
				if err != nil {
					return ErrBadMessage
				}
				// 重复且不一致 → 400（RFC 9112 6.3）；一致的话按一个算
				if seenCL && n != p.req.ContentLength {
					return ErrBadMessage
				}
				seenCL = true
				p.req.ContentLength = n
				p.bodyLeft = n
				// 体的大小这里就知道，别让它一路 append 长过去：
				// 100KB 的请求体会把 16K→32K→64K→128K 重分配一遍，
				// 每步都带一次整段 memcpy。一次到位。
				//
				// **看的是 cap 不是 len**：reset 刚把 Body 截成
				// [:0]，看 len 的话条件恒真，每请求都丢热缓冲重分配
				// （实测 8gbit 上占全部堆分配的 96%）。
				// 上限也得有——Content-Length 是对端说的。
				if n > int64(cap(p.req.Body)) && n <= maxPreallocBody {
					p.req.Body = make([]byte, 0, n)
				}
			}
		}
		if string(name) == "Upgrade" {
			p.upgrade = true
		}
		// 同名头用逗号合并（RFC 9110 5.3）
		key := string(name)
		if last, ok := p.req.Header[key]; ok {
			merged := last + ", " + string(value)
			p.req.Header[key] = merged
		} else {
			p.req.Header[key] = string(value)
		}
		off = cr + 2
	}
	if p.chunked {
		// 体在 chunked 那条路上按块收
		p.req.ContentLength = -1
	} else if !seenCL {
		// 没有体的信号：按"没有体"处理（请求里只有 chunked 和
		// Content-Length 两种，都没有就是没有体）
		p.bodyLeft = 0
	}
	return nil
}

// indexCRLF 在 block 里找 CRLF（不跨过 CR 单独出现的那些）。
func indexCRLF(b []byte, off int) int {
	for i := off; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

func equalFoldString(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != s[i] {
			return false
		}
	}
	return true
}

// parseContentLength 解一个十进制长度。**只认十进制**（RFC 9112 6.3），
// 十六进制那种（有些老实现发）不收，免得两种解释打架。
func parseContentLength(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, errors.New("empty content-length")
	}
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, errors.New("bad content-length")
		}
		n = n*10 + int64(c-'0')
		if n > maxPreallocBody*maxContentLengthFactor {
			return 0, errors.New("content-length too large")
		}
	}
	return n, nil
}

// maxContentLengthFactor 是 Content-Length 的上限倍数。
//
// 预分配的上限是 maxPreallocBody（1MB），但**收**的上限得比它高：一个
// 声明 1GB 的请求，服务端不该替它分配，但它真要一字节一字节发过来、
// 我们也真收到了，那就得收。这里给 1024 倍（1GB）——再大就当畸形。
const maxContentLengthFactor = 1024

// parseChunked 按块收体。返回消化了多少（不含调用方已经给过的部分）。
func (p *Parser) parseChunked(buf []byte) (int, error) {
	off := 0
	for {
		switch p.chunkState {
		case ckSize:
			cr := indexCRLF(buf, off)
			if cr < 0 {
				if len(buf)-off > 64 {
					// chunk-size 行不该这么长
					return off, ErrBadMessage
				}
				return off, nil
			}
			size, err := parseChunkSize(buf[off:cr])
			if err != nil {
				return off, err
			}
			off = cr + 2
			if size == 0 {
				p.chunkState = ckTrailer
				continue
			}
			p.chunkLeft = size
			p.chunkState = ckData

		case ckData:
			n := len(buf) - off
			if int64(n) > p.chunkLeft {
				n = int(p.chunkLeft)
			}
			if n > 0 {
				p.req.Body = append(p.req.Body, buf[off:off+n]...)
				off += n
				p.chunkLeft -= int64(n)
			}
			if p.chunkLeft > 0 {
				return off, nil // 这块还没收完
			}
			p.chunkState = ckDataCRLF

		case ckDataCRLF:
			if len(buf)-off < 2 {
				return off, nil
			}
			if buf[off] != '\r' || buf[off+1] != '\n' {
				return off, ErrBadMessage
			}
			off += 2
			p.chunkState = ckSize

		case ckTrailer:
			// trailer 段：若干头（这里丢掉，但要把行吃掉），最后空行结束
			cr := indexCRLF(buf, off)
			if cr < 0 {
				if len(buf)-off > int(p.maxHeaderSize) {
					return off, ErrHeaderTooLarge
				}
				return off, nil
			}
			if cr == off {
				off += 2 // 空行：整条报文结束
				p.done = true
				return off, nil
			}
			off = cr + 2
		}
	}
}

// parseChunkSize 解 `十六进制数 [;扩展]`。
func parseChunkSize(b []byte) (int64, error) {
	i := 0
	var n int64
	for i < len(b) {
		c := b[i]
		var d int64
		switch {
		case '0' <= c && c <= '9':
			d = int64(c - '0')
		case 'a' <= c && c <= 'f':
			d = int64(c-'a') + 10
		case 'A' <= c && c <= 'F':
			d = int64(c-'A') + 10
		default:
			goto ext
		}
		n = n*16 + d
		if n > maxPreallocBody*maxContentLengthFactor {
			return 0, ErrBadMessage
		}
		i++
	}
ext:
	if i == 0 {
		return 0, ErrBadMessage
	}
	if i < len(b) && b[i] != ';' {
		// 十六进制后面只能跟分号（chunk 扩展）
		return 0, ErrBadMessage
	}
	return n, nil
}

// parseHeaderInto 是解析的入口：buf 是"上次没消化的 + 这次新读的"。
//
// 解完第一条就停（这是自己写的主要好处之一，httparser 会把整个 buf 里的
// 都解完）。
func (p *Parser) parseHeaderInto(buf []byte) (int, error) {
	// 头块结束 = CRLF CRLF。先找 '\r' 再确认，比逐字符扫快。
	for i := 0; i < len(buf); {
		j := findCRLF(buf, i)
		if j < 0 {
			break
		}
		if j+2 < len(buf) && buf[j+2] == '\r' && j+3 < len(buf) && buf[j+3] == '\n' {
			// 找到了空行：头块是 buf[:j+2]
			if j+2 > int(p.maxHeaderSize) {
				return 0, ErrHeaderTooLarge
			}
			if err := p.parseHeaderBlock(buf[:j+2]); err != nil {
				return 0, err
			}
			p.state = stBody
			return j + 4, nil
		}
		i = j + 2
	}
	// 头块还没读完。**一个字都不消费**：那半个方法名/半行头不能丢。
	if len(buf) > int(p.maxHeaderSize) {
		return 0, ErrHeaderTooLarge
	}
	return 0, nil
}

// parse 推进一次解析，返回消化了多少字节。
func (p *Parser) parse(buf []byte) (int, error) {
	if p.state == stHeader {
		n, err := p.parseHeaderInto(buf)
		if err != nil {
			return 0, err
		}
		if !p.done && n > 0 {
			// 头好了，接着收体（可能有 0 字节的体）
			m, err := p.parseBody(buf[n:])
			return n + m, err
		}
		return n, nil
	}
	return p.parseBody(buf)
}

// parseBody 收体。返回消化了多少。
func (p *Parser) parseBody(buf []byte) (int, error) {
	if p.chunked {
		n, err := p.parseChunked(buf)
		if err != nil {
			return n, err
		}
		if p.chunkState == ckTrailer && p.done {
			return n, nil
		}
		return n, nil
	}
	// Content-Length（或者没有体）
	if p.bodyLeft <= 0 {
		p.done = true
		return 0, nil
	}
	n := len(buf)
	if int64(n) > p.bodyLeft {
		n = int(p.bodyLeft)
	}
	if n > 0 {
		p.req.Body = append(p.req.Body, buf[:n]...)
		p.bodyLeft -= int64(n)
	}
	if p.bodyLeft <= 0 {
		p.done = true
	}
	return n, nil
}
