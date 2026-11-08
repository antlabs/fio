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

package http2

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/antlabs/fio/http"
)

func collectFrames(t *testing.T, b []byte) []FrameType {
	t.Helper()
	var types []FrameType
	p := NewFrameParser()
	if _, err := p.Parse(b, func(f *Frame) error {
		types = append(types, f.Type)
		return nil
	}); err != nil {
		t.Fatalf("解析输出帧: %v", err)
	}
	return types
}

type frameInfo struct {
	typ     FrameType
	stream  uint32
	end     bool
	payload []byte
}

func collectFrameInfos(t *testing.T, b []byte) []frameInfo {
	t.Helper()
	var out []frameInfo
	p := NewFrameParser()
	if _, err := p.Parse(b, func(f *Frame) error {
		out = append(out, frameInfo{
			typ:     f.Type,
			stream:  f.StreamID,
			end:     f.Flags&FlagDataEndStream != 0 || f.Flags&FlagHeadersEndStream != 0,
			payload: append([]byte(nil), f.Payload...),
		})
		return nil
	}); err != nil {
		t.Fatalf("解析输出帧: %v", err)
	}
	return out
}

// 响应体被流控挡住时，收尾的空 DATA+END_STREAM 必须排在 body 后面，
// 不能先发出去（对端会看到"流结束了"之后又来 body）。
func TestWriteDataEndStreamAfterPending(t *testing.T) {
	c := NewConn(true, nil)
	c.mu.Lock()
	c.peerInitialWindow = 0 // 新流的发送窗口是 0
	c.mu.Unlock()

	if err := c.WriteHeaders(1, []HeaderField{{Name: ":status", Value: "200"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteData(1, []byte("body"), false); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteData(1, nil, true); err != nil {
		t.Fatal(err)
	}

	for _, f := range collectFrameInfos(t, c.TakeOutput()) {
		if f.typ == FrameData {
			t.Fatalf("流窗口为 0 时不该发 DATA: %+v", f)
		}
	}

	// 把流窗口打开：body 和收尾空帧按顺序出去。
	// Feed 会直接把这一轮产生的输出交出来。
	_, out, err := c.Feed(AppendWindowUpdate(nil, 1, 100))
	if err != nil {
		t.Fatal(err)
	}
	var data []frameInfo
	for _, f := range collectFrameInfos(t, out) {
		if f.typ == FrameData {
			data = append(data, f)
		}
	}
	if len(data) != 2 {
		t.Fatalf("DATA 帧数 = %d, want 2（body + 空 END_STREAM）", len(data))
	}
	if string(data[0].payload) != "body" || data[0].end {
		t.Errorf("第一帧 = %q end=%v, want body 且不带 END_STREAM", data[0].payload, data[0].end)
	}
	if len(data[1].payload) != 0 || !data[1].end {
		t.Errorf("第二帧 = %q end=%v, want 空帧且带 END_STREAM", data[1].payload, data[1].end)
	}
}

func hasFrame(types []FrameType, want FrameType) bool {
	for _, typ := range types {
		if typ == want {
			return true
		}
	}
	return false
}

func firstRSTCode(t *testing.T, b []byte) ErrCode {
	t.Helper()
	var code ErrCode
	found := false
	p := NewFrameParser()
	if _, err := p.Parse(b, func(f *Frame) error {
		if f.Type == FrameRSTStream && len(f.Payload) >= 4 && !found {
			code = ErrCode(binary.BigEndian.Uint32(f.Payload))
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("解析输出帧: %v", err)
	}
	if !found {
		t.Fatal("输出里没有 RST_STREAM")
	}
	return code
}

// 流级错误只回 RST_STREAM，不能把整条连接的错误往上抛（engine 会把
// 连接关掉，一个坏请求杀掉同一条连接上所有正常请求）。
func TestStreamErrorDoesNotKillConn(t *testing.T) {
	rec := &recorder{}
	srv := NewConn(false, rec)
	if _, _, err := srv.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}

	cli := NewConn(true, nil)
	// 缺 :path → 流级 PROTOCOL_ERROR
	bad := cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
	}, true)
	_, out, err := srv.Feed(bad)
	if err != nil {
		t.Fatalf("流级错误不该往上抛: %v", err)
	}
	if !hasFrame(collectFrames(t, out), FrameRSTStream) {
		t.Fatal("输出里没有 RST_STREAM")
	}

	// 连接还能继续用
	good := cli.MustHeaders(3, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/ok"},
	}, true)
	if _, _, err := srv.Feed(good); err != nil {
		t.Fatalf("后续正常请求失败: %v", err)
	}
	if len(rec.headers) != 1 {
		t.Fatalf("正常请求的 OnHeaders 次数 = %d, want 1", len(rec.headers))
	}
}

// 超过声明的并发流上限：新流 REFUSED_STREAM，已有的流不受影响。
func TestMaxConcurrentStreams(t *testing.T) {
	rec := &recorder{}
	srv := NewConn(false, rec)
	srv.localMaxStreams = 1
	if _, _, err := srv.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}

	cli := NewConn(true, nil)
	fields := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
	}
	if _, _, err := srv.Feed(cli.MustHeaders(1, fields, true)); err != nil {
		t.Fatal(err)
	}

	// 流 1 还没被服务端回完（还在表里），流 3 应该被拒。
	_, out, err := srv.Feed(cli.MustHeaders(3, fields, true))
	if err != nil {
		t.Fatalf("REFUSED_STREAM 不该往上抛: %v", err)
	}
	if code := firstRSTCode(t, out); code != ErrCodeRefusedStream {
		t.Errorf("RST code = %v, want REFUSED_STREAM", code)
	}
	if len(rec.headers) != 1 {
		t.Errorf("被拒的流不该进 handler, OnHeaders 次数 = %d", len(rec.headers))
	}
}

func newTestBridge(t *testing.T, maxHeader int, maxBody int64, called *int) (*httpBridge, *Conn) {
	t.Helper()
	b := &httpBridge{
		h: http.HandlerFunc(func(c *http.Ctx) error {
			*called++
			return c.String("ok")
		}),
		maxHeaderSize: maxHeader,
		maxBodySize:   maxBody,
		streams:       make(map[uint32]*streamReq),
	}
	srv := NewConn(false, b)
	if _, _, err := srv.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}
	return b, srv
}

// 头太大：OnHeaders 阶段就回 431，不建请求、不收 body。
func TestBridgeHeaderTooLarge(t *testing.T) {
	var called int
	_, srv := newTestBridge(t, 100, defMaxBodySize, &called)

	cliRec := &recorder{}
	cli := NewConn(true, cliRec)
	in := cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
		{Name: "x-big", Value: strings.Repeat("a", 200)},
	}, true)
	_, out, err := srv.Feed(in)
	if err != nil {
		t.Fatal(err)
	}
	if called != 0 {
		t.Fatalf("handler 被调用了 %d 次, want 0", called)
	}
	if _, _, err := cli.Feed(out); err != nil {
		t.Fatal(err)
	}
	if len(cliRec.headers) != 1 || cliRec.headers[0].fields[0].Value != "431" {
		t.Fatalf("响应 = %v, want :status 431", cliRec.headers)
	}
}

// Content-Length 超限：**只看头就回 413**，不等 body 到达。
func TestBridgeBodyTooLargeByContentLength(t *testing.T) {
	var called int
	_, srv := newTestBridge(t, defMaxHeaderSize, 4, &called)

	cliRec := &recorder{}
	cli := NewConn(true, cliRec)
	// 故意不带 END_STREAM、不发 DATA：应该在 OnHeaders 阶段就被拒。
	in := cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
		{Name: "content-length", Value: "8"},
	}, false)
	_, out, err := srv.Feed(in)
	if err != nil {
		t.Fatal(err)
	}
	if called != 0 {
		t.Fatalf("handler 被调用了 %d 次, want 0", called)
	}
	if _, _, err := cli.Feed(out); err != nil {
		t.Fatal(err)
	}
	if len(cliRec.headers) != 1 || cliRec.headers[0].fields[0].Value != "413" {
		t.Fatalf("响应 = %v, want :status 413", cliRec.headers)
	}
}

// 没有 Content-Length 的请求：OnData 累计超限也回 413。
func TestBridgeBodyTooLargeByData(t *testing.T) {
	var called int
	_, srv := newTestBridge(t, defMaxHeaderSize, 4, &called)

	cliRec := &recorder{}
	cli := NewConn(true, cliRec)
	in := cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
	}, false)
	in = append(in, AppendData(nil, 1, []byte("12345678"), true)...)
	_, out, err := srv.Feed(in)
	if err != nil {
		t.Fatal(err)
	}
	if called != 0 {
		t.Fatalf("handler 被调用了 %d 次, want 0", called)
	}
	if _, _, err := cli.Feed(out); err != nil {
		t.Fatal(err)
	}
	if len(cliRec.headers) != 1 || cliRec.headers[0].fields[0].Value != "413" {
		t.Fatalf("响应 = %v, want :status 413", cliRec.headers)
	}
}

// 收到对端 GOAWAY 之后还要能回 PING（RFC 9113 6.8；h2spec 3.8）。
func TestGoAwayReceivedStillPing(t *testing.T) {
	srv := NewConn(false, &recorder{})
	if _, _, err := srv.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.Feed(AppendGoAway(nil, 0, uint32(ErrCodeNo), nil)); err != nil {
		t.Fatal(err)
	}
	_, out, err := srv.Feed(AppendPing(nil, [8]byte{'1', '2', '3', '4', '5', '6', '7', '8'}, false))
	if err != nil {
		t.Fatal(err)
	}

	acked := false
	p := NewFrameParser()
	if _, err := p.Parse(out, func(f *Frame) error {
		if f.Type == FramePing && f.Flags&FlagPingAck != 0 {
			acked = true
		}
		return nil
	}); err != nil {
		t.Fatalf("解析输出: %v", err)
	}
	if !acked {
		t.Fatal("收到 GOAWAY 之后的 PING 没有回 ACK")
	}
}

// 被 431 拒掉的流后面再来 trailer：不能当成一个新请求交给 handler，
// 流结束之后表项要清掉。
func TestBridgeRejectedStreamIgnoresTrailer(t *testing.T) {
	var called int
	b, srv := newTestBridge(t, 100, defMaxBodySize, &called)

	cli := NewConn(true, nil)
	if _, _, err := srv.Feed(cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
		{Name: "x-big", Value: strings.Repeat("a", 200)},
	}, false)); err != nil {
		t.Fatal(err)
	}
	if b.streams[1] != rejectedStreamReq {
		t.Fatalf("被拒的流没有占位: %v", b.streams[1])
	}

	if _, _, err := srv.Feed(cli.MustHeaders(1, []HeaderField{
		{Name: "x-trailer", Value: "v"},
	}, true)); err != nil {
		t.Fatal(err)
	}
	if called != 0 {
		t.Fatalf("被拒的流不该进 handler, 调用 %d 次", called)
	}
	if _, ok := b.streams[1]; ok {
		t.Fatal("流结束后占位没清掉")
	}
}

// 被 431 拒掉的流后面再来 DATA：同样忽略，END_STREAM 时清表。
func TestBridgeRejectedStreamIgnoresData(t *testing.T) {
	var called int
	b, srv := newTestBridge(t, 100, defMaxBodySize, &called)

	cli := NewConn(true, nil)
	if _, _, err := srv.Feed(cli.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
		{Name: "x-big", Value: strings.Repeat("a", 200)},
	}, false)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.Feed(AppendData(nil, 1, []byte("body"), true)); err != nil {
		t.Fatal(err)
	}
	if called != 0 {
		t.Fatalf("被拒的流不该进 handler, 调用 %d 次", called)
	}
	if _, ok := b.streams[1]; ok {
		t.Fatal("流结束后占位没清掉")
	}
}

// body 按 Content-Length 预分配，且 h2 的小写头名要能认出来。
func TestBridgeBodyPrealloc(t *testing.T) {
	const n = 1000
	b := &httpBridge{
		maxHeaderSize: defMaxHeaderSize,
		maxBodySize:   defMaxBodySize,
		streams:       make(map[uint32]*streamReq),
	}
	c := NewConn(false, nil)
	b.OnHeaders(c, 1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/upload"},
		{Name: "content-length", Value: "1000"},
	}, false)

	s := b.streams[1]
	if s == nil {
		t.Fatal("streamReq 没建出来")
	}
	if s.contentLen != n {
		t.Fatalf("contentLen = %d, want %d（h2 头名是小写）", s.contentLen, n)
	}
	if cap(s.body) != n {
		t.Fatalf("body cap = %d, want %d（应该按 Content-Length 预分配）", cap(s.body), n)
	}
}

// 连续两个请求：header map / body / writer 的 header map 都要清干净，
// 不能串到下一个请求。
func TestBridgeSequentialRequests(t *testing.T) {
	type snap struct {
		method, path string
		header       map[string]string
		body         []byte
	}
	var got []snap

	b := &httpBridge{
		h: http.HandlerFunc(func(c *http.Ctx) error {
			r := c.Request()
			h := make(map[string]string, len(r.Header))
			for k, v := range r.Header {
				h[k] = v
			}
			got = append(got, snap{
				method: r.Method,
				path:   r.Target,
				header: h,
				body:   append([]byte(nil), r.Body...),
			})
			c.Set("x-req", r.Header["x-seq"])
			return c.String("ok")
		}),
		maxHeaderSize: defMaxHeaderSize,
		maxBodySize:   defMaxBodySize,
		streams:       make(map[uint32]*streamReq),
	}
	srv := NewConn(false, b)
	if _, _, err := srv.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}

	cliRec := &recorder{}
	cli := NewConn(true, cliRec)
	seqs := []string{"one", "two"}
	for i, seq := range seqs {
		sid := uint32(2*i + 1)
		in := cli.MustHeaders(sid, []HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/" + seq},
			{Name: "x-seq", Value: seq},
		}, false)
		in = append(in, AppendData(nil, sid, []byte(seq), true)...)
		_, out, err := srv.Feed(in)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := cli.Feed(out); err != nil {
			t.Fatal(err)
		}
	}

	if len(got) != 2 {
		t.Fatalf("handler 调用 %d 次, want 2", len(got))
	}
	for i, seq := range seqs {
		if got[i].header["x-seq"] != seq {
			t.Errorf("第 %d 个请求 x-seq = %q, want %q", i, got[i].header["x-seq"], seq)
		}
		if string(got[i].body) != seq {
			t.Errorf("第 %d 个请求 body = %q, want %q", i, got[i].body, seq)
		}
		if got[i].path != "/"+seq {
			t.Errorf("第 %d 个请求 path = %q", i, got[i].path)
		}
	}
	// 响应头也不能串：第一个响应的 x-req 不能出现在第二个响应里。
	if len(cliRec.headers) != 2 {
		t.Fatalf("客户端收到 %d 个 HEADERS, want 2", len(cliRec.headers))
	}
	for i, seq := range seqs {
		var xreq string
		for _, f := range cliRec.headers[i].fields {
			if f.Name == "x-req" {
				xreq = f.Value
			}
		}
		if xreq != seq {
			t.Errorf("第 %d 个响应 x-req = %q, want %q（header map 没复用干净）", i, xreq, seq)
		}
	}
}
