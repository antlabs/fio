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
	"bytes"
	"strings"
	"sync"
	"testing"
)

// recorder 收流事件。
//
// 这个结构体本身**不加锁**——包里的测试都是单 goroutine 跑的（手工喂
// Feed），不需要。跑在 engine 上的测试用 syncRecorder（回调在事件循环
// 的 goroutine 上，和在测试 goroutine 上读它的代码是两个 goroutine）。
type recorder struct {
	headers []struct {
		streamID  uint32
		fields    []HeaderField
		endStream bool
	}
	data    []byte
	rst     uint32
	rstCode ErrCode
}

func (r *recorder) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	r.headers = append(r.headers, struct {
		streamID  uint32
		fields    []HeaderField
		endStream bool
	}{streamID, append([]HeaderField(nil), headers...), endStream})
}

func (r *recorder) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {
	r.data = append(r.data, data...)
}

func (r *recorder) OnRSTStream(c *Conn, streamID uint32, code ErrCode) {
	r.rst = streamID
	r.rstCode = code
}

// syncRecorder 是 recorder 的加锁版，给跑在 engine 上的测试用。
//
// 事件循环的 goroutine 调回调，测试 goroutine 读——不加锁 -race 必报。
// 真实的 StreamHandler 实现也该这么写。
type syncRecorder struct {
	mu      sync.Mutex
	headers []struct {
		streamID  uint32
		fields    []HeaderField
		endStream bool
	}
	data []byte
}

func (r *syncRecorder) OnHeaders(c *Conn, streamID uint32, headers []HeaderField, endStream bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.headers = append(r.headers, struct {
		streamID  uint32
		fields    []HeaderField
		endStream bool
	}{streamID, append([]HeaderField(nil), headers...), endStream})
}

func (r *syncRecorder) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data = append(r.data, data...)
}

func (r *syncRecorder) OnRSTStream(c *Conn, streamID uint32, code ErrCode) {}

func (r *syncRecorder) headerCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.headers)
}

func (r *syncRecorder) headerAt(i int) (uint32, []HeaderField) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.headers) {
		return 0, nil
	}
	return r.headers[i].streamID, r.headers[i].fields
}

// 完整走一遍：客户端发请求头 + 数据，服务端解出来。
func TestRequestResponse(t *testing.T) {
	srvRec := &recorder{}
	cliRec := &recorder{}
	server := NewConn(false, srvRec)
	client := NewConn(true, cliRec)

	// 服务端等序言，所以客户端要先发序言 + SETTINGS
	clientOut := append([]byte(nil), clientPreface...)
	clientOut = AppendSettings(clientOut, [2]uint32{0x3, 100})
	clientOut = append(clientOut, client.MustHeaders(1,
		[]HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":path", Value: "/echo"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
			{Name: "content-type", Value: "application/grpc"},
		}, false)...)

	// 服务端收
	_, out, err := server.Feed(clientOut)
	if err != nil {
		t.Fatalf("服务端 Feed: %v", err)
	}
	// 收到的应该有一个 SETTINGS ACK
	if !bytes.Contains(out, []byte{0, 0, 0, byte(FrameSettings), FlagSettingsAck, 0, 0, 0, 0}) {
		t.Error("服务端没有回 SETTINGS ACK")
	}

	if len(srvRec.headers) != 1 {
		t.Fatalf("服务端收到 %d 个 HEADERS, want 1", len(srvRec.headers))
	}
	h := srvRec.headers[0]
	if h.streamID != 1 {
		t.Errorf("流 ID = %d, want 1", h.streamID)
	}
	want := map[string]string{
		":method":      "POST",
		":path":        "/echo",
		":scheme":      "https",
		":authority":   "example.com",
		"content-type": "application/grpc",
	}
	got := map[string]string{}
	for _, f := range h.fields {
		got[f.Name] = f.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	// 客户端发数据
	dataOut := client.MustData(1, []byte("hello grpc"), true)
	if _, _, err := server.Feed(dataOut); err != nil {
		t.Fatalf("服务端 Feed 数据: %v", err)
	}
	if string(srvRec.data) != "hello grpc" {
		t.Errorf("服务端收到数据 %q, want %q", srvRec.data, "hello grpc")
	}
}

// 服务端回响应，客户端解出来。
func TestResponse(t *testing.T) {
	cliRec := &recorder{}
	server := NewConn(false, &recorder{})
	client := NewConn(true, cliRec)

	// 先把序言喂了，让服务端进入正常状态
	if _, _, err := server.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}

	// **客户端先开流 1**（发请求），服务端才有得回。
	//
	// 流 ID 是"谁开的谁那侧管"：客户端开的流，服务端只能在上面回响应。
	// 直接给客户端发一个它没开过的流上的 HEADERS，是"服务端开了个奇数
	// 流"——协议上的连接级错误（RFC 9113 5.1.1）。
	if _, _, err := server.Feed(client.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/svc/method"},
	}, false)); err != nil {
		t.Fatalf("服务端收请求头: %v", err)
	}

	// 服务端发响应头 + 数据
	out := server.MustHeaders(1, []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/grpc"},
	}, false)
	out = AppendData(out, 1, []byte("response body"), true)

	if _, _, err := client.Feed(out); err != nil {
		t.Fatalf("客户端 Feed: %v", err)
	}
	if len(cliRec.headers) != 1 {
		t.Fatalf("客户端收到 %d 个 HEADERS, want 1", len(cliRec.headers))
	}
	if cliRec.headers[0].fields[0].Name != ":status" ||
		cliRec.headers[0].fields[0].Value != "200" {
		t.Errorf(":status = %v", cliRec.headers[0].fields[0])
	}
	if string(cliRec.data) != "response body" {
		t.Errorf("数据 = %q", cliRec.data)
	}
}

// PING 要回 PING ACK（原样带上 8 字节）。
func TestPing(t *testing.T) {
	server := NewConn(false, &recorder{})
	if _, _, err := server.Feed(clientPreface); err != nil {
		t.Fatal(err)
	}

	var payload [8]byte
	copy(payload[:], "12345678")
	_, out, err := server.Feed(AppendPing(nil, payload, false))
	if err != nil {
		t.Fatal(err)
	}

	// 回的应该是一个 PING ACK
	p := NewFrameParser()
	var frames []Frame
	p.Parse(out, func(f *Frame) error {
		frames = append(frames, Frame{Type: f.Type, Flags: f.Flags,
			Payload: append([]byte(nil), f.Payload...)})
		return nil
	})
	if len(frames) != 1 {
		t.Fatalf("回了 %d 个帧, want 1", len(frames))
	}
	if frames[0].Type != FramePing || frames[0].Flags&FlagPingAck == 0 {
		t.Errorf("回的不是 PING ACK: %v flags=%#x", frames[0].Type, frames[0].Flags)
	}
	if string(frames[0].Payload) != "12345678" {
		t.Errorf("ACK 载荷 = %q, want 12345678", frames[0].Payload)
	}
}

// 客户端序言不对要拒绝（这是 HTTP/2 连接的敲门砖）。
func TestBadPreface(t *testing.T) {
	server := NewConn(false, &recorder{})
	// GET / HTTP/1.1 是 HTTP/1.1 的请求，不是 HTTP/2 序言
	_, _, err := server.Feed([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err == nil {
		t.Fatal("错误的序言应该被拒绝")
	}
	if !strings.Contains(err.Error(), "preface") {
		t.Errorf("错误信息该提到 preface: %v", err)
	}
}

// GOAWAY 之后连接标记成关闭。
func TestGoAway(t *testing.T) {
	server := NewConn(false, &recorder{})
	server.Feed(clientPreface)

	if _, _, err := server.Feed(AppendGoAway(nil, 3, uint32(ErrCodeEnhanceCalm), []byte("slow down"))); err != nil {
		t.Fatal(err)
	}
	if !server.GoAway() {
		t.Error("收到 GOAWAY 之后 GoAway() 应该是 true")
	}
	if server.GoAwayCode() != ErrCodeEnhanceCalm {
		t.Errorf("GOAWAY 码 = %v, want ENHANCE_YOUR_CALM", server.GoAwayCode())
	}
}

// RST_STREAM 要通知到流处理者，并且把流删掉。
func TestRSTStream(t *testing.T) {
	rec := &recorder{}
	server := NewConn(false, rec)
	server.Feed(clientPreface)

	// 先建一个流（头要合法：:method/:scheme/:path 一个都不能少）
	server.Feed(server.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/"},
	}, false))
	if server.GetStream(1) == nil {
		t.Fatal("流 1 没建起来")
	}

	if _, _, err := server.Feed(AppendRSTStream(nil, 1, uint32(ErrCodeCancel))); err != nil {
		t.Fatal(err)
	}
	if rec.rst != 1 || rec.rstCode != ErrCodeCancel {
		t.Errorf("RST 通知 = %d/%v", rec.rst, rec.rstCode)
	}
	if server.GetStream(1) != nil {
		t.Error("RST 之后流应该被删掉")
	}
}

// 头块被拆成 HEADERS + CONTINUATION 时要能拼回来。
func TestContinuationRoundTrip(t *testing.T) {
	rec := &recorder{}
	server := NewConn(false, rec)
	server.Feed(clientPreface)

	// 用较小的分片上限，逼它拆
	server.peerMaxFrameSize = 64

	fields := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/a/very/long/path/that/will/not/fit/in/one/frame"},
		{Name: "user-agent", Value: "fio-test/1.0 (this is a long user agent string)"},
	}
	block, err := server.encoder.Encode(fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(block) <= 64 {
		t.Fatalf("头块只有 %d 字节, 没触发拆分(要 > 64)", len(block))
	}

	var buf []byte
	if err := server.writeHeaderBlock(1, block, false); err != nil {
		t.Fatal(err)
	}
	buf = server.TakeOutput()

	// 切一下看看是不是 HEADERS + CONTINUATION
	p := NewFrameParser()
	var types []FrameType
	p.Parse(buf, func(f *Frame) error {
		types = append(types, f.Type)
		return nil
	})
	if len(types) < 2 || types[0] != FrameHeaders || types[1] != FrameContinuation {
		t.Fatalf("帧序列 = %v, want HEADERS + CONTINUATION...", types)
	}

	// 喂回去，头要能解出来
	if _, _, err := server.Feed(buf); err != nil {
		t.Fatal(err)
	}
	if len(rec.headers) != 1 {
		t.Fatalf("收到 %d 个 HEADERS", len(rec.headers))
	}
	got := map[string]string{}
	for _, f := range rec.headers[0].fields {
		got[f.Name] = f.Value
	}
	for _, f := range fields {
		if got[f.Name] != f.Value {
			t.Errorf("%s = %q, want %q", f.Name, got[f.Name], f.Value)
		}
	}
}

// DATA 被拆成多帧时，末端才带 END_STREAM。
func TestDataSplit(t *testing.T) {
	rec := &recorder{}
	server := NewConn(false, rec)
	server.Feed(clientPreface)
	server.Feed(server.MustHeaders(1, []HeaderField{{Name: ":method", Value: "POST"}}, false))

	server.peerMaxFrameSize = 1024
	payload := bytes.Repeat([]byte("x"), 5000)
	if err := server.WriteData(1, payload, true); err != nil {
		t.Fatal(err)
	}
	out := server.TakeOutput()

	p := NewFrameParser()
	var lastEnd bool
	var n int
	var got []byte
	p.Parse(out, func(f *Frame) error {
		n++
		lastEnd = f.EndStream()
		got = append(got, f.Payload...)
		return nil
	})
	if n < 2 {
		t.Fatalf("切出 %d 个 DATA 帧, 应该拆成多个", n)
	}
	if !lastEnd {
		t.Error("最后一帧应该带 END_STREAM")
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("拼回来的数据不对: %d 字节 vs %d", len(got), len(payload))
	}
}

// 序言和它后面跟着的帧被切开喂进来时，**解析器没吃完的半个帧不能算成
// 已消费**——算错了引擎就把那几个字节丢掉，下一次从帧中间开始解析。
//
// 实测症状（真实客户端发 256KB 请求体时偶发）：服务端把 body 里的
// 'x'（0x78）读成帧长，报 "frame exceeds max size: 7895160 > 16384"，
// 自己发 GOAWAY 把连接断了——7895160 就是 'xxx' 那三个字节。
func TestPrefaceWithPartialFrame(t *testing.T) {
	server := NewConn(false, &recorder{})

	// 序言之后跟一个 SETTINGS 帧，切在帧头中间
	stream := append([]byte(nil), clientPreface...)
	stream = AppendSettings(stream, [2]uint32{0x3, 100})
	cut := len(clientPreface) + 4

	n1, _, err := server.Feed(stream[:cut])
	if err != nil {
		t.Fatalf("第一次 Feed: %v", err)
	}
	if n1 != len(clientPreface) {
		t.Errorf("第一次 Feed 消费 %d 字节, want %d（后面 %d 字节是半截帧头，得留给下一次）",
			n1, len(clientPreface), cut-len(clientPreface))
	}

	// 第二次喂的是**引擎真正会喂的那段**：上一次没消费的尾巴（n1 之后）
	n2, _, err := server.Feed(stream[n1:])
	if err != nil {
		t.Fatalf("第二次 Feed: %v（半截帧被上一次吞掉的话，这里会从帧中间解析）", err)
	}
	if n1+n2 != len(stream) {
		t.Errorf("两次一共消费 %d 字节, want %d", n1+n2, len(stream))
	}
}

// 发送侧流控（确定性版本，不依赖网络时序）。
//
// 对端把 INITIAL_WINDOW_SIZE 声明成 20 字节：发 100 字节时只能先发 20，
// 其余排队；每收到一次 WINDOW_UPDATE 就续发一段，最后一帧必须带
// END_STREAM。多发一个字节对端就会判流控违规、整条连接断掉。
func TestSendFlowControlWindow(t *testing.T) {
	server := NewConn(false, &recorder{})

	// 序言 + 客户端 SETTINGS（流窗口 20）+ 一个 GET
	client := NewConn(true, &recorder{})
	in := append([]byte(nil), clientPreface...)
	in = AppendSettings(in, [2]uint32{0x4, 20}) // INITIAL_WINDOW_SIZE
	in = append(in, client.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/big"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "x"},
	}, true)...)
	if _, _, err := server.Feed(in); err != nil {
		t.Fatalf("Feed 请求: %v", err)
	}
	if err := server.WriteData(1, make([]byte, 100), true); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	// 数一数服务端吐出来的 DATA 帧
	dataFrames := func(t *testing.T, out []byte) (sent int, lastEnd bool, n int) {
		t.Helper()
		p := NewFrameParser()
		if _, err := p.Parse(out, func(f *Frame) error {
			if f.Type == FrameData {
				sent += len(f.Payload)
				lastEnd = f.EndStream()
				n++
			}
			return nil
		}); err != nil {
			t.Fatalf("解析服务端输出: %v", err)
		}
		return
	}

	got, lastEnd, _ := dataFrames(t, server.takeOutput())
	if got != 20 {
		t.Fatalf("窗口 20 时先发了 %d 字节, want 20（多了就是对端会判违规）", got)
	}
	if lastEnd {
		t.Error("还没发完就带了 END_STREAM")
	}

	// 续 30：应该再发 30（Feed 自己会把输出交出来，takeOutput 拿不到）
	_, out, err := server.Feed(AppendWindowUpdate(nil, 1, 30))
	if err != nil {
		t.Fatalf("Feed WINDOW_UPDATE: %v", err)
	}
	got, lastEnd, _ = dataFrames(t, out)
	if got != 30 {
		t.Fatalf("收到 +30 之后发了 %d 字节, want 30", got)
	}
	if lastEnd {
		t.Error("还剩 50 字节，不该带 END_STREAM")
	}

	// 再续 100：剩 50 全发完，最后一帧带 END_STREAM
	_, out, err = server.Feed(AppendWindowUpdate(nil, 1, 100))
	if err != nil {
		t.Fatalf("Feed WINDOW_UPDATE: %v", err)
	}
	got, lastEnd, n := dataFrames(t, out)
	if got != 50 || !lastEnd {
		t.Fatalf("收尾发了 %d 字节 (END_STREAM=%v), want 50/true", got, lastEnd)
	}
	if n == 0 {
		t.Error("收尾一个 DATA 帧都没有")
	}
}

// 对端改 SETTINGS_INITIAL_WINDOW_SIZE 时，**已存在的流按差值调窗口**
// （RFC 9113 6.5.2），不是重置成新值；调大之后攒着的数据要续发。
func TestSettingsInitialWindowDelta(t *testing.T) {
	server := NewConn(false, &recorder{})
	client := NewConn(true, &recorder{})

	in := append([]byte(nil), clientPreface...)
	in = AppendSettings(in, [2]uint32{0x4, 20}) // 流窗口先给 20
	in = append(in, client.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/big"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "x"},
	}, true)...)
	if _, _, err := server.Feed(in); err != nil {
		t.Fatalf("Feed 请求: %v", err)
	}
	if err := server.WriteData(1, make([]byte, 60), true); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	// 窗口 20 → 先发 20，剩 40 排队（把那 20 取走，后面只看新增的）
	if _, out, _ := server.Feed(nil); len(out) == 0 {
		t.Fatalf("窗口 20 时应该先发出去一段")
	}

	// 把 INITIAL_WINDOW_SIZE 从 20 改到 50：差值 +30，该再发 30
	_, out, err := server.Feed(AppendSettings(nil, [2]uint32{0x4, 50}))
	if err != nil {
		t.Fatalf("Feed SETTINGS: %v", err)
	}
	sent := 0
	p := NewFrameParser()
	if _, err := p.Parse(out, func(f *Frame) error {
		if f.Type == FrameData {
			sent += len(f.Payload)
		}
		return nil
	}); err != nil {
		t.Fatalf("解析输出: %v", err)
	}
	if sent != 30 {
		t.Fatalf("窗口按差值 +30 之后发了 %d 字节, want 30（重置成新值会多发）", sent)
	}
}

// endStreamRecorder 记下 endStream 到过没有（recorder 只攒数据）。
type endStreamRecorder struct {
	recorder
	gotEnd bool
}

func (r *endStreamRecorder) OnData(c *Conn, streamID uint32, data []byte, endStream bool) {
	r.recorder.OnData(c, streamID, data, endStream)
	if endStream {
		r.gotEnd = true
	}
}

// 空的 DATA + END_STREAM 也要把 endStream 交给上层。
//
// 这是"这段没有，流到此结束"的合法写法：bodyless 的 POST、只写响应头不写体
// 的响应都这么收尾。按 len(payload) > 0 过滤的话 endStream 传不上去，上层
// 永远等不到结束（实测：请求级 handler 的响应收尾、examples/http2/client
// 全卡死在这）。
func TestEmptyDataEndStream(t *testing.T) {
	rec := &endStreamRecorder{}
	server := NewConn(false, rec)
	client := NewConn(true, &recorder{})

	in := append([]byte(nil), clientPreface...)
	in = AppendSettings(in, [2]uint32{0x3, 100})
	in = append(in, client.MustHeaders(1, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/x"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "a"},
	}, false)...)
	in = append(in, AppendData(nil, 1, nil, true)...) // 空的 DATA + END_STREAM
	if _, _, err := server.Feed(in); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if !rec.gotEnd {
		t.Fatal("空的 DATA + END_STREAM 没把 endStream 交给上层")
	}
}
