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

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// startServerAndDial 起一个自建服务端，用 quic-go 的客户端拨进去。
// 返回服务端连接和客户端连接（握手已完成）。
func startServerAndDial(t *testing.T) (*Conn, *quic.Conn) {
	t.Helper()
	cert, err := tls.X509KeyPair(testCertPEM, testKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", Config{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ln.Serve()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	cc, err := quic.DialAddr(ctx, ln.Addr().String(),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatalf("客户端握手失败: %v", err)
	}
	t.Cleanup(func() { cc.CloseWithError(0, "") })

	srv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return srv, cc
}

// 并发多条双向流 + 大块数据：客户端开 n 条流各写一大块（多包，验证
// STREAM 帧的切块和偏移），服务端并行读出来核对。
func TestConcurrentStreamsLargeWrites(t *testing.T) {
	srv, cc := startServerAndDial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const (
		nStreams = 16
		bodyLen  = 8 * 1024 // 8KB：一个包塞不下，要走切块
	)
	var wg sync.WaitGroup
	errs := make(chan error, nStreams)

	// 客户端：每条流写一段可识别的数据，半关之后把服务端的回显读回来
	for i := 0; i < nStreams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			str, err := cc.OpenStreamSync(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "!!! 客户端开流失败: %v\n", err)
				errs <- err
				return
			}
			body := bytes.Repeat([]byte{byte('A' + i)}, bodyLen)
			if _, err := str.Write(body); err != nil {
				fmt.Fprintf(os.Stderr, "!!! 客户端写失败: %v\n", err)
				errs <- err
				return
			}
			str.Close() // 半关：写侧结束，读侧还开着等回显
			got, err := io.ReadAll(str)
			if err != nil {
				fmt.Fprintf(os.Stderr, "!!! 客户端读回显失败: %v\n", err)
				errs <- fmt.Errorf("客户端读回显失败: %w", err)
				return
			}
			if !bytes.Equal(got, body) {
				errs <- fmt.Errorf("回显不对：%d 字节，期望 %d", len(got), bodyLen)
			}
		}(i)
	}

	// 服务端：读 n 条流（每条的数据必须是一整块同一个字节），原样回显
	for i := 0; i < nStreams; i++ {
		str, err := srv.AcceptStream()
		if err != nil {
			t.Fatalf("AcceptStream: %v", err)
		}
		wg.Add(1)
		go func(str *Stream) {
			defer wg.Done()
			got, err := io.ReadAll(str)
			if err != nil {
				errs <- fmt.Errorf("流 %d 读失败: %w", str.StreamID(), err)
				return
			}
			if len(got) != bodyLen {
				errs <- fmt.Errorf("流 %d 收到 %d 字节，期望 %d", str.StreamID(), len(got), bodyLen)
				return
			}
			b := got[0]
			for _, x := range got {
				if x != b {
					errs <- fmt.Errorf("流 %d 的数据混了（%c 里出现 %c）", str.StreamID(), b, x)
					return
				}
			}
			if _, err := str.Write(got); err != nil {
				errs <- err
			}
			str.Close()
		}(str)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("超时")
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// 服务端开单向流，客户端能读到（HTTP/3 的控制流就是这条路）。
func TestServerUniStream(t *testing.T) {
	srv, cc := startServerAndDial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	str := srv.OpenUniStream()
	if _, err := str.Write([]byte("settings!")); err != nil {
		t.Fatal(err)
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}

	us, err := cc.AcceptUniStream(ctx)
	if err != nil {
		t.Fatalf("客户端收单向流失败: %v", err)
	}
	got, err := io.ReadAll(us)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "settings!" {
		t.Fatalf("收到 %q", got)
	}
}

// 客户端开单向流，服务端 AcceptUniStream 能收到。
func TestClientUniStream(t *testing.T) {
	srv, cc := startServerAndDial(t)

	us, err := cc.OpenUniStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := us.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	us.Close()

	done := make(chan string, 1)
	go func() {
		str, err := srv.AcceptUniStream()
		if err != nil {
			done <- "ERR:" + err.Error()
			return
		}
		b, _ := io.ReadAll(str)
		done <- string(b)
	}()
	select {
	case v := <-done:
		if v != "ping" {
			t.Fatalf("收到 %q", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等服务端单向流超时")
	}
}

// retireSet 的水位推进：并发的流乱序关，水位要跟着最低的那条走。
func TestRetireSet(t *testing.T) {
	r := retireSet{next: 0, pend: map[uint64]struct{}{}}
	if r.retired(0) {
		t.Fatal("0 不该是已回收")
	}
	r.done(4) // 后关的先到
	if r.retired(0) || r.retired(4) {
		t.Fatal("0 还没关，水位不该推过它")
	}
	r.done(0)
	if !r.retired(0) || !r.retired(4) {
		t.Fatal("0 关掉之后 0 和 4 都该回收了")
	}
	if r.retired(8) {
		t.Fatal("8 还没见过")
	}
	r.done(8)
	if !r.retired(8) || r.retired(12) {
		t.Fatal("水位推过头了")
	}
}
