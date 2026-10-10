// Copyright 2021-2024 antlabs. All rights reserved.
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

package websocket

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var badUTF8 = []byte{128, 129, 130, 131}

type testServerOptionReadTimeout struct {
	err chan error
	run int32
}

func (defcallback *testServerOptionReadTimeout) OnOpen(_ *Conn) {
}

func (defcallback *testServerOptionReadTimeout) OnMessage(_ *Conn, _ Opcode, _ []byte) {
}

func (defcallback *testServerOptionReadTimeout) OnClose(c *Conn, err error) {
	atomic.AddInt32(&defcallback.run, int32(1))
	defcallback.err <- err
}

// 测试客户端和服务端都有的配置项
func Test_CommonOption(t *testing.T) {
	m := NewMultiEventLoopAndStartMust(WithEventLoops(1), WithBusinessGoNum(1, 1, 1), WithLogLevel(slog.LevelError))
	t.Run("0.server.local: Without setting WithClientCallbackFunc", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerTCPDelay(), WithServerMultiEventLoop(m))
			if err != nil {
				t.Error(err)
			}
			_ = c
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientCallbackFunc(func(c *Conn) {
		}, func(c *Conn, mt Opcode, payload []byte) {
		}, func(c *Conn, err error) {
		}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("0.server.global: Without setting WithClientCallbackFunc", func(t *testing.T) {
		upgrade := NewUpgrade(WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientCallbackFunc(func(c *Conn) {
		}, func(c *Conn, mt Opcode, payload []byte) {
		}, func(c *Conn, err error) {
		}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("0.server.global: Without setting WithClientCallbackFunc", func(t *testing.T) {
		upgrade := NewUpgrade(WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("0.client: WithClientCallbackFunc", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerTCPDelay(), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				err := c.WriteMessage(mt, payload)
				if err != nil {
					t.Error(err)
					return
				}
				atomic.AddInt32(&run, int32(1))
			}))
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		messageDone := make(chan bool, 1)
		url := strings.ReplaceAll(ts.URL, "http", "ws")
		clientRun := int32(0)
		clientConn, err := Dial(url, WithClientCallbackFunc(func(c *Conn) {
			atomic.AddInt32(&clientRun, 10)
		}, func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&clientRun, 100)
			messageDone <- true
		}, func(c *Conn, err error) {
			atomic.AddInt32(&clientRun, 1000)
			done <- true
		}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}
		defer clientConn.Close()

		err = clientConn.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		clientConn.StartReadLoop()
		for i := 0; i < 2; i++ {
			select {
			case <-messageDone:
				clientConn.Close()
			case <-done:
			case <-time.After(100 * time.Millisecond):
			}
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}

		if atomic.LoadInt32(&clientRun) != 1110 {
			t.Errorf("not run client:method fail:%d, need:1110\n", atomic.LoadInt32(&clientRun))
		}
	})

	t.Run("2.server.local: WithServerTCPDelay", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerTCPDelay(), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				atomic.AddInt32(&run, int32(1))
				done <- true
			}))
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientCallback(&testDefaultCallback{}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case <-done:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("2.server.global: WithServerTCPDelay", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		upgrade := NewUpgrade(WithServerTCPDelay(), WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			done <- true
		}))

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientCallback(&testDefaultCallback{}))
		if err != nil {
			t.Error(err)
			return
		}

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("2.client: WithClientTCPDelay ", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				err2 := c.WriteMessage(mt, payload)
				if err2 != nil {
					t.Error(err2)
					return
				}
			}))
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientTCPDelay(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			done <- true
		}))
		if err != nil {
			t.Error(err)
			return
		}

		con.StartReadLoop()
		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run client callback:method fail")
		}
	})

	t.Run("3.server.local: WithServerDisableUTF8Check", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerEnableUTF8Check(), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err2 := c.WriteMessage(op, payload)
				if err2 != nil {
					t.Error(err2)
					return
				}
				atomic.AddInt32(&run, int32(1))
				done <- true
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientEnableUTF8Check(), WithClientCallback(&testDefaultCallback{}))
		if err != nil {
			t.Error(err)
		}
		defer con.Close()

		err = con.WriteMessage(Text, badUTF8)
		if err == nil {
			t.Error("写入非法utf8数据，没有报错")
		}

		err = con.WriteMessage(Binary, badUTF8)
		if err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("3.server.global: WithServerDisableUTF8Check", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		upgrade := NewUpgrade(WithServerMultiEventLoop(m), WithServerEnableUTF8Check(), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
				return
			}

			atomic.AddInt32(&run, int32(1))
			done <- true
		}))

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientEnableUTF8Check(), WithClientCallback(&testDefaultCallback{}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Text, badUTF8)
		if err == nil {
			t.Error("写入非法utf8数据，没有报错")
		}
		_ = con.WriteMessage(Binary, badUTF8)

		select {
		case <-done:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("3.client: WithClientDisableUTF8Check", func(t *testing.T) {
		// 客户端不检查utf8， 服务端检查utf8
		run := int32(0)
		done := make(chan bool, 1)
		upgrade := NewUpgrade(WithServerEnableUTF8Check(), WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
				return
			}
			atomic.AddInt32(&run, int32(1))
			done <- true
		}))

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientCallback(&testDefaultCallback{}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Text, badUTF8)
		if err != nil {
			t.Error("关闭utf8检查, 写入非法utf8数据，不报错")
			return
		}

		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 0 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("4.server.local: WithServerOnMessageFunc", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				atomic.AddInt32(&run, int32(1))
				done <- true
			}))
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientCallback(&testDefaultCallback{}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case <-done:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("4.server.global: WithServerOnMessageFunc", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		upgrade := NewUpgrade(WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			done <- true
		}), WithServerMultiEventLoop(m))

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientCallback(&testDefaultCallback{}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("4.client: WithClientOnMessageFunc", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				err2 := c.WriteMessage(mt, payload)
				if err2 != nil {
					t.Error(err2)
					return
				}
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			done <- true
		}))
		if err != nil {
			t.Error(err)
			return
		}

		con.StartReadLoop()
		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run client callback:method fail")
		}
	})

	t.Run("5.server.local: WithServerReplyPing", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerReplyPing(), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, o Opcode, b []byte) {
			atomic.AddInt32(&run, int32(1))
			if o != Pong || bytes.Equal(b, []byte("hello")) {
				t.Error("need Pong")
			}
			done <- true
		}))
		if err != nil {
			t.Error(err)
		}

		con.StartReadLoop()
		err = con.WritePing([]byte("hello"))
		if err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("5.server.global: WithServerReplyPing", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		upgrade := NewUpgrade(WithServerReplyPing(), WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, o Opcode, b []byte) {
			atomic.AddInt32(&run, int32(1))
			if o != Pong || bytes.Equal(b, []byte("hello")) {
				t.Error("need Pong")
			}
			done <- true
		}))
		if err != nil {
			t.Error(err)
		}

		con.StartReadLoop()
		err = con.WritePing([]byte("hello"))
		if err != nil {
			t.Errorf("WritePing:%v", err)
		}
		select {
		case <-done:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("5.client: WithClientReplyPing", func(t *testing.T) {
		run := int32(0)
		done := make(chan bool, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerReplyPing(), WithServerOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				if mt == Text {
					err2 := c.WritePing([]byte("hello"))
					if err2 != nil {
						t.Error(err2)
					}
				} else if mt == Pong {
				} else {
					t.Error("unknown opcode")
				}

				atomic.AddInt32(&run, int32(1))
				if atomic.LoadInt32(&run) >= 2 {
					done <- true
				}
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientReplyPing(), WithClientOnMessageFunc(func(c *Conn, o Opcode, b []byte) {
		}))
		if err != nil {
			t.Error(err)
			return
		}

		con.StartReadLoop()
		err = con.WriteMessage(Text, []byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case <-done:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 2 {
			t.Errorf("run:%d\n", run)
		}
	})

	t.Run("6.server.local: WithServerIgnorePong", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerIgnorePong(), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err2 := c.WriteMessage(op, payload)
				if err2 != nil {
					t.Error(err2)
				}

			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			fmt.Printf("opcode:%v\n", mt)
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WritePong([]byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		err = con.WriteMessage(Text, []byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(400 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("6.server.global: WithServerIgnorePong", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerIgnorePong(), WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err1 := c.WriteMessage(op, payload)
			if err1 != nil {
				t.Error(err1)
			}
		}))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			fmt.Printf("opcode:%v\n", mt)
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WritePong([]byte("hello"))
		if err != nil {
			t.Errorf("WritePong:%v", err)
		}
		err = con.WriteMessage(Text, []byte("hello"))
		if err != nil {
			t.Errorf("WriteMessage:%v", err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(400 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("6.client: WithClientIgnorePong", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerIgnorePong(), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err1 := c.WritePong([]byte("hello"))
				if err1 != nil {
					t.Error(err1)
					return
				}

				err1 = c.WriteMessage(op, payload)
				if err1 != nil {
					t.Error(err1)
					return
				}

			}))
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientIgnorePong(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Text, []byte("hello"))
		if err != nil {
			t.Errorf("WriteMessage:%v", err)
			return
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(400 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("7.server.local: WithServerWindowsMultipleTimesPayloadSize", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerWindowsMultipleTimesPayloadSize(-1), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err := c.WriteMessage(op, payload)
				if err != nil {
					t.Error(err)
				}
			}))
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("7.server.global: WithServerWindowsMultipleTimesPayloadSize", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerMultiEventLoop(m), WithServerWindowsMultipleTimesPayloadSize(-1), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
			}
		}))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("7.client: WithServerWindowsMultipleTimesPayloadSize", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err := c.WriteMessage(op, payload)
				if err != nil {
					t.Error(err)
				}
			}))
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientWindowsMultipleTimesPayloadSize(-1), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})
	t.Run("8.server.local: WithServerWindowsParseMode", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err := c.WriteMessage(op, payload)
				if err != nil {
					t.Error(err)
				}
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("8.server.global: WithServerWindowsParseMode", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
			}
		}))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("8.client: WithClientWindowsParseMode", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err := c.WriteMessage(op, payload)
				if err != nil {
					t.Error(err)
				}
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("9.server.local: WithServerBufioParseMode", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err := c.WriteMessage(op, payload)
				if err != nil {
					t.Error(err)
				}
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("9.server.global: WithServerBufioParseMode", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
			}
		}))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("9.client: WithClientBufioParseMode", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err := c.WriteMessage(op, payload)
				if err != nil {
					t.Error(err)
				}
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("10.client: WithClientDecompression", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerDecompressAndCompress(),
				WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
					err := c.WriteMessage(op, payload)
					if err != nil {
						t.Error(err)
					}
				}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientCompression(), WithClientDecompression(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}

		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("11.server.local: WithServerDisableBufioClearHack", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerDisableBufioClearHack(), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err := c.WriteMessage(op, payload)
				if err != nil {
					t.Error(err)
				}
			}))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientDisableBufioClearHack(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Binary, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		con.StartReadLoop()
		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("11.client: WithClientBufioParseMode", func(t *testing.T) {
		// 11.server.local 已经测试过客户端，所以这里留空
	})

	// TODO: 这个api可能不会加，
	// t.Run("13-15.server.local.1: WriteMessageDelay", func(t *testing.T) {
	// 	run := int32(0)
	// 	data := make(chan string, 1)
	// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		c, err := Upgrade(w, r, WithServerMaxDelayWriteDuration(time.Millisecond*20), WithServerMaxDelayWriteNum(3), WithServerDelayWriteInitBufferSize(4096), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 			c.WriteMessageDelay(op, payload)
	// 			c.WriteMessageDelay(op, payload)
	// 			c.WriteMessageDelay(op, payload)
	// 		}))
	// 		if err != nil {
	// 			t.Error(err)
	// 		}
	// 		c.StartReadLoop()
	// 	}))

	// 	defer ts.Close()

	// 	url := strings.ReplaceAll(ts.URL, "http", "ws")
	// 	con, err := Dial(url, WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
	// 		atomic.AddInt32(&run, int32(1))
	// 		if run == 3 {
	// 		}
	// 		data <- string(payload)
	// 	}))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}
	// 	defer con.Close()

	// 	con.WriteMessage(Binary, []byte("hello"))
	// 	con.StartReadLoop()
	// 	for i := 0; i < 3; i++ {
	// 		select {
	// 		case d := <-data:
	// 			if d != "hello" {
	// 				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
	// 			}
	// 		case <-time.After(1000 * time.Millisecond):
	// 		}
	// 	}
	// 	if atomic.LoadInt32(&run) != 3 {
	// 		t.Errorf("not run server:method fail:%d\n", atomic.LoadInt32(&run))
	// 	}
	// })

	// t.Run("13-15.server.global.2: WriteMessageDelay", func(t *testing.T) {
	// 	run := int32(0)
	// 	data := make(chan string, 1)
	// 	upgrade := NewUpgrade(WithServerMaxDelayWriteDuration(time.Millisecond*20), WithServerMaxDelayWriteNum(3), WithServerDelayWriteInitBufferSize(4096), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 		c.WriteMessageDelay(op, payload)
	// 		c.WriteMessageDelay(op, payload)
	// 		c.WriteMessageDelay(op, payload)
	// 	}))

	// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		c, err := upgrade.Upgrade(w, r)
	// 		if err != nil {
	// 			t.Error(err)
	// 		}
	// 		c.StartReadLoop()
	// 	}))

	// 	defer ts.Close()

	// 	url := strings.ReplaceAll(ts.URL, "http", "ws")
	// 	con, err := Dial(url, WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
	// 		atomic.AddInt32(&run, int32(1))
	// 		data <- string(payload)
	// 	}))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}
	// 	defer con.Close()

	// 	con.WriteMessage(Binary, []byte("hello"))
	// 	con.StartReadLoop()
	// 	select {
	// 	case d := <-data:
	// 		if d != "hello" {
	// 			t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
	// 		}
	// 	case <-time.After(1000 * time.Millisecond):
	// 	}
	// 	if atomic.LoadInt32(&run) != 3 {
	// 		t.Error("not run server:method fail")
	// 	}
	// })

	// t.Run("13-15.client: WriteMessageDelay", func(t *testing.T) {
	// 	run := int32(0)
	// 	data := make(chan string, 1)
	// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		c, err := Upgrade(w, r,
	// 			WithServerDecompressAndCompress(),
	// 			WithServerBufioParseMode(),
	// 			WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 				c.WriteMessage(op, payload)
	// 				atomic.AddInt32(&run, int32(1))
	// 				data <- string(payload)
	// 			}))
	// 		if err != nil {
	// 			t.Error(err)
	// 		}
	// 		c.StartReadLoop()
	// 	}))

	// 	defer ts.Close()

	// 	url := strings.ReplaceAll(ts.URL, "http", "ws")
	// 	con, err := Dial(url, WithClientDecompressAndCompress(),
	// 		WithClientDecompression(),
	// 		WithClientMaxDelayWriteDuration(30*time.Millisecond),
	// 		WithClientMaxDelayWriteNum(3),
	// 		WithClientWindowsParseMode(),
	// 		WithClientDelayWriteInitBufferSize(4096),
	// 		WithClientOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 			c.WriteMessageDelay(op, []byte("hello"))
	// 			c.WriteMessageDelay(op, []byte("hello"))
	// 			c.WriteMessageDelay(op, []byte("hello"))
	// 		}))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}
	// 	defer con.Close()

	// 	con.WriteMessage(Binary, []byte("hello"))
	// 	con.StartReadLoop()
	// 	select {
	// 	case d := <-data:
	// 		if d != "hello" {
	// 			t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
	// 		}
	// 	case <-time.After(1000 * time.Millisecond):
	// 	}
	// 	if atomic.LoadInt32(&run) != 1 {
	// 		t.Error("not run server:method fail")
	// 	}
	// })

	// t.Run("13-15.client: WriteMessageDelay-Compress", func(t *testing.T) {
	// 	run := int32(0)
	// 	data := make(chan string, 1)
	// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		c, err := Upgrade(w, r,
	// 			WithServerDecompressAndCompress(),
	// 			// WithServerBufioParseMode(),
	// 			WithServerCallbackFunc(nil, func(c *Conn, op Opcode, payload []byte) {
	// 				if op != Binary {
	// 					t.Error("opcode error")
	// 				}
	// 				c.WriteMessage(op, payload)
	// 			}, func(c *Conn, err error) {
	// 				// t.Errorf("%T\n", err)
	// 			},
	// 			))
	// 		if err != nil {
	// 			t.Error(err)
	// 		}

	// 		if !c.compression {
	// 			t.Error("compression fail")
	// 		}

	// 		if !c.decompression {
	// 			t.Error("compression fail")
	// 		}
	// 		c.StartReadLoop()
	// 	}))

	// 	defer ts.Close()

	// 	url := strings.ReplaceAll(ts.URL, "http", "ws")
	// 	con, err := Dial(url,
	// 		WithClientDecompressAndCompress(),
	// 		WithClientMaxDelayWriteDuration(30*time.Millisecond),
	// 		WithClientMaxDelayWriteNum(3),
	// 		WithClientWindowsParseMode(),
	// 		WithClientDelayWriteInitBufferSize(4096),
	// 		WithClientOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 			if op != Binary {
	// 				t.Error("opcode error")
	// 			}
	// 			err := c.WriteMessageDelay(op, []byte("hello"))
	// 			if err != nil {
	// 				t.Error(err)
	// 			}
	// 			err = c.WriteMessageDelay(op, []byte("hello"))
	// 			if err != nil {
	// 				t.Error(err)
	// 			}
	// 			err = c.WriteMessageDelay(op, []byte("hello"))
	// 			if err != nil {
	// 				t.Error(err)
	// 			}
	// 			data <- "hello"
	// 			atomic.AddInt32(&run, int32(1))
	// 		}))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}
	// 	defer con.Close()

	// 	if !con.compression {
	// 		t.Error("not compression:method fail")
	// 	}
	// 	err = con.WriteMessage(Binary, []byte("hello"))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}

	// 	con.StartReadLoop()
	// 	select {
	// 	case d := <-data:
	// 		if d != "hello" {
	// 			t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
	// 		}
	// 	case <-time.After(1000 * time.Millisecond):
	// 		t.Errorf("write message timeout\n")
	// 	}
	// 	if atomic.LoadInt32(&run) != 1 {
	// 		t.Error("not run server:method fail")
	// 	}
	// })

	// t.Run("13-15.client: WriteMessageDelay-Compress-checkUTF8", func(t *testing.T) {
	// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		c, err := Upgrade(w, r,
	// 			WithServerBufioParseMode(),
	// 			WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 			}))
	// 		if err != nil {
	// 			t.Error(err)
	// 		}
	// 		c.StartReadLoop()
	// 	}))

	// 	defer ts.Close()

	// 	url := strings.ReplaceAll(ts.URL, "http", "ws")
	// 	con, err := Dial(url,
	// 		WithClientEnableUTF8Check(),
	// 		WithClientOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 		}))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}
	// 	defer con.Close()

	// 	err = con.WriteMessageDelay(Text, []byte{128, 129, 130, 131})
	// 	if err == nil {
	// 		t.Error("not check utf8:method fail")
	// 	}
	// 	con.StartReadLoop()
	// })

	// t.Run("13-15.client: WriteMessageDelay-timeout-send", func(t *testing.T) {
	// 	run := int32(0)
	// 	data := make(chan string, 1)
	// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		c, err := Upgrade(w, r,
	// 			WithServerDecompressAndCompress(),
	// 			WithServerBufioParseMode(),
	// 			WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 				c.WriteMessage(op, payload)
	// 				atomic.AddInt32(&run, int32(1))
	// 				data <- string(payload)
	// 			}))
	// 		if err != nil {
	// 			t.Error(err)
	// 		}
	// 		c.StartReadLoop()
	// 	}))

	// 	defer ts.Close()

	// 	url := strings.ReplaceAll(ts.URL, "http", "ws")
	// 	con, err := Dial(url, WithClientDecompressAndCompress(),
	// 		WithClientDecompression(),
	// 		WithClientMaxDelayWriteDuration(30*time.Millisecond),
	// 		WithClientMaxDelayWriteNum(3),
	// 		WithClientWindowsParseMode(),
	// 		WithClientDelayWriteInitBufferSize(4096),
	// 		WithClientOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 		}))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}
	// 	defer con.Close()

	// 	err = con.WriteMessageDelay(Text, []byte("hello"))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}
	// 	con.StartReadLoop()
	// 	select {
	// 	case d := <-data:
	// 		if d != "hello" {
	// 			t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
	// 		}
	// 	case <-time.After(1000 * time.Millisecond):
	// 		t.Errorf("13-15.client: WriteMessageDelay-timeout-send: timeout \n")
	// 	}
	// 	if atomic.LoadInt32(&run) != 1 {
	// 		t.Error("not run server:method fail")
	// 	}
	// })

	// t.Run("13-15.client: WriteMessageDelay-Compress-Close", func(t *testing.T) {
	// 	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		c, err := Upgrade(w, r,
	// 			WithServerBufioParseMode(),
	// 			WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 			}))
	// 		if err != nil {
	// 			t.Error(err)
	// 		}
	// 		c.StartReadLoop()
	// 	}))

	// 	defer ts.Close()

	// 	url := strings.ReplaceAll(ts.URL, "http", "ws")
	// 	con, err := Dial(url,
	// 		WithClientEnableUTF8Check(),
	// 		WithClientOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
	// 		}))
	// 	if err != nil {
	// 		t.Error(err)
	// 	}
	// 	defer con.Close()

	// 	con.Close()
	// 	err = con.WriteMessageDelay(Text, []byte{128, 129, 130, 131})
	// 	if err != ErrClosed {
	// 		t.Error("not Close:method fail")
	// 	}
	// 	con.StartReadLoop()
	// })

	t.Run("16.1.WithServerReadTimeout:local-Upgrade", func(t *testing.T) {
		var tsort testServerOptionReadTimeout

		tsort.err = make(chan error, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerMultiEventLoop(m), WithServerCallback(&tsort), WithServerReadTimeout(time.Millisecond*60))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}))
		if err != nil {
			t.Error(err)
		}
		defer con.Close()

		err = con.WriteMessage(Text, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		select {
		case d := <-tsort.err:
			if d == nil {
				t.Errorf("got:nil, need:error\n")
			}
		case <-time.After(1000 * time.Millisecond):
			t.Errorf(" Test_ServerOption:WithServerReadTimeout timeout\n")
		}
		if atomic.LoadInt32(&tsort.run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("16.2.WithServerReadTimeout", func(t *testing.T) {
		var tsort testServerOptionReadTimeout

		upgrade := NewUpgrade(WithServerMultiEventLoop(m), WithServerCallback(&tsort), WithServerReadTimeout(time.Millisecond*60))
		tsort.err = make(chan error, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}))
		if err != nil {
			t.Error(err)
		}
		defer con.Close()

		err = con.WriteMessage(Text, []byte("hello"))
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case d := <-tsort.err:
			if d == nil {
				t.Errorf("got:nil, need:error\n")
			}
		case <-time.After(400 * time.Millisecond):
			t.Errorf(" Test_ServerOption:WithServerReadTimeout timeout\n")
		}
		if atomic.LoadInt32(&tsort.run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("16.3.WithClientReadTimeout", func(t *testing.T) {
		var tsort testServerOptionReadTimeout

		upgrade := NewUpgrade(WithServerMultiEventLoop(m), WithServerCallback(&tsort), WithServerReadTimeout(time.Millisecond*60))
		tsort.err = make(chan error, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientReadTimeout(2*time.Second), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Text, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
		select {
		case d := <-tsort.err:
			if d == nil {
				t.Errorf("got:nil, need:error\n")
			}
		case <-time.After(400 * time.Millisecond):
			t.Errorf(" Test_ServerOption:WithServerReadTimeout timeout\n")
		}
		if atomic.LoadInt32(&tsort.run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("17.client.WithClientOnCloseFunc", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerMultiEventLoop(m), WithServerEnableUTF8Check(), WithServerOnCloseFunc(func(c *Conn, err error) {
			c.Close()
		}))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
			c.Close()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientDisableBufioClearHack(),
			WithClientEnableUTF8Check(), WithClientOnCloseFunc(func(c *Conn, err error) {
				data <- err.Error()
			}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()
		// 服务端 upgrade 完就 Close，这笔写发得出去发不出去看时序：对端
		// 的 FIN 先到，写就是 ErrClosed。**不能断言它一定成功**——实测
		// 迁移前的代码这个断言三次挂两次。这里要验的是下面的 OnClose
		// 回调，不是这一笔写。
		err = con.WriteMessage(Text, []byte("hello"))
		if err != nil && !errors.Is(err, ErrClosed) {
			t.Errorf("unexpected error:%s\n", err)
			return
		}
		con.StartReadLoop()
		select {
		case <-data:
			atomic.AddInt32(&run, 1)
		case <-time.After(500 * time.Millisecond):
		}

		if atomic.LoadInt32(&run) != 1 {
			t.Errorf("not run server:method fail:%d\n", atomic.LoadInt32(&run))
		}
	})

	t.Run("22.1.WithServerReadMaxMessage:local-Upgrade", func(t *testing.T) {
		var tsort testServerOptionReadTimeout

		tsort.err = make(chan error, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := Upgrade(w, r, WithServerCallback(&tsort), WithServerReadMaxMessage(1<<10), WithServerMultiEventLoop(m))
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Text, bytes.Repeat([]byte("1"), 1025))
		if err != nil {
			t.Error(err)
		}
		select {
		case d := <-tsort.err:
			if d == nil {
				t.Errorf("got:nil, need:error\n")
			}
		case <-time.After(1000 * time.Millisecond):
			t.Errorf(" Test_ServerOption:WithServerReadMaxMessage timeout\n")
		}
		if atomic.LoadInt32(&tsort.run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("22.2.WithServerReadMaxMessage", func(t *testing.T) {
		var tsort testServerOptionReadTimeout

		upgrade := NewUpgrade(WithServerCallback(&tsort), WithServerReadMaxMessage(1<<10), WithServerMultiEventLoop(m))
		tsort.err = make(chan error, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		err = con.WriteMessage(Text, bytes.Repeat([]byte("1"), 1025))
		if err != nil {
			t.Error(err)
		}
		select {
		case d := <-tsort.err:
			if d == nil {
				t.Errorf("got:nil, need:error\n")
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf(" Test_ServerOption:WithServerReadTimeout timeout\n")
		}
		if atomic.LoadInt32(&tsort.run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("22.3.WithClientReadMaxMessage", func(t *testing.T) {
		var tsort testServerOptionReadTimeout

		upgrade := NewUpgrade(WithServerMultiEventLoop(m))
		tsort.err = make(chan error, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
			time.Sleep(time.Second / 100)
			err = c.WriteMessage(Binary, bytes.Repeat([]byte("1"), 1025))
			if err != nil {
				t.Error(err)
				return
			}
			c.StartReadLoop()
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientCallback(&tsort), WithClientMultiEventLoop(m), WithClientReadMaxMessage(1<<10))
		if err != nil {
			t.Error(err)
			return
		}
		defer con.Close()

		select {
		case d := <-tsort.err:
			if d == nil {
				t.Errorf("got:nil, need:error\n")
			}
			fmt.Printf(">>> err = %v\n", d)
		case <-time.After(100 * time.Millisecond):
			t.Errorf(" Test_ServerOption:WithServerReadMaxMessage timeout\n")
		}
		if atomic.LoadInt32(&tsort.run) != 1 {
			t.Error("not run server:method fail")
		}
	})
}
