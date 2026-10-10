package websocket

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/antlabs/wsutil/fixedwriter"
	"github.com/antlabs/wsutil/frame"
	"github.com/antlabs/wsutil/opcode"
)

var (
	testBinaryMessage64kb = bytes.Repeat([]byte("1"), 65535)
	testTextMessage64kb   = bytes.Repeat([]byte("中"), 65535/len("中"))
	testBinaryMessage10   = bytes.Repeat([]byte("1"), 10)
)

// testConnWriter 把帧直接写进连接（绕过 WriteMessage），用来构造
// 不合法的帧测错误路径。以前是 connToNewConn 那层 unsafe 转换，
// 现在 IO 归 engine，直接走 ec.Write。
type testConnWriter struct{ c *Conn }

func (w *testConnWriter) Write(p []byte) (int, error) {
	if w.c.ec == nil {
		return 0, ErrClosed
	}
	if err := w.c.ec.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func Test_Conn(t *testing.T) {
	t.Run("conn size", func(t *testing.T) {
		// 在未加入tls功能时，Conn的大小为160字节够用了。
		fmt.Printf("%d\n", unsafe.Sizeof(Conn{}))
		// conn大小改变历史
		// 新增上下文接管，从 小于160到184
		// 把Callback移到Conn, 从184到200
		fmt.Printf("conn.size = %d\n", unsafe.Sizeof(Conn{}))
		if unsafe.Sizeof(Conn{}) > 216 {
			t.Errorf("Conn size:%d is too large", unsafe.Sizeof(Conn{}))
		}
	})

}

type testMessageHandler struct {
	DefCallback
	t           *testing.T
	need        []byte
	callbed     int32
	callbedChan chan bool
	server      bool
	count       int
	done        chan struct{}
	output      bool
}

func (t *testMessageHandler) OnMessage(c *Conn, op opcode.Opcode, msg []byte) {
	need := append([]byte(nil), t.need...)
	atomic.StoreInt32(&t.callbed, 1)
	t.callbedChan <- true
	if t.count == 0 {
		return
	}
	t.count--

	message := "#client"
	if t.server {
		message = "#server"
	}
	// if t.output {
	// 	// fmt.Printf(">>>>>%p %s, %#v\n", &msg, message, msg)
	// }
	if len(msg) < 30 {
		if !bytes.Equal(msg, need) {
			t.t.Errorf(">>>>>%p %s, %#v\n", &msg, message, msg)
		}
	} else {

		md51 := md5.Sum(need)
		md52 := md5.Sum(msg)
		if !bytes.Equal(md51[:], md52[:]) {
			t.t.Errorf("md51 %x, md52 %x\n", md51, md52)
		}
	}
	err := c.WriteMessage(op, msg)
	if err != nil {
		t.t.Error(err)
	}
	// if !t.server {
	// 	// c.Close()
	// }
}

func (t *testMessageHandler) OnClose(c *Conn, err error) {
	message := "#client.OnClose"
	if t.server {
		message = "#server.OnClose"
	}

	fmt.Printf("OnClose: %s:%s\n", message, err)
	if t.done != nil {
		close(t.done)
	}
}

func newServrEcho(t *testing.T, data []byte, output bool) *httptest.Server {
	m := NewMultiEventLoopAndStartMust(WithLogLevel(slog.LevelError), WithBusinessGoNum(1, 1, 1), WithEventLoops(1))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := Upgrade(w, r,
			WithServerCallback(&testMessageHandler{t: t, need: data, server: true, count: -1, output: true, callbedChan: make(chan bool, 10)}),
			WithServerMultiEventLoop(m),
		)
		if err != nil {
			t.Error(err)
			return
		}

	}))

	ts.URL = "ws" + strings.TrimPrefix(ts.URL, "http")
	return ts
}

// 测试read message
func Test_ReadMessage(t *testing.T) {

	m := NewMultiEventLoopAndStartMust(WithEventLoops(1), WithLogLevel(slog.LevelDebug), WithBusinessGoNum(1, 1, 1))
	t.Run("ReadMessage10", func(t *testing.T) {
		ts := newServrEcho(t, testBinaryMessage10, true)
		client := &testMessageHandler{t: t, need: append([]byte(nil), testBinaryMessage10...), count: 1, done: make(chan struct{}), output: true}
		client.callbedChan = make(chan bool, 1)
		c, err := Dial(ts.URL, WithClientCallback(client), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}

		if c == nil {
			t.Error("c is nil")
			return
		}

		tmp := append([]byte(nil), testBinaryMessage10...)

		err = c.WriteMessage(Binary, tmp)
		if err != nil {
			t.Error(err)
			return
		}
		// <-client.done
		select {
		case <-client.callbedChan:
		case <-time.After(time.Second / 3):
		}
		if atomic.LoadInt32(&client.callbed) != 1 {
			t.Errorf("not callbed:%s", ts.URL)
		}
	})

	t.Run("ReadMessage64K", func(t *testing.T) {
		ts := newServrEcho(t, testBinaryMessage64kb, false)
		client := &testMessageHandler{t: t, need: append([]byte(nil), testBinaryMessage64kb...), count: 1}
		client.callbedChan = make(chan bool, 1)
		c, err := Dial(ts.URL, WithClientCallback(client), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}

		if c == nil {
			t.Error("c is nil")
			return
		}

		tmp := append([]byte(nil), testBinaryMessage64kb...)
		err = c.WriteMessage(Binary, tmp)
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case <-client.callbedChan:
		case <-time.After(time.Second / 3):
		}
		if err != nil {
			t.Error(err)
			return
		}

		if atomic.LoadInt32(&client.callbed) != 1 {
			t.Error("not callbed")
		}
	})

	t.Run("ReadMessage64K_Text", func(t *testing.T) {
		ts := newServrEcho(t, testTextMessage64kb, false)
		client := &testMessageHandler{t: t, need: append([]byte(nil), testTextMessage64kb...), count: 1}
		client.callbedChan = make(chan bool, 1)
		c, err := Dial(ts.URL, WithClientCallback(client), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
			return
		}

		if c == nil {
			t.Error("c is nil")
			return
		}
		tmp := append([]byte(nil), testTextMessage64kb...)
		err = c.WriteMessage(Text, tmp)
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case <-client.callbedChan:
		case <-time.After(time.Second / 3):
		}
		if atomic.LoadInt32(&client.callbed) != 1 {
			t.Errorf("not callbed:%d\n", client.callbed)
		}
	})

	t.Run("ReadMessage_Fail_Rsv.1", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := Upgrade(w, r, WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
				err1 := c.WriteMessage(op, payload)
				if err1 != nil {
					t.Error(err1)
				}
			}), WithServerMultiEventLoop(m))
			if err != nil {
				t.Error(err)
			}
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientCompression(), WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}

		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		// err = con.WriteMessage(Binary, []byte("hello"))
		maskValue := rand.Uint32()
		var fw fixedwriter.FixedWriter
		err = frame.WriteFrame(&fw, &testConnWriter{con}, []byte("hello"), true, true, con.isClient(), Binary, maskValue)
		if err != nil {
			t.Error(err)
		}

		select {
		case d := <-data:
			if d != "hello" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) > 0 {
			// 需要不运行server
			t.Errorf("need not run server")
		}
	})

	t.Run("ReadMessage_Fail_Rsv.2", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := Upgrade(w, r,
				// WithServerDecompression(),
				WithServerDecompressAndCompress(),
				WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
					err1 := c.WriteMessage(op, payload)
					if err1 != nil {
						t.Error(err1)
					}
				}), WithServerMultiEventLoop(m))
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url,
			WithClientDecompressAndCompress(),
			WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				atomic.AddInt32(&run, int32(1))
				// data <- string(payload)
			}),
			WithClientMultiEventLoop(m),
		)
		if err != nil {
			t.Error(err)
		}

		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		// err = con.WriteMessage(Binary, []byte("hello"))
		maskValue := rand.Uint32()
		var fw fixedwriter.FixedWriter
		err = frame.WriteFrame(&fw, &testConnWriter{con}, []byte("hello"), true, true, con.isClient(), Ping, maskValue)
		if err != nil {
			t.Error(err)
		}

		select {
		case <-data:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) > 0 {
			// 需要不运行server
			t.Errorf("need not run server")
		}
	})
}

// 测试分段frame
func TestFragmentFrame(t *testing.T) {

	m := NewMultiEventLoopAndStartMust(WithLogLevel(slog.LevelError), WithBusinessGoNum(1, 1, 1), WithEventLoops(1))
	t.Run("FragmentFrame10", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
			}
		}), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientDisableBufioClearHack(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		err = con.writeFragment(Binary, []byte("hello"), 1)
		if err != nil {
			t.Error(err)
			return
		}

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

	t.Run("Ping-FragmentFrame-Fail", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerOnCloseFunc(func(c *Conn, err error) {
			atomic.AddInt32(&run, int32(1))
			data <- err.Error()
		}), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientDisableBufioClearHack(), WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}))
		if err != nil {
			t.Errorf("%s:%s", err, ts.URL)
			return
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		err = con.writeFragment(Ping, []byte("hello"), 1)
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case <-data:
		case <-time.After(1000 * time.Millisecond):
		}

		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("Text-FragmentFrame-Fail", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerOnCloseFunc(func(c *Conn, err error) {
			atomic.AddInt32(&run, int32(1))
			data <- err.Error()
		}), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientDisableBufioClearHack(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}), WithClientMultiEventLoop(m))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()
		// con.writeFragment(Ping, []byte("hello"), 1)

		maskValue := rand.Uint32()
		var fw fixedwriter.FixedWriter
		err = frame.WriteFrame(&fw, &testConnWriter{con}, []byte("h"), false, false, con.isClient(), Text, maskValue)
		if err != nil {
			t.Error(err)
		}
		maskValue = rand.Uint32()
		err = frame.WriteFrame(&fw, &testConnWriter{con}, []byte{}, true, false, con.isClient(), Text, maskValue)
		if err != nil {
			t.Error(err)
		}

		select {
		case <-data:
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	// 分段传递，并且压缩
	t.Run("FragmentFrame-Compression", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerDecompression(), WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
			}
		}), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientDisableBufioClearHack(), WithClientMultiEventLoop(m), WithClientDecompressAndCompress(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
			data <- string(payload)
		}))
		if err != nil {
			t.Error(err)
			return
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		err = con.writeFragment(Binary, []byte("hello"), 1)
		if err != nil {
			t.Error(err)
			return
		}

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

	t.Run("FragmentFrame-Small-Buffer", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
			}
		}), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientDisableBufioClearHack(), WithClientEnableUTF8Check(),
			WithClientDecompressAndCompress(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				atomic.AddInt32(&run, int32(1))
				data <- string(payload)
			}))
		if err != nil {
			t.Error(err)
		}

		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		sendData := []byte("hell")
		// 这里必须要报错
		err = con.writeFragment(Text, sendData, 5)
		if err != nil {
			t.Errorf("error:%v", err)
		}

		select {
		case d := <-data:
			if d != string(sendData) {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("FragmentFrame-Client-Not-UTF8", func(t *testing.T) {
		upgrade := NewUpgrade(WithServerOnMessageFunc(func(c *Conn, op Opcode, payload []byte) {
			err := c.WriteMessage(op, payload)
			if err != nil {
				t.Error(err)
			}
		}), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error("upgrade", err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientDisableBufioClearHack(), WithClientEnableUTF8Check(),
			WithClientDecompressAndCompress(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			}))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		// 这里必须要报错
		err = con.writeFragment(Text, []byte{128, 129, 130, 131}, 1)
		if err == nil {
			t.Error("not error")
		}
	})

	t.Run("FragmentFrame-Server-Not-UTF8", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerEnableUTF8Check(), WithServerMultiEventLoop(m), WithServerOnCloseFunc(func(c *Conn, err error) {
			data <- err.Error()
		}))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientDisableBufioClearHack(), WithClientMultiEventLoop(m),
			WithClientDecompressAndCompress(), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			}))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()
		// 这里必须要报错
		err = con.writeFragment(Text, []byte{128, 129, 130, 131}, 1)
		if err != nil {
			t.Error("error")
		}

		select {
		case <-data:
			atomic.AddInt32(&run, 1)
		case <-time.After(500 * time.Millisecond):
		}

		if atomic.LoadInt32(&run) != 1 {
			t.Errorf("not run server:method fail:%d\n", atomic.LoadInt32(&run))
		}
	})
}

type testPingPongCloseHandler struct {
	DefCallback
	run  int32
	data chan string
}

func (t *testPingPongCloseHandler) OnClose(c *Conn, err error) {
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	atomic.AddInt32(&t.run, 1)
	t.data <- "eof"
}

func Test_WriteControl(t *testing.T) {
	m := NewMultiEventLoopAndStartMust(WithLogLevel(slog.LevelError), WithBusinessGoNum(1, 1, 1), WithEventLoops(1))
	t.Run("WriteControl > maxControlFrameSize.message.fail", func(t *testing.T) {
		var shandler testPingPongCloseHandler
		shandler.data = make(chan string, 1)
		upgrade := NewUpgrade(WithServerCallback(&shandler), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error("upgrade", err)
			}
		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
		}))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		err = con.WriteControl(Close, bytes.Repeat([]byte{1}, 126))
		// 这里必须要报错
		if err == nil {
			t.Error("not error")
		}
	})
}

func Test_API(t *testing.T) {

}

// 测试ping pong close control信息
func TestPingPongClose(t *testing.T) {
	// 写一个超过maxControlFrameSize的消息
	m := NewMultiEventLoopAndStartMust(WithLogLevel(slog.LevelError), WithBusinessGoNum(1, 1, 1), WithEventLoops(1))
	t.Run("1.>maxControlFrameSize.fail", func(t *testing.T) {
		run := int32(0)
		var shandler testPingPongCloseHandler
		shandler.data = make(chan string, 1)
		upgrade := NewUpgrade(WithServerCallback(&shandler), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
		}))
		if err != nil {
			t.Error(err)
			return
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		err = con.WriteMessage(Close, bytes.Repeat([]byte("a"), maxControlFrameSize+3))
		if err != nil {
			t.Error(err)
		}

		select {
		case d := <-shandler.data:
			if d != "eof" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&shandler.run) != 1 {
			t.Errorf("not run server:method fail:%d", atomic.LoadInt32(&shandler.run))
		}
	})

	t.Run("3.WriteCloseEmpty.fail", func(t *testing.T) {
		run := int32(0)
		var shandler testPingPongCloseHandler
		shandler.data = make(chan string, 1)
		upgrade := NewUpgrade(WithServerCallback(&shandler), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
		}))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		err = con.WriteMessage(Close, nil)
		if err != nil {
			t.Error(err)
		}

		select {
		case d := <-shandler.data:
			if d != "eof" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&shandler.run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("4.WriteClose Payload < 2.fail", func(t *testing.T) {
		run := int32(0)
		var shandler testPingPongCloseHandler
		shandler.data = make(chan string, 1)
		upgrade := NewUpgrade(WithServerCallback(&shandler), WithServerMultiEventLoop(m))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
		}))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		err = con.WriteMessage(Close, []byte{1})
		if err != nil {
			t.Error(err)
		}

		select {
		case d := <-shandler.data:
			if d != "eof" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&shandler.run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("5.WriteClose Payload > 2, utf8.check.fail", func(t *testing.T) {
		run := int32(0)
		var shandler testPingPongCloseHandler
		shandler.data = make(chan string, 1)
		upgrade := NewUpgrade(WithServerEnableUTF8Check(), WithServerMultiEventLoop(m), WithServerCallback(&shandler))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
		}))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		err = con.WriteMessage(Close, []byte{128, 129, 130, 131})
		if err != nil {
			t.Error(err)
		}

		select {
		case d := <-shandler.data:
			if d != "eof" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&shandler.run) != 1 {
			t.Error("not run server:method fail")
		}
	})

	t.Run("6.WriteClose status code.fail", func(t *testing.T) {
		run := int32(0)
		var shandler testPingPongCloseHandler
		shandler.data = make(chan string, 1)
		upgrade := NewUpgrade(WithServerEnableUTF8Check(), WithServerMultiEventLoop(m), WithServerCallback(&shandler))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Error(err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientDialTimeout(time.Second), WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
			atomic.AddInt32(&run, int32(1))
		}))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()

		var badSc StatusCode = 3
		err = con.WriteCloseTimeout(badSc, 10*time.Second)
		if err != nil {
			t.Error(err)
		}

		select {
		case d := <-shandler.data:
			if d != "eof" {
				t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
			}
		case <-time.After(1000 * time.Millisecond):
		}
		if atomic.LoadInt32(&shandler.run) != 1 {
			t.Error("not run server:method fail")
		}
	})
	t.Run("7.WriteClose", func(t *testing.T) {
		run := int32(0)
		statusCodes := []StatusCode{
			NormalClosure,
			EndpointGoingAway,
			ProtocolError,
			DataCannotAccept,
			NotConsistentMessageType,
			TerminatingConnection,
			TooBigMessage,
			NoExtensions,
			ServerTerminating,
			1004,
			3000,
		}

		for scindex, st := range statusCodes {
			var shandler testPingPongCloseHandler
			shandler.data = make(chan string, 1)
			upgrade := NewUpgrade(WithServerEnableUTF8Check(), WithServerMultiEventLoop(m), WithServerCallback(&shandler))
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := upgrade.Upgrade(w, r)
				if err != nil {
					t.Error(err)
				}

			}))

			defer ts.Close()

			url := strings.ReplaceAll(ts.URL, "http", "ws")
			con, err := Dial(url, WithClientDialTimeout(time.Second), WithClientMultiEventLoop(m), WithClientOnMessageFunc(func(c *Conn, mt Opcode, payload []byte) {
				atomic.AddInt32(&run, int32(1))
			}))
			if err != nil {
				t.Error(err)
			}
			if con == nil {
				t.Error("c is nil")
				return
			}
			defer con.Close()

			err = con.WriteCloseTimeout(st, 10*time.Second)
			if err != nil {
				t.Error(err)
			}

			select {
			case d := <-shandler.data:
				if d != "eof" {
					t.Errorf("write message or read message fail:got:%s, need:hello\n", d)
				}
			case <-time.After(1000 * time.Millisecond):
			}
			if atomic.LoadInt32(&shandler.run) != 1 {
				t.Errorf("not run server:method fail, status code index:%d", scindex)
			}
		}
	})

	t.Run("8.fail-control", func(t *testing.T) {
		run := int32(0)
		data := make(chan string, 1)
		upgrade := NewUpgrade(WithServerMultiEventLoop(m), WithServerOnCloseFunc(func(c *Conn, err error) {
			atomic.AddInt32(&run, 1)
			data <- err.Error()
		}))
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := upgrade.Upgrade(w, r)
			if err != nil {
				t.Errorf("upgrader:%s", err)
			}

		}))

		defer ts.Close()

		url := strings.ReplaceAll(ts.URL, "http", "ws")
		con, err := Dial(url, WithClientDialTimeout(time.Second), WithClientMultiEventLoop(m), WithClientDisableBufioClearHack(),
			WithClientEnableUTF8Check(), WithClientOnCloseFunc(func(c *Conn, err error) {
			}))
		if err != nil {
			t.Error(err)
		}
		if con == nil {
			t.Error("c is nil")
			return
		}
		defer con.Close()
		// 这里必须要报错
		err = con.WriteMessage(4 /*这是rfc保留的frame*/, []byte("hello"))
		if err != nil {
			t.Error("not error")
		}

		select {
		case <-data:
		case <-time.After(500 * time.Millisecond):
		}

		if atomic.LoadInt32(&run) != 1 {
			t.Errorf("not run server:method fail:%d\n", atomic.LoadInt32(&run))
		}
	})
}
