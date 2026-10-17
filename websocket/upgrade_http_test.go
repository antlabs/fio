//go:build linux || darwin

package websocket

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/antlabs/fio/engine"
	fiohttp "github.com/antlabs/fio/http"
)

type nativeUpgradeCallback struct {
	DefCallback
	opened   atomic.Bool
	badOrder atomic.Bool
	mu       sync.Mutex
	msgs     []string
	done     chan struct{}
}

func (h *nativeUpgradeCallback) OnOpen(*Conn) { h.opened.Store(true) }

func (h *nativeUpgradeCallback) OnMessage(c *Conn, op Opcode, msg []byte) {
	if !h.opened.Load() {
		h.badOrder.Store(true)
	}
	h.mu.Lock()
	h.msgs = append(h.msgs, string(msg))
	h.mu.Unlock()
	_ = c.WriteMessage(op, msg)
	h.done <- struct{}{}
}

func (h *nativeUpgradeCallback) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.msgs...)
}

// 在 fio 自己的 http 服务端上做 WebSocket 握手（native upgrade），并且
// 把握手和第一帧拼在同一次 write 里——这是 handlerChanged 那条路径。
func TestUpgradeConnNative(t *testing.T) {
	cb := &nativeUpgradeCallback{done: make(chan struct{}, 2)}
	// 默认 worker 池（不是 inline）：handler 切换发生在 worker 的
	// OnData 里，readAndDispatch 也在同一个 worker 上继续消费剩余字节。
	m := NewMultiEventLoopMust(
		WithEventLoops(1),
		WithLogLevel(slog.LevelError),
	)
	m.Start()
	defer m.Free()

	up := NewUpgrade(
		WithServerMultiEventLoop(m),
		WithServerCallback(cb),
	)
	newHandler := func() engine.Handler {
		ch := fiohttp.NewConnHandler(fiohttp.HandlerFunc(func(*fiohttp.Ctx) error {
			return nil
		}), 0)
		ch.OnUpgrade(func(c *engine.Conn, r *fiohttp.Request) {
			if _, err := up.UpgradeConn(c, r); err != nil {
				t.Logf("upgrade: %v", err)
			}
		})
		return ch
	}
	ln, err := engine.ListenAndServe(m.MultiEventLoop, "127.0.0.1:0", newHandler)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 握手 + 第一帧一次写出去。
	req := "GET /ws HTTP/1.1\r\n" +
		"Host: " + ln.Addr() + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write(append([]byte(req), maskedTextFrame("hello")...)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("握手响应: %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if got := string(readTextFrame(t, br)); got != "hello" {
		t.Fatalf("第一帧回显 %q, want hello", got)
	}

	// 握手之后单独发一帧：继续走新 handler。
	if _, err := conn.Write(maskedTextFrame("world")); err != nil {
		t.Fatal(err)
	}
	if got := string(readTextFrame(t, br)); got != "world" {
		t.Fatalf("第二帧回显 %q, want world", got)
	}

	select {
	case <-cb.done:
	case <-time.After(2 * time.Second):
		t.Fatal("回调没有收到消息")
	}
	select {
	case <-cb.done:
	case <-time.After(2 * time.Second):
		t.Fatal("回调没有收到第二帧")
	}
	if cb.badOrder.Load() {
		t.Fatal("OnMessage 跑在 OnOpen 前面")
	}
	if got := cb.messages(); len(got) != 2 || got[0] != "hello" || got[1] != "world" {
		t.Fatalf("回调消息 %v", got)
	}
}

func maskedTextFrame(payload string) []byte {
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	frame := make([]byte, 0, 6+len(payload))
	frame = append(frame, 0x81, byte(0x80|len(payload)))
	frame = append(frame, mask[:]...)
	for i := 0; i < len(payload); i++ {
		frame = append(frame, payload[i]^mask[i%4])
	}
	return frame
}

func readTextFrame(t *testing.T, br *bufio.Reader) []byte {
	t.Helper()
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != 0x81 {
		t.Fatalf("opcode/fin = %#x", hdr[0])
	}
	n := int(hdr[1] & 0x7f)
	if n > 125 {
		t.Fatalf("unexpected payload length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		t.Fatal(err)
	}
	return payload
}
