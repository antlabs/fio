package engine

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func runEcho(t *testing.T, batch int) (gets, puts, realloc int64) {
	m, err := NewAndStart(WithEventLoops(1))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Free()
	ln, err := ListenAndServe(m, "127.0.0.1:0", func() Handler { return echoHandler{} })
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const n = 2000
	msg := make([]byte, 1024*batch)
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	for i := 0; i < n; i++ {
		if _, err := conn.Write(msg); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
	}
	return m.RbufGetNum(), m.RbufPutNum(), m.ReallocNum()
}

// batch=1: 一条一条发; batch=10: 一次发 10KB（Pipeline 那样）
func TestRbufChurn1(t *testing.T) {
	g, p, r := runEcho(t, 1)
	fmt.Printf("CHURN batch=1 msgs=2000 gets=%d puts=%d realloc=%d\n", g, p, r)
}
func TestRbufChurn10(t *testing.T) {
	g, p, r := runEcho(t, 10)
	fmt.Printf("CHURN batch=10 msgs=2000 gets=%d puts=%d realloc=%d\n", g, p, r)
}
