//go:build darwin || linux

package win

import (
	"net"
	"slices"
	"testing"
	"time"
)

// An idle process with a pending overlapped receive wakes as soon as data
// arrives (host poller), not after its idle poll backoff (up to 10 ms).
func TestPollerWakeLatency(t *testing.T) {
	h := wsaInit(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s := h.call(ws2, "socket", 2, 1, 6)
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	if r := h.call(ws2, "connect", s, sin(h, loop4, uint16(l.Addr().(*net.TCPAddr).Port)), 16); r != 0 {
		t.Fatalf("connect err %d", h.lastError())
	}
	peer := <-accepted
	defer peer.Close()
	port := h.call(dK32, "CreateIoCompletionPort", s, 0, 1, 0)
	n, key, op := h.alloc(4), h.alloc(8), h.alloc(8)
	var lat []time.Duration
	for range 15 {
		sent := make(chan time.Time, 1)
		go func() {
			time.Sleep(40 * time.Millisecond) // the guest is idle meanwhile
			sent <- time.Now()
			peer.Write([]byte("x"))
		}()
		ovRecv(t, h, s, 8, ovl(h, 0))
		if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 3000); r != 1 {
			t.Fatalf("GQCS = %d err %d", r, h.lastError())
		}
		lat = append(lat, time.Since(<-sent))
	}
	slices.Sort(lat)
	if med := lat[len(lat)/2]; med > 2*time.Millisecond {
		t.Fatalf("median wake latency %v (all %v), want < 2ms", med, lat)
	}
}
