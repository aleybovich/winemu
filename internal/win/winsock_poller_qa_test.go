//go:build darwin || linux

package win

import (
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func pollerGoroutines() int {
	buf := make([]byte, 1<<20)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), "(*netPoller).run(")
}

// armedPoller returns a harness process whose poller is blocked in select on
// a pending WSARecv of a connected socket (the host peer never sends).
func armedPoller(t *testing.T) (*testEmu, uint64, net.Conn) {
	t.Helper()
	h := wsaInit(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	s := h.call(ws2, "socket", 2, 1, 6)
	if r := h.call(ws2, "connect", s, sin(h, loop4, uint16(l.Addr().(*net.TCPAddr).Port)), 16); r != 0 {
		t.Fatalf("connect err %d", h.lastError())
	}
	peer := <-accepted
	t.Cleanup(func() { peer.Close() })
	port := h.call(dK32, "CreateIoCompletionPort", s, 0, 1, 0)
	ovRecv(t, h, s, 8, ovl(h, 0))
	n, key, op := h.alloc(4), h.alloc(8), h.alloc(8)
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 60); r != 0 || h.lastError() != 258 {
		t.Fatalf("GQCS = %d err %d, want timeout", r, h.lastError())
	}
	if p := h.E.net.ovl.poller; p == nil || !p.armed {
		t.Fatalf("poller not armed after an idle wait with a pending WSARecv")
	}
	return h, s, peer
}

func waitPollers(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for pollerGoroutines() > want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := pollerGoroutines(); got > want {
		t.Fatalf("%d poller goroutines still running after process exit, want %d", got, want)
	}
}

// The poller goroutine of a process ends when the process ends, also while
// it is blocked in select on a socket that is closed by the exit.
func TestPollerExitsWithProcess(t *testing.T) {
	before := pollerGoroutines()
	h, _, _ := armedPoller(t)
	h.E.endProcess(0)
	waitPollers(t, before)
}

// ... and when the socket outlives the process (a duplicate is still open
// in another process, so its host fd stays open and never becomes ready).
func TestPollerExitsWithProcessSharedSocket(t *testing.T) {
	before := pollerGoroutines()
	h, s, _ := armedPoller(t)
	b := sibling(t, h)
	info := h.alloc(sizeofProtoInfoW)
	if r := h.call(ws2, "WSADuplicateSocketW", s, uint64(b.E.proc.pid), info); r != 0 {
		t.Fatalf("WSADuplicateSocketW err %d", h.lastError())
	}
	b.call(ws2, "WSAStartup", 0x0202, b.alloc(408))
	binfo := b.alloc(sizeofProtoInfoW)
	b.write(binfo, h.read(info, sizeofProtoInfoW))
	if bs := b.call(ws2, "WSASocketW", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, binfo, 0, 1); bs == ^uint64(0) {
		t.Fatalf("WSASocketW(FROM_PROTOCOL_INFO) err %d", b.lastError())
	}
	h.E.endProcess(0)
	waitPollers(t, before)
}
