//go:build darwin || linux

package win

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// guestRun runs dll!name in a goroutine and returns its result or the
// process exit code; it fails the test after limit.
func guestRun(t *testing.T, h *testEmu, limit time.Duration, dll, name string, args ...uint64) (ret uint64, exited bool, code uint32) {
	t.Helper()
	type res struct {
		ret    uint64
		exited bool
		code   uint32
	}
	done := make(chan res, 1)
	go func() {
		r, x, c := h.tryCall(dll, name, args...)
		done <- res{r, x, c}
	}()
	select {
	case r := <-done:
		return r.ret, r.exited, r.code
	case <-time.After(limit):
		t.Fatalf("%s!%s did not return within %v", dll, name, limit)
	}
	return
}

// dialLater connects to 127.0.0.1:port from the host after d (longer than
// the deadlock detector's window).
func dialLater(t *testing.T, port uint16, d time.Duration) {
	t.Helper()
	go func() {
		time.Sleep(d)
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			t.Cleanup(func() { c.Close() })
		}
	}()
}

// An open but idle socket must not hide a real deadlock: an INFINITE wait on
// an event nobody can set still terminates with STATUS_POSSIBLE_DEADLOCK.
func TestWinsockIdleSocketDoesNotMaskDeadlock(t *testing.T) {
	h := wsaInit(t)
	listener4(t, h)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	_, exited, code := guestRun(t, h, 20*time.Second, dK32, "WaitForSingleObject", ev, infinite)
	if !exited || code != 0xC0000194 {
		t.Fatalf("exited=%v code=%#x, want deadlock termination 0xC0000194", exited, code)
	}
}

// A thread blocked in accept (no timeout) is never reported as deadlocked.
func TestWinsockBlockedAcceptNotDeadlocked(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	dialLater(t, port, 3*time.Second)
	r, exited, code := guestRun(t, h, 20*time.Second, ws2, "accept", ls, 0, 0)
	if exited || r == sockErr {
		t.Fatalf("accept = %#x exited=%v code=%#x err %d", r, exited, code, h.lastError())
	}
}

// A wait on an event associated with a socket by WSAEventSelect is not a
// deadlock: the network can set it.
func TestWinsockEventSelectWaitNotDeadlocked(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	ev := h.call(ws2, "WSACreateEvent")
	if r := h.call(ws2, "WSAEventSelect", ls, ev, fdAccept); r != 0 {
		t.Fatalf("WSAEventSelect err %d", h.lastError())
	}
	dialLater(t, port, 3*time.Second)
	r, exited, code := guestRun(t, h, 20*time.Second, dK32, "WaitForSingleObject", ev, infinite)
	if exited || r != 0 {
		t.Fatalf("wait = %#x exited=%v code=%#x", r, exited, code)
	}
}
