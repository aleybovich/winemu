//go:build darwin || linux

package win

import (
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// Host errno -> WSA code for the codes callers branch on.
func TestWsaErrMapping(t *testing.T) {
	for en, want := range map[syscall.Errno]uint32{
		syscall.EAGAIN: wsaEWOULDBLOCK, syscall.EINPROGRESS: wsaEWOULDBLOCK, syscall.ECONNREFUSED: wsaECONNREFUSED,
		syscall.EADDRINUSE: wsaEADDRINUSE, syscall.ENOTCONN: wsaENOTCONN, syscall.EINVAL: wsaEINVAL,
		syscall.ECONNRESET: wsaECONNRESET, syscall.ETIMEDOUT: wsaETIMEDOUT, syscall.EISCONN: wsaEISCONN,
	} {
		if got := wsaErr(en); got != want {
			t.Errorf("wsaErr(%v) = %d, want %d", en, got, want)
		}
	}
}

// WSAStartup negotiates min(requested, 2.2); wHighVersion is always 2.2.
func TestWSAStartupVersionNegotiation(t *testing.T) {
	h := newTestEmu(t)
	d := h.alloc(408)
	for req, want := range map[uint64]uint16{0x0101: 0x0101, 0x0002: 0x0002, 0x0302: 0x0202, 0x0003: 0x0202, 0x0203: 0x0202} {
		if r := h.call(ws2, "WSAStartup", req, d); r != 0 || h.r16(d) != want || h.r16(d+2) != 0x0202 {
			t.Errorf("WSAStartup(%#x) = %d, wVersion %#x wHigh %#x, want %#x", req, r, h.r16(d), h.r16(d+2), want)
		}
	}
}

// getpeername on an unconnected socket fails with WSAENOTCONN.
func TestGetpeernameNotConnected(t *testing.T) {
	h := wsaInit(t)
	s := h.call(ws2, "socket", 2, 1, 6)
	sa, n := h.alloc(16), h.alloc(4)
	h.w32(n, 16)
	if r := h.call(ws2, "getpeername", s, sa, n); r != sockErr32 || h.lastError() != wsaENOTCONN {
		t.Fatalf("getpeername = %#x err %d", r, h.lastError())
	}
}

// MSG_WAITALL on a blocking stream socket returns only once the buffer is full.
func TestRecvWaitAll(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	go func() {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("ab"))
		time.Sleep(300 * time.Millisecond)
		c.Write([]byte("cd"))
		time.Sleep(300 * time.Millisecond)
	}()
	s := h.call(ws2, "accept", ls, 0, 0)
	if s == sockErr {
		t.Fatalf("accept err %d", h.lastError())
	}
	buf := h.alloc(8)
	if r := h.call(ws2, "recv", s, buf, 4, wsMsgWaitAll); r != 4 || string(h.read(buf, 4)) != "abcd" {
		t.Fatalf("recv(MSG_WAITALL) = %d %q err %d", int32(r), h.read(buf, 4), h.lastError())
	}
	// at EOF MSG_WAITALL returns what is left (here: graceful close -> 0)
	if r := h.call(ws2, "recv", s, buf, 4, wsMsgWaitAll); r != 0 {
		t.Fatalf("recv at EOF = %d err %d", int32(r), h.lastError())
	}
}

// A failed non-blocking connect is reported in exceptfds (not writefds) and
// SO_ERROR holds WSAECONNREFUSED.
func TestSelectFailedConnectExceptfds(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	h.call(ws2, "closesocket", ls) // nothing listens on port now
	c := h.call(ws2, "socket", 2, 1, 6)
	setNB(t, h, c, 1)
	if r := h.call(ws2, "connect", c, sin(h, loop4, port), 16); r != sockErr32 || h.lastError() != wsaEWOULDBLOCK {
		t.Fatalf("connect = %#x err %d", r, h.lastError())
	}
	wr, ex := fdset(h, c), fdset(h, c)
	tv := h.alloc(16)
	h.w32(tv, 2)
	if r := h.call(ws2, "select", 0, 0, wr, ex, tv); r != 1 || h.r32(ex) != 1 || h.r32(wr) != 0 {
		t.Fatalf("select = %d, writefds %d exceptfds %d err %d", int32(r), h.r32(wr), h.r32(ex), h.lastError())
	}
	v, n := h.alloc(4), h.alloc(4)
	h.w32(n, 4)
	if r := h.call(ws2, "getsockopt", c, 0xFFFF, 0x1007, v, n); r != 0 || h.r32(v) != wsaECONNREFUSED {
		t.Fatalf("SO_ERROR = %d (ret %#x)", h.r32(v), r)
	}
}
