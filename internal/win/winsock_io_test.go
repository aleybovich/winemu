//go:build darwin || linux

package win

import (
	"testing"
	"time"
)

const (
	fionbio  = 0x8004667E
	fionread = 0x4004667F
)

// tcpPair returns a connected (client, server) socket pair over 127.0.0.1.
func tcpPair(t *testing.T, h *testEmu) (c, s uint64) {
	t.Helper()
	ls, port := listener4(t, h)
	c = h.call(ws2, "socket", 2, 1, 6)
	if r := h.call(ws2, "connect", c, sin(h, loop4, port), 16); r != 0 {
		t.Fatalf("connect err %d", h.lastError())
	}
	sa, n := h.alloc(16), h.alloc(4)
	h.w32(n, 16)
	s = h.call(ws2, "accept", ls, sa, n)
	if s == sockErr || h.r32(n) != 16 || h.r16(sa) != 2 {
		t.Fatalf("accept = %#x len %d err %d", s, h.r32(n), h.lastError())
	}
	h.call(ws2, "closesocket", ls)
	return c, s
}

func setNB(t *testing.T, h *testEmu, s uint64, on uint32) {
	t.Helper()
	a := h.alloc(4)
	h.w32(a, on)
	if r := h.call(ws2, "ioctlsocket", s, fionbio, a); r != 0 {
		t.Fatalf("FIONBIO err %d", h.lastError())
	}
}

func TestSendRecvTCP(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	msg := h.astr("hello, socket")
	if r := h.call(ws2, "send", c, msg, 13, 0); r != 13 {
		t.Fatalf("send = %d err %d", int32(r), h.lastError())
	}
	// wait for the data to arrive, then FIONREAD
	arg := h.alloc(4)
	for i := 0; i < 100 && h.r32(arg) < 13; i++ {
		h.call(ws2, "ioctlsocket", s, fionread, arg)
		time.Sleep(time.Millisecond)
	}
	if h.r32(arg) != 13 {
		t.Fatalf("FIONREAD = %d", h.r32(arg))
	}
	buf := h.alloc(64)
	if r := h.call(ws2, "recv", s, buf, 5, 2); r != 5 || string(h.read(buf, 5)) != "hello" { // MSG_PEEK
		t.Fatalf("recv(PEEK) = %d %q", int32(r), h.read(buf, 5))
	}
	if r := h.call(ws2, "recv", s, buf, 64, 0); r != 13 || string(h.read(buf, 13)) != "hello, socket" {
		t.Fatalf("recv = %d %q err %d", int32(r), h.read(buf, 13), h.lastError())
	}
	setNB(t, h, s, 1)
	if r := h.call(ws2, "recv", s, buf, 64, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEWOULDBLOCK {
		t.Fatalf("non-blocking recv = %#x err %d", r, h.lastError())
	}
	setNB(t, h, s, 0)
	// blocking recv honours SO_RCVTIMEO
	to := h.alloc(4)
	h.w32(to, 50)
	if r := h.call(ws2, "setsockopt", s, 0xFFFF, 0x1006, to, 4); r != 0 {
		t.Fatalf("SO_RCVTIMEO err %d", h.lastError())
	}
	start := time.Now()
	if r := h.call(ws2, "recv", s, buf, 64, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaETIMEDOUT {
		t.Fatalf("recv timeout = %#x err %d", r, h.lastError())
	}
	if d := time.Since(start); d < 40*time.Millisecond {
		t.Fatalf("recv timed out after %v", d)
	}
	// graceful close -> recv returns 0
	h.call(ws2, "shutdown", c, 1)
	if r := h.call(ws2, "recv", s, buf, 64, 0); r != 0 {
		t.Fatalf("recv after peer shutdown = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "recv", 0x7FF0, buf, 64, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaENOTSOCK {
		t.Fatalf("recv(bogus) = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "ioctlsocket", s, 0x1234, arg); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEINVAL {
		t.Fatalf("ioctlsocket(bad cmd) = %#x err %d", r, h.lastError())
	}
}

func TestRecvNotConnected(t *testing.T) {
	h := wsaInit(t)
	s := h.call(ws2, "socket", 2, 1, 6)
	buf := h.alloc(8)
	if r := h.call(ws2, "recv", s, buf, 8, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaENOTCONN {
		t.Fatalf("recv(unconnected) = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "send", s, buf, 8, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaENOTCONN {
		t.Fatalf("send(unconnected) = %#x err %d", r, h.lastError())
	}
}

func TestUDPSendtoRecvfrom(t *testing.T) {
	h := wsaInit(t)
	a := h.call(ws2, "socket", 2, 2, 17)
	b := h.call(ws2, "socket", 2, 2, 17)
	if h.call(ws2, "bind", a, sin(h, loop4, 0), 16) != 0 {
		t.Fatalf("bind err %d", h.lastError())
	}
	sa, n := h.alloc(16), h.alloc(4)
	h.w32(n, 16)
	h.call(ws2, "getsockname", a, sa, n)
	if r := h.call(ws2, "sendto", b, h.astr("datagram"), 8, 0, sa, 16); r != 8 {
		t.Fatalf("sendto = %#x err %d", r, h.lastError())
	}
	from, fl := h.alloc(16), h.alloc(4)
	h.w32(fl, 16)
	buf := h.alloc(16)
	if r := h.call(ws2, "recvfrom", a, buf, 16, 0, from, fl); r != 8 || string(h.read(buf, 8)) != "datagram" || h.r16(from) != 2 || h.r32(fl) != 16 {
		t.Fatalf("recvfrom = %#x %q fam %d err %d", r, h.read(buf, 8), h.r16(from), h.lastError())
	}
	// truncated datagram -> WSAEMSGSIZE with the buffer filled
	h.call(ws2, "sendto", b, h.astr("0123456789"), 10, 0, sa, 16)
	if r := h.call(ws2, "recvfrom", a, buf, 4, 0, 0, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEMSGSIZE || string(h.read(buf, 4)) != "0123" {
		t.Fatalf("short recvfrom = %#x err %d %q", r, h.lastError(), h.read(buf, 4))
	}
	if r := h.call(ws2, "sendto", b, buf, 4, 0, sa, 3); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEFAULT {
		t.Fatalf("sendto(short addr) = %#x err %d", r, h.lastError())
	}
}

// fdset writes a Windows fd_set {u_int fd_count; SOCKET fd_array[64]}.
func fdset(h *testEmu, socks ...uint64) uint64 {
	a := h.alloc(8 + 64*8)
	h.w32(a, uint32(len(socks)))
	for i, s := range socks {
		h.w64(a+8+8*uint64(i), s)
	}
	return a
}

func TestSelect(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	tv := h.alloc(8) // timeval{0, 20000}
	h.w32(tv+4, 20000)
	rd := fdset(h, s)
	if r := h.call(ws2, "select", 0, rd, 0, 0, tv); r != 0 || h.r32(rd) != 0 {
		t.Fatalf("select(no data) = %d count %d", int32(r), h.r32(rd))
	}
	h.call(ws2, "send", c, h.astr("x"), 1, 0)
	h.w32(tv+4, 0)
	h.w32(tv, 1)
	if r := h.call(ws2, "select", 0, fdset(h, s), 0, 0, tv); r != 1 {
		t.Fatalf("select(wait for data) = %d err %d", int32(r), h.lastError())
	}
	rd = fdset(h, s, c)
	wr := fdset(h, c)
	if r := h.call(ws2, "select", 0, rd, wr, 0, 0); r != 2 || h.r32(rd) != 1 || h.r64(rd+8) != s || h.r32(wr) != 1 {
		t.Fatalf("select = %d rd %d/%#x wr %d err %d", int32(r), h.r32(rd), h.r64(rd+8), h.r32(wr), h.lastError())
	}
	if h.call(ws2, "__WSAFDIsSet", s, rd) == 0 || h.call(ws2, "__WSAFDIsSet", c, rd) != 0 {
		t.Fatal("__WSAFDIsSet")
	}
	if r := h.call(ws2, "select", 0, fdset(h, 0x7FF0), 0, 0, tv); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaENOTSOCK {
		t.Fatalf("select(bogus) = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "select", 0, 0, 0, 0, tv); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEINVAL {
		t.Fatalf("select(no sets) = %#x err %d", r, h.lastError())
	}
}
