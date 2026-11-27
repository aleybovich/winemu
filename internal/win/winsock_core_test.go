//go:build darwin || linux

package win

import (
	"testing"
)

const ws2 = "ws2_32.dll"

// wsaInit returns a harness with WSAStartup done.
func wsaInit(t *testing.T) *testEmu {
	t.Helper()
	h := newTestEmu(t)
	if r := h.call(ws2, "WSAStartup", 0x0202, h.alloc(408)); r != 0 {
		t.Fatalf("WSAStartup = %d", r)
	}
	return h
}

// sin builds a sockaddr_in for 127.0.0.1:port.
func sin(h *testEmu, ip [4]byte, port uint16) uint64 {
	a := h.alloc(16)
	h.write(a, []byte{2, 0, byte(port >> 8), byte(port), ip[0], ip[1], ip[2], ip[3]})
	return a
}

// sin6 builds a sockaddr_in6 for [::1]:port.
func sin6Loop(h *testEmu, port uint16) uint64 {
	a := h.alloc(28)
	h.write(a, []byte{23, 0, byte(port >> 8), byte(port)})
	h.write(a+8+15, []byte{1})
	return a
}

func sockPort(h *testEmu, a uint64) uint16 {
	b := h.read(a+2, 2)
	return uint16(b[0])<<8 | uint16(b[1])
}

var loop4 = [4]byte{127, 0, 0, 1}

// listener4 creates a TCP socket listening on 127.0.0.1:<ephemeral>.
func listener4(t *testing.T, h *testEmu) (s uint64, port uint16) {
	t.Helper()
	s = h.call(ws2, "socket", 2, 1, 6)
	if s == sockErr {
		t.Fatalf("socket: %d", h.lastError())
	}
	if r := h.call(ws2, "bind", s, sin(h, loop4, 0), 16); r != 0 {
		t.Fatalf("bind = %#x, err %d", r, h.lastError())
	}
	if r := h.call(ws2, "listen", s, 5); r != 0 {
		t.Fatalf("listen = %#x, err %d", r, h.lastError())
	}
	sa, n := h.alloc(16), h.alloc(4)
	h.w32(n, 16)
	if r := h.call(ws2, "getsockname", s, sa, n); r != 0 || h.r32(n) != 16 || h.r16(sa) != 2 {
		t.Fatalf("getsockname = %#x len %d fam %d err %d", r, h.r32(n), h.r16(sa), h.lastError())
	}
	return s, sockPort(h, sa)
}

func TestWSAStartupLayout(t *testing.T) {
	h := newTestEmu(t)
	d := h.alloc(408)
	if r := h.call(ws2, "WSAStartup", 0x0202, d); r != 0 {
		t.Fatalf("WSAStartup = %d", r)
	}
	if h.r16(d) != 0x0202 || h.r16(d+2) != 0x0202 {
		t.Fatalf("versions %#x %#x", h.r16(d), h.r16(d+2))
	}
	// 64-bit WSADATA: lpVendorInfo at 8, szDescription at 16, szSystemStatus at 273
	if h.readAStr(d+16) == "" || h.readAStr(d+273) != "Running" {
		t.Fatalf("desc %q status %q", h.readAStr(d+16), h.readAStr(d+273))
	}
	if r := h.call(ws2, "WSAStartup", 0x0000, d); r != wsaVERNOTSUPPORTED {
		t.Fatalf("WSAStartup(0.0) = %d", r)
	}
	if r := h.call(ws2, "WSAStartup", 0x0202, 0); r != wsaEFAULT {
		t.Fatalf("WSAStartup(NULL) = %d", r)
	}
	if h.call(ws2, "WSACleanup") != 0 {
		t.Fatal("WSACleanup failed")
	}
	if r := h.call(ws2, "WSACleanup"); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaNOTINITIALISED {
		t.Fatalf("second WSACleanup = %#x err %d", r, h.lastError())
	}
}

func TestSocketNotInitialised(t *testing.T) {
	h := newTestEmu(t)
	if s := h.call(ws2, "socket", 2, 1, 6); s != sockErr || h.lastError() != wsaNOTINITIALISED {
		t.Fatalf("socket before WSAStartup = %#x err %d", s, h.lastError())
	}
}

func TestSocketBadArgs(t *testing.T) {
	h := wsaInit(t)
	if s := h.call(ws2, "socket", 99, 1, 0); s != sockErr || h.lastError() != wsaEAFNOSUPPORT {
		t.Fatalf("socket(af 99) = %#x err %d", s, h.lastError())
	}
	if s := h.call(ws2, "socket", 2, 77, 0); s != sockErr || h.lastError() != wsaESOCKTNOSUPPORT {
		t.Fatalf("socket(type 77) = %#x err %d", s, h.lastError())
	}
	if r := h.call(ws2, "closesocket", 0x7FF0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaENOTSOCK {
		t.Fatalf("closesocket(bogus) = %#x err %d", r, h.lastError())
	}
	s := h.call(ws2, "socket", 2, 1, 0)
	n := h.alloc(4)
	h.w32(n, 16)
	if r := h.call(ws2, "getsockname", s, h.alloc(16), n); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEINVAL {
		t.Fatalf("getsockname(unbound) = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "bind", s, sin(h, loop4, 0), 8); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEFAULT {
		t.Fatalf("bind(short) = %#x err %d", r, h.lastError())
	}
	// a socket is a kernel handle
	if h.call(dK32, "CloseHandle", s) != 1 {
		t.Fatalf("CloseHandle(socket) err %d", h.lastError())
	}
	if r := h.call(ws2, "closesocket", s); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaENOTSOCK {
		t.Fatalf("closesocket after CloseHandle = %#x err %d", r, h.lastError())
	}
}

func TestBindListenIPv6PortZero(t *testing.T) {
	h := wsaInit(t)
	s := h.call(ws2, "WSASocketW", 23, 1, 0, 0, 0, 0x81) // WSA_FLAG_OVERLAPPED|NO_HANDLE_INHERIT
	if s == sockErr {
		t.Fatalf("WSASocketW(AF_INET6): %d", h.lastError())
	}
	if r := h.call(ws2, "bind", s, sin6Loop(h, 0), 28); r != 0 {
		t.Fatalf("bind [::1]:0 err %d", h.lastError())
	}
	if r := h.call(ws2, "listen", s, 0x7FFFFFFF); r != 0 {
		t.Fatalf("listen err %d", h.lastError())
	}
	sa, n := h.alloc(28), h.alloc(4)
	h.w32(n, 27)
	if r := h.call(ws2, "getsockname", s, sa, n); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEFAULT {
		t.Fatalf("getsockname(short buf) = %#x err %d", r, h.lastError())
	}
	h.w32(n, 28)
	if r := h.call(ws2, "getsockname", s, sa, n); r != 0 || h.r32(n) != 28 || h.r16(sa) != 23 || sockPort(h, sa) == 0 || h.read(sa+23, 1)[0] != 1 {
		t.Fatalf("getsockname = %#x len %d fam %d port %d", r, h.r32(n), h.r16(sa), sockPort(h, sa))
	}
	if h.call(ws2, "closesocket", s) != 0 {
		t.Fatal("closesocket")
	}
}

func TestAddrInUseAndRefused(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	s2 := h.call(ws2, "socket", 2, 1, 6)
	if r := h.call(ws2, "bind", s2, sin(h, loop4, port), 16); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEADDRINUSE {
		t.Fatalf("bind in-use port = %#x err %d", r, h.lastError())
	}
	h.call(ws2, "closesocket", ls)
	// nothing listens on port now -> refused (blocking connect)
	c := h.call(ws2, "socket", 2, 1, 6)
	if r := h.call(ws2, "connect", c, sin(h, loop4, port), 16); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaECONNREFUSED {
		t.Fatalf("connect refused = %#x err %d", r, h.lastError())
	}
}
