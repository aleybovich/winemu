//go:build darwin || linux

package win

import (
	"strings"
	"testing"
	"time"
)

func TestWinsockOrdinals(t *testing.T) {
	h := wsaInit(t)
	for _, c := range []struct {
		dll  string
		ords map[uint32]string
	}{{"ws2_32.dll", ws2Ordinals}, {"wsock32.dll", wsock32Ordinals}} {
		mod := h.call(dK32, "LoadLibraryA", h.astr(c.dll))
		if mod == 0 {
			t.Fatalf("LoadLibrary(%s) err %d", c.dll, h.lastError())
		}
		for o, name := range c.ords {
			if registry[c.dll].funcs[name] == nil {
				continue // not implemented: neither by name nor by ordinal
			}
			byOrd := h.call(dK32, "GetProcAddress", mod, uint64(o))
			byName := h.call(dK32, "GetProcAddress", mod, h.astr(name))
			if byOrd == 0 || byOrd != byName {
				t.Errorf("%s: ordinal %d -> %#x, %s -> %#x", c.dll, o, byOrd, name, byName)
			}
		}
	}
	// spot-check the classic numbering, incl. where ws2_32 and wsock32 differ
	for dll, want := range map[string]map[uint32]string{
		"ws2_32.dll":  {10: "ioctlsocket", 11: "inet_addr", 12: "inet_ntoa", 51: "gethostbyaddr", 55: "getservbyname", 56: "getservbyport", 151: "__WSAFDIsSet"},
		"wsock32.dll": {10: "inet_addr", 11: "inet_ntoa", 12: "ioctlsocket", 52: "gethostbyname", 115: "WSAStartup", 1107: "WSARecvEx"},
	} {
		for o, n := range want {
			if registry[dll].ords[o] != n {
				t.Errorf("%s ordinal %d = %q, want %q", dll, o, registry[dll].ords[o], n)
			}
		}
	}
}

func TestWsock32Forwarders(t *testing.T) {
	for _, n := range wsock32Forwarded {
		if registry["ws2_32.dll"].funcs[n] == nil {
			t.Errorf("wsock32 forwards %s, which ws2_32 does not implement", n)
		}
	}
	h := newTestEmu(t)
	if r := h.call("wsock32.dll", "WSAStartup", 0x0101, h.alloc(408)); r != 0 {
		t.Fatalf("wsock32 WSAStartup = %d", r)
	}
	if r := h.call("wsock32.dll", "inet_addr", h.astr("1.2.3.4")); uint32(r) != 0x04030201 {
		t.Fatalf("wsock32 inet_addr = %#x", r)
	}
}

func TestWSASendRecvBuffers(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	// two WSABUFs: "abc" + "defg"
	bufs := h.alloc(32)
	h.w32(bufs, 3)
	h.w64(bufs+8, h.astr("abc"))
	h.w32(bufs+16, 4)
	h.w64(bufs+24, h.astr("defg"))
	sent := h.alloc(4)
	if r := h.call(ws2, "WSASend", c, bufs, 2, sent, 0, 0, 0); r != 0 || h.r32(sent) != 7 {
		t.Fatalf("WSASend = %#x sent %d err %d", r, h.r32(sent), h.lastError())
	}
	// receive into 2+16 byte buffers, waiting for all 7 bytes
	rb := h.alloc(32)
	b1, b2 := h.alloc(2), h.alloc(16)
	h.w32(rb, 2)
	h.w64(rb+8, b1)
	h.w32(rb+16, 16)
	h.w64(rb+24, b2)
	got, flags := h.alloc(4), h.alloc(4)
	deadline := time.Now().Add(time.Second)
	total := ""
	for len(total) < 7 && time.Now().Before(deadline) {
		h.w32(flags, 0)
		if r := h.call(ws2, "WSARecv", s, rb, 2, got, flags, 0, 0); r != 0 {
			t.Fatalf("WSARecv = %#x err %d", r, h.lastError())
		}
		n := int(h.r32(got))
		total += string(h.read(b1, min(n, 2))) + string(h.read(b2, max(n-2, 0)))
	}
	if total != "abcdefg" {
		t.Fatalf("WSARecv got %q", total)
	}
	if r := h.call(ws2, "WSARecv", s, rb, 2, got, 0, 0, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEFAULT {
		t.Fatalf("WSARecv(NULL flags) = %#x err %d", r, h.lastError())
	}
	// overlapped WSASend on a writable socket completes at once (WS-B2)
	if r := h.call(ws2, "WSASend", c, bufs, 2, sent, 0, h.alloc(32), 0); r != 0 || h.r32(sent) == 0 {
		t.Fatalf("overlapped WSASend = %#x sent %d err %d", r, h.r32(sent), h.lastError())
	}
}

func TestWSAPollAndIoctl(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	fds := h.alloc(32) // {s, POLLRDNORM}, {c, POLLWRNORM}
	h.w64(fds, s)
	h.w16(fds+8, pollRdNorm)
	h.w64(fds+16, c)
	h.w16(fds+24, pollWrNorm)
	if r := h.call(ws2, "WSAPoll", fds, 2, 0); r != 1 || h.r16(fds+10) != 0 || h.r16(fds+26) != pollWrNorm {
		t.Fatalf("WSAPoll = %d rev %#x %#x", int32(r), h.r16(fds+10), h.r16(fds+26))
	}
	h.call(ws2, "send", c, h.astr("z"), 1, 0)
	if r := h.call(ws2, "WSAPoll", fds, 1, 1000); r != 1 || h.r16(fds+10) != pollRdNorm {
		t.Fatalf("WSAPoll(wait) = %d rev %#x", int32(r), h.r16(fds+10))
	}
	out, n := h.alloc(4), h.alloc(4)
	if r := h.call(ws2, "WSAIoctl", s, fionread, 0, 0, out, 4, n, 0, 0); r != 0 || h.r32(out) != 1 || h.r32(n) != 4 {
		t.Fatalf("WSAIoctl(FIONREAD) = %#x %d err %d", r, h.r32(out), h.lastError())
	}
	ka := h.alloc(12)
	h.w32(ka, 1)
	h.w32(ka+4, 30000)
	h.w32(ka+8, 5000)
	if r := h.call(ws2, "WSAIoctl", c, sioKeepalive, ka, 12, 0, 0, n, 0, 0); r != 0 {
		t.Fatalf("SIO_KEEPALIVE_VALS err %d", h.lastError())
	}
	opt, ol := h.alloc(4), h.alloc(4)
	h.w32(ol, 4)
	if h.call(ws2, "getsockopt", c, 0xFFFF, 8, opt, ol); h.r32(opt) != 1 {
		t.Fatalf("SO_KEEPALIVE after SIO_KEEPALIVE_VALS = %d", h.r32(opt))
	}
	if r := h.call(ws2, "WSAIoctl", c, 0x12345678, 0, 0, 0, 0, n, 0, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEOPNOTSUPP {
		t.Fatalf("WSAIoctl(unknown) = %#x err %d", r, h.lastError())
	}
	h.w64(fds, 0x7FF0)
	if r := h.call(ws2, "WSAPoll", fds, 1, 0); r != 1 || h.r16(fds+10) != pollNval {
		t.Fatalf("WSAPoll(bogus) = %d rev %#x", int32(r), h.r16(fds+10))
	}
}

func TestSockOpts(t *testing.T) {
	h := wsaInit(t)
	s := h.call(ws2, "socket", 23, 1, 6)
	opt, ol := h.alloc(8), h.alloc(4)
	get := func(level, name uint64) (uint64, uint32) {
		h.w32(ol, 4)
		h.w32(opt, 0xAAAA)
		return h.call(ws2, "getsockopt", s, level, name, opt, ol), h.r32(opt)
	}
	if r, v := get(41, 27); r != 0 || v != 1 {
		t.Fatalf("IPV6_V6ONLY default = %d (r %#x)", v, r)
	}
	h.w32(opt, 1)
	for _, o := range [][2]uint64{{0xFFFF, 4}, {6, 1}, {0xFFFF, 8}, {0xFFFF, 0xFFFFFFFB}} {
		h.w32(opt, 1)
		if r := h.call(ws2, "setsockopt", s, o[0], o[1], opt, 4); r != 0 {
			t.Fatalf("setsockopt(%#x,%#x) err %d", o[0], o[1], h.lastError())
		}
		if r, v := get(o[0], o[1]); r != 0 || v != 1 {
			t.Fatalf("getsockopt(%#x,%#x) = %d", o[0], o[1], v)
		}
	}
	if r, v := get(0xFFFF, 0x1008); r != 0 || v != 1 {
		t.Fatalf("SO_TYPE = %d", v)
	}
	if r, v := get(0xFFFF, 0x1007); r != 0 || v != 0 {
		t.Fatalf("SO_ERROR = %d", v)
	}
	h.w32(opt, 1|5<<16)
	if r := h.call(ws2, "setsockopt", s, 0xFFFF, 0x80, opt, 4); r != 0 {
		t.Fatalf("SO_LINGER err %d", h.lastError())
	}
	if _, v := get(0xFFFF, 0x80); v != 1|5<<16 {
		t.Fatalf("SO_LINGER = %#x", v)
	}
	if r := h.call(ws2, "setsockopt", s, 0xFFFF, 4, opt, 2); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEFAULT {
		t.Fatalf("setsockopt(short) = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "setsockopt", s, 0xFFFF, 0x7777, opt, 4); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaENOPROTOOPT {
		t.Fatalf("setsockopt(unknown) = %#x err %d", r, h.lastError())
	}
	h.w32(ol, 2)
	if r := h.call(ws2, "getsockopt", s, 0xFFFF, 4, opt, ol); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEFAULT {
		t.Fatalf("getsockopt(short) = %#x err %d", r, h.lastError())
	}
	s4 := h.call(ws2, "socket", 2, 1, 6)
	h.w32(ol, 4)
	if r := h.call(ws2, "getsockopt", s4, 41, 27, opt, ol); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEINVAL {
		t.Fatalf("IPV6_V6ONLY on IPv4 socket = %#x err %d", r, h.lastError())
	}
}

func TestWSAAcceptCondition(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	code := h.call(dK32, "VirtualAlloc", 0, 4096, 0x3000, 0x40)
	h.write(code, []byte{0xB8, cfReject, 0, 0, 0, 0xC3}) // mov eax, CF_REJECT; ret
	c := h.call(ws2, "socket", 2, 1, 6)
	h.call(ws2, "connect", c, sin(h, loop4, port), 16)
	if r := h.call(ws2, "WSAAccept", ls, 0, 0, code, 0); r != sockErr || h.lastError() != wsaECONNREFUSED {
		t.Fatalf("WSAAccept(reject) = %#x err %d", r, h.lastError())
	}
	h.write(code, []byte{0xB8, cfAccept, 0, 0, 0, 0xC3})
	c2 := h.call(ws2, "socket", 2, 1, 6)
	h.call(ws2, "connect", c2, sin(h, loop4, port), 16)
	if r := h.call(ws2, "WSAAccept", ls, 0, 0, code, 0); r == sockErr {
		t.Fatalf("WSAAccept(accept) err %d", h.lastError())
	}
}

func TestWSAErrorMessages(t *testing.T) {
	h := newTestEmu(t)
	buf := h.alloc(512)
	if r := h.call(dK32, "FormatMessageA", 0x1200, 0, wsaECONNREFUSED, 0, buf, 512, 0); r == 0 || !strings.HasPrefix(h.readAStr(buf), "No connection could be made") {
		t.Fatalf("FormatMessage(10061) = %d %q", r, h.readAStr(buf))
	}
}
