//go:build darwin || linux

package win

import "testing"

// addrinfo walks a Windows (A or W) addrinfo list:
// flags@0 family@4 socktype@8 protocol@12 addrlen@16 canonname@24 addr@32 next@40.
type aiEntry struct {
	family, socktype, proto uint32
	addrlen                 uint64
	port                    uint16
	addr                    []byte
}

func readAddrinfo(h *testEmu, p uint64) []aiEntry {
	var out []aiEntry
	for ; p != 0; p = h.r64(p + 40) {
		sa := h.r64(p + 32)
		x := aiEntry{family: h.r32(p + 4), socktype: h.r32(p + 8), proto: h.r32(p + 12), addrlen: h.r64(p + 16), port: sockPort(h, sa)}
		if x.family == 2 {
			x.addr = h.read(sa+4, 4)
		} else {
			x.addr = h.read(sa+8, 16)
		}
		out = append(out, x)
	}
	return out
}

func TestGetaddrinfoLocalhost(t *testing.T) {
	h := wsaInit(t)
	hints := h.alloc(48)
	h.w32(hints+8, 1) // SOCK_STREAM
	res := h.alloc(8)
	if r := h.call(ws2, "getaddrinfo", h.astr("localhost"), h.astr("80"), hints, res); r != 0 {
		t.Fatalf("getaddrinfo = %d", r)
	}
	es := readAddrinfo(h, h.r64(res))
	if len(es) != 2 || es[0].family != 23 || es[1].family != 2 || es[1].addrlen != 16 || es[0].addrlen != 28 {
		t.Fatalf("entries %+v", es)
	}
	for _, x := range es {
		if x.port != 80 || x.socktype != 1 || x.proto != 6 {
			t.Fatalf("entry %+v", x)
		}
	}
	if string(es[1].addr) != "\x7f\x00\x00\x01" || es[0].addr[15] != 1 {
		t.Fatalf("addrs %v %v", es[0].addr, es[1].addr)
	}
	h.call(ws2, "freeaddrinfo", h.r64(res))

	// IPv4 only, wide, numeric, canonical name
	h.w32(hints+4, 2)
	h.w32(hints, 2|4) // AI_CANONNAME|AI_NUMERICHOST
	if r := h.call(ws2, "GetAddrInfoW", h.wstr("10.1.2.3"), 0, hints, res); r != 0 {
		t.Fatalf("GetAddrInfoW = %d", r)
	}
	es = readAddrinfo(h, h.r64(res))
	if len(es) != 1 || string(es[0].addr) != "\x0a\x01\x02\x03" || h.readWStr(h.r64(h.r64(res)+24)) != "10.1.2.3" {
		t.Fatalf("entries %+v", es)
	}
	h.call(ws2, "FreeAddrInfoW", h.r64(res))
	if r := h.call(ws2, "getaddrinfo", h.astr("not-numeric"), 0, hints, res); r != wsaHOSTNOTFOUND || h.lastError() != wsaHOSTNOTFOUND {
		t.Fatalf("AI_NUMERICHOST(name) = %d", r)
	}
	if r := h.call(ws2, "getaddrinfo", 0, 0, 0, res); r != wsaHOSTNOTFOUND {
		t.Fatalf("getaddrinfo(NULL,NULL) = %d", r)
	}
	h.w32(hints, 0)
	h.w32(hints+4, 99)
	if r := h.call(ws2, "getaddrinfo", h.astr("localhost"), 0, hints, res); r != wsaEAFNOSUPPORT {
		t.Fatalf("bad family = %d", r)
	}
	// passive, no node -> wildcard
	h.w32(hints+4, 23)
	h.w32(hints, 1)
	if r := h.call(ws2, "getaddrinfo", 0, h.astr("8080"), hints, res); r != 0 {
		t.Fatalf("passive = %d", r)
	}
	if es = readAddrinfo(h, h.r64(res)); len(es) != 1 || es[0].port != 8080 || string(es[0].addr) != string(make([]byte, 16)) {
		t.Fatalf("passive %+v", es)
	}
	if r := h.call(ws2, "getaddrinfo", h.astr("localhost"), h.astr("no-such-service-xyz"), hints, res); r != wsaTYPENOTFOUND {
		t.Fatalf("bad service = %d", r)
	}
}

func TestGetnameinfo(t *testing.T) {
	h := wsaInit(t)
	host, serv := h.alloc(64), h.alloc(16)
	if r := h.call(ws2, "getnameinfo", sin(h, [4]byte{192, 168, 1, 7}, 8080), 16, host, 64, serv, 16, 2|8); r != 0 || h.readAStr(host) != "192.168.1.7" || h.readAStr(serv) != "8080" {
		t.Fatalf("getnameinfo numeric = %d %q %q", r, h.readAStr(host), h.readAStr(serv))
	}
	if r := h.call(ws2, "getnameinfo", sin6Loop(h, 443), 28, host, 64, serv, 16, 2); r != 0 || h.readAStr(host) != "::1" || h.readAStr(serv) != "https" {
		t.Fatalf("getnameinfo v6 = %d %q %q", r, h.readAStr(host), h.readAStr(serv))
	}
	if r := h.call(ws2, "getnameinfo", sin(h, loop4, 1), 16, host, 64, 0, 0, 0); r != 0 || h.readAStr(host) != "localhost" {
		t.Fatalf("getnameinfo loopback = %d %q", r, h.readAStr(host))
	}
	if r := h.call(ws2, "getnameinfo", sin(h, loop4, 1), 16, host, 3, 0, 0, 2); r != wsaEFAULT {
		t.Fatalf("getnameinfo(small) = %d", r)
	}
	if r := h.call(ws2, "getnameinfo", sin(h, loop4, 1), 8, host, 64, 0, 0, 2); r != wsaEFAULT {
		t.Fatalf("getnameinfo(short sa) = %d", r)
	}
	whost := h.alloc(128)
	if r := h.call(ws2, "GetNameInfoW", sin(h, loop4, 80), 16, whost, 64, 0, 0, 2); r != 0 || h.readWStr(whost) != "127.0.0.1" {
		t.Fatalf("GetNameInfoW = %d %q", r, h.readWStr(whost))
	}
}

func TestInetConversions(t *testing.T) {
	h := wsaInit(t)
	dst := h.alloc(64)
	if r := h.call(ws2, "inet_pton", 2, h.astr("1.2.3.4"), dst); r != 1 || string(h.read(dst, 4)) != "\x01\x02\x03\x04" {
		t.Fatalf("inet_pton v4 = %d", r)
	}
	if r := h.call(ws2, "inet_pton", 2, h.astr("1.2.3"), dst); r != 0 {
		t.Fatalf("inet_pton(invalid) = %d", r)
	}
	if r := h.call(ws2, "inet_pton", 99, h.astr("1.2.3.4"), dst); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEAFNOSUPPORT {
		t.Fatalf("inet_pton(bad af) = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "InetPtonW", 23, h.wstr("fe80::1"), dst); r != 1 || h.r16(dst) != 0x80fe || h.read(dst+15, 1)[0] != 1 {
		t.Fatalf("InetPtonW = %d", r)
	}
	out := h.alloc(64)
	if r := h.call(ws2, "inet_ntop", 23, dst, out, 64); r != out || h.readAStr(out) != "fe80::1" {
		t.Fatalf("inet_ntop = %#x %q", r, h.readAStr(out))
	}
	if r := h.call(ws2, "InetNtopW", 2, sin(h, loop4, 0)+4, out, 16); r != out || h.readWStr(out) != "127.0.0.1" {
		t.Fatalf("InetNtopW = %#x %q", r, h.readWStr(out))
	}
	if r := h.call(ws2, "inet_ntop", 2, dst, out, 4); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("inet_ntop(small) = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "inet_addr", h.astr("127.0.0.1")); uint32(r) != 0x0100007F {
		t.Fatalf("inet_addr = %#x", r)
	}
	if r := h.call(ws2, "inet_addr", h.astr("0x7f.1")); uint32(r) != 0x0100007F {
		t.Fatalf("inet_addr(short form) = %#x", r)
	}
	if r := h.call(ws2, "inet_addr", h.astr("300.1.1.1")); uint32(r) != 0xFFFFFFFF {
		t.Fatalf("inet_addr(invalid) = %#x", r)
	}
	if r := h.call(ws2, "inet_ntoa", 0x0100007F); h.readAStr(r) != "127.0.0.1" {
		t.Fatalf("inet_ntoa = %q", h.readAStr(r))
	}
}

func TestHostNameAndHostent(t *testing.T) {
	h := wsaInit(t)
	buf := h.alloc(256)
	if r := h.call(ws2, "gethostname", buf, 256); r != 0 || h.readAStr(buf) == "" {
		t.Fatalf("gethostname = %d %q", r, h.readAStr(buf))
	}
	name := h.readAStr(buf)
	if r := h.call(ws2, "gethostname", buf, 2); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEFAULT {
		t.Fatalf("gethostname(small) = %#x err %d", r, h.lastError())
	}
	// hostent: h_name@0 h_aliases@8 h_addrtype@16 h_length@18 h_addr_list@24
	he := h.call(ws2, "gethostbyname", h.astr(name))
	if he == 0 || h.r16(he+16) != 2 || h.r16(he+18) != 4 || h.r64(h.r64(he+24)) == 0 {
		t.Fatalf("gethostbyname(own name) = %#x err %d", he, h.lastError())
	}
	he = h.call(ws2, "gethostbyname", h.astr("localhost"))
	if he == 0 || string(h.read(h.r64(h.r64(he+24)), 4)) != "\x7f\x00\x00\x01" {
		t.Fatalf("gethostbyname(localhost) = %#x", he)
	}
	// servent (Win64): s_name@0 s_aliases@8 s_proto@16 s_port@24
	se := h.call(ws2, "getservbyname", h.astr("http"), h.astr("tcp"))
	if se == 0 || h.r16(se+24) != 0x5000 || h.readAStr(h.r64(se+16)) != "tcp" {
		t.Fatalf("getservbyname = %#x", se)
	}
	se = h.call(ws2, "getservbyport", 0xBB01, 0)
	if se == 0 || h.readAStr(h.r64(se)) != "https" {
		t.Fatalf("getservbyport = %#x", se)
	}
	if h.call(ws2, "getservbyname", h.astr("no-such-svc"), 0) != 0 || h.lastError() != wsaNODATA {
		t.Fatal("getservbyname(unknown)")
	}
	// protoent: p_name@0 p_aliases@8 p_proto@16
	pe := h.call(ws2, "getprotobyname", h.astr("udp"))
	if pe == 0 || h.r16(pe+16) != 17 {
		t.Fatalf("getprotobyname = %#x", pe)
	}
	if pe = h.call(ws2, "getprotobynumber", 6); pe == 0 || h.readAStr(h.r64(pe)) != "tcp" {
		t.Fatalf("getprotobynumber = %#x", pe)
	}
}
