//go:build darwin || linux

package win

import "testing"

const (
	sizeofProtoInfoW = 628
	sizeofProtoInfoA = 372
	xp1IFSHandles    = 0x20000
)

// WSAEnumProtocolsW: size probe, protocol filter and entry layout.
func TestWSAEnumProtocolsW(t *testing.T) {
	h := wsaInit(t)
	n := h.alloc(4)
	h.w32(n, 0)
	if r := h.call(ws2, "WSAEnumProtocolsW", 0, 0, n); r != sockErr32 || h.lastError() != wsaENOBUFS || h.r32(n) < 4*sizeofProtoInfoW {
		t.Fatalf("probe = %#x err %d need %d", r, h.lastError(), h.r32(n))
	}
	if r := h.call(ws2, "WSAEnumProtocolsW", 0, 0, 0); r != sockErr32 || h.lastError() != wsaEFAULT {
		t.Fatalf("NULL length = %#x err %d", r, h.lastError())
	}
	// only TCP (Go's internal/poll asks for {IPPROTO_TCP, 0})
	protos := h.alloc(8)
	h.w32(protos, 6)
	buf := h.alloc(8 * sizeofProtoInfoW)
	h.w32(n, 8*sizeofProtoInfoW)
	r := h.call(ws2, "WSAEnumProtocolsW", protos, buf, n)
	if r != 2 {
		t.Fatalf("TCP entries = %d err %d", int64(r), h.lastError())
	}
	fams := map[uint32]bool{}
	for i := range uint64(2) {
		p := buf + i*sizeofProtoInfoW
		if h.r32(p)&xp1IFSHandles == 0 || h.r32(p+protoInfoTypeOffset) != 1 || h.r32(p+protoInfoProtoOffset) != 6 {
			t.Fatalf("entry %d: flags %#x type %d proto %d", i, h.r32(p), h.r32(p+protoInfoTypeOffset), h.r32(p+protoInfoProtoOffset))
		}
		if h.r32(p+40) != 1 { // ProtocolChain.ChainLen = BASE_PROTOCOL
			t.Fatalf("entry %d chain len %d", i, h.r32(p+40))
		}
		fams[h.r32(p+protoInfoAFOffset)] = true
		if name := h.readWStr(p + 116); name == "" {
			t.Fatalf("entry %d: empty szProtocol", i)
		}
	}
	if !fams[2] || !fams[23] {
		t.Fatalf("families %v", fams)
	}
	// all protocols: TCP+UDP for IPv4 and IPv6
	h.w32(n, 8*sizeofProtoInfoW)
	if r := h.call(ws2, "WSAEnumProtocolsW", 0, buf, n); r != 4 {
		t.Fatalf("all entries = %d err %d", int64(r), h.lastError())
	}
}

func TestWSAEnumProtocolsA(t *testing.T) {
	h := wsaInit(t)
	n := h.alloc(4)
	h.w32(n, sizeofProtoInfoA) // too small for 4 entries
	buf := h.alloc(4 * sizeofProtoInfoA)
	if r := h.call(ws2, "WSAEnumProtocolsA", 0, buf, n); r != sockErr32 || h.lastError() != wsaENOBUFS || h.r32(n) != 4*sizeofProtoInfoA {
		t.Fatalf("small buffer = %#x err %d need %d", r, h.lastError(), h.r32(n))
	}
	if r := h.call(ws2, "WSAEnumProtocolsA", 0, buf, n); r != 4 {
		t.Fatalf("entries = %d err %d", int64(r), h.lastError())
	}
	if s := h.readAStr(buf + 116); s == "" {
		t.Fatal("empty szProtocol")
	}
}

// getsockopt(SO_PROTOCOL_INFOW) describes the socket (Go checks XP1_IFS_HANDLES).
func TestSoProtocolInfo(t *testing.T) {
	h := wsaInit(t)
	s := h.call(ws2, "socket", 23, 2, 17)
	val, n := h.alloc(sizeofProtoInfoW), h.alloc(4)
	h.w32(n, sizeofProtoInfoW)
	if r := h.call(ws2, "getsockopt", s, wsSolSocket, 0x2005, val, n); r != 0 || h.r32(n) != sizeofProtoInfoW {
		t.Fatalf("SO_PROTOCOL_INFOW = %#x err %d len %d", r, h.lastError(), h.r32(n))
	}
	if h.r32(val)&xp1IFSHandles == 0 || h.r32(val+protoInfoAFOffset) != 23 || h.r32(val+protoInfoTypeOffset) != 2 || h.r32(val+protoInfoProtoOffset) != 17 {
		t.Fatalf("info: flags %#x af %d type %d proto %d", h.r32(val), h.r32(val+protoInfoAFOffset), h.r32(val+protoInfoTypeOffset), h.r32(val+protoInfoProtoOffset))
	}
	h.w32(n, sizeofProtoInfoW-1)
	if r := h.call(ws2, "getsockopt", s, wsSolSocket, 0x2005, val, n); r != sockErr32 || h.lastError() != wsaEFAULT {
		t.Fatalf("short buffer = %#x err %d", r, h.lastError())
	}
	h.w32(n, sizeofProtoInfoA)
	if r := h.call(ws2, "getsockopt", s, wsSolSocket, 0x2004, val, n); r != 0 || h.r32(n) != sizeofProtoInfoA {
		t.Fatalf("SO_PROTOCOL_INFOA = %#x err %d", r, h.lastError())
	}
}

// int-returning winsock functions return SOCKET_ERROR as the 32-bit -1 in
// EAX (RAX = 0x00000000FFFFFFFF, what real code leaves there); only
// SOCKET-returning ones return the 64-bit INVALID_SOCKET.
func TestSocketErrorIs32Bit(t *testing.T) {
	h := wsaInit(t)
	for _, name := range []string{"send", "recv", "bind", "listen", "closesocket", "WSARecv", "WSASend", "WSAIoctl", "getsockopt", "WSAEventSelect"} {
		if r := h.call(ws2, name, 0x7770, 0, 0, 0, 0, 0, 0, 0, 0); r != 0xFFFFFFFF {
			t.Errorf("%s(bad socket) = %#x, want 0xFFFFFFFF", name, r)
		}
	}
	if r := h.call(ws2, "accept", 0x7770, 0, 0); r != ^uint64(0) {
		t.Errorf("accept(bad socket) = %#x, want INVALID_SOCKET", r)
	}
	if r := h.call(ws2, "socket", 99, 1, 0); r != ^uint64(0) {
		t.Errorf("socket(bad af) = %#x, want INVALID_SOCKET", r)
	}
}

const sockErr32 = 0xFFFFFFFF // SOCKET_ERROR of int-returning functions
