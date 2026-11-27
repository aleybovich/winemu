//go:build darwin || linux

package win

import "testing"

var (
	guidAcceptEx     = []byte{0xf1, 0x7d, 0x36, 0xb5, 0xac, 0xcb, 0xcf, 0x11, 0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}
	guidGetAcceptExS = []byte{0xf2, 0x7d, 0x36, 0xb5, 0xac, 0xcb, 0xcf, 0x11, 0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}
	guidConnectEx    = []byte{0xb9, 0x07, 0xa2, 0x25, 0xf3, 0xdd, 0x60, 0x46, 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}
	guidDisconnectEx = []byte{0x11, 0x2e, 0xda, 0x7f, 0x30, 0x86, 0x6f, 0x43, 0xa0, 0x31, 0xf5, 0x36, 0xa6, 0xee, 0xc1, 0x57}
)

// extFn fetches an extension function pointer with WSAIoctl.
func extFn(t *testing.T, h *testEmu, s uint64, guid []byte) uint64 {
	t.Helper()
	g, out, n := h.alloc(16), h.alloc(8), h.alloc(4)
	h.write(g, guid)
	if r := h.call(ws2, "WSAIoctl", s, sioGetExtensionFuncPtr, g, 16, out, 8, n, 0, 0); r != 0 || h.r32(n) != 8 || h.r64(out) == 0 {
		t.Fatalf("SIO_GET_EXTENSION_FUNCTION_POINTER = %#x err %d", r, h.lastError())
	}
	return h.r64(out)
}

func callPtr(h *testEmu, fn uint64, args ...uint64) uint64 { return h.E.CallGuest(fn, args...) }

func TestExtensionPointerErrors(t *testing.T) {
	h := wsaInit(t)
	s := h.call(ws2, "socket", 2, 1, 6)
	g, out, n := h.alloc(16), h.alloc(8), h.alloc(4)
	h.write(g, []byte("not a known guid"))
	if r := h.call(ws2, "WSAIoctl", s, sioGetExtensionFuncPtr, g, 16, out, 8, n, 0, 0); r != sockErr32 || h.lastError() != wsaEINVAL {
		t.Fatalf("unknown GUID = %#x err %d", r, h.lastError())
	}
	h.write(g, guidConnectEx)
	if r := h.call(ws2, "WSAIoctl", s, sioGetExtensionFuncPtr, g, 16, out, 4, n, 0, 0); r != sockErr32 || h.lastError() != wsaEFAULT {
		t.Fatalf("short output = %#x err %d", r, h.lastError())
	}
	for _, gd := range [][]byte{guidAcceptEx, guidGetAcceptExS, guidDisconnectEx} {
		extFn(t, h, s, gd)
	}
	// UDP: SIO_UDP_CONNRESET is accepted
	u := h.call(ws2, "socket", 2, 2, 17)
	v := h.alloc(4)
	if r := h.call(ws2, "WSAIoctl", u, sioUDPConnReset, v, 4, 0, 0, n, 0, 0); r != 0 {
		t.Fatalf("SIO_UDP_CONNRESET err %d", h.lastError())
	}
}

// AcceptEx + ConnectEx with send data over an IOCP; GetAcceptExSockaddrs
// returns both addresses; SO_UPDATE_*_CONTEXT complete the sockets.
func TestAcceptExConnectEx(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	iocp := h.call(dK32, "CreateIoCompletionPort", ls, 0, 1, 0)
	as := h.call(ws2, "WSASocketW", 2, 1, 6, 0, 0, 1)
	const addrLen = 16 + 16
	buf := h.alloc(4 + 2*addrLen)
	acceptEx := extFn(t, h, ls, guidAcceptEx)
	aov, nrecv := ovl(h, 0), h.alloc(4)
	if r := callPtr(h, acceptEx, ls, as, buf, 4, addrLen, addrLen, nrecv, aov); r != 0 || h.lastError() != wsaIOPending {
		t.Fatalf("AcceptEx = %d err %d", r, h.lastError())
	}
	c := h.call(ws2, "WSASocketW", 2, 1, 6, 0, 0, 1)
	connectEx := extFn(t, h, c, guidConnectEx)
	cov := ovl(h, 0)
	if r := callPtr(h, connectEx, c, sin(h, loop4, port), 16, 0, 0, 0, cov); r != 0 || h.lastError() != wsaEINVAL {
		t.Fatalf("ConnectEx on unbound socket = %d err %d", r, h.lastError())
	}
	h.call(ws2, "bind", c, sin(h, loop4, 0), 16)
	h.call(dK32, "CreateIoCompletionPort", c, iocp, 2, 0)
	data := h.alloc(4)
	h.write(data, []byte("ping"))
	sent := h.alloc(4)
	r := callPtr(h, connectEx, c, sin(h, loop4, port), 16, data, 4, sent, cov)
	if r != 1 && h.lastError() != wsaIOPending {
		t.Fatalf("ConnectEx = %d err %d", r, h.lastError())
	}
	// both complete: the accept once the 4 data bytes arrived
	keys := map[uint64]uint32{}
	ents, removed := h.alloc(2*sizeofOverlappedEntry), h.alloc(4)
	for len(keys) < 2 {
		if r := h.call(dK32, "GetQueuedCompletionStatusEx", iocp, ents, 2, removed, 3000, 0); r != 1 {
			t.Fatalf("GQCSEx = %d err %d (have %v)", r, h.lastError(), keys)
		}
		for i := range uint64(h.r32(removed)) {
			e := ents + i*sizeofOverlappedEntry
			if h.r64(e+16) != 0 {
				t.Fatalf("entry %d status %#x", i, h.r64(e+16))
			}
			keys[h.r64(e)] = h.r32(e + 24)
		}
	}
	if keys[1] != 4 || keys[2] != 4 {
		t.Fatalf("completions %v, want accept 4 bytes, connect 4 bytes", keys)
	}
	if string(h.read(buf, 4)) != "ping" {
		t.Fatalf("accept data %q", h.read(buf, 4))
	}
	lp, ll, rp, rl := h.alloc(8), h.alloc(4), h.alloc(8), h.alloc(4)
	callPtr(h, extFn(t, h, ls, guidGetAcceptExS), buf, 4, addrLen, addrLen, lp, ll, rp, rl)
	csa, cn := h.alloc(16), h.alloc(4)
	h.w32(cn, 16)
	h.call(ws2, "getsockname", c, csa, cn)
	if h.r32(ll) != 16 || h.r32(rl) != 16 || sockPort(h, h.r64(lp)) != port || sockPort(h, h.r64(rp)) != sockPort(h, csa) {
		t.Fatalf("sockaddrs: local %d/%d remote %d/%d (client port %d)", h.r32(ll), sockPort(h, h.r64(lp)), h.r32(rl), sockPort(h, h.r64(rp)), sockPort(h, csa))
	}
	lsv := h.alloc(8)
	h.w64(lsv, ls)
	if r := h.call(ws2, "setsockopt", as, wsSolSocket, wsSoUpdateAcceptCtx, lsv, 8); r != 0 {
		t.Fatalf("SO_UPDATE_ACCEPT_CONTEXT err %d", h.lastError())
	}
	if r := h.call(ws2, "setsockopt", c, wsSolSocket, wsSoUpdateConnectCtx, 0, 0); r != 0 {
		t.Fatalf("SO_UPDATE_CONNECT_CONTEXT err %d", h.lastError())
	}
	pa, pn := h.alloc(16), h.alloc(4)
	h.w32(pn, 16)
	if r := h.call(ws2, "getpeername", as, pa, pn); r != 0 || sockPort(h, pa) != sockPort(h, csa) {
		t.Fatalf("getpeername(accepted) = %#x err %d", r, h.lastError())
	}
	// the accepted socket works for overlapped I/O
	sendAll(t, h, as, []byte("pong"))
	rov := ovl(h, 0)
	ovRecv(t, h, c, 8, rov)
	n, fl := h.alloc(4), h.alloc(4)
	if r := h.call(ws2, "WSAGetOverlappedResult", c, rov, n, 1, fl); r != 1 || h.r32(n) != 4 {
		t.Fatalf("recv on ConnectEx socket = %d n %d err %d", r, h.r32(n), h.lastError())
	}
	// AcceptEx argument errors
	if r := callPtr(h, acceptEx, ls, as, buf, 0, addrLen, addrLen, nrecv, ovl(h, 0)); r != 0 || h.lastError() != wsaEINVAL {
		t.Fatalf("AcceptEx with connected accept socket = %d err %d", r, h.lastError())
	}
	as2 := h.call(ws2, "socket", 2, 1, 6)
	if r := callPtr(h, acceptEx, ls, as2, buf, 0, 8, addrLen, nrecv, ovl(h, 0)); r != 0 || h.lastError() != wsaEFAULT {
		t.Fatalf("AcceptEx short address buffer = %d err %d", r, h.lastError())
	}
	// DisconnectEx(TF_REUSE_SOCKET): the socket can connect again
	disc := extFn(t, h, c, guidDisconnectEx)
	if r := callPtr(h, disc, c, 0, tfReuseSocket, 0); r != 1 {
		t.Fatalf("DisconnectEx err %d", h.lastError())
	}
	if r := h.call(ws2, "bind", c, sin(h, loop4, 0), 16); r != 0 {
		t.Fatalf("bind after DisconnectEx(reuse) err %d", h.lastError())
	}
	if r := callPtr(h, disc, c, 0, 0, 0); r != 0 || h.lastError() != wsaENOTCONN {
		t.Fatalf("DisconnectEx unconnected = %d err %d", r, h.lastError())
	}
}

// IOCP object semantics independent of sockets.
func TestIOCPPostAndErrors(t *testing.T) {
	h := wsaInit(t)
	port := h.call(dK32, "CreateIoCompletionPort", invalidHandle, 0, 0, 0)
	if port == 0 {
		t.Fatalf("create port err %d", h.lastError())
	}
	if r := h.call(dK32, "CreateIoCompletionPort", invalidHandle, port, 0, 0); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("INVALID_HANDLE_VALUE + port = %#x err %d", r, h.lastError())
	}
	if r := h.call(dK32, "CreateIoCompletionPort", 0x1230, 0, 0, 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("bad file handle = %#x err %d", r, h.lastError())
	}
	for i := range uint64(3) {
		h.call(dK32, "PostQueuedCompletionStatus", port, 10+i, 100+i, 0x5000+i)
	}
	ents, removed := h.alloc(4*sizeofOverlappedEntry), h.alloc(4)
	if r := h.call(dK32, "GetQueuedCompletionStatusEx", port, ents, 2, removed, 0, 0); r != 1 || h.r32(removed) != 2 || h.r64(ents) != 100 || h.r64(ents+8) != 0x5000 || h.r32(ents+24) != 10 {
		t.Fatalf("GQCSEx = %d removed %d first %d/%#x/%d", r, h.r32(removed), h.r64(ents), h.r64(ents+8), h.r32(ents+24))
	}
	n, key, op := h.alloc(4), h.alloc(8), h.alloc(8)
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 0); r != 1 || h.r64(key) != 102 || h.r32(n) != 12 {
		t.Fatalf("GQCS = %d key %d", r, h.r64(key))
	}
	if r := h.call(dK32, "GetQueuedCompletionStatusEx", port, ents, 2, removed, 30, 0); r != 0 || h.lastError() != 258 || h.r32(removed) != 0 {
		t.Fatalf("GQCSEx timeout = %d err %d removed %d", r, h.lastError(), h.r32(removed))
	}
	if r := h.call(dK32, "GetQueuedCompletionStatusEx", port, ents, 0, removed, 0, 0); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("GQCSEx count 0 = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "GetQueuedCompletionStatus", 0x1230, n, key, op, 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("GQCS bad port = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "PostQueuedCompletionStatus", 0x1230, 0, 0, 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("PQCS bad port = %d err %d", r, h.lastError())
	}
}

// TransmitFile: head + file range (OVERLAPPED offset) + tail, overlapped;
// without OVERLAPPED it sends from the file pointer and advances it.
func TestTransmitFile(t *testing.T) {
	h := wsaInit(t)
	path := h.wstr(tempFilePath(t, h, "tf.txt"))
	fh := h.call(dK32, "CreateFileW", path, qaGenericRW, 0, 0, qaCreateAlways, qaFileAttrNormal, 0)
	data := h.alloc(16)
	h.write(data, []byte("0123456789"))
	h.call(dK32, "WriteFile", fh, data, 10, h.alloc(4), 0)
	h.call(dK32, "SetFilePointer", fh, 0, 0, 0)
	c, s := tcpPair(t, h)
	tfb := h.alloc(32) // TRANSMIT_FILE_BUFFERS {Head, HeadLength, Tail, TailLength}
	head, tail := h.alloc(4), h.alloc(4)
	h.write(head, []byte("H:"))
	h.write(tail, []byte(":T"))
	h.w64(tfb, head)
	h.w32(tfb+8, 2)
	h.w64(tfb+16, tail)
	h.w32(tfb+24, 2)
	ov := ovl(h, 0)
	h.w32(ov+16, 6) // Offset
	r := h.call("mswsock.dll", "TransmitFile", c, fh, 0, 0, ov, tfb, 0)
	if r != 1 && h.lastError() != wsaIOPending {
		t.Fatalf("TransmitFile = %d err %d", r, h.lastError())
	}
	n, fl := h.alloc(4), h.alloc(4)
	if r := h.call(ws2, "WSAGetOverlappedResult", c, ov, n, 1, fl); r != 1 || h.r32(n) != 8 {
		t.Fatalf("result = %d n %d err %d", r, h.r32(n), h.lastError())
	}
	buf := h.alloc(64)
	if k := h.call(ws2, "recv", s, buf, 64, 0); string(h.read(buf, int(k))) != "H:6789:T" {
		t.Fatalf("received %q", h.read(buf, int(k)))
	}
	// synchronous, 4 bytes from the file pointer (0), which then advances
	if r := h.call("mswsock.dll", "TransmitFile", c, fh, 4, 0, 0, 0, 0); r != 1 {
		t.Fatalf("sync TransmitFile err %d", h.lastError())
	}
	if p := h.call(dK32, "SetFilePointer", fh, 0, 0, 1); uint32(p) != 4 {
		t.Fatalf("file pointer %d, want 4", p)
	}
	if k := h.call(ws2, "recv", s, buf, 64, 0); string(h.read(buf, int(k))) != "0123" {
		t.Fatalf("received %q", h.read(buf, int(k)))
	}
	if r := h.call("mswsock.dll", "TransmitFile", c, 0x4440, 0, 0, 0, 0, 0); r != 0 || h.lastError() != wsaEINVAL {
		t.Fatalf("bad file handle = %d err %d", r, h.lastError())
	}
}
