//go:build darwin || linux

package win

import "testing"

// AcceptEx with dwReceiveDataLength > 0 completes only after the first data
// arrives, not when the connection is accepted.
func TestAcceptExWaitsForData(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	iocp := h.call(dK32, "CreateIoCompletionPort", ls, 0, 9, 0)
	as := h.call(ws2, "WSASocketW", 2, 1, 6, 0, 0, 1)
	const addrLen = 16 + 16
	buf := h.alloc(8 + 2*addrLen)
	acceptEx := extFn(t, h, ls, guidAcceptEx)
	aov, nrecv := ovl(h, 0), h.alloc(4)
	if r := callPtr(h, acceptEx, ls, as, buf, 8, addrLen, addrLen, nrecv, aov); r != 0 || h.lastError() != wsaIOPending {
		t.Fatalf("AcceptEx = %d err %d", r, h.lastError())
	}
	c := h.call(ws2, "socket", 2, 1, 6)
	if r := h.call(ws2, "connect", c, sin(h, loop4, port), 16); r != 0 {
		t.Fatalf("connect err %d", h.lastError())
	}
	n, key, op := h.alloc(4), h.alloc(8), h.alloc(8)
	if r := h.call(dK32, "GetQueuedCompletionStatus", iocp, n, key, op, 150); r != 0 || h.lastError() != 258 || h.r64(op) != 0 {
		t.Fatalf("AcceptEx completed before data: %d err %d n %d", r, h.lastError(), h.r32(n))
	}
	sendAll(t, h, c, []byte("hi"))
	if r := h.call(dK32, "GetQueuedCompletionStatus", iocp, n, key, op, 3000); r != 1 || h.r32(n) != 2 || h.r64(key) != 9 || h.r64(op) != aov {
		t.Fatalf("GQCS = %d n %d key %d err %d", r, h.r32(n), h.r64(key), h.lastError())
	}
	if string(h.read(buf, 2)) != "hi" {
		t.Fatalf("data %q", h.read(buf, 2))
	}
}
