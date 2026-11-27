//go:build darwin || linux

package win

import (
	"bytes"
	"testing"
)

const sizeofOverlapped = 32

// wsabuf allocates a buffer of n bytes (filled with data) and a WSABUF for it.
func wsabuf(h *testEmu, n int, data []byte) (wb, buf uint64) {
	buf = h.alloc(max(n, 1))
	h.write(buf, data)
	wb = h.alloc(16)
	h.w32(wb, uint32(n))
	h.w64(wb+8, buf)
	return wb, buf
}

// ovl allocates an OVERLAPPED with hEvent ev.
func ovl(h *testEmu, ev uint64) uint64 {
	o := h.alloc(sizeofOverlapped)
	h.w64(o+24, ev)
	return o
}

// ovRecv issues an overlapped WSARecv of n bytes on s.
func ovRecv(t *testing.T, h *testEmu, s uint64, n int, ov uint64) (r uint64, buf uint64) {
	t.Helper()
	wb, buf := wsabuf(h, n, nil)
	flags, got := h.alloc(4), h.alloc(4)
	return h.call(ws2, "WSARecv", s, wb, 1, got, flags, ov, 0), buf
}

func sendAll(t *testing.T, h *testEmu, s uint64, data []byte) {
	t.Helper()
	b := h.alloc(len(data))
	h.write(b, data)
	if r := h.call(ws2, "send", s, b, uint64(len(data)), 0); r != uint64(len(data)) {
		t.Fatalf("send = %d err %d", int64(r), h.lastError())
	}
}

// A pending WSARecv completes when data arrives: event set, OVERLAPPED
// written, WSAGetOverlappedResult reports the byte count.
func TestOvlRecvEventPending(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	ev := h.call(ws2, "WSACreateEvent")
	ov := ovl(h, ev)
	r, buf := ovRecv(t, h, s, 16, ov)
	if uint32(r) != 0xFFFFFFFF || h.lastError() != wsaIOPending || h.r64(ov) != statusPending {
		t.Fatalf("WSARecv = %#x err %d internal %#x", r, h.lastError(), h.r64(ov))
	}
	n, fl := h.alloc(4), h.alloc(4)
	if r := h.call(ws2, "WSAGetOverlappedResult", s, ov, n, 0, fl); r != 0 || h.lastError() != wsaIOIncomplete {
		t.Fatalf("result while pending = %d err %d", r, h.lastError())
	}
	sendAll(t, h, c, []byte("hello"))
	if r := h.call(dK32, "WaitForSingleObject", ev, 3000); r != 0 {
		t.Fatalf("wait event = %#x", r)
	}
	if r := h.call(ws2, "WSAGetOverlappedResult", s, ov, n, 0, fl); r != 1 || h.r32(n) != 5 || h.r64(ov) != 0 || h.r64(ov+8) != 5 {
		t.Fatalf("result = %d n %d internal %#x/%d err %d", r, h.r32(n), h.r64(ov), h.r64(ov+8), h.lastError())
	}
	if got := h.read(buf, 5); string(got) != "hello" {
		t.Fatalf("data %q", got)
	}
	if r := h.call(ws2, "WSAGetOverlappedResult", s, 0, n, 0, fl); r != 0 || h.lastError() != wsaEFAULT {
		t.Fatalf("NULL overlapped = %d err %d", r, h.lastError())
	}
	if r := h.call(ws2, "WSAGetOverlappedResult", 0x777, ov, n, 0, fl); r != 0 || h.lastError() != wsaENOTSOCK {
		t.Fatalf("bad socket = %d err %d", r, h.lastError())
	}
}

// Data already queued: WSARecv completes at once (returns 0), still sets the
// event; WSAGetOverlappedResult with fWait blocks for a pending op.
func TestOvlRecvImmediateAndWait(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	sendAll(t, h, c, []byte("abc"))
	ev := h.call(ws2, "WSACreateEvent")
	ov := ovl(h, ev)
	wb, buf := wsabuf(h, 8, nil)
	flags, got := h.alloc(4), h.alloc(4)
	h.call(dK32, "Sleep", 20)
	if r := h.call(ws2, "WSARecv", s, wb, 1, got, flags, ov, 0); r != 0 || h.r32(got) != 3 || string(h.read(buf, 3)) != "abc" {
		t.Fatalf("immediate WSARecv = %#x got %d err %d", r, h.r32(got), h.lastError())
	}
	if r := h.call(dK32, "WaitForSingleObject", ev, 0); r != 0 {
		t.Fatalf("event not set after immediate completion: %#x", r)
	}
	ov2 := ovl(h, 0)
	if r, _ := ovRecv(t, h, s, 8, ov2); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaIOPending {
		t.Fatalf("second WSARecv = %#x err %d", r, h.lastError())
	}
	sendAll(t, h, c, []byte("xy"))
	n, fl := h.alloc(4), h.alloc(4)
	if r := h.call(ws2, "WSAGetOverlappedResult", s, ov2, n, 1, fl); r != 1 || h.r32(n) != 2 {
		t.Fatalf("waiting result = %d n %d err %d", r, h.r32(n), h.lastError())
	}
	if r := h.call(dK32, "GetOverlappedResult", s, ov2, n, 0); r != 1 || h.r32(n) != 2 {
		t.Fatalf("GetOverlappedResult = %d n %d err %d", r, h.r32(n), h.lastError())
	}
}

// Completions go to the associated port with the key; skip-on-success
// suppresses the packet of an immediate completion only.
func TestOvlIOCP(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	port := h.call(dK32, "CreateIoCompletionPort", s, 0, 77, 0)
	if port == 0 {
		t.Fatalf("associate: err %d", h.lastError())
	}
	if r := h.call(dK32, "CreateIoCompletionPort", s, port, 78, 0); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("second association = %#x err %d", r, h.lastError())
	}
	ov := ovl(h, 0)
	ovRecv(t, h, s, 16, ov)
	sendAll(t, h, c, []byte("12345"))
	n, key, op := h.alloc(4), h.alloc(8), h.alloc(8)
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 3000); r != 1 || h.r32(n) != 5 || h.r64(key) != 77 || h.r64(op) != ov {
		t.Fatalf("GQCS = %d n %d key %d ov %#x/%#x err %d", r, h.r32(n), h.r64(key), h.r64(op), ov, h.lastError())
	}
	// immediate completion without skip mode: a packet
	sendAll(t, h, c, []byte("z"))
	h.call(dK32, "Sleep", 20)
	if r, _ := ovRecv(t, h, s, 16, ovl(h, 0)); r != 0 {
		t.Fatalf("immediate recv = %#x err %d", r, h.lastError())
	}
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 0); r != 1 || h.r32(n) != 1 {
		t.Fatalf("packet for immediate completion: %d n %d err %d", r, h.r32(n), h.lastError())
	}
	// with FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: none
	if r := h.call(dK32, "SetFileCompletionNotificationModes", s, 3); r != 1 {
		t.Fatalf("SetFileCompletionNotificationModes err %d", h.lastError())
	}
	sendAll(t, h, c, []byte("w"))
	h.call(dK32, "Sleep", 20)
	if r, _ := ovRecv(t, h, s, 16, ovl(h, 0)); r != 0 {
		t.Fatalf("immediate recv (skip) = %#x err %d", r, h.lastError())
	}
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 0); r != 0 || h.lastError() != 258 || h.r64(op) != 0 {
		t.Fatalf("skip mode: GQCS = %d err %d ov %#x", r, h.lastError(), h.r64(op))
	}
	// asynchronous completion still queues a packet in skip mode
	ov = ovl(h, 0)
	ovRecv(t, h, s, 16, ov)
	sendAll(t, h, c, []byte("async"))
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 3000); r != 1 || h.r32(n) != 5 || h.r64(op) != ov {
		t.Fatalf("async in skip mode: %d n %d err %d", r, h.r32(n), h.lastError())
	}
	// low bit in hEvent: no packet
	ev := h.call(ws2, "WSACreateEvent")
	ov = ovl(h, ev|1)
	ovRecv(t, h, s, 16, ov)
	sendAll(t, h, c, []byte("e"))
	if r := h.call(dK32, "WaitForSingleObject", ev, 3000); r != 0 {
		t.Fatalf("event (low bit) = %#x", r)
	}
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 0); r != 0 || h.lastError() != 258 {
		t.Fatalf("hEvent|1 must not queue a packet: %d err %d", r, h.lastError())
	}
}

// CancelIoEx aborts the pending operation: the packet reports
// ERROR_OPERATION_ABORTED, a second cancel finds nothing.
func TestOvlCancelIoEx(t *testing.T) {
	h := wsaInit(t)
	_, s := tcpPair(t, h)
	port := h.call(dK32, "CreateIoCompletionPort", s, 0, 5, 0)
	ov := ovl(h, 0)
	ovRecv(t, h, s, 16, ov)
	if r := h.call(dK32, "CancelIoEx", s, ov); r != 1 {
		t.Fatalf("CancelIoEx err %d", h.lastError())
	}
	n, key, op := h.alloc(4), h.alloc(8), h.alloc(8)
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, n, key, op, 3000); r != 0 || h.lastError() != errOperAborted || h.r64(op) != ov {
		t.Fatalf("GQCS after cancel = %d err %d ov %#x", r, h.lastError(), h.r64(op))
	}
	fl := h.alloc(4)
	if r := h.call(ws2, "WSAGetOverlappedResult", s, ov, n, 0, fl); r != 0 || h.lastError() != wsaOperationAborted {
		t.Fatalf("WSAGetOverlappedResult = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "CancelIoEx", s, ov); r != 0 || h.lastError() != errNotFound {
		t.Fatalf("second CancelIoEx = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "CancelIoEx", 0x1234, 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("CancelIoEx(bad) = %d err %d", r, h.lastError())
	}
	// CancelIo cancels the calling thread's operations; closesocket aborts the rest
	ov2 := ovl(h, 0)
	ovRecv(t, h, s, 16, ov2)
	if r := h.call(dK32, "CancelIo", s); r != 1 || h.r64(ov2) != statusCancelled {
		t.Fatalf("CancelIo = %d internal %#x", r, h.r64(ov2))
	}
	ov3 := ovl(h, 0)
	ovRecv(t, h, s, 16, ov3)
	h.call(ws2, "closesocket", s)
	if h.r64(ov3) != statusCancelled {
		t.Fatalf("closesocket: internal %#x", h.r64(ov3))
	}
}

// A large overlapped send stays pending until the peer reads.
func TestOvlSendLarge(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	const size = 8 << 20
	data := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	wb, _ := wsabuf(h, size, data)
	ev := h.call(ws2, "WSACreateEvent")
	ov := ovl(h, ev)
	sent := h.alloc(4)
	r := h.call(ws2, "WSASend", c, wb, 1, sent, 0, ov, 0)
	if uint32(r) != 0xFFFFFFFF || h.lastError() != wsaIOPending {
		t.Fatalf("large WSASend = %#x err %d (expected pending)", r, h.lastError())
	}
	buf := h.alloc(1 << 20)
	var got []byte
	for len(got) < size {
		n := h.call(ws2, "recv", s, buf, 1<<20, 0)
		if int64(n) <= 0 {
			t.Fatalf("recv = %d err %d after %d", int64(n), h.lastError(), len(got))
		}
		got = append(got, h.read(buf, int(n))...)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch")
	}
	n, fl := h.alloc(4), h.alloc(4)
	if r := h.call(ws2, "WSAGetOverlappedResult", c, ov, n, 1, fl); r != 1 || h.r32(n) != size {
		t.Fatalf("send result = %d n %d err %d", r, h.r32(n), h.lastError())
	}
}
