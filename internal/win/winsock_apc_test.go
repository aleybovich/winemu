//go:build darwin || linux

package win

import "testing"

// Completion routines run as APCs in the issuing thread's alertable waits
// only; the wait then returns WAIT_IO_COMPLETION.
func TestOvlCompletionRoutine(t *testing.T) {
	h := wsaInit(t)
	c, s := tcpPair(t, h)
	var calls [][4]uint64
	cr := h.E.stub("test", "completion", func(e *Emu) uint64 {
		calls = append(calls, [4]uint64{e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3)})
		return 0
	})
	recv := func(ov uint64) uint64 {
		wb, _ := wsabuf(h, 8, nil)
		return h.call(ws2, "WSARecv", s, wb, 1, h.alloc(4), h.alloc(4), ov, cr)
	}
	ov := ovl(h, 0)
	if r := recv(ov); r != sockErr32 || h.lastError() != wsaIOPending {
		t.Fatalf("WSARecv = %#x err %d", r, h.lastError())
	}
	sendAll(t, h, c, []byte("data"))
	h.call(dK32, "Sleep", 50)
	if len(calls) != 0 {
		t.Fatal("completion routine ran outside an alertable wait")
	}
	if r := h.call(dK32, "SleepEx", 2000, 1); r != waitIOCompletion || len(calls) != 1 {
		t.Fatalf("SleepEx(alertable) = %#x calls %d", r, len(calls))
	}
	if calls[0] != [4]uint64{0, 4, ov, 0} {
		t.Fatalf("routine args %v", calls[0])
	}
	// an immediate completion queues the routine as well
	sendAll(t, h, c, []byte("x"))
	h.call(dK32, "Sleep", 20)
	if r := recv(ovl(h, 0)); r != 0 || len(calls) != 1 {
		t.Fatalf("immediate WSARecv = %#x calls %d", r, len(calls))
	}
	if r := h.call(dK32, "SleepEx", 0, 1); r != waitIOCompletion || len(calls) != 2 || calls[1][1] != 1 {
		t.Fatalf("SleepEx(0, TRUE) = %#x calls %v", r, calls)
	}
	// a pending wait is ended by the APC: WaitForSingleObjectEx
	ev := h.call(ws2, "WSACreateEvent")
	recv(ovl(h, 0))
	sendAll(t, h, c, []byte("yz"))
	if r := h.call(dK32, "WaitForSingleObjectEx", ev, 2000, 1); r != waitIOCompletion || len(calls) != 3 {
		t.Fatalf("WaitForSingleObjectEx(alertable) = %#x calls %d", r, len(calls))
	}
	// WSAWaitForMultipleEvents(fAlertable)
	recv(ovl(h, 0))
	sendAll(t, h, c, []byte("w"))
	if r := h.call(ws2, "WSAWaitForMultipleEvents", 1, h.wptrs(ev), 0, 2000, 1); r != waitIOCompletion || len(calls) != 4 {
		t.Fatalf("WSAWaitForMultipleEvents(alertable) = %#x calls %d", r, len(calls))
	}
	// GetQueuedCompletionStatusEx(fAlertable): FALSE, WAIT_IO_COMPLETION
	port := h.call(dK32, "CreateIoCompletionPort", invalidHandle, 0, 0, 0)
	recv(ovl(h, 0))
	sendAll(t, h, c, []byte("v"))
	ents, removed := h.alloc(sizeofOverlappedEntry), h.alloc(4)
	if r := h.call(dK32, "GetQueuedCompletionStatusEx", port, ents, 1, removed, 2000, 1); r != 0 || h.lastError() != waitIOCompletion || len(calls) != 5 {
		t.Fatalf("GQCSEx(alertable) = %d err %#x calls %d", r, h.lastError(), len(calls))
	}
	// not alertable: no APC, plain timeout
	if r := h.call(dK32, "WaitForMultipleObjectsEx", 1, h.wptrs(ev), 0, 10, 0); r != waitTimeout {
		t.Fatalf("WaitForMultipleObjectsEx(non-alertable) = %#x", r)
	}
}
