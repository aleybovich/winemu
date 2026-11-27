//go:build darwin || linux

package win

import "testing"

// A cancelled operation runs its completion routine with
// dwError = WSA_OPERATION_ABORTED and cbTransferred = 0.
func TestOvlCompletionRoutineCancelled(t *testing.T) {
	h := wsaInit(t)
	_, s := tcpPair(t, h)
	var calls [][4]uint64
	cr := h.E.stub("test", "completion_cancel", func(e *Emu) uint64 {
		calls = append(calls, [4]uint64{e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3)})
		return 0
	})
	wb, _ := wsabuf(h, 8, nil)
	ov := ovl(h, 0)
	if r := h.call(ws2, "WSARecv", s, wb, 1, h.alloc(4), h.alloc(4), ov, cr); r != sockErr32 || h.lastError() != wsaIOPending {
		t.Fatalf("WSARecv = %#x err %d", r, h.lastError())
	}
	if r := h.call(dK32, "CancelIoEx", s, ov); r != 1 {
		t.Fatalf("CancelIoEx err %d", h.lastError())
	}
	if r := h.call(dK32, "SleepEx", 2000, 1); r != waitIOCompletion || len(calls) != 1 {
		t.Fatalf("SleepEx(alertable) = %#x calls %d", r, len(calls))
	}
	if calls[0] != [4]uint64{wsaOperationAborted, 0, ov, 0} {
		t.Fatalf("routine args %v, want [%d 0 %#x 0]", calls[0], wsaOperationAborted, ov)
	}
}
