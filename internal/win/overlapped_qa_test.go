package win

import (
	"runtime"
	"strings"
	"testing"
)

// QA regression tests for the unified overlapped-I/O semantics
// (GetOverlappedResult(Ex), GetQueuedCompletionStatus, CancelIo).

// qaOv returns an OVERLAPPED with the given Internal / InternalHigh.
func qaOv(h *testEmu, st uint32, n uint64) uint64 {
	ov := h.alloc(32)
	h.write(ov, make([]byte, 32))
	h.w64(ov, uint64(st))
	h.w64(ov+8, n)
	return ov
}

// GetOverlappedResult fails for every !NT_SUCCESS status (errors and all
// warnings), succeeds for success and informational statuses, writes the
// byte count either way and accepts a NULL lpNumberOfBytesTransferred.
func TestQAOverlappedResultStatusClasses(t *testing.T) {
	h := newTestEmu(t)
	f := h.call(dK32, "CreateEventW", 0, 1, 0, 0) // neither a pipe nor a socket
	for _, c := range []struct {
		name string
		st   uint32
		ok   bool
		err  uint32 // 0: any non-zero error
	}{
		{"success", 0, true, 0},
		{"informational", 0x40000000, true, 0}, // STATUS_OBJECT_NAME_EXISTS
		{"warning", 0x80000011, false, 0},      // STATUS_DEVICE_BUSY
		{"error", statusCancelled, false, errOperationAborted},
		{"WSA status", 0xC0F00000 | wsaECONNRESET, false, wsaECONNRESET},
	} {
		n := h.alloc(4)
		h.setLastError(0)
		r := h.call(dK32, "GetOverlappedResult", f, qaOv(h, c.st, 5), n, 0)
		le := h.lastError()
		if (r == 1) != c.ok || h.r32(n) != 5 || !c.ok && (le == 0 || c.err != 0 && le != c.err) {
			t.Errorf("%s: r=%d n=%d err=%d, want ok=%v err=%d", c.name, r, h.r32(n), le, c.ok, c.err)
		}
	}
	if r := h.call(dK32, "GetOverlappedResult", f, qaOv(h, 0, 5), 0, 0); r != 1 {
		t.Errorf("NULL count, success: r=%d err=%d", r, h.lastError())
	}
	if r := h.call(dK32, "GetOverlappedResult", f, qaOv(h, statusCancelled, 0), 0, 0); r != 0 || h.lastError() != errOperationAborted {
		t.Errorf("NULL count, error: r=%d err=%d", r, h.lastError())
	}
}

// GetQueuedCompletionStatus returns FALSE (with the packet's out params)
// for a packet whose status is a warning or an error.
func TestQAGqcsStatusClasses(t *testing.T) {
	h := newTestEmu(t)
	port := h.call(dK32, "CreateIoCompletionPort", ^uint64(0), 0, 0, 1)
	o, ok := h.E.handles.get(port).(*iocpObj)
	if !ok {
		t.Fatalf("CreateIoCompletionPort err %d", h.lastError())
	}
	nb, key, pov := h.alloc(4), h.alloc(8), h.alloc(8)
	for _, c := range []struct {
		name string
		st   uint32
		ok   bool
		err  uint32
	}{
		{"informational", 0x40000000, true, 0},
		{"warning", statusBufferOverflow, false, errMoreData},
		{"error", statusPipeBroken, false, errBrokenPipe},
		{"WSA status", 0xC0F00000 | wsaECONNRESET, false, wsaECONNRESET},
	} {
		o.post(iocpPacket{n: 3, key: 9, ov: 0x1000, st: c.st})
		h.w64(pov, 0)
		r := h.call(dK32, "GetQueuedCompletionStatus", port, nb, key, pov, 0)
		if (r == 1) != c.ok || !c.ok && h.lastError() != c.err || h.r64(pov) != 0x1000 || h.r32(nb) != 3 || h.r64(key) != 9 {
			t.Errorf("%s: r=%d err=%d ov=%#x n=%d key=%d", c.name, r, h.lastError(), h.r64(pov), h.r32(nb), h.r64(key))
		}
	}
}

// An overlapped pipe operation that fails at once (not ERROR_IO_PENDING)
// queues no completion packet and does not signal the event.
func TestQANamedPipeSyncFailureNoPacket(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\qa-syncfail`
	s := h.mkPipe(name, tPipeDuplex|tFlagOverlap, tPipeMsg, 1)
	c := h.openPipe(name, 0)
	port := h.call(dK32, "CreateIoCompletionPort", s, 0, 7, 0)
	if port == 0 {
		t.Fatalf("CreateIoCompletionPort err %d", h.lastError())
	}
	h.call(dK32, "CloseHandle", c)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	ov := qaOv(h, 0, 0)
	h.w64(ov+24, ev)
	if r := h.call(dK32, "ReadFile", s, h.alloc(8), 8, 0, ov); r != 0 || h.lastError() != errBrokenPipe {
		t.Fatalf("ReadFile = %d err %d, want ERROR_BROKEN_PIPE", r, h.lastError())
	}
	if r := h.call(dK32, "GetQueuedCompletionStatus", port, h.alloc(4), h.alloc(8), h.alloc(8), 0); r != 0 || h.lastError() != errTimeout258 {
		t.Errorf("packet queued for a synchronous failure: r=%d err=%d", r, h.lastError())
	}
	if r := h.call(dK32, "WaitForSingleObject", ev, 0); r != errTimeout258 {
		t.Errorf("event signalled for a synchronous failure: %#x", r)
	}
}

// CancelIo cancels only the calling thread's operations; CancelIoEx(h,
// NULL) cancels those of every thread.
func TestQACancelIoCallingThreadOnly(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\qa-cancel-thread`
	s := h.mkPipe(name, tPipeDuplex|tFlagOverlap, tPipeMsg, 1)
	h.openPipe(name, 0)
	start := h.E.stub("test", "qa_thread", func(e *Emu) uint64 { return 0 })
	th := h.call(dK32, "CreateThread", 0, 0, start, 0, 4, 0) // CREATE_SUSPENDED
	to, ok := h.E.handles.get(th).(*threadObj)
	if !ok || to.t == nil {
		t.Fatalf("CreateThread err %d", h.lastError())
	}
	ovOther, _ := pendingPipeRead(t, h, s, 0)
	ovMine, _ := pendingPipeRead(t, h, s, 0)
	// the harness runs every call on the main thread: hand the first read
	// to the other thread as if that thread had issued it
	x := h.E.npEndOf(s)
	if x == nil {
		t.Fatal("not a pipe end")
	}
	x.k().mu.Lock()
	ok = len(x.pending) == 2 && x.pending[0].ov == ovOther
	if ok {
		x.pending[0].t = to.t
	}
	x.k().mu.Unlock()
	if !ok {
		t.Fatal("unexpected pending operations")
	}
	if r := h.call(dK32, "CancelIo", s); r != 1 {
		t.Fatalf("CancelIo err %d", h.lastError())
	}
	if st := uint32(h.r64(ovMine)); st != statusCancelled {
		t.Errorf("own read: Internal %#x, want STATUS_CANCELLED", st)
	}
	if st := uint32(h.r64(ovOther)); st != statusPending {
		t.Errorf("other thread's read: Internal %#x, want STATUS_PENDING", st)
	}
	if r := h.call(dK32, "CancelIoEx", s, 0); r != 1 || uint32(h.r64(ovOther)) != statusCancelled {
		t.Errorf("CancelIoEx(NULL) = %d Internal %#x err %d", r, h.r64(ovOther), h.lastError())
	}
}

// GetOverlappedResultEx(bAlertable) runs queued APCs and fails with
// WAIT_IO_COMPLETION; a non-alertable wait leaves them queued.
func TestQAGetOverlappedResultExAlertable(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("alertable waits need the host poller")
	}
	h := newTestEmu(t)
	const name = `\\.\pipe\qa-alertable`
	s := h.mkPipe(name, tPipeDuplex|tFlagOverlap, tPipeMsg, 1)
	h.openPipe(name, 0)
	ov, _ := pendingPipeRead(t, h, s, 0)
	ran := 0
	apc := h.E.stub("test", "qa_apc", func(e *Emu) uint64 { ran++; return 0 })
	h.E.queueAPC(h.E.Cur, apc, 0)
	n := h.alloc(4)
	if r := h.call(dK32, "GetOverlappedResultEx", s, ov, n, 20, 0); r != 0 || h.lastError() != errTimeout258 || ran != 0 {
		t.Fatalf("non-alertable = %d err %d ran %d, want WAIT_TIMEOUT, APC not run", r, h.lastError(), ran)
	}
	if r := h.call(dK32, "GetOverlappedResultEx", s, ov, n, 1000, 1); r != 0 || h.lastError() != waitIOCompletion || ran != 1 {
		t.Fatalf("alertable = %d err %#x ran %d, want WAIT_IO_COMPLETION, APC run", r, h.lastError(), ran)
	}
}

// A second registration of a name in the same DLL is recorded in regDups
// (which TestRegistryNoDuplicates requires to be empty).
func TestQARegDupsRecorded(t *testing.T) {
	n := len(regDups)
	t.Cleanup(func() { regDups = regDups[:n] })
	const dll = "qa_dup_test.dll"
	delete(registry, dll)
	t.Cleanup(func() { delete(registry, dll) })
	reg(dll, "F", retTrue)
	if len(regDups) != n {
		t.Fatalf("first registration recorded as a duplicate: %v", regDups[n:])
	}
	reg(dll, "F", retTrue)
	if len(regDups) != n+1 || !strings.EqualFold(regDups[n], dll+"!F") {
		t.Fatalf("duplicate not recorded: %v", regDups[n:])
	}
}
