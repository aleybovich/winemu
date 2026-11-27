package win

import (
	"math"
	"strings"
	"testing"

	"winemu/internal/cpu"
)

// dupAllowed lists "dll!name" registrations that intentionally register a
// name twice in the same DLL (none today).
var dupAllowed = map[string]bool{}

// Registration silently overwrites and init order picks the winner, so no
// API may be registered twice in the same DLL. Registrations made by tests
// into *_test.dll tables are ignored (they repeat with -count).
func TestRegistryNoDuplicates(t *testing.T) {
	for _, d := range regDups {
		if strings.HasSuffix(strings.SplitN(d, "!", 2)[0], "_test.dll") || dupAllowed[d] {
			continue
		}
		t.Errorf("%s registered more than once", d)
	}
}

func TestOverlappedAPIsRegisteredOnce(t *testing.T) {
	dups := map[string]bool{}
	for _, d := range regDups {
		dups[d] = true
	}
	for _, n := range []string{"GetOverlappedResult", "GetOverlappedResultEx", "CancelIo", "CancelIoEx"} {
		if table(dK32).funcs[n] == nil {
			t.Errorf("%s not registered", n)
		}
		if dups[dK32+"!"+n] {
			t.Errorf("%s registered more than once", n)
		}
	}
}

// One NTSTATUS -> Win32 table serves RtlNtStatusToDosError and every
// overlapped result (files, pipes, sockets).
func TestNtStatusToWin32Table(t *testing.T) {
	for _, c := range []struct{ st, w32 uint32 }{
		{0, 0},
		{0xC0000011, errHandleEOF},        // STATUS_END_OF_FILE
		{0xC0000008, errInvalidHandle},    // STATUS_INVALID_HANDLE
		{0xC000014B, errBrokenPipe},       // STATUS_PIPE_BROKEN
		{0x80000005, errMoreData},         // STATUS_BUFFER_OVERFLOW
		{0xC00000B1, errNoData},           // STATUS_PIPE_CLOSING
		{0xC00000B0, errPipeNotConnected}, // STATUS_PIPE_DISCONNECTED
		{0xC00000B3, errPipeListening},    // STATUS_PIPE_LISTENING
		{0xC00000AD, errBadPipe},          // STATUS_INVALID_PIPE_STATE
		{0xC00000AE, errPipeBusy},         // STATUS_PIPE_BUSY
		{0xC0000120, errOperationAborted}, // STATUS_CANCELLED
		{0xC000020D, 64},                  // STATUS_CONNECTION_RESET -> ERROR_NETNAME_DELETED
		{0xC0000236, 1225},                // STATUS_CONNECTION_REFUSED
		{0xC00000B5, 121},                 // STATUS_IO_TIMEOUT -> ERROR_SEM_TIMEOUT
		{0xC000020A, 52},                  // STATUS_ADDRESS_ALREADY_EXISTS -> ERROR_DUP_NAME (Wine ntdll/tests/error.c)
		{0xC0000207, 1214},                // STATUS_INVALID_ADDRESS_COMPONENT -> ERROR_INVALID_NETNAME (ditto)
		{0xC0000001, 31},                  // STATUS_UNSUCCESSFUL -> ERROR_GEN_FAILURE (ditto)
		{0xC000013C, 64},                  // STATUS_REMOTE_DISCONNECT -> ERROR_NETNAME_DELETED (Wine ntdll/error.c)
		{0xC000013B, 64},                  // STATUS_LOCAL_DISCONNECT -> ERROR_NETNAME_DELETED
		{0xC0000241, 1236},                // STATUS_CONNECTION_ABORTED -> ERROR_CONNECTION_ABORTED
		{0xC0000237, 1226},                // STATUS_GRACEFUL_DISCONNECT -> ERROR_GRACEFUL_DISCONNECT
		{0xC000023C, 1231},                // STATUS_NETWORK_UNREACHABLE -> ERROR_NETWORK_UNREACHABLE
		{0xC000023D, 1232},                // STATUS_HOST_UNREACHABLE -> ERROR_HOST_UNREACHABLE
		{0xC0FFFFFF, 317},                 // unknown
	} {
		if got := ntToWin(c.st); got != c.w32 {
			t.Errorf("ntToWin(%#x) = %d, want %d", c.st, got, c.w32)
		}
		h := newTestEmu(t)
		if got := uint32(h.call(dNt, "RtlNtStatusToDosError", uint64(c.st))); got != c.w32 {
			t.Errorf("RtlNtStatusToDosError(%#x) = %d, want %d", c.st, got, c.w32)
		}
	}
	// the Win32 -> NTSTATUS map used for pipe completions round-trips
	for code, st := range pipeStatus {
		if got := ntToWin(st); got != code {
			t.Errorf("pipe status %#x -> %d, want %d", st, got, code)
		}
	}
}

// pendingPipeRead starts an overlapped read on the server end s that stays
// pending (nothing written yet).
func pendingPipeRead(t *testing.T, h *testEmu, s, ev uint64) (ov, buf uint64) {
	t.Helper()
	ov, buf = h.alloc(32), h.alloc(8)
	h.write(ov, make([]byte, 32))
	h.w64(ov+24, ev)
	if r := h.call(dK32, "ReadFile", s, buf, 8, 0, ov); r != 0 || h.lastError() != errIOPending {
		t.Fatalf("ReadFile(ov) %d err %d", r, h.lastError())
	}
	return ov, buf
}

func TestNamedPipeCancelIoEx(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\ovl-cancel`
	s := h.mkPipe(name, tPipeDuplex|tFlagOverlap, tPipeMsg, 1)
	c := h.openPipe(name, 0)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	ov, _ := pendingPipeRead(t, h, s, ev)
	other := h.alloc(32)
	if r := h.call(dK32, "CancelIoEx", s, other); r != 0 || h.lastError() != errNotFound {
		t.Fatalf("CancelIoEx(other ov) = %d err %d, want ERROR_NOT_FOUND", r, h.lastError())
	}
	if r := h.call(dK32, "CancelIoEx", s, ov); r != 1 {
		t.Fatalf("CancelIoEx = %d err %d", r, h.lastError())
	}
	if st := uint32(h.r64(ov)); st != statusCancelled {
		t.Fatalf("Internal = %#x, want STATUS_CANCELLED", st)
	}
	if r := h.call(dK32, "WaitForSingleObject", ev, 0); r != 0 {
		t.Fatalf("event not set after cancel: %#x", r)
	}
	n := h.alloc(4)
	if r := h.call(dK32, "GetOverlappedResult", s, ov, n, 1); r != 0 || h.lastError() != errOperationAborted || h.r32(n) != 0 {
		t.Fatalf("GetOverlappedResult = %d err %d n %d, want ERROR_OPERATION_ABORTED", r, h.lastError(), h.r32(n))
	}
	if r := h.call(dK32, "CancelIoEx", s, ov); r != 0 || h.lastError() != errNotFound {
		t.Fatalf("second CancelIoEx = %d err %d", r, h.lastError())
	}
	// the cancelled read consumed nothing: a new read gets the message
	h.writeH(c, "hey")
	buf, nr := h.alloc(8), h.alloc(4)
	ov2 := h.alloc(32)
	h.write(ov2, make([]byte, 32))
	if r := h.call(dK32, "ReadFile", s, buf, 8, nr, ov2); r != 1 || h.r32(nr) != 3 || string(h.read(buf, 3)) != "hey" {
		t.Fatalf("ReadFile after cancel = %d n %d err %d", r, h.r32(nr), h.lastError())
	}
	// CancelIo: the calling thread's pending operations; none left is success
	ov3, _ := pendingPipeRead(t, h, s, 0)
	if r := h.call(dK32, "CancelIo", s); r != 1 || uint32(h.r64(ov3)) != statusCancelled {
		t.Fatalf("CancelIo = %d internal %#x", r, h.r64(ov3))
	}
	if r := h.call(dK32, "CancelIo", s); r != 1 {
		t.Fatalf("CancelIo(nothing pending) = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "CancelIoEx", s, 0); r != 0 || h.lastError() != errNotFound {
		t.Fatalf("CancelIoEx(all, none pending) = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "CancelIo", 0x1234); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("CancelIo(bad) = %d err %d", r, h.lastError())
	}
}

// GetOverlappedResultEx on a pending pipe read times out, then reports the
// completion once the client writes.
func TestNamedPipeGetOverlappedResultEx(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\ovl-ex`
	s := h.mkPipe(name, tPipeDuplex|tFlagOverlap, tPipeMsg, 1)
	c := h.openPipe(name, 0)
	ov, buf := pendingPipeRead(t, h, s, 0)
	n := h.alloc(4)
	if r := h.call(dK32, "GetOverlappedResultEx", s, ov, n, 20, 0); r != 0 || h.lastError() != errTimeout258 {
		t.Fatalf("pending, 20 ms = %d err %d, want WAIT_TIMEOUT", r, h.lastError())
	}
	h.writeH(c, "ok")
	if r := h.call(dK32, "GetOverlappedResultEx", s, ov, n, 1000, 0); r != 1 || h.r32(n) != 2 || string(h.read(buf, 2)) != "ok" {
		t.Fatalf("GetOverlappedResultEx = %d n %d err %d", r, h.r32(n), h.lastError())
	}
}

// A named pipe associated with a completion port queues a packet for each
// overlapped completion: pending, immediate, and cancelled; not when the
// event's low bit is set or after FILE_SKIP_COMPLETION_PORT_ON_SUCCESS for
// immediate success.
func TestNamedPipeIocp(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\ovl-iocp`
	s := h.mkPipe(name, tPipeDuplex|tFlagOverlap, tPipeMsg, 1)
	c := h.openPipe(name, 0)
	port := h.call(dK32, "CreateIoCompletionPort", s, 0, 7, 0)
	if port == 0 {
		t.Fatalf("CreateIoCompletionPort err %d", h.lastError())
	}
	if r := h.call(dK32, "CreateIoCompletionPort", s, port, 8, 0); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("second association = %#x err %d", r, h.lastError())
	}
	nb, key, pov := h.alloc(4), h.alloc(8), h.alloc(8)
	get := func(ms uint32) uint64 {
		h.w64(pov, 0)
		return h.call(dK32, "GetQueuedCompletionStatus", port, nb, key, pov, uint64(ms))
	}
	// pending read, completed by the client's write
	ov, _ := pendingPipeRead(t, h, s, 0)
	if r := get(0); r != 0 || h.lastError() != errTimeout258 {
		t.Fatalf("packet before completion: %d err %d", r, h.lastError())
	}
	h.writeH(c, "abc")
	if r := get(1000); r != 1 || h.r64(pov) != ov || h.r64(key) != 7 || h.r32(nb) != 3 {
		t.Fatalf("GQCS = %d ov %#x/%#x key %d n %d err %d", r, h.r64(pov), ov, h.r64(key), h.r32(nb), h.lastError())
	}
	// immediate success also queues a packet
	h.writeH(c, "de")
	ov2, buf := h.alloc(32), h.alloc(8)
	h.write(ov2, make([]byte, 32))
	if r := h.call(dK32, "ReadFile", s, buf, 8, 0, ov2); r != 1 {
		t.Fatalf("ReadFile(immediate) = %d err %d", r, h.lastError())
	}
	if r := get(0); r != 1 || h.r64(pov) != ov2 || h.r32(nb) != 2 {
		t.Fatalf("immediate GQCS = %d ov %#x n %d err %d", r, h.r64(pov), h.r32(nb), h.lastError())
	}
	// cancellation queues a packet reporting ERROR_OPERATION_ABORTED
	ov3, _ := pendingPipeRead(t, h, s, 0)
	h.call(dK32, "CancelIoEx", s, ov3)
	if r := get(0); r != 0 || h.r64(pov) != ov3 || h.lastError() != errOperationAborted {
		t.Fatalf("cancel GQCS = %d ov %#x err %d", r, h.r64(pov), h.lastError())
	}
	// hEvent low bit set: no packet
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	h.writeH(c, "f")
	ov4 := h.alloc(32)
	h.write(ov4, make([]byte, 32))
	h.w64(ov4+24, ev|1)
	if r := h.call(dK32, "ReadFile", s, buf, 8, 0, ov4); r != 1 {
		t.Fatalf("ReadFile(ev|1) = %d err %d", r, h.lastError())
	}
	if r := get(0); r != 0 || h.lastError() != errTimeout258 {
		t.Fatalf("packet despite hEvent|1: %d ov %#x", r, h.r64(pov))
	}
	// skip port on success: immediate completion queues nothing
	if r := h.call(dK32, "SetFileCompletionNotificationModes", s, 1); r != 1 {
		t.Fatalf("SetFileCompletionNotificationModes err %d", h.lastError())
	}
	h.writeH(c, "g")
	h.write(ov2, make([]byte, 32))
	if r := h.call(dK32, "ReadFile", s, buf, 8, 0, ov2); r != 1 {
		t.Fatalf("ReadFile(skip) = %d err %d", r, h.lastError())
	}
	if r := get(0); r != 0 || h.lastError() != errTimeout258 {
		t.Fatalf("packet despite skip-on-success: %d", r)
	}
}

// fmin/fmax and their f/l variants have C semantics (a NaN operand is
// ignored); the l variants were once registered with Go's math.Min/Max.
func TestFminFmaxNaN(t *testing.T) {
	h := newTestEmu(t)
	nan := math.NaN()
	for _, c := range []struct {
		name string
		want float64
	}{{"fmin", 1}, {"fminl", 1}, {"fmax", 1}, {"fmaxl", 1}} {
		var a, b cpu.Vec
		a.SetF64(0, nan)
		b.SetF64(0, 1)
		h.E.Cur.CPU.X[0], h.E.Cur.CPU.X[1] = a, b
		table(dUcrt).funcs[c.name].fn(h.E)
		if got := h.E.Cur.CPU.X[0].F64(0); got != c.want {
			t.Errorf("%s(NaN, 1) = %v, want %v", c.name, got, c.want)
		}
	}
}
