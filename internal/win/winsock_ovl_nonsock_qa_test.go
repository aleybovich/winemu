//go:build darwin || linux

package win

import "testing"

// GetOverlappedResult(Ex) and CancelIo(Ex) on handles that are not sockets:
// files and anonymous pipes complete overlapped I/O synchronously and leave
// the status in OVERLAPPED.Internal / byte count in InternalHigh.

func newOv(h *testEmu) uint64 {
	ov := h.alloc(32)
	h.write(ov, make([]byte, 32))
	return ov
}

func TestGetOverlappedResultFile(t *testing.T) {
	h := newTestEmu(t)
	path := h.wstr(tempFilePath(t, h, "ovres.txt"))
	fh := h.call(dK32, "CreateFileW", path, qaGenericRW, 0, 0, qaCreateAlways, qaFileAttrNormal|0x40000000, 0) // FILE_FLAG_OVERLAPPED
	if fh == qaInvalidHandle || fh == 0 {
		t.Fatalf("CreateFileW = %#x err %d", fh, h.lastError())
	}
	defer h.call(dK32, "CloseHandle", fh)
	ov, n := newOv(h), h.alloc(4)
	data := "overlapped file data"
	if r := h.call(dK32, "WriteFile", fh, h.astr(data), uint64(len(data)), 0, ov); r != 1 {
		t.Fatalf("WriteFile(ov) = %d err %d", r, h.lastError())
	}
	h.w32(n, 0xDEAD)
	if r := h.call(dK32, "GetOverlappedResult", fh, ov, n, 0); r != 1 || h.r32(n) != uint32(len(data)) {
		t.Fatalf("GetOverlappedResult(write) = %d n=%d err %d", r, h.r32(n), h.lastError())
	}
	ov = newOv(h)
	h.w32(ov+8+8, 5) // Offset = 5
	buf := h.alloc(64)
	if r := h.call(dK32, "ReadFile", fh, buf, 64, 0, ov); r != 1 {
		t.Fatalf("ReadFile(ov) = %d err %d", r, h.lastError())
	}
	h.w32(n, 0xDEAD)
	if r := h.call(dK32, "GetOverlappedResultEx", fh, ov, n, 0, 0); r != 1 || h.r32(n) != uint32(len(data)-5) {
		t.Fatalf("GetOverlappedResultEx(read) = %d n=%d err %d", r, h.r32(n), h.lastError())
	}
	if got := h.readAStr(buf)[:len(data)-5]; got != data[5:] {
		t.Fatalf("read %q", got)
	}
	// a handle that is not a socket can be associated with a port; nothing is pending on it
	port := h.call(dK32, "CreateIoCompletionPort", fh, 0, 7, 0)
	if port == 0 {
		t.Fatalf("CreateIoCompletionPort(file) err %d", h.lastError())
	}
	defer h.call(dK32, "CloseHandle", port)
	if r := h.call(dK32, "CancelIo", fh); r != 1 {
		t.Fatalf("CancelIo(file) = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "CancelIoEx", fh, 0); r != 0 || h.lastError() != errNotFound {
		t.Fatalf("CancelIoEx(file, NULL) = %d err %d, want ERROR_NOT_FOUND", r, h.lastError())
	}
	if r := h.call(dK32, "CancelIoEx", 0xBAD0, 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("CancelIoEx(bad) = %d err %d", r, h.lastError())
	}
}

func TestGetOverlappedResultAnonPipe(t *testing.T) {
	h := newTestEmu(t)
	rw := h.alloc(16)
	if h.call(dK32, "CreatePipe", rw, rw+8, 0, 0) != 1 {
		t.Fatalf("CreatePipe err %d", h.lastError())
	}
	rd, wr := h.r64(rw), h.r64(rw+8)
	ov, n := newOv(h), h.alloc(4)
	if r := h.call(dK32, "WriteFile", wr, h.astr("abc"), 3, 0, ov); r != 1 {
		t.Fatalf("WriteFile(pipe, ov) = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "GetOverlappedResult", wr, ov, n, 1); r != 1 || h.r32(n) != 3 {
		t.Fatalf("GetOverlappedResult(pipe write) = %d n=%d err %d", r, h.r32(n), h.lastError())
	}
	ov = newOv(h)
	buf := h.alloc(8)
	if r := h.call(dK32, "ReadFile", rd, buf, 8, 0, ov); r != 1 {
		t.Fatalf("ReadFile(pipe, ov) = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "GetOverlappedResult", rd, ov, n, 1); r != 1 || h.r32(n) != 3 {
		t.Fatalf("GetOverlappedResult(pipe read) = %d n=%d err %d", r, h.r32(n), h.lastError())
	}
}

// An OVERLAPPED filled in by the caller (event only, or a status written by
// another component): pending, failed and successful states.
func TestGetOverlappedResultStates(t *testing.T) {
	h := newTestEmu(t)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	ov, n := newOv(h), h.alloc(4)
	h.w64(ov+24, ev)
	h.w64(ov, statusPending)
	if r := h.call(dK32, "GetOverlappedResult", 0, ov, n, 0); r != 0 || h.lastError() != errIOIncomplete {
		t.Fatalf("pending, no wait = %d err %d, want ERROR_IO_INCOMPLETE", r, h.lastError())
	}
	if r := h.call(dK32, "GetOverlappedResultEx", 0, ov, n, 20, 0); r != 0 || h.lastError() != errTimeout258 {
		t.Fatalf("pending, 20 ms = %d err %d, want WAIT_TIMEOUT", r, h.lastError())
	}
	h.w64(ov, 0xC0000011) // STATUS_END_OF_FILE
	h.w64(ov+8, 0)
	if r := h.call(dK32, "GetOverlappedResult", 0, ov, n, 1); r != 0 || h.lastError() != errHandleEOF {
		t.Fatalf("EOF = %d err %d, want ERROR_HANDLE_EOF", r, h.lastError())
	}
	h.w64(ov, 0)
	h.w64(ov+8, 42)
	if r := h.call(dK32, "GetOverlappedResult", 0, ov, n, 1); r != 1 || h.r32(n) != 42 {
		t.Fatalf("success = %d n=%d err %d", r, h.r32(n), h.lastError())
	}
}
