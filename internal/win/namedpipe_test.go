package win

import (
	"testing"
	"time"
)

const (
	tPipeDuplex   = 3
	tPipeMsg      = 4 | 2 // PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE
	tFlagOverlap  = 0x40000000
	tUnlimited    = 255
	tGenericRW    = genericRead | genericWrite
	tOpenExisting = 3
)

func (h *testEmu) mkPipe(name string, openMode, pipeMode, maxInst uint32) uint64 {
	h.t.Helper()
	return h.call(dK32, "CreateNamedPipeW", h.wstr(name), uint64(openMode), uint64(pipeMode), uint64(maxInst), 512, 512, 0, 0)
}

func (h *testEmu) openPipe(name string, flags uint32) uint64 {
	h.t.Helper()
	return h.call(dK32, "CreateFileW", h.wstr(name), tGenericRW, 0, 0, tOpenExisting, uint64(flags), 0)
}

func (h *testEmu) writeH(fh uint64, s string) (uint64, uint32) {
	h.t.Helper()
	b, n := h.alloc(len(s)+1), h.alloc(4)
	h.write(b, []byte(s))
	r := h.call(dK32, "WriteFile", fh, b, uint64(len(s)), n, 0)
	return r, h.r32(n)
}

func (h *testEmu) readH(fh uint64, size int) (uint64, string, uint32) {
	h.t.Helper()
	b, n := h.alloc(size+1), h.alloc(4)
	r := h.call(dK32, "ReadFile", fh, b, uint64(size), n, 0)
	return r, string(h.read(b, int(h.r32(n)))), h.lastError()
}

func TestNamedPipeByteMode(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\np-byte`
	if c := h.openPipe(name, 0); c != invalidHandle || h.lastError() != errFileNotFound {
		t.Fatalf("open before create: %#x err %d", c, h.lastError())
	}
	s := h.mkPipe(name, tPipeDuplex, 0, 1)
	if s == invalidHandle {
		t.Fatalf("CreateNamedPipeW err %d", h.lastError())
	}
	if ft := h.call(dK32, "GetFileType", s); ft != filePipe {
		t.Fatalf("GetFileType = %d", ft)
	}
	if r, _, err := h.readH(s, 4); r != 0 || err != errPipeListening {
		t.Fatalf("read on listening: %d err %d", r, err)
	}
	c := h.openPipe(`\\.\PIPE\NP-Byte`, 0) // names are case-insensitive
	if c == invalidHandle {
		t.Fatalf("client open err %d", h.lastError())
	}
	if c2 := h.openPipe(name, 0); c2 != invalidHandle || h.lastError() != errPipeBusy {
		t.Fatalf("second client: %#x err %d", c2, h.lastError())
	}
	if r := h.call(dK32, "ConnectNamedPipe", s, 0); r != 0 || h.lastError() != errPipeConnected {
		t.Fatalf("ConnectNamedPipe after client: %d err %d", r, h.lastError())
	}
	h.writeH(c, "hel")
	h.writeH(c, "lo")
	if r, got, _ := h.readH(s, 16); r != 1 || got != "hello" {
		t.Fatalf("server read %d %q", r, got)
	}
	h.writeH(s, "back")
	avail := h.alloc(4)
	if r := h.call(dK32, "PeekNamedPipe", c, 0, 0, 0, avail, 0); r != 1 || h.r32(avail) != 4 {
		t.Fatalf("peek %d avail %d", r, h.r32(avail))
	}
	if r, got, _ := h.readH(c, 2); r != 1 || got != "ba" {
		t.Fatalf("client read %d %q", r, got)
	}
	// client goes away: data read, then broken pipe; writes see "being closed"
	h.call(dK32, "CloseHandle", c)
	if r, _, err := h.readH(s, 4); r != 0 || err != errBrokenPipe {
		t.Fatalf("read after client close: %d err %d", r, err)
	}
	if r, _ := h.writeH(s, "x"); r != 0 || h.lastError() != errNoData {
		t.Fatalf("write after client close: %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "ConnectNamedPipe", s, 0); r != 0 || h.lastError() != errNoData {
		t.Fatalf("connect before disconnect: %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "DisconnectNamedPipe", s); r != 1 {
		t.Fatalf("DisconnectNamedPipe err %d", h.lastError())
	}
	if c := h.openPipe(name, 0); c != invalidHandle || h.lastError() != errPipeBusy {
		t.Fatalf("open on disconnected instance: %#x err %d", c, h.lastError())
	}
	h.call(dK32, "CloseHandle", s)
	if c := h.openPipe(name, 0); c != invalidHandle || h.lastError() != errFileNotFound {
		t.Fatalf("open after last instance closed: %#x err %d", c, h.lastError())
	}
}

func TestNamedPipeMessageMode(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\np-msg`
	s := h.mkPipe(name, tPipeDuplex, tPipeMsg, tUnlimited)
	c := h.openPipe(name, 0)
	mode := h.alloc(4)
	h.w32(mode, 2) // PIPE_READMODE_MESSAGE
	if r := h.call(dK32, "SetNamedPipeHandleState", c, mode, 0, 0); r != 1 {
		t.Fatalf("SetNamedPipeHandleState err %d", h.lastError())
	}
	h.writeH(c, "abc")
	h.writeH(c, "de")
	avail, left := h.alloc(4), h.alloc(4)
	if r := h.call(dK32, "PeekNamedPipe", s, 0, 0, 0, avail, left); r != 1 || h.r32(avail) != 5 || h.r32(left) != 3 {
		t.Fatalf("peek %d avail %d left %d", r, h.r32(avail), h.r32(left))
	}
	if r, got, err := h.readH(s, 2); r != 0 || err != errMoreData || got != "ab" {
		t.Fatalf("short read %d %q err %d", r, got, err)
	}
	if r, got, _ := h.readH(s, 16); r != 1 || got != "c" {
		t.Fatalf("rest %d %q", r, got)
	}
	if r, got, _ := h.readH(s, 16); r != 1 || got != "de" {
		t.Fatalf("second message %d %q", r, got)
	}
	// TransactNamedPipe refuses to run while unread data is in the pipe
	h.writeH(s, "unread")
	in, out, n := h.alloc(8), h.alloc(8), h.alloc(4)
	if r := h.call(dK32, "TransactNamedPipe", c, in, 1, out, 8, n, 0); r != 0 || h.lastError() != errPipeBusy {
		t.Fatalf("transact with unread data %d err %d", r, h.lastError())
	}
	if r, got, _ := h.readH(c, 8); r != 1 || got != "unread" {
		t.Fatalf("client read %d %q", r, got)
	}
	// second instance of an unlimited pipe; info reflects the server end
	if s2 := h.mkPipe(name, tPipeDuplex, tPipeMsg, tUnlimited); s2 == invalidHandle {
		t.Fatalf("second instance err %d", h.lastError())
	}
	fl, os, is, mi := h.alloc(4), h.alloc(4), h.alloc(4), h.alloc(4)
	if r := h.call(dK32, "GetNamedPipeInfo", s, fl, os, is, mi); r != 1 || h.r32(fl) != 5 || h.r32(os) != 512 || h.r32(mi) != 255 {
		t.Fatalf("info %d flags %d out %d max %d", r, h.r32(fl), h.r32(os), h.r32(mi))
	}
	if r := h.call(dK32, "GetNamedPipeInfo", c, fl, 0, 0, 0); r != 1 || h.r32(fl) != 4 {
		t.Fatalf("client info %d flags %d", r, h.r32(fl))
	}
}

func TestNamedPipeErrors(t *testing.T) {
	h := newTestEmu(t)
	if r := h.mkPipe(`\\.\nopipe\x`, tPipeDuplex, 0, 1); r != invalidHandle || h.lastError() != errInvalidName {
		t.Fatalf("bad name: %#x err %d", r, h.lastError())
	}
	if r := h.mkPipe(`\\.\pipe\e`, tPipeDuplex, 2, 1); r != invalidHandle || h.lastError() != errInvalidParameter {
		t.Fatalf("message read mode on byte pipe: %#x err %d", r, h.lastError())
	}
	if r := h.mkPipe(`\\.\pipe\e`, tPipeDuplex, 0, 0); r != invalidHandle || h.lastError() != errInvalidParameter {
		t.Fatalf("zero instances: %#x err %d", r, h.lastError())
	}
	s := h.mkPipe(`\\.\pipe\e`, tPipeDuplex, 0, 1)
	if r := h.mkPipe(`\\.\pipe\e`, tPipeDuplex, 0, 1); r != invalidHandle || h.lastError() != errPipeBusy {
		t.Fatalf("instance limit: %#x err %d", r, h.lastError())
	}
	if r := h.mkPipe(`\\.\pipe\e`, tPipeDuplex|0x80000, 0, 1); r != invalidHandle || h.lastError() != errAccessDenied {
		t.Fatalf("FILE_FLAG_FIRST_PIPE_INSTANCE: %#x err %d", r, h.lastError())
	}
	c := h.openPipe(`\\.\pipe\e`, 0)
	mode := h.alloc(4)
	h.w32(mode, 2)
	if r := h.call(dK32, "SetNamedPipeHandleState", c, mode, 0, 0); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("message mode on byte pipe: %d err %d", r, h.lastError())
	}
	out, n := h.alloc(8), h.alloc(4)
	if r := h.call(dK32, "TransactNamedPipe", c, out, 1, out, 8, n, 0); r != 0 || h.lastError() != errBadPipe {
		t.Fatalf("transact on byte pipe: %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "ConnectNamedPipe", c, 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("connect on client end: %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "WaitNamedPipeW", h.wstr(`\\.\pipe\none`), 0); r != 0 || h.lastError() != errFileNotFound {
		t.Fatalf("WaitNamedPipe(missing) %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "WaitNamedPipeW", h.wstr(`\\.\pipe\e`), 50); r != 0 || h.lastError() != errSemTimeout {
		t.Fatalf("WaitNamedPipe(busy) %d err %d", r, h.lastError())
	}
	// server disconnects: the client end is no longer connected
	h.call(dK32, "DisconnectNamedPipe", s)
	if r, _, err := h.readH(c, 1); r != 0 || err != errPipeNotConnected {
		t.Fatalf("client read after disconnect: %d err %d", r, err)
	}
	if r := h.call(dK32, "DisconnectNamedPipe", s); r != 0 || h.lastError() != errPipeNotConnected {
		t.Fatalf("second disconnect %d err %d", r, h.lastError())
	}
	in := h.alloc(4)
	if r := h.call(dK32, "CallNamedPipeW", h.wstr(`\\.\pipe\none`), in, 1, out, 1, n, 1); r != 0 || h.lastError() != errFileNotFound {
		t.Fatalf("CallNamedPipe(missing) %d err %d", r, h.lastError())
	}
}

// Overlapped ConnectNamedPipe completes through the event when a client in
// another process connects.
func TestNamedPipeOverlappedConnect(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\np-ov`
	s := h.mkPipe(name, tPipeDuplex|tFlagOverlap, tPipeMsg, tUnlimited)
	ev := h.call(dK32, "CreateEventW", 0, 1, 1, 0) // manual, initially set
	ov := h.alloc(32)
	h.w64(ov+24, ev)
	if r := h.call(dK32, "ConnectNamedPipe", s, ov); r != 0 || h.lastError() != errIOPending {
		t.Fatalf("ConnectNamedPipe(ov) %d err %d", r, h.lastError())
	}
	n := h.alloc(4)
	if r := h.call(dK32, "GetOverlappedResult", s, ov, n, 0); r != 0 || h.lastError() != errIOIncomplete {
		t.Fatalf("GetOverlappedResult(pending) %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "WaitForSingleObject", ev, 50); r != waitTimeout {
		t.Fatalf("event set while pending: %#x", r)
	}
	b := sibling(t, h)
	bc := b.openPipe(name, 0)
	if bc == invalidHandle {
		t.Fatalf("client open err %d", b.lastError())
	}
	if r := h.call(dK32, "WaitForSingleObject", ev, 2000); r != 0 {
		t.Fatalf("event not set: %#x", r)
	}
	if r := h.call(dK32, "GetOverlappedResult", s, ov, n, 1); r != 1 || h.r32(ov) != 0 {
		t.Fatalf("GetOverlappedResult %d status %#x err %d", r, h.r32(ov), h.lastError())
	}
	// overlapped read pending until the client writes
	buf := h.alloc(8)
	h.call(dK32, "ResetEvent", ev)
	if r := h.call(dK32, "ReadFile", s, buf, 8, 0, ov); r != 0 || h.lastError() != errIOPending {
		t.Fatalf("ReadFile(ov) %d err %d", r, h.lastError())
	}
	b.writeH(bc, "hi")
	if r := h.call(dK32, "GetOverlappedResult", s, ov, n, 1); r != 1 || h.r32(n) != 2 || string(h.read(buf, 2)) != "hi" {
		t.Fatalf("overlapped read %d n %d err %d", r, h.r32(n), h.lastError())
	}
}

// A message-mode server in one process answers CallNamedPipe from another.
func TestNamedPipeCallAcrossProcesses(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	h.E.proc.markStarted()
	b.E.proc.markStarted()
	const name = `\\.\pipe\np-call`
	s := h.mkPipe(name, tPipeDuplex, tPipeMsg, tUnlimited)
	done := make(chan string, 1)
	go func() {
		var res string
		for range 3 {
			if h.call(dK32, "ConnectNamedPipe", s, 0) == 0 && h.lastError() != errPipeConnected {
				res = "connect failed"
				break
			}
			r, got, _ := h.readH(s, 4)
			if r != 1 || len(got) != 1 {
				res = "read failed"
				break
			}
			h.writeH(s, string(got[0]+1))
			h.call(dK32, "FlushFileBuffers", s)
			h.call(dK32, "DisconnectNamedPipe", s)
			res += got
		}
		done <- res
	}()
	in, out, n := b.alloc(4), b.alloc(4), b.alloc(4)
	for _, c := range "AX" {
		b.write(in, []byte{byte(c)})
		if r := b.call(dK32, "CallNamedPipeW", b.wstr(name), in, 1, out, 1, n, 2000); r != 1 || b.r32(n) != 1 || b.read(out, 1)[0] != byte(c)+1 {
			t.Fatalf("CallNamedPipe %c: %d n %d err %d", c, r, b.r32(n), b.lastError())
		}
	}
	// TransactNamedPipe on a client handle in message read mode
	if r := b.call(dK32, "WaitNamedPipeW", b.wstr(name), 2000); r != 1 {
		t.Fatalf("WaitNamedPipe err %d", b.lastError())
	}
	c := b.openPipe(name, 0)
	mode := b.alloc(4)
	b.w32(mode, 2)
	b.call(dK32, "SetNamedPipeHandleState", c, mode, 0, 0)
	b.write(in, []byte("T"))
	if r := b.call(dK32, "TransactNamedPipe", c, in, 1, out, 4, n, 0); r != 1 || b.r32(n) != 1 || b.read(out, 1)[0] != 'U' {
		t.Fatalf("TransactNamedPipe: %d n %d err %d", r, b.r32(n), b.lastError())
	}
	b.call(dK32, "CloseHandle", c)
	select {
	case got := <-done:
		if got != "AXT" {
			t.Fatalf("server: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server stuck")
	}
}
