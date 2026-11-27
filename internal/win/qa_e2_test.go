package win

import (
	"os"
	"path/filepath"
	"testing"
)

// QA (WS-E2): GetOverlappedResult turns OVERLAPPED.Internal (an NTSTATUS)
// into the result like kernel32 does: InternalHigh is stored whenever the
// operation is no longer pending, and only an NT error/warning status
// (high bit set) fails.
func TestQAGetOverlappedResultStatusMapping(t *testing.T) {
	h := newTestEmu(t)
	ov, n := h.alloc(32), h.alloc(4)
	for _, c := range []struct {
		status uint32
		ret    uint64
		err    uint32
	}{
		{0, 1, 0},
		{0x40000000, 1, 0},                   // STATUS_OBJECT_NAME_EXISTS: informational, success
		{0xC0000011, 0, errHandleEOF},        // STATUS_END_OF_FILE
		{0xC000014B, 0, errBrokenPipe},       // STATUS_PIPE_BROKEN
		{0x80000005, 0, errMoreData},         // STATUS_BUFFER_OVERFLOW
		{0xC00000B1, 0, errNoData},           // STATUS_PIPE_CLOSING
		{0xC00000B0, 0, errPipeNotConnected}, // STATUS_PIPE_DISCONNECTED
		{0xC0000120, 0, errOperationAborted}, // STATUS_CANCELLED
		{0xC0000008, 0, errInvalidHandle},    // STATUS_INVALID_HANDLE
	} {
		h.w64(ov, uint64(c.status))
		h.w64(ov+8, 7)
		h.w32(n, 0xEEEE)
		h.call(dK32, "SetLastError", 0)
		r := h.call(dK32, "GetOverlappedResult", 0, ov, n, 0)
		if r != c.ret || h.r32(n) != 7 || (c.ret == 0 && h.lastError() != c.err) {
			t.Errorf("status %#x: ret %d n %d err %d, want ret %d n 7 err %d", c.status, r, h.r32(n), h.lastError(), c.ret, c.err)
		}
	}
	// still pending, no wait: ERROR_IO_INCOMPLETE and the count is untouched
	h.w64(ov, statusPending)
	h.w32(n, 0xEEEE)
	if r := h.call(dK32, "GetOverlappedResult", 0, ov, n, 0); r != 0 || h.lastError() != errIOIncomplete || h.r32(n) != 0xEEEE {
		t.Errorf("pending: ret %d err %d n %#x", r, h.lastError(), h.r32(n))
	}
}

// An overlapped message read that completes at once with a partial message
// reports ERROR_MORE_DATA through ReadFile and GetOverlappedResult alike.
func TestQANamedPipeOverlappedMoreData(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\qa-ovmore`
	s := h.mkPipe(name, tPipeDuplex|tFlagOverlap, tPipeMsg, 1)
	c := h.openPipe(name, 0)
	h.writeH(c, "hello")
	ov, n, buf := h.alloc(32), h.alloc(4), h.alloc(8)
	if r := h.call(dK32, "ReadFile", s, buf, 2, 0, ov); r != 0 || h.lastError() != errMoreData {
		t.Fatalf("ReadFile(ov) %d err %d", r, h.lastError())
	}
	if h.r32(ov) != 0x80000005 {
		t.Fatalf("Internal %#x", h.r32(ov))
	}
	if r := h.call(dK32, "GetOverlappedResult", s, ov, n, 0); r != 0 || h.lastError() != errMoreData || h.r32(n) != 2 {
		t.Fatalf("GetOverlappedResult %d err %d n %d", r, h.lastError(), h.r32(n))
	}
	if r, got, _ := h.readH(s, 8); r != 1 || got != "llo" {
		t.Fatalf("rest of message %d %q", r, got)
	}
}

// PIPE_NOWAIT server: ConnectNamedPipe never blocks; it succeeds only on
// the first call for an instance disconnected from a previous client.
func TestQANamedPipeNowait(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\qa-nowait`
	s := h.mkPipe(name, tPipeDuplex, 1, 1) // PIPE_NOWAIT, byte mode
	if r := h.call(dK32, "ConnectNamedPipe", s, 0); r != 0 || h.lastError() != errPipeListening {
		t.Fatalf("fresh instance: %d err %d", r, h.lastError())
	}
	c := h.openPipe(name, 0)
	if r := h.call(dK32, "ConnectNamedPipe", s, 0); r != 0 || h.lastError() != errPipeConnected {
		t.Fatalf("client connected: %d err %d", r, h.lastError())
	}
	if r, _, err := h.readH(s, 4); r != 0 || err != errNoData {
		t.Fatalf("nowait read on empty pipe: %d err %d", r, err)
	}
	h.writeH(c, "left")
	h.call(dK32, "DisconnectNamedPipe", s) // discards the unread data
	if r := h.call(dK32, "ConnectNamedPipe", s, 0); r != 1 {
		t.Fatalf("first connect after disconnect: %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "ConnectNamedPipe", s, 0); r != 0 || h.lastError() != errPipeListening {
		t.Fatalf("second connect: %d err %d", r, h.lastError())
	}
	c2 := h.openPipe(name, 0)
	avail := h.alloc(4)
	if r := h.call(dK32, "PeekNamedPipe", s, 0, 0, 0, avail, 0); r != 1 || h.r32(avail) != 0 {
		t.Fatalf("data survived disconnect: %d avail %d", r, h.r32(avail))
	}
	h.call(dK32, "CloseHandle", c2)
	if r := h.call(dK32, "ConnectNamedPipe", s, 0); r != 0 || h.lastError() != errNoData {
		t.Fatalf("client closed, not disconnected: %d err %d", r, h.lastError())
	}
	h.call(dK32, "CloseHandle", c)
}

// The client reads what the server wrote before closing, then gets
// ERROR_BROKEN_PIPE; its writes fail with ERROR_NO_DATA.
func TestQANamedPipeServerClosesFirst(t *testing.T) {
	h := newTestEmu(t)
	const name = `\\.\pipe\qa-srvclose`
	s := h.mkPipe(name, tPipeDuplex, 0, 1)
	c := h.openPipe(name, 0)
	h.writeH(s, "bye")
	h.call(dK32, "CloseHandle", s)
	if r, got, _ := h.readH(c, 8); r != 1 || got != "bye" {
		t.Fatalf("pending data %d %q", r, got)
	}
	if r, _, err := h.readH(c, 8); r != 0 || err != errBrokenPipe {
		t.Fatalf("read after server close %d err %d", r, err)
	}
	if r, _ := h.writeH(c, "x"); r != 0 || h.lastError() != errNoData {
		t.Fatalf("write after server close %d err %d", r, h.lastError())
	}
	// the name is gone with its last instance
	if r := h.openPipe(name, 0); r != invalidHandle || h.lastError() != errFileNotFound {
		t.Fatalf("open after close %#x err %d", r, h.lastError())
	}
}

// UnregisterWaitEx(INVALID_HANDLE_VALUE) returns only after a running
// callback has finished, also when called by a thread whose re-execution
// slot (Thread.xop) is already in use, like a pool thread.
func TestQAUnregisterWaitExBlocksForRunningCallback(t *testing.T) {
	for _, busySlot := range []bool{false, true} {
		h := newTestEmu(t)
		ev := h.call(dK32, "CreateEventW", 0, 1, 1, 0)
		// the callback is Sleep(300): it runs for 300 ms on the wait thread
		wh := regWait(h, ev, procAddr(h, dK32, "Sleep"), 300, infinite, wtExecuteOnlyOnce)
		h.call(dK32, "Sleep", 50) // let the callback start
		if busySlot {
			h.E.Cur.xop = npTxn{}
		}
		start := h.call(dK32, "GetTickCount")
		if r := h.call(dK32, "UnregisterWaitEx", wh, invalidHandle); r != 1 {
			t.Fatalf("busySlot=%v: UnregisterWaitEx %d err %d", busySlot, r, h.lastError())
		}
		if d := h.call(dK32, "GetTickCount") - start; d < 150 {
			t.Errorf("busySlot=%v: returned after %d ms, before the callback finished", busySlot, d)
		}
	}
}

// Builtin cmd looks a program up in the current directory and PATH only
// (not in the directory of the program that started it), and its own
// messages end in CRLF.
func TestQACmdSearchesCwdAndPathOnly(t *testing.T) {
	h := newTestEmu(t)
	h.E.proc.markStarted()
	apps := filepath.Join(h.E.Opt.Prefix, "drive_c", "apps")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apps, "tool.exe"), []byte("not an image"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.E.exeHost = filepath.Join(apps, "parent.exe")
	si, pi, code := h.alloc(104), h.alloc(24), h.alloc(4)
	h.w32(si, 104)
	run := func(cmdline string) (uint32, string) {
		t.Helper()
		if r := h.call(dK32, "CreateProcessW", 0, h.wstr(cmdline), 0, 0, 0, 0, 0, 0, si, pi); r != 1 {
			t.Fatalf("CreateProcess(%s) err %d", cmdline, h.lastError())
		}
		if r := h.call(dK32, "WaitForSingleObject", h.r64(pi), 5000); r != 0 {
			t.Fatalf("wait %#x", r)
		}
		h.call(dK32, "GetExitCodeProcess", h.r64(pi), code)
		b, _ := os.ReadFile(filepath.Join(h.E.Opt.Prefix, "drive_c", "err.txt"))
		return h.r32(code), string(b)
	}
	want := "'tool.exe' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
	if c, msg := run(`C:\windows\system32\cmd.exe /c tool.exe 2>C:\err.txt`); c != 1 || msg != want {
		t.Fatalf("app dir searched: code %d %q", c, msg)
	}
	h.call(dK32, "SetEnvironmentVariableW", h.wstr("PATH"), h.wstr(`C:\windows\system32;C:\apps`))
	if c, msg := run(`C:\windows\system32\cmd.exe /c tool.exe 2>C:\err.txt`); c != 1 || msg != "The system cannot execute the specified program.\r\n" {
		t.Fatalf("PATH not searched: code %d %q", c, msg)
	}
}

// The wait callback gets (Context, TimerOrWaitFired): TRUE on a timeout,
// FALSE when the object was signalled; none runs after UnregisterWait.
func TestQARegisterWaitTimerOrWaitFired(t *testing.T) {
	h := newTestEmu(t)
	var got [][2]uint64
	cb := h.E.stub("winemu", "__qa_wait_cb", func(e *Emu) uint64 {
		got = append(got, [2]uint64{e.Arg(0), e.Arg(1) & 0xFF})
		return 0
	})
	never := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	regWait(h, never, cb, 11, 30, wtExecuteOnlyOnce)
	set := h.call(dK32, "CreateEventW", 0, 1, 1, 0)
	regWait(h, set, cb, 22, infinite, wtExecuteOnlyOnce)
	h.call(dK32, "Sleep", 300)
	if len(got) != 2 || !(got[0] == [2]uint64{22, 0} && got[1] == [2]uint64{11, 1}) && !(got[0] == [2]uint64{11, 1} && got[1] == [2]uint64{22, 0}) {
		t.Fatalf("callbacks %v, want {22 0} and {11 1}", got)
	}
	// repeating wait on an auto-reset event, unregistered before the signal
	auto := h.call(dK32, "CreateEventW", 0, 0, 0, 0)
	wh := regWait(h, auto, cb, 33, infinite, 0)
	h.call(dK32, "Sleep", 20)
	if r := h.call(dK32, "UnregisterWait", wh); r != 1 {
		t.Fatalf("UnregisterWait %d err %d", r, h.lastError())
	}
	h.call(dK32, "SetEvent", auto)
	h.call(dK32, "Sleep", 100)
	if len(got) != 2 {
		t.Fatalf("callback after unregister: %v", got)
	}
	if r := h.call(dK32, "WaitForSingleObject", auto, 0); r != 0 {
		t.Fatalf("unregistered wait consumed the signal: %#x", r)
	}
}
