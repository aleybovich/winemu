package win

// QA self-tests for the unit harness (harness_test.go): they exercise the
// harness the way API workstreams use it.

import (
	"strings"
	"testing"
	"time"
)

// Prefixed so they cannot collide with constants added by API workstreams.
const (
	qaGenericRW      = 0x80000000 | 0x40000000
	qaGenericRead    = 0x80000000
	qaCreateAlways   = 2
	qaOpenExisting   = 3
	qaFileAttrNormal = 0x80
	qaInvalidHandle  = ^uint64(0)
)

// tempFilePath returns a guest path inside the guest's temp directory,
// obtained through GetTempPathW (out-buffer + size probe).
func tempFilePath(t *testing.T, h *testEmu, name string) string {
	t.Helper()
	need := h.call(dK32, "GetTempPathW", 0, 0)
	if need == 0 {
		t.Fatalf("GetTempPathW size probe failed, lastError %d", h.lastError())
	}
	buf := h.alloc(int(2 * need))
	n := h.call(dK32, "GetTempPathW", need, buf)
	if n == 0 || n >= need {
		t.Fatalf("GetTempPathW(%d) = %d", need, n)
	}
	dir := h.readWStr(buf)
	if !strings.HasSuffix(dir, `\`) {
		t.Fatalf("GetTempPathW = %q, want trailing backslash", dir)
	}
	return dir + name
}

// CreateFileW has 7 arguments (3 on the stack); WriteFile/ReadFile/GetFileSizeEx
// write through out pointers.
func TestHarnessQAStackArgsAndOutPointers(t *testing.T) {
	h := newTestEmu(t)
	path := h.wstr(tempFilePath(t, h, "qa.txt"))
	fh := h.call(dK32, "CreateFileW", path, qaGenericRW, 0, 0, qaCreateAlways, qaFileAttrNormal, 0)
	if fh == qaInvalidHandle || fh == 0 {
		t.Fatalf("CreateFileW = %#x, lastError %d", fh, h.lastError())
	}
	data := "hello, stack args"
	n := h.alloc(4)
	h.w32(n, 0xDEADBEEF)
	if h.call(dK32, "WriteFile", fh, h.astr(data), uint64(len(data)), n, 0) == 0 || h.r32(n) != uint32(len(data)) {
		t.Fatalf("WriteFile: written %d, lastError %d", h.r32(n), h.lastError())
	}
	size := h.alloc(8)
	if h.call(dK32, "GetFileSizeEx", fh, size) == 0 || h.r64(size) != uint64(len(data)) {
		t.Fatalf("GetFileSizeEx = %d, lastError %d", h.r64(size), h.lastError())
	}
	if h.call(dK32, "CloseHandle", fh) == 0 {
		t.Fatalf("CloseHandle failed, lastError %d", h.lastError())
	}

	fh = h.call(dK32, "CreateFileW", path, qaGenericRead, 1, 0, qaOpenExisting, qaFileAttrNormal, 0)
	if fh == qaInvalidHandle {
		t.Fatalf("reopen: lastError %d", h.lastError())
	}
	buf := h.alloc(64)
	h.w32(n, 0xDEADBEEF)
	if h.call(dK32, "ReadFile", fh, buf, 64, n, 0) == 0 || h.r32(n) != uint32(len(data)) || string(h.read(buf, len(data))) != data {
		t.Fatalf("ReadFile: read %d %q, lastError %d", h.r32(n), h.read(buf, len(data)), h.lastError())
	}
	h.call(dK32, "CloseHandle", fh)
}

func TestHarnessQALastErrorOnFailure(t *testing.T) {
	h := newTestEmu(t)
	h.setLastError(0)
	path := h.wstr(tempFilePath(t, h, "does-not-exist.txt"))
	if fh := h.call(dK32, "CreateFileW", path, qaGenericRead, 0, 0, qaOpenExisting, qaFileAttrNormal, 0); fh != qaInvalidHandle {
		t.Fatalf("CreateFileW(missing) = %#x, want INVALID_HANDLE_VALUE", fh)
	}
	if h.lastError() != errFileNotFound {
		t.Fatalf("lastError = %d, want %d", h.lastError(), errFileNotFound)
	}
	if got := h.call(dK32, "GetLastError"); got != errFileNotFound {
		t.Fatalf("GetLastError() = %d, want %d", got, errFileNotFound)
	}
	h.setLastError(0)
	if r := h.call(dK32, "CloseHandle", 0x7FFF0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("CloseHandle(bogus) = %d, lastError %d, want 0 / %d", r, h.lastError(), errInvalidHandle)
	}
}

func TestHarnessQAOtherDLLs(t *testing.T) {
	h := newTestEmu(t)

	// advapi32: size probe through an in/out DWORD, then a real call.
	size := h.alloc(4)
	if r := h.call(dAdv, "GetUserNameW", 0, size); r != 0 || h.lastError() != errInsufficientBuf || h.r32(size) == 0 {
		t.Fatalf("GetUserNameW probe = %d, size %d, lastError %d", r, h.r32(size), h.lastError())
	}
	buf := h.alloc(int(2 * h.r32(size)))
	if r := h.call(dAdv, "GetUserNameW", buf, size); r != 1 || h.readWStr(buf) == "" {
		t.Fatalf("GetUserNameW = %d %q, lastError %d", r, h.readWStr(buf), h.lastError())
	}

	// ws2_32: struct out-parameter, and the winsock last error.
	wsa := h.alloc(408)
	if r := h.call("ws2_32.dll", "WSAStartup", 0x0202, wsa); r != 0 || h.r16(wsa) != 0x0202 {
		t.Fatalf("WSAStartup = %d, wVersion %#x", r, h.r16(wsa))
	}
	h.call("ws2_32.dll", "WSASetLastError", 10022)
	if got := h.call("ws2_32.dll", "WSAGetLastError"); got != 10022 {
		t.Fatalf("WSAGetLastError = %d, want 10022", got)
	}
	// DLL names are case-insensitive and resolve to the same table.
	if got := h.call("WS2_32.DLL", "WSAGetLastError"); got != 10022 {
		t.Fatalf("WS2_32.DLL!WSAGetLastError = %d, want 10022", got)
	}
}

// Blocking APIs must return (timeout) rather than hang the test.
func TestHarnessQABlockingWait(t *testing.T) {
	h := newTestEmu(t)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0) // manual reset, unsignalled
	if ev == 0 {
		t.Fatalf("CreateEventW failed, lastError %d", h.lastError())
	}

	type result struct {
		ret uint64
		dur time.Duration
	}
	wait := func(timeoutMs uint64) result {
		t.Helper()
		done := make(chan result, 1)
		go func() {
			start := time.Now()
			r, _, _ := h.tryCall(dK32, "WaitForSingleObject", ev, timeoutMs)
			done <- result{r, time.Since(start)}
		}()
		select {
		case r := <-done:
			return r
		case <-time.After(10 * time.Second):
			t.Fatalf("WaitForSingleObject(%d ms) did not return", timeoutMs)
			return result{}
		}
	}

	if r := wait(100); r.ret != waitTimeout || r.dur < 90*time.Millisecond {
		t.Fatalf("unsignalled wait(100) = %#x after %v, want WAIT_TIMEOUT after >= 100ms", r.ret, r.dur)
	}
	if r := wait(0); r.ret != waitTimeout {
		t.Fatalf("unsignalled wait(0) = %#x, want WAIT_TIMEOUT", r.ret)
	}
	if h.call(dK32, "SetEvent", ev) == 0 {
		t.Fatalf("SetEvent failed")
	}
	if r := wait(infinite); r.ret != waitObject0 {
		t.Fatalf("signalled wait(INFINITE) = %#x, want WAIT_OBJECT_0", r.ret)
	}
	// The harness is reusable after a blocking call.
	if r := wait(50); r.ret != waitObject0 {
		t.Fatalf("manual-reset event wait again = %#x, want WAIT_OBJECT_0", r.ret)
	}
	h.setLastError(0)
	if r := wait(0); r.ret != waitObject0 {
		t.Fatalf("wait(0) = %#x", r.ret)
	}
	if r, _, _ := h.tryCall(dK32, "WaitForSingleObject", 0x7FFF0, 0); r != waitFailed || h.lastError() != errInvalidHandle {
		t.Fatalf("wait(bogus) = %#x, lastError %d, want WAIT_FAILED / %d", r, h.lastError(), errInvalidHandle)
	}
	if r := h.call(dK32, "Sleep", 30); r != 0 {
		t.Fatalf("Sleep = %d", r)
	}
}

// Two harness instances in one test are independent processes.
func TestHarnessQAIsolation(t *testing.T) {
	a, b := newTestEmu(t), newTestEmu(t)
	if a.E == b.E {
		t.Fatal("same Emu")
	}

	// last error
	a.setLastError(111)
	b.setLastError(222)
	if a.call(dK32, "GetLastError") != 111 || b.call(dK32, "GetLastError") != 222 {
		t.Fatalf("last error shared: a=%d b=%d", a.lastError(), b.lastError())
	}

	// handles: a handle created in a is not valid in b
	ev := a.call(dK32, "CreateEventW", 0, 1, 0, 0)
	if ev == 0 {
		t.Fatal("CreateEventW failed")
	}
	if r := b.call(dK32, "SetEvent", ev); r != 0 {
		t.Fatalf("b.SetEvent(a's handle %#x) = %d, want failure", ev, r)
	}
	if r := b.call(dK32, "CloseHandle", ev); r != 0 || b.lastError() != errInvalidHandle {
		t.Fatalf("b.CloseHandle(a's handle %#x) = %d, lastError %d", ev, r, b.lastError())
	}
	if a.call(dK32, "SetEvent", ev) == 0 || a.call(dK32, "CloseHandle", ev) == 0 {
		t.Fatal("a's handle broken by b")
	}

	// memory: same guest address, independent contents
	pa, pb := a.alloc(16), b.alloc(16)
	a.w64(pa, 0x1111)
	b.w64(pb, 0x2222)
	if pa == pb {
		if a.r64(pa) != 0x1111 || b.r64(pb) != 0x2222 {
			t.Fatalf("memory shared at %#x: a=%#x b=%#x", pa, a.r64(pa), b.r64(pb))
		}
	} else if a.r64(pa) != 0x1111 {
		t.Fatalf("a memory clobbered")
	}

	// environment
	if a.call(dK32, "SetEnvironmentVariableW", a.wstr("QA_ONLY_IN_A"), a.wstr("1")) == 0 {
		t.Fatal("SetEnvironmentVariableW failed")
	}
	b.setLastError(0)
	if r := b.call(dK32, "GetEnvironmentVariableW", b.wstr("QA_ONLY_IN_A"), b.alloc(16), 8); r != 0 || b.lastError() != 203 {
		t.Fatalf("b sees a's env var: ret %d lastError %d", r, b.lastError())
	}

	// stdout
	out := a.call(dK32, "GetStdHandle", uint64(0xFFFFFFF5))
	a.call(dK32, "WriteFile", out, a.astr("only a\n"), 7, a.alloc(4), 0)
	if b.stdout() != "" || a.stdout() != "only a\n" {
		t.Fatalf("stdout: a=%q b=%q", a.stdout(), b.stdout())
	}
}

// An INFINITE wait that nothing can satisfy is reported by the scheduler's
// deadlock detector (about 2s) as process termination with
// STATUS_POSSIBLE_DEADLOCK, which tryCall reports instead of hanging.
func TestHarnessQADeadlockTerminates(t *testing.T) {
	h := newTestEmu(t)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	done := make(chan uint32, 1)
	go func() {
		_, exited, code := h.tryCall(dK32, "WaitForSingleObject", ev, infinite)
		if !exited {
			code = 0
		}
		done <- code
	}()
	select {
	case code := <-done:
		if code != 0xC0000194 {
			t.Fatalf("deadlocked wait: exit code %#x, want 0xC0000194", code)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("deadlocked WaitForSingleObject(INFINITE) did not return")
	}
}
