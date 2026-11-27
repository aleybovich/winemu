package win

import (
	"encoding/binary"
	"testing"
	"time"
)

// jobTotal returns TotalProcesses of the job (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).
func jobTotal(t *testing.T, h *testEmu, jh uint64) uint32 {
	t.Helper()
	info := h.alloc(48)
	if h.call(dK32, "QueryInformationJobObject", jh, jobBasicAccounting, info, 48, 0) != 1 {
		t.Fatalf("query err %d", h.lastError())
	}
	return h.r32(info + 36)
}

// jobbed puts h into a new job with the given limit flags.
func jobbed(t *testing.T, h *testEmu, limits uint32) uint64 {
	t.Helper()
	h.E.proc.markStarted()
	jh := h.call(dK32, "CreateJobObjectW", 0, 0)
	if limits != 0 {
		info := h.alloc(144)
		h.w32(info+16, limits)
		if h.call(dK32, "SetInformationJobObject", jh, jobExtendedLimit, info, 144) != 1 {
			t.Fatalf("set limits err %d", h.lastError())
		}
	}
	if h.call(dK32, "AssignProcessToJobObject", jh, pseudoProcess) != 1 {
		t.Fatalf("assign: err %d", h.lastError())
	}
	return jh
}

// system() runs its command interpreter as a child of the caller: it joins
// the caller's job, and so do the interpreter's children.
func TestXprocSystemChildrenJoinJob(t *testing.T) {
	h := newTestEmu(t)
	jh := jobbed(t, h, 0)
	if r := h.call(dUcrt, "system", h.astr(`cmd /d /c exit 3`)); int32(r) != 3 {
		t.Fatalf("system = %d", int32(r))
	}
	if n := jobTotal(t, h, jh); n != 3 { // self, system's cmd, inner cmd
		t.Fatalf("TotalProcesses %d, want 3", n)
	}
}

// With JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, children of a job member are
// not associated with the job, whichever way they are started.
func TestXprocSilentBreakawayCmdChildren(t *testing.T) {
	h := newTestEmu(t)
	jh := jobbed(t, h, jobLimitSilentBreakawayOK)
	if r := h.call(dUcrt, "system", h.astr(`cmd /d /c exit 3`)); int32(r) != 3 {
		t.Fatalf("system = %d", int32(r))
	}
	if n := jobTotal(t, h, jh); n != 1 {
		t.Fatalf("TotalProcesses %d, want 1 (only the member itself)", n)
	}
}

// An idle process (all threads waiting) releases its run lock while the
// scheduler sleeps, so another process's ReadProcessMemory does not wait for
// the sleep to end.
func TestXprocIdleSleepReleasesRunLock(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	ev := b.call(dK32, "CreateEventW", 0, 1, 0, 0)
	done := make(chan uint64, 1)
	go func() { done <- b.call(dK32, "WaitForSingleObject", ev, 1500) }()
	time.Sleep(50 * time.Millisecond) // b is now idle in its scheduler
	hb, src, dst := procHandle(h, b), b.alloc(8), h.alloc(8)
	t0 := time.Now()
	if r := h.call(dK32, "ReadProcessMemory", hb, src, dst, 8, 0); r != 1 {
		t.Fatalf("ReadProcessMemory = %d, err %d", r, h.lastError())
	}
	if d := time.Since(t0); d > 700*time.Millisecond {
		t.Fatalf("ReadProcessMemory took %v behind an idle sleep", d)
	}
	if r := <-done; r != 0x102 {
		t.Fatalf("wait = %#x, want WAIT_TIMEOUT", r)
	}
}

// A process exit requested while another thread runs its DLL_THREAD_DETACH
// notifications (ExitThread) ends the process; it is not swallowed by the
// best-effort detach. The detach callback here calls ExitProcess(7).
func TestThreadDetachKeepsProcessExit(t *testing.T) {
	h := newTestEmu(t)
	k32, err := h.E.LoadDLL(dK32)
	if err != nil {
		t.Fatal(err)
	}
	exitProc, ok1 := h.E.GetExport(k32, "ExitProcess", 0, false)
	exitThread, ok2 := h.E.GetExport(k32, "ExitThread", 0, false)
	if !ok1 || !ok2 {
		t.Fatal("exports missing")
	}
	code := h.call(dK32, "VirtualAlloc", 0, 0x1000, 0x3000, 0x40) // PAGE_EXECUTE_READWRITE
	if code == 0 {
		t.Fatalf("VirtualAlloc err %d", h.lastError())
	}
	// cmp edx,3 (DLL_THREAD_DETACH); jne ret; mov ecx,7; mov rax,ExitProcess; jmp rax; ret
	prog := []byte{0x83, 0xFA, 0x03, 0x75, 0x11, 0xB9, 7, 0, 0, 0, 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0, 0xC3}
	binary.LittleEndian.PutUint64(prog[12:], exitProc)
	h.write(code, prog)
	cbs := h.alloc(16)
	h.w64(cbs, code)
	h.E.modules = append(h.E.modules, &Module{Name: "detach_test.dll", Native: true, initDone: true, tlsCallback: cbs})

	th := h.call(dK32, "CreateThread", 0, 0, exitThread, 3, 0, 0)
	if th == 0 {
		t.Fatalf("CreateThread err %d", h.lastError())
	}
	r, exited, c := h.tryCall(dK32, "WaitForSingleObject", th, 2000)
	if !exited || c != 7 {
		t.Fatalf("wait = %#x, exited %v code %d; want process exit 7", r, exited, c)
	}
}
