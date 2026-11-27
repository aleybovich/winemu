package win

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	errNotOwner     = 288
	errTooManyPosts = 298
	waitTimeoutRet  = 0x102
)

// sibling returns a harness for a second process on h's kernel.
func sibling(t *testing.T, h *testEmu) *testEmu {
	t.Helper()
	dir := t.TempDir()
	out, err := os.Create(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	opt := h.E.Opt
	opt.Stdout, opt.Stderr = out, out
	e := newEmu(opt, h.E.k, 0, h.E.proc.pid)
	if _, err := e.setupProcess(filepath.Join(dir, "sib.exe"), nil, 1<<20); err != nil {
		t.Fatal(err)
	}
	return &testEmu{t: t, E: e, dir: dir, outF: out, errF: out}
}

func TestKernelProcessIdentity(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	pid := h.call(dK32, "GetCurrentProcessId")
	bpid := b.call(dK32, "GetCurrentProcessId")
	if pid != uint64(os.Getpid()) || bpid == pid || bpid%4 != 0 || bpid == 0 {
		t.Fatalf("pids %d %d", pid, bpid)
	}
	if tid, btid := h.call(dK32, "GetCurrentThreadId"), b.call(dK32, "GetCurrentThreadId"); tid == btid {
		t.Fatalf("thread ids not unique across processes: %d", tid)
	}
	hp := h.call(dK32, "OpenProcess", 0x1F0FFF, 0, bpid)
	if hp == 0 || h.call(dK32, "GetProcessId", hp) != bpid {
		t.Fatalf("OpenProcess(sibling) = %#x, lastError %d", hp, h.lastError())
	}
	code := h.alloc(4)
	if h.call(dK32, "GetExitCodeProcess", hp, code) != 1 || h.r32(code) != stillActive {
		t.Fatalf("GetExitCodeProcess(running) = %d", h.r32(code))
	}
	if h.call(dK32, "GetProcessId", pseudoProcess) != pid {
		t.Fatal("GetProcessId(GetCurrentProcess())")
	}
	// errors
	h.setLastError(0)
	if h.call(dK32, "OpenProcess", 0x1F0FFF, 0, 0x7FFFFFF0) != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("OpenProcess(unknown) lastError %d", h.lastError())
	}
	if h.call(dK32, "OpenProcess", 0x1F0FFF, 0, 0) != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("OpenProcess(0) lastError %d", h.lastError())
	}
	for _, api := range []string{"GetProcessId", "TerminateProcess"} {
		h.setLastError(0)
		if h.call(dK32, api, 0x1234, 0) != 0 || h.lastError() != errInvalidHandle {
			t.Fatalf("%s(bad handle) lastError %d", api, h.lastError())
		}
	}
	if h.call(dK32, "GetExitCodeProcess", 0x1234, code) != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("GetExitCodeProcess(bad handle) lastError %d", h.lastError())
	}
	// exit of the sibling signals its process object and records the code
	b.E.endProcess(9)
	if h.call(dK32, "WaitForSingleObject", hp, 0) != 0 {
		t.Fatal("exited process not signaled")
	}
	if h.call(dK32, "GetExitCodeProcess", hp, code) != 1 || h.r32(code) != 9 {
		t.Fatalf("exit code %d", h.r32(code))
	}
	if h.call(dK32, "TerminateProcess", hp, 1) != 0 || h.lastError() != errAccessDenied {
		t.Fatalf("TerminateProcess(exited) lastError %d", h.lastError())
	}
	if h.call(dK32, "OpenProcess", 0x1F0FFF, 0, bpid) != 0 {
		t.Fatal("OpenProcess of an exited process succeeded")
	}
}

func TestKernelNamedObjectsAcrossProcesses(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	name := h.wstr("ws-d-event")
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, name)
	if ev == 0 || h.lastError() != 0 {
		t.Fatalf("CreateEventW = %#x lastError %d", ev, h.lastError())
	}
	bname := b.wstr("ws-d-event")
	bev := b.call(dK32, "OpenEventW", 0x1F0003, 0, bname)
	if bev == 0 {
		t.Fatalf("OpenEventW in sibling failed %d", b.lastError())
	}
	if b.call(dK32, "CreateEventW", 0, 1, 0, bname) == 0 || b.lastError() != errAlreadyExists {
		t.Fatalf("CreateEventW(existing) lastError %d", b.lastError())
	}
	if h.call(dK32, "WaitForSingleObject", ev, 0) != waitTimeoutRet {
		t.Fatal("event signaled too early")
	}
	b.call(dK32, "SetEvent", bev)
	if h.call(dK32, "WaitForSingleObject", ev, 0) != 0 {
		t.Fatal("SetEvent in one process not seen by the other")
	}
	// the name goes away with the last handle in either process
	h.call(dK32, "CloseHandle", ev)
	if b.call(dK32, "OpenEventW", 0x1F0003, 0, bname) == 0 {
		t.Fatal("name dropped while the sibling still holds handles")
	}
	b.E.handles.closeAll()
	b.setLastError(0)
	if b.call(dK32, "OpenEventW", 0x1F0003, 0, bname) != 0 || b.lastError() != errFileNotFound {
		t.Fatalf("name survived its last handle (lastError %d)", b.lastError())
	}
	// mutex and semaphore namespaces
	m := h.call(dK32, "CreateMutexW", 0, 1, h.wstr("ws-d-mutex"))
	bm := b.call(dK32, "OpenMutexW", 0x1F0001, 0, b.wstr("ws-d-mutex"))
	if m == 0 || bm == 0 {
		t.Fatal("named mutex")
	}
	if b.call(dK32, "WaitForSingleObject", bm, 0) != waitTimeoutRet {
		t.Fatal("mutex owned by the other process acquired")
	}
	if b.call(dK32, "ReleaseMutex", bm) != 0 || b.lastError() != errNotOwner {
		t.Fatalf("ReleaseMutex by non-owner lastError %d", b.lastError())
	}
	h.call(dK32, "ReleaseMutex", m)
	if b.call(dK32, "WaitForSingleObject", bm, 0) != 0 {
		t.Fatal("released mutex not acquirable by the other process")
	}
	s := h.call(dK32, "CreateSemaphoreW", 0, 0, 2, h.wstr("ws-d-sem"))
	bs := b.call(dK32, "OpenSemaphoreW", 0x1F0003, 0, b.wstr("ws-d-sem"))
	if s == 0 || bs == 0 {
		t.Fatal("named semaphore")
	}
	h.call(dK32, "ReleaseSemaphore", s, 2, 0)
	if b.call(dK32, "WaitForSingleObject", bs, 0) != 0 {
		t.Fatal("semaphore count not shared")
	}
}

func TestKernelSemaphoreAndMutexErrors(t *testing.T) {
	h := newTestEmu(t)
	for _, c := range [][2]uint64{{3, 2}, {0, 0}, {uint64(1<<32 - 1), 2}} {
		h.setLastError(0)
		if h.call(dK32, "CreateSemaphoreW", 0, c[0], c[1], 0) != 0 || h.lastError() != errInvalidParameter {
			t.Fatalf("CreateSemaphore(%d, %d) lastError %d", int32(c[0]), c[1], h.lastError())
		}
	}
	s := h.call(dK32, "CreateSemaphoreW", 0, 1, 2, 0)
	prev := h.alloc(4)
	h.w32(prev, 0xAAAA)
	if h.call(dK32, "ReleaseSemaphore", s, 2, prev) != 0 || h.lastError() != errTooManyPosts || h.r32(prev) != 0xAAAA {
		t.Fatalf("ReleaseSemaphore overflow: lastError %d prev %#x", h.lastError(), h.r32(prev))
	}
	if h.call(dK32, "ReleaseSemaphore", s, 1, prev) != 1 || h.r32(prev) != 1 {
		t.Fatalf("ReleaseSemaphore prev %d", h.r32(prev))
	}
	if h.call(dK32, "ReleaseSemaphore", s, 0, 0) != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("ReleaseSemaphore(0) lastError %d", h.lastError())
	}
	for _, api := range []string{"ReleaseSemaphore", "ReleaseMutex", "ResetEvent", "SetEvent"} {
		h.setLastError(0)
		if h.call(dK32, api, 0x1234, 1, 0) != 0 || h.lastError() != errInvalidHandle {
			t.Fatalf("%s(bad handle) lastError %d", api, h.lastError())
		}
	}
	m := h.call(dK32, "CreateMutexW", 0, 0, 0)
	if h.call(dK32, "ReleaseMutex", m) != 0 || h.lastError() != errNotOwner {
		t.Fatalf("ReleaseMutex(unowned) lastError %d", h.lastError())
	}
}

func TestKernelHandleInheritFlag(t *testing.T) {
	h := newTestEmu(t)
	sa := h.alloc(24)
	h.w32(sa, 24)
	h.w32(sa+16, 1)
	flags := h.alloc(4)
	ev := h.call(dK32, "CreateEventW", sa, 1, 0, 0)
	if h.call(dK32, "GetHandleInformation", ev, flags) != 1 || h.r32(flags) != 1 {
		t.Fatalf("inheritable event flags %d", h.r32(flags))
	}
	if h.call(dK32, "SetHandleInformation", ev, 1, 0) != 1 || h.call(dK32, "GetHandleInformation", ev, flags) != 1 || h.r32(flags) != 0 {
		t.Fatalf("after clearing: flags %d", h.r32(flags))
	}
	ev2 := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	h.call(dK32, "SetHandleInformation", ev2, 1, 1)
	if h.call(dK32, "GetHandleInformation", ev2, flags); h.r32(flags) != 1 {
		t.Fatal("SetHandleInformation(INHERIT) not stored")
	}
	h.call(dK32, "SetHandleInformation", ev2, 0, 0) // empty mask: no change
	if h.call(dK32, "GetHandleInformation", ev2, flags); h.r32(flags) != 1 {
		t.Fatal("empty mask changed the flags")
	}
	for _, api := range []string{"GetHandleInformation", "SetHandleInformation"} {
		h.setLastError(0)
		if h.call(dK32, api, 0x1234, flags, 0) != 0 || h.lastError() != errInvalidHandle {
			t.Fatalf("%s(bad handle) lastError %d", api, h.lastError())
		}
	}
}

func TestKernelPipe(t *testing.T) {
	h := newTestEmu(t)
	rw := h.alloc(16)
	if h.call(dK32, "CreatePipe", rw, rw+8, 0, 0) != 1 {
		t.Fatal("CreatePipe failed")
	}
	r, w := h.r64(rw), h.r64(rw+8)
	n := h.alloc(4)
	if h.call(dK32, "GetFileType", r) != filePipe {
		t.Fatal("GetFileType(pipe)")
	}
	if h.call(dK32, "WriteFile", w, h.astr("abc"), 3, n, 0) != 1 || h.r32(n) != 3 {
		t.Fatal("WriteFile(pipe)")
	}
	buf := h.alloc(16)
	if h.call(dK32, "ReadFile", r, buf, 16, n, 0) != 1 || h.r32(n) != 3 || string(h.read(buf, 3)) != "abc" {
		t.Fatalf("ReadFile(pipe) = %d %q", h.r32(n), h.read(buf, 3))
	}
	h.call(dK32, "CloseHandle", w)
	if h.call(dK32, "ReadFile", r, buf, 16, n, 0) != 0 || h.lastError() != errBrokenPipe || h.r32(n) != 0 {
		t.Fatalf("ReadFile after writer closed: lastError %d", h.lastError())
	}
	// writing with the read end closed fails
	h.call(dK32, "CreatePipe", rw, rw+8, 0, 0)
	h.call(dK32, "CloseHandle", h.r64(rw))
	if h.call(dK32, "WriteFile", h.r64(rw+8), h.astr("x"), 1, n, 0) != 0 || h.lastError() != errBrokenPipe {
		t.Fatalf("WriteFile to closed pipe lastError %d", h.lastError())
	}
}

// A wait in one process is woken by a SetEvent from another goroutine
// (another process), promptly and without tripping the deadlock detector.
func TestKernelCrossProcessWakeup(t *testing.T) {
	h := newTestEmu(t)
	ev := h.call(dK32, "CreateEventW", 0, 0, 0, h.wstr("ws-d-wake"))
	b := sibling(t, h)
	bev := b.call(dK32, "OpenEventW", 0x1F0003, 0, b.wstr("ws-d-wake"))
	b.E.proc.markStarted() // b is a running process from the kernel's view
	done := make(chan uint64)
	start := time.Now()
	go func() {
		time.Sleep(2500 * time.Millisecond) // longer than the deadlock window
		done <- b.call(dK32, "SetEvent", bev)
	}()
	if r := h.call(dK32, "WaitForSingleObject", ev, infinite); r != 0 {
		t.Fatalf("WaitForSingleObject = %#x\n%s", r, h.stderr())
	}
	if <-done != 1 {
		t.Fatal("SetEvent failed")
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("wake-up took %v", el)
	}
}

// With every process blocked, the detector still ends an INFINITE wait.
func TestKernelDeadlockDetected(t *testing.T) {
	h := newTestEmu(t)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	start := time.Now()
	_, exited, code := h.tryCall(dK32, "WaitForSingleObject", ev, infinite)
	if !exited || code != 0xC0000194 || time.Since(start) > 10*time.Second {
		t.Fatalf("exited %v code %#x after %v", exited, code, time.Since(start))
	}
}
