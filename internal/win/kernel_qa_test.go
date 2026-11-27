package win

// WS-D QA: Win32 contract checks for the multi-process kernel.

import (
	"path/filepath"
	"testing"
	"time"
)

// secAttrs writes a SECURITY_ATTRIBUTES with the given bInheritHandle.
func secAttrs(h *testEmu, inherit bool) uint64 {
	sa := h.alloc(24)
	h.w32(sa, 24)
	h.w32(sa+16, uint32(b2u(inherit)))
	return sa
}

// CreateFile honours SECURITY_ATTRIBUTES.bInheritHandle (HANDLE_FLAG_INHERIT).
func TestQAWSDCreateFileInherit(t *testing.T) {
	h := newTestEmu(t)
	flags := h.alloc(4)
	for i, tc := range []struct {
		sa   uint64
		want uint32
	}{
		{0, 0},
		{secAttrs(h, false), 0},
		{secAttrs(h, true), 1},
	} {
		path := h.wstr(filepath.Join(h.dir, "inh.txt"))
		fh := h.call(dK32, "CreateFileW", path, 0x40000000, 0, tc.sa, 2 /*CREATE_ALWAYS*/, 0x80, 0)
		if fh == invalidHandle {
			t.Fatalf("case %d: CreateFileW failed, lastError %d", i, h.lastError())
		}
		h.w32(flags, 0xFF)
		if h.call(dK32, "GetHandleInformation", fh, flags) != 1 || h.r32(flags) != tc.want {
			t.Fatalf("case %d: flags %d, want %d", i, h.r32(flags), tc.want)
		}
		h.call(dK32, "CloseHandle", fh)
	}
	// a failed CreateFile does not touch the table
	missing := h.wstr(filepath.Join(h.dir, "no", "such"))
	if fh := h.call(dK32, "CreateFileW", missing, 0x80000000, 0, secAttrs(h, true), 3, 0x80, 0); fh != invalidHandle {
		t.Fatalf("CreateFileW(missing) = %#x", fh)
	}
	// CreateFile2: lpSecurityAttributes at offset 16 of CREATEFILE2_EXTENDED_PARAMETERS
	ext := h.alloc(32)
	h.w32(ext, 32)
	h.w32(ext+4, 0x80)
	h.w64(ext+16, secAttrs(h, true))
	fh := h.call(dK32, "CreateFile2", h.wstr(filepath.Join(h.dir, "inh2.txt")), 0x40000000, 0, 2, ext)
	if fh == invalidHandle || h.call(dK32, "GetHandleInformation", fh, flags) != 1 || h.r32(flags) != 1 {
		t.Fatalf("CreateFile2 inherit: handle %#x flags %d", fh, h.r32(flags))
	}
}

// A mutex whose owner thread ended is abandoned: the next successful wait
// returns WAIT_ABANDONED_0 (+index for wait-any), then the mutex is owned
// normally.
func TestQAWSDMutexAbandoned(t *testing.T) {
	for _, mode := range []string{"single", "any", "all"} {
		t.Run(mode, func(t *testing.T) {
			h := newTestEmu(t)
			b := sibling(t, h)
			name := "qa-abandon-" + mode
			if mb := b.call(dK32, "CreateMutexW", 0, 1, b.wstr(name)); mb == 0 {
				t.Fatal("CreateMutexW failed")
			}
			m := h.call(dK32, "OpenMutexW", 0x1F0001, 0, h.wstr(name))
			if m == 0 {
				t.Fatalf("OpenMutexW lastError %d", h.lastError())
			}
			if r := h.call(dK32, "WaitForSingleObject", m, 0); r != waitTimeoutRet {
				t.Fatalf("owned mutex wait = %#x", r)
			}
			b.E.endProcess(0) // owner thread ends without ReleaseMutex
			evOff := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
			evOn := h.call(dK32, "CreateEventW", 0, 1, 1, 0)
			hs := h.alloc(16)
			var r, want uint64
			switch mode {
			case "single":
				r, want = h.call(dK32, "WaitForSingleObject", m, 0), 0x80
			case "any":
				h.w64(hs, evOff)
				h.w64(hs+8, m)
				r, want = h.call(dK32, "WaitForMultipleObjects", 2, hs, 0, 0), 0x81
			case "all":
				h.w64(hs, evOn)
				h.w64(hs+8, m)
				r, want = h.call(dK32, "WaitForMultipleObjects", 2, hs, 1, 0), 0x80
			}
			if r != want {
				t.Fatalf("wait on abandoned mutex = %#x, want %#x", r, want)
			}
			// now owned by this thread: recursive acquire is a plain success
			if r := h.call(dK32, "WaitForSingleObject", m, 0); r != 0 {
				t.Fatalf("second wait = %#x, want 0", r)
			}
			if h.call(dK32, "ReleaseMutex", m) != 1 || h.call(dK32, "ReleaseMutex", m) != 1 {
				t.Fatalf("ReleaseMutex lastError %d", h.lastError())
			}
		})
	}
}

// WaitForMultipleObjects rejects nCount 0 and > MAXIMUM_WAIT_OBJECTS (64).
func TestQAWSDWaitMultipleCount(t *testing.T) {
	h := newTestEmu(t)
	hs := h.alloc(8 * 65)
	ev := h.call(dK32, "CreateEventW", 0, 1, 1, 0)
	for i := range 65 {
		h.w64(hs+8*uint64(i), ev)
	}
	for _, n := range []uint64{0, 65} {
		for _, all := range []uint64{0, 1} {
			h.setLastError(0)
			if r := h.call(dK32, "WaitForMultipleObjects", n, hs, all, 0); r != 0xFFFFFFFF || h.lastError() != errInvalidParameter {
				t.Fatalf("n=%d all=%d: %#x lastError %d", n, all, r, h.lastError())
			}
		}
	}
	if r := h.call(dK32, "WaitForMultipleObjects", 64, hs, 0, 0); r != 0 {
		t.Fatalf("n=64: %#x", r)
	}
}

// Process ids, thread ids and handle values are multiples of 4 and unique.
func TestQAWSDIdsAndHandlesMultipleOf4(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	seen := map[uint64]bool{h.call(dK32, "GetCurrentProcessId"): true}
	ids := []uint64{b.call(dK32, "GetCurrentProcessId"), h.call(dK32, "GetCurrentThreadId"), b.call(dK32, "GetCurrentThreadId")}
	tid := h.alloc(4)
	var handles []uint64
	for range 3 {
		th := h.call(dK32, "CreateThread", 0, 0, 0x1000, 0, 4 /*CREATE_SUSPENDED*/, tid)
		if th == 0 {
			t.Fatalf("CreateThread lastError %d", h.lastError())
		}
		ids = append(ids, uint64(h.r32(tid)))
		handles = append(handles, th, h.call(dK32, "CreateEventW", 0, 1, 0, 0))
	}
	for _, id := range ids {
		if id == 0 || id%4 != 0 || seen[id] {
			t.Fatalf("id %#x (ids %#x)", id, ids)
		}
		seen[id] = true
	}
	seenH := map[uint64]bool{}
	for _, v := range handles {
		if v == 0 || v%4 != 0 || seenH[v] {
			t.Fatalf("handle %#x (handles %#x)", v, handles)
		}
		seenH[v] = true
	}
}

// A blocked-forever process is not a deadlock while another live process is
// still running (it may still signal the object).
func TestQAWSDNoDeadlockWhileOtherProcessRuns(t *testing.T) {
	h := newTestEmu(t)
	h.E.proc.markStarted() // h: live, running (never idle)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, h.wstr("qa-running-peer"))
	b := sibling(t, h)
	bev := b.call(dK32, "OpenEventW", 0x1F0003, 0, b.wstr("qa-running-peer"))
	b.E.proc.markStarted()
	type res struct {
		r      uint64
		exited bool
	}
	done := make(chan res, 1)
	go func() {
		r, exited, _ := b.tryCall(dK32, "WaitForSingleObject", bev, infinite)
		done <- res{r, exited}
	}()
	time.Sleep(3 * time.Second) // longer than the deadlock window
	h.call(dK32, "SetEvent", ev)
	select {
	case v := <-done:
		if v.exited || v.r != 0 {
			t.Fatalf("waiter exited %v r %#x\n%s", v.exited, v.r, b.stderr())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter not woken")
	}
}

// endSession asks every other process to exit and returns once they have.
func TestQAWSDEndSession(t *testing.T) {
	k := newKernel()
	p := k.newProcess(nil, 0, 0)
	p.markStarted()
	go func() {
		for !p.killReq.Load() {
			time.Sleep(time.Millisecond)
		}
		p.exit(p.killCode.Load())
	}()
	start := time.Now()
	k.endSession(7, 5*time.Second)
	if code, done := p.exitStatus(); !done || code != 7 || time.Since(start) > time.Second {
		t.Fatalf("done %v code %d after %v", done, code, time.Since(start))
	}
	// a process that never reacts is abandoned after the grace period
	q := k.newProcess(nil, 0, 0)
	q.markStarted()
	start = time.Now()
	k.endSession(7, 100*time.Millisecond)
	if el := time.Since(start); el < 100*time.Millisecond || el > time.Second {
		t.Fatalf("grace %v", el)
	}
}

// DuplicateHandle's bInheritHandle sets HANDLE_FLAG_INHERIT on the new handle;
// pseudo handles duplicate to real handles of the current process/thread.
func TestQAWSDDuplicateHandleInherit(t *testing.T) {
	h := newTestEmu(t)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	out, flags := h.alloc(8), h.alloc(4)
	for _, inherit := range []uint64{1, 0} {
		if h.call(dK32, "DuplicateHandle", pseudoProcess, ev, pseudoProcess, out, 0, inherit, 2 /*DUPLICATE_SAME_ACCESS*/) != 1 {
			t.Fatalf("DuplicateHandle lastError %d", h.lastError())
		}
		d := h.r64(out)
		if d == ev || d%4 != 0 || h.call(dK32, "GetHandleInformation", d, flags) != 1 || uint64(h.r32(flags)) != inherit {
			t.Fatalf("inherit=%d: dup %#x flags %d", inherit, d, h.r32(flags))
		}
	}
	if h.call(dK32, "DuplicateHandle", pseudoProcess, pseudoProcess, pseudoProcess, out, 0, 0, 2) != 1 {
		t.Fatal("DuplicateHandle(GetCurrentProcess())")
	}
	if p := h.r64(out); p == pseudoProcess || h.call(dK32, "GetProcessId", p) != h.call(dK32, "GetCurrentProcessId") {
		t.Fatalf("duplicated process handle %#x", p)
	}
	h.setLastError(0)
	if h.call(dK32, "DuplicateHandle", pseudoProcess, 0x7FF0, pseudoProcess, out, 0, 0, 2) != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("DuplicateHandle(bad) lastError %d", h.lastError())
	}
}
