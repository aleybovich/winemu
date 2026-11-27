package win

import (
	"bytes"
	"sync"
	"testing"
)

// procHandle returns a handle in h's table for b's process.
func procHandle(h, b *testEmu) uint64 { return h.E.handles.add(&processObj{p: b.E.proc}) }

func TestXprocVirtualMemoryEx(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	const addr = 0x30000000
	if r := h.call(dK32, "VirtualAllocEx", hb, addr, 0x20000, 0x3000, pageRW); r != addr {
		t.Fatalf("VirtualAllocEx = %#x err %d", r, h.lastError())
	}
	if b.E.Mem.FindRegion(addr) == nil || h.E.Mem.FindRegion(addr) != nil {
		t.Fatal("reservation not in the target only")
	}
	if h.call(dK32, "VirtualAllocEx", hb, addr, 0x10000, 0x2000, pageRW) != 0 || h.lastError() != errInvalidAddress {
		t.Fatalf("occupied: err %d", h.lastError())
	}
	h.setLastError(0)
	if h.call(dK32, "VirtualAllocEx", 0x7FF0, 0, 0x1000, 0x3000, pageRW) != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("bad handle: err %d", h.lastError())
	}
	info := h.alloc(48)
	if h.call(dK32, "VirtualQueryEx", hb, addr+0x1234, info, 48) != 48 || h.r64(info+8) != addr || h.r32(info+40) != 0x20000 {
		t.Fatalf("VirtualQueryEx base %#x type %#x", h.r64(info+8), h.r32(info+40))
	}
	old := h.alloc(4)
	if h.call(dK32, "VirtualProtectEx", hb, addr, 0x1000, 2, old) != 1 || h.r32(old) != pageRW {
		t.Fatalf("VirtualProtectEx old %#x", h.r32(old))
	}
	if h.call(dK32, "VirtualFreeEx", hb, addr, 0, 0x8000) != 1 || b.E.Mem.FindRegion(addr) != nil {
		t.Fatal("VirtualFreeEx")
	}
	if h.call(dK32, "VirtualFreeEx", hb, addr, 0, 0x8000) != 0 || h.lastError() != errInvalidAddress {
		t.Fatalf("double free: err %d", h.lastError())
	}
}

func TestXprocReadWriteProcessMemory(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	dst := b.alloc(64)
	src, n := h.alloc(64), h.alloc(8)
	h.write(src, []byte("hello child"))
	if h.call(dK32, "WriteProcessMemory", hb, dst, src, 11, n) != 1 || h.r64(n) != 11 || b.readAStr(dst) != "hello child" {
		t.Fatalf("WriteProcessMemory: n %d %q err %d", h.r64(n), b.readAStr(dst), h.lastError())
	}
	back := h.alloc(64)
	if h.call(dK32, "ReadProcessMemory", hb, dst, back, 11, n) != 1 || h.readAStr(back) != "hello child" {
		t.Fatalf("ReadProcessMemory %q", h.readAStr(back))
	}
	// a range running into unmapped memory: partial copy
	edge := b.E.Mem.FindRegion(dst)
	end := edge.Base + edge.Size
	for b.E.Mem.FindRegion(end) != nil {
		end = b.E.Mem.FindRegion(end).Base + b.E.Mem.FindRegion(end).Size
	}
	if h.call(dK32, "ReadProcessMemory", hb, end-4, back, 16, n) != 0 || h.lastError() != errPartialCopy || h.r64(n) != 4 {
		t.Fatalf("partial read: err %d n %d", h.lastError(), h.r64(n))
	}
	if h.call(dK32, "WriteProcessMemory", hb, 0x10, src, 4, 0) != 0 || h.lastError() != errPartialCopy {
		t.Fatalf("write to unmapped: err %d", h.lastError())
	}
	if h.call(dK32, "ReadProcessMemory", 0x7FF0, dst, back, 4, 0) != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("bad handle: err %d", h.lastError())
	}
}

func TestXprocSuspendResumeOtherProcess(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	th := h.E.handles.add(&threadObj{t: b.E.threads[0]})
	for i, want := range []uint64{0, 1} {
		if r := h.call(dK32, "SuspendThread", th); r != want {
			t.Fatalf("SuspendThread #%d = %d", i, r)
		}
	}
	for i, want := range []uint64{2, 1, 0} {
		if r := h.call(dK32, "ResumeThread", th); r != want {
			t.Fatalf("ResumeThread #%d = %d", i, r)
		}
	}
	if h.call(dK32, "ResumeThread", 0x7FF0) != 0xFFFFFFFF || h.lastError() != errInvalidHandle {
		t.Fatal("ResumeThread(bad)")
	}
}

func TestXprocTerminateUnstarted(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	if h.call(dK32, "TerminateProcess", hb, 9) != 1 {
		t.Fatalf("TerminateProcess err %d", h.lastError())
	}
	code := h.alloc(4)
	if h.call(dK32, "GetExitCodeProcess", hb, code) != 1 || h.r32(code) != 9 || h.call(dK32, "WaitForSingleObject", hb, 0) != 0 {
		t.Fatalf("exit code %d", h.r32(code))
	}
}

func TestXprocDuplicateHandleAcross(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	out := h.alloc(8)
	if h.call(dK32, "DuplicateHandle", pseudoProcess, ev, hb, out, 0, 1, 2) != 1 {
		t.Fatalf("into child: err %d", h.lastError())
	}
	bev := h.r64(out)
	if b.E.handles.get(bev) != h.E.handles.get(ev) || !b.E.handles.inheritable(bev) || h.E.handles.get(bev) == h.E.handles.get(ev) && bev != ev {
		t.Fatalf("child handle %#x", bev)
	}
	b.call(dK32, "SetEvent", bev)
	if h.call(dK32, "WaitForSingleObject", ev, 0) != 0 {
		t.Fatal("event set by the child not seen")
	}
	// from the child into the caller, closing the source
	if h.call(dK32, "DuplicateHandle", hb, bev, pseudoProcess, out, 0, 0, 3) != 1 || b.E.handles.get(bev) != nil {
		t.Fatalf("from child: err %d", h.lastError())
	}
	if h.E.handles.get(h.r64(out)) != h.E.handles.get(ev) || h.E.handles.inheritable(h.r64(out)) {
		t.Fatal("duplicated object or inherit flag")
	}
	// close a handle in another process (no target)
	x := b.call(dK32, "CreateEventW", 0, 1, 0, 0)
	if h.call(dK32, "DuplicateHandle", hb, x, 0, 0, 0, 0, 1) != 1 || b.E.handles.get(x) != nil {
		t.Fatal("DUPLICATE_CLOSE_SOURCE without target")
	}
	if h.call(dK32, "DuplicateHandle", hb, x, pseudoProcess, out, 0, 0, 2) != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("stale source: err %d", h.lastError())
	}
	if h.call(dK32, "DuplicateHandle", pseudoProcess, ev, 0x7FF0, out, 0, 0, 2) != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("bad target: err %d", h.lastError())
	}
	// the process pseudo handle names the source process
	if h.call(dK32, "DuplicateHandle", hb, pseudoProcess, pseudoProcess, out, 0, 0, 2) != 1 ||
		h.call(dK32, "GetProcessId", h.r64(out)) != uint64(b.E.proc.pid) {
		t.Fatal("pseudo process of the source")
	}
}

func TestXprocAttributeList(t *testing.T) {
	h := newTestEmu(t)
	size := h.alloc(8)
	if h.call(dK32, "InitializeProcThreadAttributeList", 0, 1, 0, size) != 0 || h.lastError() != errInsufficientBuf || h.r64(size) == 0 {
		t.Fatalf("size probe: err %d size %d", h.lastError(), h.r64(size))
	}
	list := h.alloc(int(h.r64(size)))
	if h.call(dK32, "InitializeProcThreadAttributeList", list, 1, 1, size) != 0 || h.lastError() != errInvalidParameter {
		t.Fatal("flags must be zero")
	}
	if h.call(dK32, "InitializeProcThreadAttributeList", list, 1, 0, size) != 1 {
		t.Fatal("init")
	}
	hs := h.alloc(16)
	if h.call(dK32, "UpdateProcThreadAttribute", list, 0, attrHandleList, hs, 7, 0, 0) != 0 || h.lastError() != errBadLength {
		t.Fatal("bad handle list size")
	}
	h.w64(hs, 0x104)
	h.w64(hs+8, 0x108)
	if h.call(dK32, "UpdateProcThreadAttribute", list, 0, attrHandleList, hs, 16, 0, 0) != 1 {
		t.Fatal("update")
	}
	if got, ok := h.E.attrHandles(list); !ok || len(got) != 2 || got[1] != 0x108 {
		t.Fatalf("handle list %v %v", got, ok)
	}
	if h.call(dK32, "UpdateProcThreadAttribute", list, 0, 0x20007, hs, 8, 0, 0) != 0 || h.lastError() != errGenFailure {
		t.Fatalf("over capacity: err %d", h.lastError())
	}
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	if h.E.checkHandleList([]uint64{ev}) {
		t.Fatal("non-inheritable handle accepted")
	}
	h.call(dK32, "SetHandleInformation", ev, 1, 1)
	if !h.E.checkHandleList([]uint64{ev}) {
		t.Fatal("inheritable handle rejected")
	}
}

func TestXprocCreateProcessAsUserBadToken(t *testing.T) {
	h := newTestEmu(t)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	for _, tok := range []uint64{0x7FF0, ev} {
		if h.call(dAdv, "CreateProcessAsUserA", tok, 0, h.astr("x.exe"), 0, 0, 0, 0, 0, 0, h.alloc(104), h.alloc(24)) != 0 ||
			h.lastError() != errInvalidHandle {
			t.Fatalf("token %#x: err %d", tok, h.lastError())
		}
	}
}

// Another process reads and writes the memory and thread state of a
// process that is running API calls concurrently (go test -race).
func TestXprocConcurrentAccess(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	b.E.proc.markStarted()
	hb := procHandle(h, b)
	th := h.E.handles.add(&threadObj{t: b.E.threads[0]})
	buf := b.alloc(64)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			b.call(dK32, "SetLastError", uint64(i))
			b.call(dK32, "Sleep", 0)
		}
	}()
	src, dst := h.alloc(8), h.alloc(8)
	h.write(src, []byte("abcdefgh"))
	for range 200 {
		h.call(dK32, "WriteProcessMemory", hb, buf, src, 8, 0)
		h.call(dK32, "ReadProcessMemory", hb, buf, dst, 8, 0)
		h.call(dK32, "SuspendThread", th)
		h.call(dK32, "ResumeThread", th)
	}
	wg.Wait()
	if !bytes.Equal(h.read(dst, 8), []byte("abcdefgh")) {
		t.Fatalf("read %q", h.read(dst, 8))
	}
}

const pageRW = 4
