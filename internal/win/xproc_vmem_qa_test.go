package win

import (
	"testing"
	"time"

	"winemu/internal/mem"
)

const (
	memCommit   = 0x1000
	memReserve  = 0x2000
	memDecommit = 0x4000
	memRelease  = 0x8000
)

// faults reports whether reading a in h's address space raises an access violation.
func faults(m *mem.Memory, a uint64) (f bool) {
	defer func() { _, f = recover().(*mem.Fault) }()
	m.R8(a)
	return false
}

// query returns (base, size, state, protect) of VirtualQuery(a).
func query(h *testEmu, a uint64) (uint64, uint64, uint32, uint32) {
	info := h.alloc(48)
	if h.call(dK32, "VirtualQuery", a, info, 48) != 48 {
		h.t.Fatalf("VirtualQuery(%#x) err %d", a, h.lastError())
	}
	return h.r64(info), h.r64(info + 24), h.r32(info + 32), h.r32(info + 36)
}

func TestVirtualAllocReserveThenCommit(t *testing.T) {
	h := newTestEmu(t)
	base := h.call(dK32, "VirtualAlloc", 0, 0x40000, memReserve, pageRW)
	if base == 0 {
		t.Fatalf("reserve err %d", h.lastError())
	}
	if b, n, st, pr := query(h, base+0x5000); b != base+0x5000 || n != 0x3B000 || st != memReserve || pr != 0 {
		t.Fatalf("reserved: base %#x size %#x state %#x prot %#x", b, n, st, pr)
	}
	if !faults(h.E.Mem, base+0x10) {
		t.Fatal("reserved page is accessible")
	}
	// commit two pages in the middle of a chunk
	if r := h.call(dK32, "VirtualAlloc", base+0x11234, 0x1000, memCommit, pageRW); r != base+0x11000 {
		t.Fatalf("commit = %#x err %d", r, h.lastError())
	}
	if b, n, st, pr := query(h, base+0x11800); b != base+0x11000 || n != 0x2000 || st != memCommit || pr != pageRW {
		t.Fatalf("committed: base %#x size %#x state %#x prot %#x", b, n, st, pr)
	}
	if _, n, st, _ := query(h, base); n != 0x11000 || st != memReserve {
		t.Fatalf("before commit: size %#x state %#x", n, st)
	}
	if _, n, st, _ := query(h, base+0x13000); n != 0x2D000 || st != memReserve {
		t.Fatalf("after commit: size %#x state %#x", n, st)
	}
	h.E.Mem.W32(base+0x11234, 7)
	if faults(h.E.Mem, base+0x12FFF) || !faults(h.E.Mem, base+0x20000) {
		t.Fatal("commit state not enforced")
	}
	// decommit: pages become reserved again and read back zero once recommitted
	if h.call(dK32, "VirtualFree", base+0x11000, 0x2000, memDecommit) != 1 {
		t.Fatalf("decommit err %d", h.lastError())
	}
	if _, _, st, _ := query(h, base+0x11000); st != memReserve {
		t.Fatalf("decommitted state %#x", st)
	}
	if !faults(h.E.Mem, base+0x11234) {
		t.Fatal("decommitted page is accessible")
	}
	h.call(dK32, "VirtualAlloc", base+0x11000, 0x1000, memCommit, pageRW)
	if v := h.r32(base + 0x11234); v != 0 {
		t.Fatalf("recommitted page not zero: %d", v)
	}
	// release needs size 0 and the allocation base
	if h.call(dK32, "VirtualFree", base, 0x1000, memRelease) != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("release with size: err %d", h.lastError())
	}
	if h.call(dK32, "VirtualFree", base, 0, memRelease) != 1 {
		t.Fatalf("release err %d", h.lastError())
	}
	if _, _, st, _ := query(h, base); st != 0x10000 {
		t.Fatalf("released state %#x", st)
	}
}

func TestVirtualAllocCommitBoundaries(t *testing.T) {
	h := newTestEmu(t)
	// MEM_COMMIT alone at a free address fails (nothing reserved)
	const free = 0x50000000
	if h.call(dK32, "VirtualAlloc", free, 0x1000, memCommit, pageRW) != 0 || h.lastError() != errInvalidAddress {
		t.Fatalf("commit unreserved: err %d", h.lastError())
	}
	// MEM_RESERVE|MEM_COMMIT commits only the requested pages
	base := h.call(dK32, "VirtualAlloc", free, 0x3000, memReserve|memCommit, pageRW)
	if base != free {
		t.Fatalf("reserve|commit = %#x err %d", base, h.lastError())
	}
	if _, n, st, _ := query(h, base); n != 0x3000 || st != memCommit {
		t.Fatalf("committed part: size %#x state %#x", n, st)
	}
	if _, n, st, _ := query(h, base+0x3000); n != 0xD000 || st != memReserve {
		t.Fatalf("rest of granule: size %#x state %#x", n, st)
	}
	// NULL address + MEM_COMMIT alone reserves and commits
	a := h.call(dK32, "VirtualAlloc", 0, 0x1000, memCommit, pageRW)
	if _, _, st, _ := query(h, a); a == 0 || st != memCommit {
		t.Fatalf("commit at NULL: %#x state %#x", a, st)
	}
	// commit past the end of the reservation fails
	if h.call(dK32, "VirtualAlloc", base+0xF000, 0x2000, memCommit, pageRW) != 0 || h.lastError() != errInvalidAddress {
		t.Fatalf("commit across reservation end: err %d", h.lastError())
	}
	// decommit of the whole region (size 0) keeps the reservation
	if h.call(dK32, "VirtualFree", base, 0, memDecommit) != 1 {
		t.Fatalf("decommit all err %d", h.lastError())
	}
	if _, n, st, _ := query(h, base); n != 0x10000 || st != memReserve {
		t.Fatalf("after decommit all: size %#x state %#x", n, st)
	}
	// neither or both of DECOMMIT/RELEASE
	if h.call(dK32, "VirtualFree", base, 0, memDecommit|memRelease) != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("decommit|release: err %d", h.lastError())
	}
	if h.call(dK32, "VirtualFree", base, 0, 0) != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("no free type: err %d", h.lastError())
	}
}

func TestXprocReserveCommitOtherProcess(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	const addr = 0x31000000
	if r := h.call(dK32, "VirtualAllocEx", hb, addr, 0x20000, memReserve, pageRW); r != addr {
		t.Fatalf("reserve = %#x err %d", r, h.lastError())
	}
	info, buf, n := h.alloc(48), h.alloc(16), h.alloc(8)
	h.call(dK32, "VirtualQueryEx", hb, addr, info, 48)
	if h.r32(info+32) != memReserve {
		t.Fatalf("state %#x", h.r32(info+32))
	}
	// reserved pages cannot be read: nothing copied
	if h.call(dK32, "ReadProcessMemory", hb, addr, buf, 16, n) != 0 || h.lastError() != errPartialCopy || h.r64(n) != 0 {
		t.Fatalf("read reserved: err %d n %d", h.lastError(), h.r64(n))
	}
	h.call(dK32, "VirtualAllocEx", hb, addr, 0x1000, memCommit, pageRW)
	if h.call(dK32, "ReadProcessMemory", hb, addr+0xFF8, buf, 16, n) != 0 || h.lastError() != errPartialCopy || h.r64(n) != 8 {
		t.Fatalf("read across commit end: err %d n %d", h.lastError(), h.r64(n))
	}
	// (faults are exact per 64 KiB chunk: the next chunk is still reserved)
	if !faults(b.E.Mem, addr+0x10000) || faults(b.E.Mem, addr) {
		t.Fatal("commit state in target not enforced")
	}
}

// Two processes reading each other's memory at the same time must not
// deadlock (each releases its own run lock while it waits for the other's).
func TestXprocMutualAccess(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	b.E.proc.markStarted()
	hb, bh := procHandle(h, b), procHandle(b, h)
	hbuf, bbuf := h.alloc(8), b.alloc(8)
	h.write(hbuf, []byte("hhhhhhhh"))
	b.write(bbuf, []byte("bbbbbbbb"))
	hdst, bdst := h.alloc(8), b.alloc(8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 300 {
			b.call(dK32, "ReadProcessMemory", bh, hbuf, bdst, 8, 0)
		}
	}()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for range 300 {
			h.call(dK32, "ReadProcessMemory", hb, bbuf, hdst, 8, 0)
		}
		<-done
	}()
	select {
	case <-finished:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: mutual ReadProcessMemory did not finish")
	}
	if string(h.read(hdst, 8)) != "bbbbbbbb" || string(b.read(bdst, 8)) != "hhhhhhhh" {
		t.Fatalf("read %q / %q", h.read(hdst, 8), b.read(bdst, 8))
	}
}

func TestXprocWriteProcessMemoryPartialCount(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	const addr = 0x32000000
	h.call(dK32, "VirtualAllocEx", hb, addr, 0x10000, memReserve, pageRW)
	h.call(dK32, "VirtualAllocEx", hb, addr, 0x1000, memCommit, pageRW)
	src, n := h.alloc(16), h.alloc(8)
	h.write(src, []byte("0123456789abcdef"))
	if h.call(dK32, "WriteProcessMemory", hb, addr+0xFFA, src, 16, n) != 0 || h.lastError() != errPartialCopy || h.r64(n) != 6 {
		t.Fatalf("partial write: err %d n %d", h.lastError(), h.r64(n))
	}
	if string(b.read(addr+0xFFA, 6)) != "012345" {
		t.Fatalf("written %q", b.read(addr+0xFFA, 6))
	}
}

// The size reported by the probe must hold every attribute the list was
// sized for: Update must not write past it.
func TestXprocAttributeListFitsProbedSize(t *testing.T) {
	h := newTestEmu(t)
	size := h.alloc(8)
	h.call(dK32, "InitializeProcThreadAttributeList", 0, 2, 0, size)
	n := h.r64(size)
	list := h.alloc(int(n) + 16)
	h.w64(list+n, 0xC0FFEE)
	if h.call(dK32, "InitializeProcThreadAttributeList", list, 2, 0, size) != 1 {
		t.Fatalf("init err %d", h.lastError())
	}
	hs, parent := h.alloc(8), h.alloc(8)
	if h.call(dK32, "UpdateProcThreadAttribute", list, 0, attrHandleList, hs, 8, 0, 0) != 1 ||
		h.call(dK32, "UpdateProcThreadAttribute", list, 0, attrParentProcess, parent, 8, 0, 0) != 1 {
		t.Fatalf("update err %d", h.lastError())
	}
	if h.r64(list+n) != 0xC0FFEE {
		t.Fatal("attribute list overflows the probed size")
	}
	if h.call(dK32, "UpdateProcThreadAttribute", list, 0, 0x20007, parent, 8, 0, 0) != 0 {
		t.Fatal("third attribute in a list sized for two")
	}
}

func TestJobIsProcessInAnyJob(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	j := h.call(dK32, "CreateJobObjectW", 0, 0)
	h.call(dK32, "AssignProcessToJobObject", j, hb)
	in := h.alloc(4)
	if h.call(dK32, "IsProcessInJob", hb, 0, in) != 1 || h.r32(in) != 1 {
		t.Fatalf("IsProcessInJob(NULL job) of a member = %d", h.r32(in))
	}
	if h.call(dK32, "IsProcessInJob", pseudoProcess, 0, in) != 1 || h.r32(in) != 0 {
		t.Fatal("caller is in no job")
	}
}

func TestXprocCreateProcessAsUserImpersonationToken(t *testing.T) {
	h := newTestEmu(t)
	tok, imp := h.alloc(8), h.alloc(8)
	if h.call(dAdv, "OpenProcessToken", pseudoProcess, 0xF01FF, tok) != 1 ||
		h.call(dAdv, "DuplicateToken", h.r64(tok), 2, imp) != 1 { // SecurityImpersonation
		t.Fatalf("token setup err %d", h.lastError())
	}
	if h.call(dAdv, "CreateProcessAsUserA", h.r64(imp), 0, h.astr("x.exe"), 0, 0, 0, 0, 0, 0, h.alloc(104), h.alloc(24)) != 0 ||
		h.lastError() != errBadTokenType {
		t.Fatalf("impersonation token: err %d", h.lastError())
	}
}

func TestXprocSuspendCountLimit(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	th := h.E.handles.add(&threadObj{t: b.E.threads[0]})
	for i := range 127 {
		if r := h.call(dK32, "SuspendThread", th); r != uint64(i) {
			t.Fatalf("suspend %d returned %d", i, r)
		}
	}
	if h.call(dK32, "SuspendThread", th) != 0xFFFFFFFF || h.lastError() != errSignalRefcountExceeded {
		t.Fatalf("128th suspend: err %d", h.lastError())
	}
	if h.call(dK32, "ResumeThread", th) != 127 {
		t.Fatal("resume after limit")
	}
}

// DUPLICATE_CLOSE_SOURCE closes the source handle even when the call fails.
func TestXprocDuplicateCloseSourceOnError(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	ev := b.call(dK32, "CreateEventW", 0, 1, 0, 0)
	if h.call(dK32, "DuplicateHandle", hb, ev, 0x7FF0, h.alloc(8), 0, 0, 3) != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("bad target: err %d", h.lastError())
	}
	if b.E.handles.get(ev) != nil {
		t.Fatal("source not closed after failed DUPLICATE_CLOSE_SOURCE")
	}
}

func TestXprocReadProcessMemoryBadLocalBuffer(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	src := b.alloc(8)
	if r, exited, _ := h.tryCall(dK32, "ReadProcessMemory", hb, src, 0x10, 8, 0); exited || r != 0 || h.lastError() != 998 {
		t.Fatalf("unmapped local buffer: r %d exited %v err %d", r, exited, h.lastError())
	}
}
