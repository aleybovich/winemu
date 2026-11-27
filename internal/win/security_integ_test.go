package win

import "testing"

// tokenID returns TokenStatistics.TokenId of tok.
func tokenID(t *testing.T, h *testEmu, tok uint64) uint64 {
	t.Helper()
	buf, _ := secTokenInfo(t, h, tok, 10) // TokenStatistics: LUID TokenId first
	return h.r64(buf)
}

// OpenProcessToken on a handle to another process yields that process's
// primary token, not the caller's.
func TestIntegOpenProcessTokenOtherProcess(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	own := tokenID(t, h, secOpenProcessToken(t, h))
	sib := tokenID(t, b, secOpenProcessToken(t, b))
	if own == sib {
		t.Fatalf("two processes share token id %#x", own)
	}
	hp := h.call(dK32, "OpenProcess", 0x1F0FFF, 0, b.call(dK32, "GetCurrentProcessId"))
	if hp == 0 {
		t.Fatalf("OpenProcess lastError %d", h.lastError())
	}
	out := h.alloc(8)
	if h.call(dAdv, "OpenProcessToken", hp, secTokenQuery, out) != 1 {
		t.Fatalf("OpenProcessToken(other) lastError %d", h.lastError())
	}
	if got := tokenID(t, h, h.r64(out)); got != sib {
		t.Fatalf("token of other process: id %#x, want %#x (own %#x)", got, sib, own)
	}
	// a real handle to the own process names the own token
	self := h.call(dK32, "OpenProcess", 0x1F0FFF, 0, h.call(dK32, "GetCurrentProcessId"))
	if h.call(dAdv, "OpenProcessToken", self, secTokenQuery, out) != 1 || tokenID(t, h, h.r64(out)) != own {
		t.Fatal("OpenProcessToken(own process handle)")
	}
	secExpectFail(t, h, "OpenProcessToken(bad handle)", h.call(dAdv, "OpenProcessToken", 0x1234, secTokenQuery, out), errInvalidHandle)
	secExpectFail(t, h, "OpenProcessToken(event handle)", h.call(dAdv, "OpenProcessToken", h.call(dK32, "CreateEventW", 0, 1, 0, 0), secTokenQuery, out), errInvalidHandle)
}

// A token object shared between processes (OpenProcessToken on another
// process, a handle to the same impersonation token) is mutated and read
// concurrently by two Emus on their own goroutines; run with -race.
func TestIntegSharedTokenConcurrentAccess(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	tok := secOpenProcessToken(t, h)
	hp := b.call(dK32, "OpenProcess", 0x1F0FFF, 0, h.call(dK32, "GetCurrentProcessId"))
	out := b.alloc(8)
	if hp == 0 || b.call(dAdv, "OpenProcessToken", hp, secTokenQuery, out) != 1 {
		t.Fatalf("OpenProcessToken(other) lastError %d", b.lastError())
	}
	tokB := b.r64(out)
	dup := h.alloc(8)
	if h.call(dAdv, "DuplicateTokenEx", tok, 0, 0, 2, 2, dup) != 1 { // SecurityImpersonation, TokenImpersonation
		t.Fatalf("DuplicateTokenEx lastError %d", h.lastError())
	}
	imp := h.r64(dup)
	impB := b.E.handles.add(h.E.handles.get(imp)) // same object in both tables

	user, _ := secTokenInfo(t, h, tok, secTokenUserCls)
	owner := h.alloc(8)
	h.w64(owner, h.r64(user)) // TOKEN_OWNER{Owner = user SID}
	label := h.alloc(16)
	h.w64(label, secSid(t, h, "S-1-16-8192")) // TOKEN_MANDATORY_LABEL{medium}
	noDacl := h.alloc(8)                      // TOKEN_DEFAULT_DACL{NULL}
	privs := h.alloc(16)                      // TOKEN_PRIVILEGES{1, {LUID 19, attr}}
	h.w32(privs, 1)
	h.w32(privs+4, 19)

	const n = 300
	var fails [2]int
	done := make(chan struct{})
	go func() { // process 1: writers
		defer close(done)
		for i := range n {
			h.w32(privs+12, uint32(i&1)*sePrivEnabled)
			for _, k := range []uint64{tok, imp} {
				if h.call(dAdv, "AdjustTokenPrivileges", k, 0, privs, 0, 0, 0) != 1 {
					fails[0]++
				}
				if h.call(dAdv, "SetTokenInformation", k, 4, owner, 8) != 1 ||
					h.call(dAdv, "SetTokenInformation", k, 6, noDacl, 8) != 1 ||
					h.call(dAdv, "SetTokenInformation", k, 25, label, 16) != 1 {
					fails[0]++
				}
			}
		}
	}()
	buf, rl, member := b.alloc(4096), b.alloc(4), b.alloc(4)
	// a member and a non-member SID (the latter scans every group)
	everyone, system := secSid(t, b, "S-1-1-0"), secSid(t, b, "S-1-5-18")
	// process 2: readers
	for range n {
		for _, c := range []uint64{2, 3, 4, 6, 10, 25} { // groups, privileges, owner, default DACL, statistics, integrity
			if b.call(dAdv, "GetTokenInformation", tokB, c, buf, 4096, rl) != 1 ||
				b.call(dAdv, "GetTokenInformation", impB, c, buf, 4096, rl) != 1 {
				fails[1]++
			}
		}
		if b.call(dAdv, "CheckTokenMembership", impB, everyone, member) != 1 || b.r32(member) != 1 ||
			b.call(dAdv, "CheckTokenMembership", impB, system, member) != 1 || b.r32(member) != 0 {
			fails[1]++
		}
		if b.call(dAdv, "DuplicateTokenEx", tokB, 0, 0, 2, 2, out) != 1 {
			fails[1]++
		}
	}
	<-done
	if fails != [2]int{} {
		t.Fatalf("failed calls: writer %d, reader %d", fails[0], fails[1])
	}
}

// The vcruntime per-thread exception slots (__current_exception & co.) are
// per process: two processes use them concurrently without sharing state,
// and each thread keeps one stable slot block in its own heap.
func TestIntegExceptionSlotsPerProcess(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	run := func(x *testEmu, res chan<- [2]uint64) {
		first := x.call(dVc, "__current_exception")
		bad := uint64(0)
		for range 200 {
			if x.call(dVc, "__current_exception") != first ||
				x.call(dVc, "__current_exception_context") != first+8 ||
				x.call(dVc, "__processing_throw") != first+16 {
				bad++
			}
		}
		res <- [2]uint64{first, bad}
	}
	rh, rb := make(chan [2]uint64, 1), make(chan [2]uint64, 1)
	go run(h, rh)
	run(b, rb)
	for _, r := range [][2]uint64{<-rh, <-rb} {
		if r[0] == 0 || r[1] != 0 {
			t.Fatalf("slot block %#x, %d unstable results", r[0], r[1])
		}
	}
}
