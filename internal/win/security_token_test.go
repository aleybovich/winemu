package win

import (
	"testing"
)

const (
	secTokenQuery    = 0x8
	secProcessToken  = ^uint64(3)
	secTokenUserCls  = 1
	secTokenGroupCls = 2
)

func secOpenProcessToken(t *testing.T, h *testEmu) uint64 {
	t.Helper()
	out := h.alloc(8)
	if h.call(dAdv, "OpenProcessToken", pseudoProcess, secTokenQuery, out) != 1 {
		t.Fatalf("OpenProcessToken failed, lastError %d", h.lastError())
	}
	return h.r64(out)
}

// secTokenInfo runs the documented two-call pattern: size probe (expects
// ERROR_INSUFFICIENT_BUFFER + *ReturnLength), a one-byte-short call, then the
// real call; it returns the buffer address and size.
func secTokenInfo(t *testing.T, h *testEmu, tok uint64, class uint32) (uint64, uint32) {
	t.Helper()
	rl := h.alloc(4)
	secExpectFail(t, h, "GetTokenInformation probe", h.call(dAdv, "GetTokenInformation", tok, uint64(class), 0, 0, rl), errInsufficientBuf)
	n := h.r32(rl)
	if n == 0 {
		t.Fatalf("class %d: probe returned length 0", class)
	}
	buf := h.alloc(int(n))
	h.w32(rl, 0)
	secExpectFail(t, h, "GetTokenInformation short", h.call(dAdv, "GetTokenInformation", tok, uint64(class), buf, uint64(n-1), rl), errInsufficientBuf)
	if h.r32(rl) != n {
		t.Fatalf("class %d: short call ReturnLength %d, want %d", class, h.r32(rl), n)
	}
	h.w32(rl, 0)
	if r := h.call(dAdv, "GetTokenInformation", tok, uint64(class), buf, uint64(n), rl); r != 1 || h.r32(rl) != n {
		t.Fatalf("class %d: GetTokenInformation = %d, ReturnLength %d, lastError %d", class, r, h.r32(rl), h.lastError())
	}
	return buf, n
}

func TestTokenInformationClasses(t *testing.T) {
	h := newTestEmu(t)
	tok := secOpenProcessToken(t, h)

	buf, n := secTokenInfo(t, h, tok, secTokenUserCls)
	user := secSidStr(h, h.r64(buf))
	if user != sidUserAccount.String() || h.r64(buf) != buf+16 || n != 16+28 {
		t.Fatalf("TokenUser = %q at %#x (buf %#x) size %d", user, h.r64(buf), buf, n)
	}

	buf, _ = secTokenInfo(t, h, tok, secTokenGroupCls)
	cnt := h.r32(buf)
	found := map[string]uint32{}
	for i := range uint64(cnt) {
		found[secSidStr(h, h.r64(buf+8+16*i))] = h.r32(buf + 8 + 16*i + 8)
	}
	if found["S-1-1-0"] != seGroupStd || found[sidNoneGroup.String()] != seGroupStd || found["S-1-16-8192"] != 0x60 {
		t.Fatalf("TokenGroups = %v", found)
	}
	if _, admin := found["S-1-5-32-544"]; admin {
		t.Fatal("token must not contain Administrators")
	}

	buf, n = secTokenInfo(t, h, tok, 3) // TokenPrivileges
	if pc := h.r32(buf); n != 4+12*pc || pc == 0 {
		t.Fatalf("TokenPrivileges count %d size %d", pc, n)
	}
	for _, c := range []struct {
		class uint32
		want  string
	}{{4, sidUserAccount.String()}, {5, sidNoneGroup.String()}} {
		buf, _ = secTokenInfo(t, h, tok, c.class)
		if got := secSidStr(h, h.r64(buf)); got != c.want || h.r64(buf) != buf+8 {
			t.Fatalf("class %d = %q, want %q", c.class, got, c.want)
		}
	}
	buf, _ = secTokenInfo(t, h, tok, 6) // TokenDefaultDacl
	if h.call(dAdv, "IsValidAcl", h.r64(buf)) != 1 || h.r16(h.r64(buf)+4) != 3 {
		t.Fatal("TokenDefaultDacl is not a valid 3-ACE ACL")
	}
	for _, c := range []struct{ class, size, val uint32 }{{8, 4, tokenPrimary}, {18, 4, 1}, {20, 4, 0}, {12, 4, 1}} {
		buf, n = secTokenInfo(t, h, tok, c.class)
		if n != c.size || h.r32(buf) != c.val {
			t.Fatalf("class %d = %d (size %d), want %d", c.class, h.r32(buf), n, c.val)
		}
	}
	buf, n = secTokenInfo(t, h, tok, 10) // TokenStatistics
	if n != 56 || h.r32(buf+24) != tokenPrimary || h.r32(buf+40) != cnt || h.r64(buf) == 0 {
		t.Fatalf("TokenStatistics size %d type %d groups %d", n, h.r32(buf+24), h.r32(buf+40))
	}
	buf, _ = secTokenInfo(t, h, tok, 25) // TokenIntegrityLevel
	if secSidStr(h, h.r64(buf)) != "S-1-16-8192" || h.r32(buf+8) != 0x60 {
		t.Fatalf("TokenIntegrityLevel = %q %#x", secSidStr(h, h.r64(buf)), h.r32(buf+8))
	}

	rl := h.alloc(4)
	big := h.alloc(256)
	secExpectFail(t, h, "class 99", h.call(dAdv, "GetTokenInformation", tok, 99, big, 256, rl), errInvalidParameter)
	secExpectFail(t, h, "TokenImpersonationLevel(primary)", h.call(dAdv, "GetTokenInformation", tok, 9, big, 256, rl), errInvalidParameter)
	secExpectFail(t, h, "bad handle", h.call(dAdv, "GetTokenInformation", 0x7777, 1, big, 256, rl), errInvalidHandle)
	// the pseudo handle GetCurrentProcessToken() names the same token
	if h.call(dAdv, "GetTokenInformation", secProcessToken, 1, big, 256, rl) != 1 || secSidStr(h, h.r64(big)) != user {
		t.Fatal("GetCurrentProcessToken pseudo handle")
	}
	if h.call(dK32, "CloseHandle", tok) != 1 {
		t.Fatal("CloseHandle(token)")
	}
	secExpectFail(t, h, "OpenProcessToken(bad)", h.call(dAdv, "OpenProcessToken", 0x7777, secTokenQuery, rl), errInvalidHandle)
}

func TestTokenThreadImpersonation(t *testing.T) {
	h := newTestEmu(t)
	out := h.alloc(8)
	secExpectFail(t, h, "OpenThreadToken(no impersonation)", h.call(dAdv, "OpenThreadToken", pseudoThread, secTokenQuery, 1, out), errNoToken)
	secExpectFail(t, h, "OpenThreadToken(bad thread)", h.call(dAdv, "OpenThreadToken", 0x7777, secTokenQuery, 1, out), errInvalidHandle)
	secExpectFail(t, h, "ImpersonateSelf(5)", h.call(dAdv, "ImpersonateSelf", 5), errBadImpersonLvl)
	if h.call(dAdv, "ImpersonateSelf", 2) != 1 || h.call(dAdv, "OpenThreadToken", pseudoThread, secTokenQuery, 1, out) != 1 {
		t.Fatalf("ImpersonateSelf/OpenThreadToken, lastError %d", h.lastError())
	}
	buf, _ := secTokenInfo(t, h, h.r64(out), 8)
	lvl, _ := secTokenInfo(t, h, h.r64(out), 9)
	if h.r32(buf) != tokenImpersonation || h.r32(lvl) != 2 {
		t.Fatalf("thread token type %d level %d", h.r32(buf), h.r32(lvl))
	}
	// SetThreadToken rejects primary tokens, accepts NULL (revert)
	secExpectFail(t, h, "SetThreadToken(primary)", h.call(dAdv, "SetThreadToken", 0, secOpenProcessToken(t, h)), errBadTokenType)
	if h.call(dAdv, "RevertToSelf") != 1 {
		t.Fatal("RevertToSelf")
	}
	secExpectFail(t, h, "OpenThreadToken(after revert)", h.call(dAdv, "OpenThreadToken", pseudoThread, secTokenQuery, 1, out), errNoToken)
	if h.call(dAdv, "ImpersonateLoggedOnUser", secOpenProcessToken(t, h)) != 1 || h.call(dAdv, "OpenThreadToken", pseudoThread, secTokenQuery, 1, out) != 1 {
		t.Fatal("ImpersonateLoggedOnUser")
	}
	if h.call(dAdv, "SetThreadToken", 0, 0) != 1 || h.call(dAdv, "OpenThreadToken", pseudoThread, secTokenQuery, 1, out) != 0 {
		t.Fatal("SetThreadToken(NULL) did not revert")
	}
}

func TestTokenSetInformation(t *testing.T) {
	h := newTestEmu(t)
	tok := secOpenProcessToken(t, h)
	p := h.alloc(16)
	set := func(class uint32, n uint64) uint64 {
		return h.call(dAdv, "SetTokenInformation", tok, uint64(class), p, n)
	}

	h.w64(p, secSid(t, h, "S-1-1-0"))
	secExpectFail(t, h, "TokenOwner=Everyone", set(4, 8), errInvalidOwner)
	secExpectFail(t, h, "TokenOwner short", set(4, 4), errBadLength)
	if set(5, 8) != 1 {
		t.Fatalf("TokenPrimaryGroup=Everyone failed, lastError %d", h.lastError())
	}
	// visible through a second handle to the same process token
	buf, _ := secTokenInfo(t, h, secOpenProcessToken(t, h), 5)
	if secSidStr(h, h.r64(buf)) != "S-1-1-0" {
		t.Fatalf("primary group = %q", secSidStr(h, h.r64(buf)))
	}
	h.w64(p, secSid(t, h, "S-1-5-32-544"))
	secExpectFail(t, h, "TokenPrimaryGroup=Administrators", set(5, 8), errInvalidPrimGrp)

	acl := h.alloc(64)
	h.call(dAdv, "InitializeAcl", acl, 64, aclRevision)
	h.call(dAdv, "AddAccessAllowedAce", acl, aclRevision, 0x10000000, secSid(t, h, "S-1-5-18"))
	h.w64(p, acl)
	if set(6, 8) != 1 {
		t.Fatalf("TokenDefaultDacl failed, lastError %d", h.lastError())
	}
	buf, n := secTokenInfo(t, h, tok, 6)
	if n != 8+8+20 || h.r16(h.r64(buf)+4) != 1 {
		t.Fatalf("default DACL size %d", n)
	}
	h.w64(p, 0)
	if set(6, 8) != 1 {
		t.Fatal("TokenDefaultDacl(NULL)")
	}
	if _, n = secTokenInfo(t, h, tok, 6); n != 8 {
		t.Fatalf("removed default DACL size %d, want 8", n)
	}

	h.w64(p, secSid(t, h, "S-1-16-12288"))
	h.w32(p+8, 0x20)
	secExpectFail(t, h, "raise integrity", set(25, 16), errPrivNotHeld)
	h.w64(p, secSid(t, h, "S-1-16-4096"))
	if set(25, 16) != 1 {
		t.Fatalf("lower integrity failed, lastError %d", h.lastError())
	}
	if buf, _ = secTokenInfo(t, h, tok, 25); secSidStr(h, h.r64(buf)) != "S-1-16-4096" {
		t.Fatalf("integrity = %q", secSidStr(h, h.r64(buf)))
	}
	secExpectFail(t, h, "TokenSessionId", set(12, 4), errPrivNotHeld)
	secExpectFail(t, h, "TokenUser (read-only)", set(1, 16), errInvalidParameter)
	secExpectFail(t, h, "bad handle", h.call(dAdv, "SetTokenInformation", 0x7777, 4, p, 8), errInvalidHandle)
}

func TestTokenDuplicateAndMembership(t *testing.T) {
	h := newTestEmu(t)
	tok := secOpenProcessToken(t, h)
	out, member := h.alloc(8), h.alloc(4)
	everyone, admins := secSid(t, h, "S-1-1-0"), secSid(t, h, "S-1-5-32-544")
	isMember := func(tk, s uint64) uint32 {
		t.Helper()
		h.w32(member, 7)
		if h.call(dAdv, "CheckTokenMembership", tk, s, member) != 1 {
			t.Fatalf("CheckTokenMembership failed, lastError %d", h.lastError())
		}
		return h.r32(member)
	}
	if isMember(0, everyone) != 1 || isMember(0, admins) != 0 || isMember(0, secSid(t, h, sidUserAccount.String())) != 1 {
		t.Fatal("CheckTokenMembership(NULL, ...)")
	}
	secExpectFail(t, h, "CheckTokenMembership(primary)", h.call(dAdv, "CheckTokenMembership", tok, everyone, member), errNoImpersonTok)
	secExpectFail(t, h, "CheckTokenMembership(bad sid)", h.call(dAdv, "CheckTokenMembership", 0, 0, member), errInvalidSid)

	secExpectFail(t, h, "DuplicateTokenEx(type 3)", h.call(dAdv, "DuplicateTokenEx", tok, 0, 0, 2, 3, out), errInvalidParameter)
	secExpectFail(t, h, "DuplicateTokenEx(level 4)", h.call(dAdv, "DuplicateTokenEx", tok, 0, 0, 4, 2, out), errBadImpersonLvl)
	secExpectFail(t, h, "DuplicateTokenEx(bad)", h.call(dAdv, "DuplicateTokenEx", 0x7777, 0, 0, 2, 2, out), errInvalidHandle)
	if h.call(dAdv, "DuplicateTokenEx", tok, 0, 0, 2, tokenImpersonation, out) != 1 {
		t.Fatalf("DuplicateTokenEx failed, lastError %d", h.lastError())
	}
	dup := h.r64(out)
	if isMember(dup, everyone) != 1 {
		t.Fatal("dup not member of Everyone")
	}
	// the duplicate is independent of the original
	p := h.alloc(8)
	h.w64(p, everyone)
	h.call(dAdv, "SetTokenInformation", dup, 5, p, 8)
	if buf, _ := secTokenInfo(t, h, tok, 5); secSidStr(h, h.r64(buf)) != sidNoneGroup.String() {
		t.Fatal("SetTokenInformation on the duplicate changed the original")
	}
	if a, b := secTokenInfoID(t, h, tok), secTokenInfoID(t, h, dup); a == b {
		t.Fatal("duplicate has the same TokenId")
	}
	if h.call(dAdv, "DuplicateToken", tok, 1, out) != 1 {
		t.Fatal("DuplicateToken")
	}
	if buf, _ := secTokenInfo(t, h, h.r64(out), 8); h.r32(buf) != tokenImpersonation {
		t.Fatal("DuplicateToken type")
	}
}

func secTokenInfoID(t *testing.T, h *testEmu, tok uint64) uint64 {
	t.Helper()
	buf, _ := secTokenInfo(t, h, tok, 10)
	return h.r64(buf)
}

func TestTokenRestricted(t *testing.T) {
	h := newTestEmu(t)
	tok := secOpenProcessToken(t, h)
	users, everyone, authUsers := secSid(t, h, "S-1-5-32-545"), secSid(t, h, "S-1-1-0"), secSid(t, h, "S-1-5-11")
	disable, restrict := h.alloc(16), h.alloc(16)
	h.w64(disable, users)
	h.w64(restrict, everyone)
	out := h.alloc(8)
	const disableMaxPrivilege = 1
	if h.call(dAdv, "IsTokenRestricted", tok) != 0 || h.lastError() != 0 {
		t.Fatal("process token reported restricted")
	}
	if h.call(dAdv, "CreateRestrictedToken", tok, disableMaxPrivilege, 1, disable, 0, 0, 1, restrict, out) != 1 {
		t.Fatalf("CreateRestrictedToken failed, lastError %d", h.lastError())
	}
	rt := h.r64(out)
	if h.call(dAdv, "IsTokenRestricted", rt) != 1 {
		t.Fatal("IsTokenRestricted(new) = 0")
	}
	if buf, _ := secTokenInfo(t, h, rt, 3); h.r32(buf) != 1 || h.r32(buf+4) != privChangeNotify {
		t.Fatalf("DISABLE_MAX_PRIVILEGE left %d privileges", h.r32(buf))
	}
	buf, _ := secTokenInfo(t, h, rt, 11) // TokenRestrictedSids
	if h.r32(buf) != 1 || secSidStr(h, h.r64(buf+8)) != "S-1-1-0" {
		t.Fatalf("restricted SIDs count %d", h.r32(buf))
	}
	if buf, _ = secTokenInfo(t, h, rt, 8); h.r32(buf) != tokenPrimary {
		t.Fatal("restricted token is not primary")
	}
	h.call(dAdv, "DuplicateTokenEx", rt, 0, 0, 2, tokenImpersonation, out)
	member := h.alloc(4)
	for _, c := range []struct {
		s    uint64
		want uint32
	}{{everyone, 1}, {users, 0}, {authUsers, 0}} {
		h.call(dAdv, "CheckTokenMembership", h.r64(out), c.s, member)
		if h.r32(member) != c.want {
			t.Fatalf("restricted membership of %s = %d, want %d", secSidStr(h, c.s), h.r32(member), c.want)
		}
	}
	secExpectFail(t, h, "CreateRestrictedToken(bad)", h.call(dAdv, "CreateRestrictedToken", 0x7777, 0, 0, 0, 0, 0, 0, 0, out), errInvalidHandle)
	h.w64(disable, 0)
	secExpectFail(t, h, "CreateRestrictedToken(bad sid)", h.call(dAdv, "CreateRestrictedToken", tok, 0, 1, disable, 0, 0, 0, 0, out), errInvalidSid)
	secExpectFail(t, h, "IsTokenRestricted(bad)", h.call(dAdv, "IsTokenRestricted", 0x7777), errInvalidHandle)
}

func TestTokenPrivileges(t *testing.T) {
	h := newTestEmu(t)
	tok := secOpenProcessToken(t, h)
	luid := h.alloc(8)
	if h.call(dAdv, "LookupPrivilegeValueW", 0, h.wstr("seshutdownprivilege"), luid) != 1 || h.r64(luid) != 19 {
		t.Fatalf("LookupPrivilegeValueW = %d", h.r64(luid))
	}
	secExpectFail(t, h, "LookupPrivilegeValueA(bogus)", h.call(dAdv, "LookupPrivilegeValueA", 0, h.astr("SeBogus"), luid), errNoSuchPriv)
	name, n := h.alloc(128), h.alloc(4)
	h.w32(n, 5)
	secExpectFail(t, h, "LookupPrivilegeNameW(small)", h.call(dAdv, "LookupPrivilegeNameW", 0, luid, name, n), errInsufficientBuf)
	if h.r32(n) != uint32(len("SeShutdownPrivilege")+1) {
		t.Fatalf("required %d", h.r32(n))
	}
	if h.call(dAdv, "LookupPrivilegeNameW", 0, luid, name, n) != 1 || h.readWStr(name) != "SeShutdownPrivilege" || h.r32(n) != 19 {
		t.Fatalf("LookupPrivilegeNameW = %q %d", h.readWStr(name), h.r32(n))
	}

	ns, prev, rl := h.alloc(16), h.alloc(16), h.alloc(4)
	h.w32(ns, 1)
	h.w32(ns+4, 19)
	h.w32(ns+12, sePrivEnabled)
	secExpectFail(t, h, "AdjustTokenPrivileges(prev too small)", h.call(dAdv, "AdjustTokenPrivileges", tok, 0, ns, 4, prev, rl), errInsufficientBuf)
	if h.r32(rl) != 16 {
		t.Fatalf("ReturnLength %d, want 16", h.r32(rl))
	}
	if h.call(dAdv, "AdjustTokenPrivileges", tok, 0, ns, 16, prev, rl) != 1 || h.lastError() != 0 {
		t.Fatalf("AdjustTokenPrivileges lastError %d", h.lastError())
	}
	if h.r32(prev) != 1 || h.r32(prev+4) != 19 || h.r32(prev+12) != 0 {
		t.Fatalf("previous state %d/%d/%#x", h.r32(prev), h.r32(prev+4), h.r32(prev+12))
	}
	buf, _ := secTokenInfo(t, h, tok, 3)
	for i := range uint64(h.r32(buf)) {
		if h.r32(buf+4+12*i) == 19 && h.r32(buf+12+12*i)&sePrivEnabled == 0 {
			t.Fatal("SeShutdownPrivilege not enabled")
		}
	}
	h.w32(ns+4, 20) // SeDebugPrivilege: not held
	if h.call(dAdv, "AdjustTokenPrivileges", tok, 0, ns, 0, 0, 0) != 1 || h.lastError() != errNotAllAssigned {
		t.Fatalf("not-held privilege: lastError %d, want %d", h.lastError(), errNotAllAssigned)
	}
	secExpectFail(t, h, "AdjustTokenPrivileges(bad)", h.call(dAdv, "AdjustTokenPrivileges", 0x7777, 0, ns, 0, 0, 0), errInvalidHandle)
}
