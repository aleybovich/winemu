package win

import "testing"

// QA additions for WS-A: cases found missing by mutation testing.

func TestQAFreeSidInvalid(t *testing.T) {
	h := newTestEmu(t)
	auth, out := h.alloc(8), h.alloc(8)
	h.write(auth, []byte{0, 0, 0, 0, 0, 5})
	if h.call(dAdv, "AllocateAndInitializeSid", auth, 1, 18, 0, 0, 0, 0, 0, 0, 0, out) != 1 {
		t.Fatalf("AllocateAndInitializeSid failed, lastError %d", h.lastError())
	}
	p := h.r64(out)
	// FreeSid returns NULL on success and the SID pointer on failure.
	if r := h.call(dAdv, "FreeSid", p+4); r != p+4 {
		t.Fatalf("FreeSid(not a block) = %#x, want %#x", r, p+4)
	}
	if r := h.call(dAdv, "FreeSid", p); r != 0 {
		t.Fatalf("FreeSid(block) = %#x, want 0", r)
	}
	if r := h.call(dAdv, "FreeSid", p); r != p {
		t.Fatalf("FreeSid(freed twice) = %#x, want %#x", r, p)
	}
}

func TestQADenyOnlyMembership(t *testing.T) {
	h := newTestEmu(t)
	tok := secOpenProcessToken(t, h)
	everyone, users := secSid(t, h, "S-1-1-0"), secSid(t, h, "S-1-5-32-545")
	disable, out := h.alloc(16), h.alloc(8)
	h.w64(disable, everyone)
	if h.call(dAdv, "CreateRestrictedToken", tok, 0, 1, disable, 0, 0, 0, 0, out) != 1 {
		t.Fatalf("CreateRestrictedToken failed, lastError %d", h.lastError())
	}
	rt := h.r64(out)
	// Disabling SIDs alone does not make a token "restricted".
	if h.call(dAdv, "IsTokenRestricted", rt) != 0 {
		t.Fatal("IsTokenRestricted(deny-only only) = 1")
	}
	buf, _ := secTokenInfo(t, h, rt, 2) // TokenGroups
	found := false
	for i := range uint64(h.r32(buf)) {
		if secSidStr(h, h.r64(buf+8+16*i)) == "S-1-1-0" {
			found = true
			if a := h.r32(buf + 16 + 16*i); a&seGroupDenyOnly == 0 || a&seGroupEnabled != 0 {
				t.Fatalf("disabled Everyone attributes %#x, want DENY_ONLY without ENABLED", a)
			}
		}
	}
	if !found {
		t.Fatal("disabled SID missing from TokenGroups")
	}
	if h.call(dAdv, "DuplicateTokenEx", rt, 0, 0, 2, tokenImpersonation, out) != 1 {
		t.Fatalf("DuplicateTokenEx failed, lastError %d", h.lastError())
	}
	member := h.alloc(4)
	for _, c := range []struct {
		s    uint64
		want uint32
	}{{everyone, 0}, {users, 1}} {
		h.w32(member, 7)
		if h.call(dAdv, "CheckTokenMembership", h.r64(out), c.s, member) != 1 || h.r32(member) != c.want {
			t.Fatalf("membership of %s = %d, want %d", secSidStr(h, c.s), h.r32(member), c.want)
		}
	}
}

func TestQALookupAccountNameSidBoundary(t *testing.T) {
	h := newTestEmu(t)
	user := h.wstr(h.E.fs.user)
	cb, cd, use, sidBuf, dom := h.alloc(4), h.alloc(4), h.alloc(4), h.alloc(64), h.alloc(128)
	h.w32(cb, 27)
	h.w32(cd, 64) // domain buffer large enough: only the SID buffer is short
	secExpectFail(t, h, "SID buffer 27", h.call(dAdv, "LookupAccountNameW", 0, user, sidBuf, cb, dom, cd, use), errInsufficientBuf)
	if h.r32(cb) != 28 {
		t.Fatalf("cbSid after short buffer = %d, want 28", h.r32(cb))
	}
	h.w32(cd, 64)
	if h.call(dAdv, "LookupAccountNameW", 0, user, sidBuf, cb, dom, cd, use) != 1 || h.r32(cb) != 28 || secSidStr(h, sidBuf) != sidUserAccount.String() {
		t.Fatalf("SID buffer 28: cb %d sid %q lastError %d", h.r32(cb), secSidStr(h, sidBuf), h.lastError())
	}
}

func TestQANetUserGetInfoLayout(t *testing.T) {
	h := newTestEmu(t)
	const (
		netapi         = "netapi32.dll"
		userPrivUser   = 1
		ufNormal       = 0x200
		unitsPerWeek   = 168
		logonServerAll = `\\*`
	)
	user, out := h.wstr(h.E.fs.user), h.alloc(8)
	get := func(level uint64) uint64 {
		t.Helper()
		if r := h.call(netapi, "NetUserGetInfo", 0, user, level, out); r != 0 {
			t.Fatalf("NetUserGetInfo(%d) = %d", level, r)
		}
		return h.r64(out)
	}
	// USER_INFO_1 (x64): priv @20, flags @40
	if b := get(1); h.r32(b+20) != userPrivUser || h.r32(b+40)&ufNormal == 0 {
		t.Fatalf("USER_INFO_1 priv %d flags %#x", h.r32(b+20), h.r32(b+40))
	}
	// USER_INFO_4 (x64): priv @20, flags @40, units_per_week @112, logon_hours @120,
	// logon_server @136, profile @168, home_dir_drive @176, password_expired @184
	b := get(4)
	if h.r32(b+20) != userPrivUser || h.r32(b+40)&ufNormal == 0 || h.r32(b+112) != unitsPerWeek || h.r64(b+120) != 0 ||
		h.readWStr(h.r64(b+136)) != logonServerAll || h.r64(b+168) == 0 || h.r64(b+176) == 0 || h.r32(b+184) != 0 {
		t.Fatalf("USER_INFO_4 priv %d flags %#x units %d hours %#x server %q",
			h.r32(b+20), h.r32(b+40), h.r32(b+112), h.r64(b+120), h.readWStr(h.r64(b+136)))
	}
	// USER_INFO_20: flags @24
	if b := get(20); h.r32(b+24)&ufNormal == 0 {
		t.Fatalf("USER_INFO_20 flags %#x", h.r32(b+24))
	}
	// USER_INFO_23: flags @24, user_sid @32
	if b := get(23); h.r32(b+24)&ufNormal == 0 || secSidStr(h, h.r64(b+32)) != sidUserAccount.String() {
		t.Fatalf("USER_INFO_23 flags %#x sid %q", h.r32(b+24), secSidStr(h, h.r64(b+32)))
	}
}

func TestQANetApiErrors(t *testing.T) {
	h := newTestEmu(t)
	const netapi = "netapi32.dll"
	name, status := h.alloc(8), h.alloc(4)
	if r := h.call(netapi, "NetGetJoinInformation", h.wstr(`\\OTHERHOST`), name, status); r != errBadNetPath {
		t.Fatalf("NetGetJoinInformation(remote) = %d, want %d", r, errBadNetPath)
	}
	if r := h.call(netapi, "NetGetJoinInformation", 0, name, status); r != 0 {
		t.Fatalf("NetGetJoinInformation = %d", r)
	}
	b := h.r64(name)
	if r := h.call(netapi, "NetApiBufferFree", b+2); r == 0 {
		t.Fatal("NetApiBufferFree(not a buffer) succeeded")
	}
	if r := h.call(netapi, "NetApiBufferFree", b); r != 0 {
		t.Fatalf("NetApiBufferFree = %d", r)
	}
}

func TestQAAclValidationAndAces(t *testing.T) {
	h := newTestEmu(t)
	user := secSid(t, h, "S-1-5-21-1-2-3-1000") // 28-byte SID, 36-byte ACE
	acl := h.alloc(128)
	if h.call(dAdv, "InitializeAcl", acl, 128, aclRevision) != 1 {
		t.Fatal("InitializeAcl")
	}
	if h.call(dAdv, "AddAccessDeniedAce", acl, aclRevision, 0x80000000, user) != 1 {
		t.Fatalf("AddAccessDeniedAce failed, lastError %d", h.lastError())
	}
	if b := h.read(acl+8, 2); b[0] != aceDeniedType || b[1] != 0 || h.r32(acl+12) != 0x80000000 {
		t.Fatalf("AddAccessDeniedAce wrote type %d flags %d mask %#x", b[0], b[1], h.r32(acl+12))
	}
	secExpectFail(t, h, "AddAccessAllowedAceEx(bad flags)",
		h.call(dAdv, "AddAccessAllowedAceEx", acl, aclRevision, 0x40, 1, user), errInvalidParameter)

	// AddAce with a list of two ACEs adds both to the count.
	list := h.alloc(72)
	h.write(list, h.read(acl+8, 36))
	h.write(list+36, h.read(acl+8, 36))
	acl2 := h.alloc(128)
	h.call(dAdv, "InitializeAcl", acl2, 128, aclRevision)
	if h.call(dAdv, "AddAce", acl2, aclRevision, ^uint64(0)>>32, list, 72) != 1 || h.r16(acl2+4) != 2 {
		t.Fatalf("AddAce(2 ACEs): count %d, lastError %d", h.r16(acl2+4), h.lastError())
	}

	// IsValidAcl: an ACE running past AclSize, and an unknown revision.
	h.w16(acl2+2, 96)      // AclSize 96 still holds both ACEs (80 bytes in use) ...
	h.w16(acl2+8+36+2, 64) // ... but the second ACE now ends at 8+36+64 = 108 > 96
	if h.call(dAdv, "IsValidAcl", acl2) != 0 {
		t.Fatal("IsValidAcl(ACE past AclSize) = 1")
	}
	h.w16(acl2+8+36+2, 36)
	if h.call(dAdv, "IsValidAcl", acl2) != 1 {
		t.Fatal("IsValidAcl(repaired) = 0")
	}
	h.write(acl2, []byte{1})
	if h.call(dAdv, "IsValidAcl", acl2) != 0 {
		t.Fatal("IsValidAcl(revision 1) = 1")
	}
}

func TestQASecurityDescriptorFlags(t *testing.T) {
	h := newTestEmu(t)
	sd, acl := h.alloc(sdSize), h.alloc(64)
	h.call(dAdv, "InitializeSecurityDescriptor", sd, sdRevision)
	h.call(dAdv, "InitializeAcl", acl, 64, aclRevision)
	if h.call(dAdv, "SetSecurityDescriptorDacl", sd, 1, acl, 1) != 1 || h.r16(sd+2) != sdDaclPresent|sdDaclDefaulted {
		t.Fatalf("SetSecurityDescriptorDacl(defaulted) control %#x", h.r16(sd+2))
	}
	present, pacl, def := h.alloc(4), h.alloc(8), h.alloc(4)
	if h.call(dAdv, "GetSecurityDescriptorDacl", sd, present, pacl, def) != 1 || h.r32(present) != 1 || h.r64(pacl) != acl || h.r32(def) != 1 {
		t.Fatalf("GetSecurityDescriptorDacl present %d acl %#x defaulted %d", h.r32(present), h.r64(pacl), h.r32(def))
	}
	grp := secSid(t, h, "S-1-5-32-545")
	if h.call(dAdv, "SetSecurityDescriptorGroup", sd, grp, 1) != 1 || h.r16(sd+2) != sdDaclPresent|sdDaclDefaulted|sdGroupDefaulted {
		t.Fatalf("SetSecurityDescriptorGroup(defaulted) control %#x", h.r16(sd+2))
	}
	if h.call(dAdv, "IsValidSecurityDescriptor", sd) != 1 {
		t.Fatalf("IsValidSecurityDescriptor(valid) = 0, lastError %d", h.lastError())
	}
	bad := h.alloc(16) // revision 0: not a SID
	h.call(dAdv, "SetSecurityDescriptorOwner", sd, bad, 0)
	if h.call(dAdv, "IsValidSecurityDescriptor", sd) != 0 {
		t.Fatal("IsValidSecurityDescriptor(invalid owner) = 1")
	}
	h.call(dAdv, "SetSecurityDescriptorOwner", sd, 0, 0)
	h.call(dAdv, "SetSecurityDescriptorDacl", sd, 1, bad, 0)
	if h.call(dAdv, "IsValidSecurityDescriptor", sd) != 0 {
		t.Fatal("IsValidSecurityDescriptor(invalid DACL) = 1")
	}
}

func TestQATokenInvalidArgs(t *testing.T) {
	h := newTestEmu(t)
	tok := secOpenProcessToken(t, h)
	bad, p := h.alloc(16), h.alloc(8) // bad: zeroed, revision 0 is not an ACL
	h.w64(p, bad)
	secExpectFail(t, h, "SetTokenInformation(TokenDefaultDacl, invalid ACL)",
		h.call(dAdv, "SetTokenInformation", tok, 6, p, 8), errInvalidAcl)
	out := h.alloc(8)
	secExpectFail(t, h, "OpenProcessToken(bad handle)", h.call(dAdv, "OpenProcessToken", 0x7777, 8, out), errInvalidHandle)
}

func TestQATokenHandleLifetime(t *testing.T) {
	h := newTestEmu(t)
	t1, t2 := secOpenProcessToken(t, h), secOpenProcessToken(t, h)
	if h.call(dK32, "CloseHandle", t1) != 1 {
		t.Fatal("CloseHandle(token)")
	}
	buf, rl := h.alloc(256), h.alloc(4)
	secExpectFail(t, h, "GetTokenInformation(closed)", h.call(dAdv, "GetTokenInformation", t1, 8, buf, 256, rl), errInvalidHandle)
	// The process token itself survives: other handles still work.
	if h.call(dAdv, "GetTokenInformation", t2, 8, buf, 256, rl) != 1 || h.r32(buf) != tokenPrimary {
		t.Fatalf("GetTokenInformation(second handle) failed, lastError %d", h.lastError())
	}
}
