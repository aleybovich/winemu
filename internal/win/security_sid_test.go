package win

import (
	"testing"
)

// secSid writes the SID given in string form into guest memory.
func secSid(t *testing.T, h *testEmu, str string) uint64 {
	t.Helper()
	s, ok := parseSid(str)
	if !ok {
		t.Fatalf("bad test SID %q", str)
	}
	a := h.alloc(s.size())
	h.write(a, s.bytes())
	return a
}

// secSidStr reads a SID from guest memory in string form ("" if invalid).
func secSidStr(h *testEmu, p uint64) string {
	s, ok := h.E.readSid(p)
	if !ok {
		return ""
	}
	return s.String()
}

func secExpectFail(t *testing.T, h *testEmu, what string, r uint64, code uint32) {
	t.Helper()
	if r != 0 || h.lastError() != code {
		t.Fatalf("%s = %d, lastError %d, want 0 / %d", what, r, h.lastError(), code)
	}
}

func TestSidAllocateAndInspect(t *testing.T) {
	h := newTestEmu(t)
	auth := h.alloc(6)
	h.write(auth, []byte{0, 0, 0, 0, 0, 5})
	out := h.alloc(8)
	if r := h.call(dAdv, "AllocateAndInitializeSid", auth, 2, 32, 544, 0, 0, 0, 0, 0, 0, out); r != 1 {
		t.Fatalf("AllocateAndInitializeSid = %d, lastError %d", r, h.lastError())
	}
	p := h.r64(out)
	if h.call(dAdv, "IsValidSid", p) != 1 || h.call(dAdv, "GetLengthSid", p) != 16 {
		t.Fatalf("IsValidSid/GetLengthSid = %d/%d", h.call(dAdv, "IsValidSid", p), h.call(dAdv, "GetLengthSid", p))
	}
	if c := h.call(dAdv, "GetSidSubAuthorityCount", p); c != p+1 || h.read(c, 1)[0] != 2 {
		t.Fatalf("GetSidSubAuthorityCount = %#x", c)
	}
	if a := h.call(dAdv, "GetSidSubAuthority", p, 1); h.r32(a) != 544 {
		t.Fatalf("GetSidSubAuthority(1) -> %d", h.r32(a))
	}
	if a := h.call(dAdv, "GetSidIdentifierAuthority", p); h.read(a, 6)[5] != 5 {
		t.Fatalf("GetSidIdentifierAuthority -> %v", h.read(a, 6))
	}
	if n := h.call(dAdv, "GetSidLengthRequired", 5); n != 28 {
		t.Fatalf("GetSidLengthRequired(5) = %d", n)
	}
	if secSidStr(h, p) != "S-1-5-32-544" {
		t.Fatalf("sid = %q", secSidStr(h, p))
	}
	if r := h.call(dAdv, "FreeSid", p); r != 0 {
		t.Fatalf("FreeSid = %#x, want NULL", r)
	}
	// boundary: more than 8 sub-authorities, NULL out pointer
	secExpectFail(t, h, "AllocateAndInitializeSid(9)", h.call(dAdv, "AllocateAndInitializeSid", auth, 9, 1, 2, 3, 4, 5, 6, 7, 8, out), errInvalidSid)
	secExpectFail(t, h, "AllocateAndInitializeSid(out=NULL)", h.call(dAdv, "AllocateAndInitializeSid", auth, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0), errInvalidParameter)
}

func TestSidIsValid(t *testing.T) {
	h := newTestEmu(t)
	p := secSid(t, h, "S-1-5-18")
	if h.call(dAdv, "IsValidSid", p) != 1 {
		t.Fatal("IsValidSid(S-1-5-18) = 0")
	}
	bad := h.alloc(80)
	h.write(bad, []byte{2, 1, 0, 0, 0, 0, 0, 5}) // revision 2
	if h.call(dAdv, "IsValidSid", bad) != 0 || h.call(dAdv, "IsValidSid", 0) != 0 {
		t.Fatal("IsValidSid accepted revision 2 / NULL")
	}
	h.write(bad, []byte{1, 16}) // 16 sub-authorities
	if h.call(dAdv, "IsValidSid", bad) != 0 {
		t.Fatal("IsValidSid accepted 16 sub-authorities")
	}
	if h.call(dAdv, "IsValidSid", 0x10) != 0 {
		t.Fatal("IsValidSid accepted an unmapped pointer")
	}
}

func TestSidStringConversion(t *testing.T) {
	h := newTestEmu(t)
	out := h.alloc(8)
	for _, c := range []struct{ in, want string }{
		{"S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1000"},
		{"s-1-1-0", "S-1-1-0"},
		{"S-1-0x123456789ABC-7", "S-1-0x123456789ABC-7"},
		{"S-1-5", "S-1-5"},
		{"BA", "S-1-5-32-544"},
		{"wd", "S-1-1-0"},
	} {
		if r := h.call(dAdv, "ConvertStringSidToSidW", h.wstr(c.in), out); r != 1 {
			t.Fatalf("ConvertStringSidToSidW(%q) failed, lastError %d", c.in, h.lastError())
		}
		p := h.r64(out)
		if r := h.call(dAdv, "ConvertSidToStringSidW", p, out); r != 1 || h.readWStr(h.r64(out)) != c.want {
			t.Fatalf("round trip %q -> %q, want %q", c.in, h.readWStr(h.r64(out)), c.want)
		}
		if h.call(dK32, "LocalFree", h.r64(out)) != 0 || h.call(dK32, "LocalFree", p) != 0 {
			t.Fatal("LocalFree failed")
		}
	}
	if r := h.call(dAdv, "ConvertStringSidToSidA", h.astr("S-1-5-32-545"), out); r != 1 || secSidStr(h, h.r64(out)) != "S-1-5-32-545" {
		t.Fatalf("ConvertStringSidToSidA = %d", r)
	}
	if r := h.call(dAdv, "ConvertSidToStringSidA", h.r64(out), out); r != 1 || h.readAStr(h.r64(out)) != "S-1-5-32-545" {
		t.Fatalf("ConvertSidToStringSidA = %d %q", r, h.readAStr(h.r64(out)))
	}
	for _, bad := range []string{"", "S-1", "S-2-5", "S-1-x", "S-1-5-", "S-1-5-4294967296", "X-1-5", "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16"} {
		h.setLastError(0)
		secExpectFail(t, h, "ConvertStringSidToSidW("+bad+")", h.call(dAdv, "ConvertStringSidToSidW", h.wstr(bad), out), errInvalidSid)
	}
	secExpectFail(t, h, "ConvertStringSidToSidW(NULL)", h.call(dAdv, "ConvertStringSidToSidW", 0, out), errInvalidParameter)
	bad := h.alloc(16)
	h.write(bad, []byte{3, 1})
	secExpectFail(t, h, "ConvertSidToStringSidW(invalid)", h.call(dAdv, "ConvertSidToStringSidW", bad, out), errInvalidSid)
	secExpectFail(t, h, "ConvertSidToStringSidW(out=NULL)", h.call(dAdv, "ConvertSidToStringSidW", secSid(t, h, "S-1-1-0"), 0), errInvalidParameter)
}

func TestSidCopyEqual(t *testing.T) {
	h := newTestEmu(t)
	src := secSid(t, h, "S-1-5-21-10-20-30-1000")
	dst := h.alloc(28)
	secExpectFail(t, h, "CopySid(27)", h.call(dAdv, "CopySid", 27, dst, src), errInsufficientBuf)
	if r := h.call(dAdv, "CopySid", 28, dst, src); r != 1 || secSidStr(h, dst) != "S-1-5-21-10-20-30-1000" {
		t.Fatalf("CopySid = %d %q", r, secSidStr(h, dst))
	}
	if h.call(dAdv, "EqualSid", src, dst) != 1 {
		t.Fatal("EqualSid(copy) = 0")
	}
	h.setLastError(99)
	if h.call(dAdv, "EqualSid", src, secSid(t, h, "S-1-5-21-10-20-30-1001")) != 0 || h.lastError() != 0 {
		t.Fatalf("EqualSid(different) lastError %d, want 0", h.lastError())
	}
	if h.call(dAdv, "EqualPrefixSid", src, secSid(t, h, "S-1-5-21-10-20-30-1001")) != 1 ||
		h.call(dAdv, "EqualPrefixSid", src, secSid(t, h, "S-1-5-21-10-20-31-1000")) != 0 {
		t.Fatal("EqualPrefixSid")
	}
	secExpectFail(t, h, "EqualSid(NULL)", h.call(dAdv, "EqualSid", src, 0), errInvalidSid)
	secExpectFail(t, h, "CopySid(invalid)", h.call(dAdv, "CopySid", 28, dst, 0), errInvalidSid)
	init := h.alloc(16)
	auth := h.alloc(6)
	h.write(auth, []byte{0, 0, 0, 0, 0, 5})
	if h.call(dAdv, "InitializeSid", init, auth, 1) != 1 || h.call(dAdv, "GetLengthSid", init) != 12 {
		t.Fatal("InitializeSid")
	}
	secExpectFail(t, h, "InitializeSid(16)", h.call(dAdv, "InitializeSid", init, auth, 16), errInvalidParameter)
}

func TestAclBuildAndQuery(t *testing.T) {
	h := newTestEmu(t)
	user := secSid(t, h, "S-1-5-21-1-2-3-1000") // 28 bytes -> ACE 36
	acl := h.alloc(128)
	secExpectFail(t, h, "InitializeAcl(4)", h.call(dAdv, "InitializeAcl", acl, 4, aclRevision), errInsufficientBuf)
	secExpectFail(t, h, "InitializeAcl(rev 1)", h.call(dAdv, "InitializeAcl", acl, 64, 1), errInvalidParameter)
	secExpectFail(t, h, "InitializeAcl(64K)", h.call(dAdv, "InitializeAcl", acl, 0x10000, aclRevision), errInvalidParameter)
	if h.call(dAdv, "InitializeAcl", acl, 82, aclRevision) != 1 || h.call(dAdv, "IsValidAcl", acl) != 1 || h.r16(acl+2) != 80 {
		t.Fatalf("InitializeAcl(82): valid %d size %d", h.call(dAdv, "IsValidAcl", acl), h.r16(acl+2))
	}
	info := h.alloc(12)
	sizeInfo := func() (uint32, uint32, uint32) {
		t.Helper()
		if h.call(dAdv, "GetAclInformation", acl, info, 12, 2) != 1 {
			t.Fatalf("GetAclInformation failed, lastError %d", h.lastError())
		}
		return h.r32(info), h.r32(info + 4), h.r32(info + 8)
	}
	if c, u, f := sizeInfo(); c != 0 || u != 8 || f != 72 {
		t.Fatalf("empty ACL size info %d/%d/%d", c, u, f)
	}
	if h.call(dAdv, "AddAccessAllowedAce", acl, aclRevision, 0x10000000, user) != 1 {
		t.Fatalf("AddAccessAllowedAce failed, lastError %d", h.lastError())
	}
	if h.call(dAdv, "AddAccessDeniedAceEx", acl, aclRevisionDS, 3, 0x40000000, user) != 1 {
		t.Fatalf("AddAccessDeniedAceEx failed, lastError %d", h.lastError())
	}
	if c, u, f := sizeInfo(); c != 2 || u != 80 || f != 0 {
		t.Fatalf("size info after 2 ACEs %d/%d/%d", c, u, f)
	}
	if h.read(acl, 1)[0] != aclRevisionDS {
		t.Fatalf("ACL revision %d, want upgrade to 4", h.read(acl, 1)[0])
	}
	secExpectFail(t, h, "AddAccessAllowedAce(full)", h.call(dAdv, "AddAccessAllowedAce", acl, aclRevision, 1, user), errAllottedSpace)
	secExpectFail(t, h, "AddAccessAllowedAce(bad sid)", h.call(dAdv, "AddAccessAllowedAce", acl, aclRevision, 1, 0), errInvalidSid)

	pace := h.alloc(8)
	if h.call(dAdv, "GetAce", acl, 1, pace) != 1 || h.r64(pace) != acl+8+36 {
		t.Fatalf("GetAce(1) -> %#x", h.r64(pace))
	}
	ace := h.r64(pace)
	if b := h.read(ace, 4); b[0] != aceDeniedType || b[1] != 3 || h.r16(ace+2) != 36 || h.r32(ace+4) != 0x40000000 || secSidStr(h, ace+8) != "S-1-5-21-1-2-3-1000" {
		t.Fatalf("denied ACE = %v mask %#x", b, h.r32(ace+4))
	}
	secExpectFail(t, h, "GetAce(2)", h.call(dAdv, "GetAce", acl, 2, pace), errInvalidParameter)

	// AddAce: copy the denied ACE to the front of a second ACL.
	acl2 := h.alloc(128)
	h.call(dAdv, "InitializeAcl", acl2, 128, aclRevision)
	h.call(dAdv, "AddAccessAllowedAce", acl2, aclRevision, 1, user)
	if h.call(dAdv, "AddAce", acl2, aclRevision, 0, ace, 36) != 1 {
		t.Fatalf("AddAce failed, lastError %d", h.lastError())
	}
	h.call(dAdv, "GetAce", acl2, 0, pace)
	if h.read(h.r64(pace), 1)[0] != aceDeniedType || h.r16(acl2+4) != 2 {
		t.Fatal("AddAce(index 0) did not insert at the front")
	}
	secExpectFail(t, h, "AddAce(truncated list)", h.call(dAdv, "AddAce", acl2, aclRevision, 0, ace, 30), errInvalidParameter)

	revInfo := h.alloc(4)
	if h.call(dAdv, "GetAclInformation", acl, revInfo, 4, 1) != 1 || h.r32(revInfo) != aclRevisionDS {
		t.Fatalf("AclRevisionInformation = %d", h.r32(revInfo))
	}
	secExpectFail(t, h, "GetAclInformation(small)", h.call(dAdv, "GetAclInformation", acl, info, 11, 2), errInsufficientBuf)
	secExpectFail(t, h, "GetAclInformation(class 3)", h.call(dAdv, "GetAclInformation", acl, info, 12, 3), errInvalidParameter)

	h.w16(acl+4, 3) // claims a third ACE that does not fit
	if h.call(dAdv, "IsValidAcl", acl) != 0 {
		t.Fatal("IsValidAcl accepted a corrupt ACE count")
	}
	secExpectFail(t, h, "GetAce(corrupt)", h.call(dAdv, "GetAce", acl, 0, pace), errInvalidAcl)
}

func TestSecurityDescriptor(t *testing.T) {
	h := newTestEmu(t)
	sd := h.alloc(sdSize)
	secExpectFail(t, h, "InitializeSecurityDescriptor(rev 2)", h.call(dAdv, "InitializeSecurityDescriptor", sd, 2), errUnknownRev)
	if h.call(dAdv, "InitializeSecurityDescriptor", sd, 1) != 1 || h.call(dAdv, "IsValidSecurityDescriptor", sd) != 1 {
		t.Fatal("InitializeSecurityDescriptor")
	}
	acl := h.alloc(64)
	h.call(dAdv, "InitializeAcl", acl, 64, aclRevision)
	if h.call(dAdv, "SetSecurityDescriptorDacl", sd, 1, acl, 0) != 1 {
		t.Fatalf("SetSecurityDescriptorDacl failed, lastError %d", h.lastError())
	}
	present, pacl, defaulted := h.alloc(4), h.alloc(8), h.alloc(4)
	if h.call(dAdv, "GetSecurityDescriptorDacl", sd, present, pacl, defaulted) != 1 || h.r32(present) != 1 || h.r64(pacl) != acl || h.r32(defaulted) != 0 {
		t.Fatalf("GetSecurityDescriptorDacl present %d acl %#x", h.r32(present), h.r64(pacl))
	}
	if h.r16(sd+2) != sdDaclPresent {
		t.Fatalf("control = %#x", h.r16(sd+2))
	}
	owner := secSid(t, h, "S-1-5-18")
	if h.call(dAdv, "SetSecurityDescriptorOwner", sd, owner, 1) != 1 || h.r64(sd+8) != owner || h.r16(sd+2) != sdDaclPresent|sdOwnerDefaulted {
		t.Fatalf("SetSecurityDescriptorOwner control %#x", h.r16(sd+2))
	}
	if h.call(dAdv, "SetSecurityDescriptorDacl", sd, 0, 0, 0) != 1 || h.r16(sd+2)&sdDaclPresent != 0 {
		t.Fatal("SetSecurityDescriptorDacl(not present)")
	}
	h.call(dAdv, "GetSecurityDescriptorDacl", sd, present, pacl, defaulted)
	if h.r32(present) != 0 {
		t.Fatal("DACL still present")
	}
	h.w16(sd+2, sdSelfRelative)
	secExpectFail(t, h, "SetSecurityDescriptorDacl(self-relative)", h.call(dAdv, "SetSecurityDescriptorDacl", sd, 1, acl, 0), errInvalidSecDesc)
	h.write(sd, []byte{2})
	secExpectFail(t, h, "IsValidSecurityDescriptor(rev 2)", h.call(dAdv, "IsValidSecurityDescriptor", sd), errUnknownRev)
}
