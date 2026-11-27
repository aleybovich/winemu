package win

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	siOwner = 1
	siGroup = 2
	siDacl  = 4
	siSacl  = 8

	seFileObject   = 1
	seService      = 2
	seRegistryKey  = 4
	seKernelObject = 6
)

// secAces returns (type, flags, mask, SID string) of every ACE of the ACL at p.
func secAces(t *testing.T, h *testEmu, p uint64) [][4]any {
	t.Helper()
	_, _, offs, ok := h.E.aclWalk(p)
	if !ok {
		t.Fatalf("invalid ACL at %#x", p)
	}
	var r [][4]any
	for _, o := range offs {
		a := p + uint64(o)
		s, _ := h.E.readSid(a + 8)
		r = append(r, [4]any{h.E.Mem.R8(a), h.E.Mem.R8(a + 1), h.E.Mem.R32(a + 4), s.String()})
	}
	return r
}

func TestGetSecurityInfo(t *testing.T) {
	h := newTestEmu(t)
	user := sidUserAccount.String()
	owner, group, dacl, sacl, sd := h.alloc(8), h.alloc(8), h.alloc(8), h.alloc(8), h.alloc(8)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	if r := h.call(dAdv, "GetSecurityInfo", ev, seKernelObject, siOwner|siGroup|siDacl, owner, group, dacl, 0, sd); r != 0 {
		t.Fatalf("GetSecurityInfo = %d", r)
	}
	p := h.r64(sd)
	if h.r16(p+2)&sdSelfRelative == 0 || h.r16(p+2)&sdDaclPresent == 0 {
		t.Fatalf("control %#x", h.r16(p+2))
	}
	if s := secSidStr(h, h.r64(owner)); s != user {
		t.Fatalf("owner %s", s)
	}
	if s := secSidStr(h, h.r64(group)); s != sidNoneGroup.String() {
		t.Fatalf("group %s", s)
	}
	if aces := secAces(t, h, h.r64(dacl)); len(aces) != 3 || aces[0][3] != user || aces[0][2] != uint32(0x10000000) {
		t.Fatalf("kernel DACL %v", aces)
	}
	if h.r64(owner) < p || h.r64(dacl) < p {
		t.Fatal("out pointers must point into the descriptor")
	}
	// the self-relative descriptor works with the SD readers
	if h.call(dAdv, "IsValidSecurityDescriptor", p) != 1 {
		t.Fatalf("IsValidSecurityDescriptor: %d", h.lastError())
	}
	present, pd, def := h.alloc(4), h.alloc(8), h.alloc(4)
	if h.call(dAdv, "GetSecurityDescriptorDacl", p, present, pd, def) != 1 || h.r32(present) != 1 || h.r64(pd) != h.r64(dacl) {
		t.Fatalf("GetSecurityDescriptorDacl present %d dacl %#x", h.r32(present), h.r64(pd))
	}
	secExpectFail(t, h, "SetSecurityDescriptorDacl(self-relative)", h.call(dAdv, "SetSecurityDescriptorDacl", p, 1, 0, 0), errInvalidSecDesc)
	if h.call(dK32, "LocalFree", p) != 0 {
		t.Fatal("LocalFree(sd) failed")
	}

	// owner only: the other out pointers receive NULL
	h.w64(dacl, 0x55)
	if r := h.call(dAdv, "GetSecurityInfo", pseudoProcess, seKernelObject, siOwner, owner, 0, dacl, 0, sd); r != 0 || h.r64(dacl) != 0 {
		t.Fatalf("owner only = %d dacl %#x", r, h.r64(dacl))
	}
	// files: the user has full control
	f := h.call(dK32, "CreateFileW", h.wstr(`C:\sec.txt`), 0xC0000000, 0, 0, 2, 0x80, 0)
	if r := h.call(dAdv, "GetSecurityInfo", f, seFileObject, siDacl, 0, 0, dacl, 0, sd); r != 0 {
		t.Fatalf("GetSecurityInfo(file) = %d", r)
	}
	if aces := secAces(t, h, h.r64(dacl)); len(aces) == 0 || aces[0][3] != user || aces[0][2] != uint32(0x1F01FF) {
		t.Fatalf("file DACL %v", aces)
	}
	if r := h.call(dAdv, "GetSecurityInfo", 0x4321, seKernelObject, siDacl, 0, 0, dacl, 0, sd); r != errInvalidHandle {
		t.Fatalf("bad handle = %d", r)
	}
	if r := h.call(dAdv, "GetSecurityInfo", ev, seKernelObject, siSacl, 0, 0, 0, sacl, sd); r != errPrivNotHeld {
		t.Fatalf("SACL = %d", r)
	}
	if r := h.call(dAdv, "GetSecurityInfo", ev, seKernelObject, siDacl, 0, 0, dacl, 0, 0); r != errInvalidParameter {
		t.Fatalf("NULL ppSecurityDescriptor = %d", r)
	}
}

func TestGetNamedSecurityInfo(t *testing.T) {
	h := newTestEmu(t)
	host := h.E.fs.toHost(`C:\named.txt`)
	if err := os.WriteFile(host, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	owner, dacl, sd := h.alloc(8), h.alloc(8), h.alloc(8)
	if r := h.call(dAdv, "GetNamedSecurityInfoW", h.wstr(`C:\named.txt`), seFileObject, siOwner|siDacl, owner, 0, dacl, 0, sd); r != 0 {
		t.Fatalf("GetNamedSecurityInfoW = %d", r)
	}
	if secSidStr(h, h.r64(owner)) != sidUserAccount.String() || len(secAces(t, h, h.r64(dacl))) == 0 {
		t.Fatal("bad owner/DACL")
	}
	if r := h.call(dAdv, "GetNamedSecurityInfoA", h.astr(filepath.Dir(`C:\named.txt`)), seFileObject, siDacl, 0, 0, dacl, 0, sd); r != 0 {
		t.Fatalf("GetNamedSecurityInfoA(dir) = %d", r)
	}
	if r := h.call(dAdv, "GetNamedSecurityInfoW", h.wstr(`C:\nope.txt`), seFileObject, siDacl, 0, 0, dacl, 0, sd); r != errFileNotFound {
		t.Fatalf("missing file = %d", r)
	}
	if r := h.call(dAdv, "GetNamedSecurityInfoW", h.wstr(`C:\nodir\x.txt`), seFileObject, siDacl, 0, 0, dacl, 0, sd); r != errPathNotFound {
		t.Fatalf("missing dir = %d", r)
	}
	if r := h.call(dAdv, "GetNamedSecurityInfoW", h.wstr(`MACHINE\SOFTWARE\x`), seRegistryKey, siDacl, 0, 0, dacl, 0, sd); r != errFileNotFound {
		t.Fatalf("registry = %d", r)
	}
	if r := h.call(dAdv, "GetNamedSecurityInfoW", h.wstr(`NoSuchService`), seService, siDacl, 0, 0, dacl, 0, sd); r != errServiceNotExist {
		t.Fatalf("service = %d", r)
	}
	if r := h.call(dAdv, "GetNamedSecurityInfoW", 0, seFileObject, siDacl, 0, 0, dacl, 0, sd); r != errInvalidParameter {
		t.Fatalf("NULL name = %d", r)
	}
}

func TestSetSecurityInfo(t *testing.T) {
	h := newTestEmu(t)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	user, admins := h.E.allocSid(sidUserAccount), h.E.allocSid(sidAdmins)
	acl := h.alloc(64)
	h.call(dAdv, "InitializeAcl", acl, 64, aclRevision)
	h.call(dAdv, "AddAccessAllowedAce", acl, aclRevision, 0x1F0003, user)
	if r := h.call(dAdv, "SetSecurityInfo", ev, seKernelObject, siDacl|siOwner|siGroup, user, admins, acl, 0); r != 0 {
		t.Fatalf("SetSecurityInfo = %d", r)
	}
	if r := h.call(dAdv, "SetSecurityInfo", ev, seKernelObject, siDacl, 0, 0, 0, 0); r != 0 {
		t.Fatalf("SetSecurityInfo(NULL DACL) = %d", r)
	}
	if r := h.call(dAdv, "SetSecurityInfo", ev, seKernelObject, siOwner, admins, 0, 0, 0); r != errInvalidOwner {
		t.Fatalf("foreign owner = %d", r)
	}
	bad := h.alloc(16)
	h.write(bad, []byte{9})
	if r := h.call(dAdv, "SetSecurityInfo", ev, seKernelObject, siDacl, 0, 0, bad, 0); r != errInvalidAcl {
		t.Fatalf("bad DACL = %d", r)
	}
	if r := h.call(dAdv, "SetSecurityInfo", ev, seKernelObject, siOwner, bad, 0, 0, 0); r != errInvalidSid {
		t.Fatalf("bad owner SID = %d", r)
	}
	if r := h.call(dAdv, "SetSecurityInfo", ev, seKernelObject, siSacl, 0, 0, 0, acl); r != errPrivNotHeld {
		t.Fatalf("SACL = %d", r)
	}
	if r := h.call(dAdv, "SetSecurityInfo", 0x4321, seKernelObject, siDacl, 0, 0, acl, 0); r != errInvalidHandle {
		t.Fatalf("bad handle = %d", r)
	}
	if err := os.WriteFile(h.E.fs.toHost(`C:\set.txt`), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"SetNamedSecurityInfoA", "SetNamedSecurityInfoW"} {
		name := h.astr(`C:\set.txt`)
		missing := h.astr(`C:\missing.txt`)
		if fn[len(fn)-1] == 'W' {
			name, missing = h.wstr(`C:\set.txt`), h.wstr(`C:\missing.txt`)
		}
		if r := h.call(dAdv, fn, name, seFileObject, siDacl, 0, 0, acl, 0); r != 0 {
			t.Fatalf("%s = %d", fn, r)
		}
		if r := h.call(dAdv, fn, missing, seFileObject, siDacl, 0, 0, acl, 0); r != errFileNotFound {
			t.Fatalf("%s(missing) = %d", fn, r)
		}
	}
}

// secExplicit writes EXPLICIT_ACCESS entries {perms, mode, inherit, trustee form, trustee ptr}.
func secExplicit(h *testEmu, entries ...[5]uint64) uint64 {
	p := h.alloc(48 * len(entries))
	for i, en := range entries {
		a := p + uint64(48*i)
		h.w32(a, uint32(en[0]))
		h.w32(a+4, uint32(en[1]))
		h.w32(a+8, uint32(en[2]))
		h.w32(a+16+12, uint32(en[3])) // TrusteeForm
		h.w64(a+16+24, en[4])         // ptstrName
	}
	return p
}

func TestSetEntriesInAcl(t *testing.T) {
	h := newTestEmu(t)
	user, users := sidUserAccount.String(), sidBuiltinUsers.String()
	usersSid := h.E.allocSid(sidBuiltinUsers)
	out := h.alloc(8)
	// GRANT by SID + DENY by name + GRANT to CURRENT_USER with inheritance
	list := secExplicit(h,
		[5]uint64{0x120089, 1, 0, 0, usersSid},
		[5]uint64{0x40000, 3, 0, 1, h.wstr("Everyone")},
		[5]uint64{0x1F01FF, 1, 3, 1, h.wstr("CURRENT_USER")})
	if r := h.call(dAdv, "SetEntriesInAclW", 3, list, 0, out); r != 0 {
		t.Fatalf("SetEntriesInAclW = %d", r)
	}
	acl := h.r64(out)
	aces := secAces(t, h, acl)
	want := [][4]any{{uint8(1), uint8(0), uint32(0x40000), "S-1-1-0"}, {uint8(0), uint8(0), uint32(0x120089), users}, {uint8(0), uint8(3), uint32(0x1F01FF), user}}
	if len(aces) != 3 || aces[0] != want[0] || aces[1] != want[1] || aces[2] != want[2] {
		t.Fatalf("ACEs %v, want %v", aces, want)
	}
	// on top of the old ACL: GRANT merges, SET replaces, REVOKE removes
	list2 := secExplicit(h,
		[5]uint64{0x2, 1, 0, 0, usersSid},
		[5]uint64{0x1, 2, 3, 1, h.wstr("CURRENT_USER")},
		[5]uint64{0, 4, 0, 1, h.wstr("Everyone")})
	out2 := h.alloc(8)
	if r := h.call(dAdv, "SetEntriesInAclW", 3, list2, acl, out2); r != 0 {
		t.Fatalf("SetEntriesInAclW(old) = %d", r)
	}
	aces = secAces(t, h, h.r64(out2))
	// REVOKE removes only allowed ACEs: the deny for Everyone stays
	want = [][4]any{{uint8(1), uint8(0), uint32(0x40000), "S-1-1-0"}, {uint8(0), uint8(3), uint32(0x1), user}, {uint8(0), uint8(0), uint32(0x12008B), users}}
	if len(aces) != 3 || aces[0] != want[0] || aces[1] != want[1] || aces[2] != want[2] {
		t.Fatalf("merged ACEs %v, want %v", aces, want)
	}
	if h.call(dK32, "LocalFree", h.r64(out2)) != 0 {
		t.Fatal("LocalFree failed")
	}
	// ANSI names
	if r := h.call(dAdv, "SetEntriesInAclA", 1, secExplicit(h, [5]uint64{1, 1, 0, 1, h.astr(`BUILTIN\Users`)}), 0, out); r != 0 || secAces(t, h, h.r64(out))[0][3] != users {
		t.Fatalf("SetEntriesInAclA = %d", r)
	}
	h.w64(out, 0x77)
	if r := h.call(dAdv, "SetEntriesInAclW", 0, 0, 0, out); r != 0 || h.r64(out) != 0 {
		t.Fatalf("empty = %d %#x", r, h.r64(out))
	}
	if r := h.call(dAdv, "SetEntriesInAclW", 1, secExplicit(h, [5]uint64{1, 1, 0, 1, h.wstr("nobody")}), 0, out); r != errNoneMapped {
		t.Fatalf("unknown name = %d", r)
	}
	if r := h.call(dAdv, "SetEntriesInAclW", 1, secExplicit(h, [5]uint64{1, 9, 0, 0, usersSid}), 0, out); r != errInvalidParameter {
		t.Fatalf("bad mode = %d", r)
	}
	bad := h.alloc(16)
	h.write(bad, []byte{9})
	if r := h.call(dAdv, "SetEntriesInAclW", 1, list, bad, out); r != errInvalidAcl {
		t.Fatalf("bad old ACL = %d", r)
	}
	if r := h.call(dAdv, "SetEntriesInAclW", 1, list, 0, 0); r != errInvalidParameter {
		t.Fatalf("NULL out = %d", r)
	}
}

func TestGetEffectiveRightsFromAcl(t *testing.T) {
	h := newTestEmu(t)
	out := h.alloc(8)
	list := secExplicit(h,
		[5]uint64{0x4, 3, 0, 1, h.wstr("CURRENT_USER")}, // deny
		[5]uint64{0x7, 1, 0, 1, h.wstr("Users")},
		[5]uint64{0x100, 1, 0, 1, h.wstr("Administrators")},
		[5]uint64{0x800, 1, 0xB, 1, h.wstr("Everyone")}) // inherit-only: ignored
	if r := h.call(dAdv, "SetEntriesInAclW", 4, list, 0, out); r != 0 {
		t.Fatalf("SetEntriesInAclW = %d", r)
	}
	acl, rights := h.r64(out), h.alloc(4)
	tr := h.alloc(32)
	h.w32(tr+12, 1)
	h.w64(tr+24, h.wstr("CURRENT_USER"))
	if r := h.call(dAdv, "GetEffectiveRightsFromAclW", acl, tr, rights); r != 0 || h.r32(rights) != 0x3 {
		t.Fatalf("user rights = %d %#x, want 0x3 (Users grant minus deny; not an admin)", r, h.r32(rights))
	}
	ta := h.alloc(32) // ANSI trustee by SID
	h.w64(ta+24, h.E.allocSid(sidAdmins))
	if r := h.call(dAdv, "GetEffectiveRightsFromAclA", acl, ta, rights); r != 0 || h.r32(rights) != 0x100 {
		t.Fatalf("admins rights = %d %#x", r, h.r32(rights))
	}
	if r := h.call(dAdv, "GetEffectiveRightsFromAclW", acl, tr, 0); r != errInvalidParameter {
		t.Fatalf("NULL out = %d", r)
	}
	bad := h.alloc(16)
	h.write(bad, []byte{9})
	if r := h.call(dAdv, "GetEffectiveRightsFromAclW", bad, tr, rights); r != errInvalidAcl {
		t.Fatalf("bad ACL = %d", r)
	}
}

// SET_ACCESS discards every existing explicit ACE of the trustee, deny ACEs
// included (ACCESS_MODE); other trustees' ACEs are kept.
func TestSetEntriesInAclSetDiscardsDeny(t *testing.T) {
	h := newTestEmu(t)
	out := h.alloc(8)
	usersSid := h.E.allocSid(sidBuiltinUsers)
	old := secExplicit(h, [5]uint64{0x40000, 3, 0, 1, h.wstr("Everyone")}, [5]uint64{0x1, 1, 0, 0, usersSid})
	if r := h.call(dAdv, "SetEntriesInAclW", 2, old, 0, out); r != 0 {
		t.Fatalf("SetEntriesInAclW = %d", r)
	}
	out2 := h.alloc(8)
	if r := h.call(dAdv, "SetEntriesInAclW", 1, secExplicit(h, [5]uint64{0x2, 2, 0, 1, h.wstr("Everyone")}), h.r64(out), out2); r != 0 {
		t.Fatalf("SetEntriesInAclW(SET) = %d", r)
	}
	aces := secAces(t, h, h.r64(out2))
	want := [][4]any{{uint8(0), uint8(0), uint32(0x2), "S-1-1-0"}, {uint8(0), uint8(0), uint32(0x1), sidBuiltinUsers.String()}}
	if len(aces) != 2 || aces[0] != want[0] || aces[1] != want[1] {
		t.Fatalf("ACEs %v, want %v", aces, want)
	}
}
