package win

// Object security: GetSecurityInfo / SetSecurityInfo and the named variants.
//
// Every object is owned by the token owner (the current user) with the
// token's primary group as group. Files and directories carry a DACL
// granting the user, SYSTEM and Administrators full control; other objects
// carry the token's default DACL. Descriptors are returned self-relative in
// one LocalFree-able block, the out pointers pointing into it. SACLs need
// SeSecurityPrivilege, which the user's token does not hold. Set* calls
// validate their input (handle/name, owner assignability, SID and ACL
// structure) like Windows does, but object security is not stored: a later
// Get* reports the defaults again.

import (
	"encoding/binary"
	"os"
	"strings"
)

const (
	ownerSecInfo = 0x1
	groupSecInfo = 0x2
	daclSecInfo  = 0x4
	saclSecInfo  = 0x8

	seFileObj     = 1
	seServiceObj  = 2
	seRegistryObj = 4

	fileAllAccess  = 0x1F01FF
	privSecurity   = 8 // SeSecurityPrivilege
	sdRelativeSize = 20
)

// sdReadable checks the descriptor at p for the read-only SD APIs, which
// accept both absolute and self-relative descriptors.
func (e *Emu) sdReadable(p uint64) bool {
	if p == 0 || !e.Mem.Valid(p) {
		e.SetLastError(errInvalidSecDesc)
		return false
	}
	if e.Mem.R8(p) != sdRevision {
		e.SetLastError(errUnknownRev)
		return false
	}
	return true
}

// sdPart returns the address of the owner (0), group (1), SACL (2) or DACL
// (3) of the absolute or self-relative descriptor at p, 0 if absent.
func (e *Emu) sdPart(p uint64, i int) uint64 {
	if e.Mem.R16(p+2)&sdSelfRelative == 0 {
		return e.Mem.R64(p + 8 + 8*uint64(i))
	}
	if off := e.Mem.R32(p + 4 + 4*uint64(i)); off != 0 {
		return p + uint64(off)
	}
	return 0
}

func (t *tokenObj) privEnabled(luid uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.privs {
		if p.luid == luid && p.attr&sePrivEnabled != 0 {
			return true
		}
	}
	return false
}

// objectSecurity returns the default security of an object of type typ and
// writes it to the out pointers (GetSecurityInfo argument order).
func (e *Emu) objectSecurity(typ, info uint32, pOwner, pGroup, pDacl, pSacl, pSD uint64) uint64 {
	if pSD == 0 && (pOwner|pGroup|pDacl|pSacl) != 0 {
		return errInvalidParameter
	}
	t := e.token(pseudoEffectiveToken)
	if t == nil {
		return errNoToken
	}
	if info&saclSecInfo != 0 && !t.privEnabled(privSecurity) {
		return errPrivNotHeld
	}
	t.mu.Lock()
	owner, group, dacl := t.owner, t.primary, append([]byte(nil), t.dacl...)
	t.mu.Unlock()
	if typ == seFileObj {
		dacl = buildAcl(aceSpec{aceAllowedType, 0, fileAllAccess, sidUserAccount},
			aceSpec{aceAllowedType, 0, fileAllAccess, sidSystem},
			aceSpec{aceAllowedType, 0, fileAllAccess, sidAdmins})
	}
	if pSD == 0 {
		return 0
	}
	b := make([]byte, sdRelativeSize)
	b[0] = sdRevision
	ctl := uint16(sdSelfRelative)
	var offs [4]uint32 // owner, group, sacl, dacl
	part := func(i int, data []byte) {
		offs[i] = uint32(len(b))
		binary.LittleEndian.PutUint32(b[4+4*i:], offs[i])
		b = append(b, data...)
	}
	if info&ownerSecInfo != 0 {
		part(0, owner.bytes())
	}
	if info&groupSecInfo != 0 {
		part(1, group.bytes())
	}
	if info&saclSecInfo != 0 {
		ctl |= 0x10 // SE_SACL_PRESENT: an empty SACL
		part(2, buildAcl())
	}
	if info&daclSecInfo != 0 {
		ctl |= sdDaclPresent
		if len(dacl) != 0 {
			part(3, dacl)
		}
	}
	binary.LittleEndian.PutUint16(b[2:], ctl)
	sd := e.heapAllocRaw(uint64(len(b)))
	e.Mem.Write(sd, b)
	e.Mem.W64(pSD, sd)
	for i, p := range []uint64{pOwner, pGroup, pSacl, pDacl} {
		if p != 0 {
			v := uint64(0)
			if offs[i] != 0 {
				v = sd + uint64(offs[i])
			}
			e.Mem.W64(p, v)
		}
	}
	return 0
}

// setObjectSecurity validates a SetSecurityInfo request.
func (e *Emu) setObjectSecurity(info uint32, owner, group, dacl uint64) uint64 {
	t := e.token(pseudoEffectiveToken)
	if t == nil {
		return errNoToken
	}
	if info&saclSecInfo != 0 && !t.privEnabled(privSecurity) {
		return errPrivNotHeld
	}
	if info&ownerSecInfo != 0 {
		s, ok := e.readSid(owner)
		if !ok {
			return errInvalidSid
		}
		t.mu.Lock()
		allowed := t.user.s.equal(s) || t.hasSid(s, seGroupOwner)
		t.mu.Unlock()
		if !allowed {
			return errInvalidOwner
		}
	}
	if info&groupSecInfo != 0 {
		if _, ok := e.readSid(group); !ok {
			return errInvalidSid
		}
	}
	if info&daclSecInfo != 0 {
		if _, ok := e.readAcl(dacl); !ok { // NULL is a valid (NULL) DACL
			return errInvalidAcl
		}
	}
	return 0
}

// namedObject checks that the named object exists.
func (e *Emu) namedObject(name string, typ uint32) uint64 {
	switch typ {
	case seFileObj:
		h := e.fs.toHost(name)
		if _, err := os.Stat(h); err != nil {
			return uint64(winErrPath(err, h))
		}
		return 0
	case seRegistryObj:
		return errFileNotFound // the registry is empty
	case seServiceObj:
		return errServiceNotExist
	}
	return errInvalidParameter
}

func (e *Emu) validObjectHandle(h uint64) bool {
	return h == pseudoProcess || h == pseudoThread || e.handles.get(h) != nil
}

// ---------------------------------------------------------------------------
// SetEntriesInAcl / GetEffectiveRightsFromAcl
//
//	TRUSTEE (x64, 32 bytes) { PTRUSTEE pMultipleTrustee @0; MultipleTrusteeOperation @8;
//	    TrusteeForm @12; TrusteeType @16; LPTSTR ptstrName (or PSID) @24 }
//	EXPLICIT_ACCESS (48 bytes) { grfAccessPermissions @0; grfAccessMode @4; grfInheritance @8; TRUSTEE @16 }

const (
	trusteeIsSid  = 0
	trusteeIsName = 1

	modeNotUsed = 0
	modeGrant   = 1
	modeSet     = 2
	modeDeny    = 3
	modeRevoke  = 4
	modeAuditOK = 5
	modeAuditNo = 6

	aceInheritOnly = 0x08
	aceInherited   = 0x10
)

// trustee resolves the TRUSTEE at p to a SID; code is a Win32 error.
func (e *Emu) trustee(p uint64, wide bool) (s sid, code uint64) {
	switch e.Mem.R32(p + 12) {
	case trusteeIsSid:
		if s, ok := e.readSid(e.Mem.R64(p + 24)); ok {
			return s, 0
		}
		return sid{}, errInvalidSid
	case trusteeIsName:
		np := e.Mem.R64(p + 24)
		if np == 0 {
			return sid{}, errInvalidParameter
		}
		name := e.Mem.CStr(np)
		if wide {
			name = e.Mem.WStr(np)
		}
		if strings.EqualFold(name, "CURRENT_USER") {
			return sidUserAccount, 0
		}
		if a, ok := e.accountByName(name); ok {
			return a.s, 0
		}
		return sid{}, errNoneMapped
	}
	return sid{}, errInvalidParameter // objects-and-SID/name forms are not supported
}

// aclEntry is one ACE of an ACL being rebuilt; raw holds ACEs other than
// access-allowed/denied, which are copied unchanged.
type aclEntry struct {
	aceSpec
	raw []byte
}

func (e *Emu) aclEntries(p uint64) ([]aclEntry, bool) {
	if p == 0 {
		return nil, true
	}
	_, _, offs, ok := e.aclWalk(p)
	if !ok {
		return nil, false
	}
	var list []aclEntry
	for _, o := range offs {
		a := p + uint64(o)
		typ := e.Mem.R8(a)
		if s, ok := e.readSid(a + 8); ok && (typ == aceAllowedType || typ == aceDeniedType) {
			list = append(list, aclEntry{aceSpec: aceSpec{typ, e.Mem.R8(a + 1), e.Mem.R32(a + 4), s}})
		} else {
			list = append(list, aclEntry{raw: e.Mem.ReadBytes(a, int(e.Mem.R16(a+2)))})
		}
	}
	return list, true
}

// setEntriesInAcl merges count EXPLICIT_ACCESS entries at list into the ACL
// old: GRANT/DENY add rights (merged into an explicit ACE of the same
// trustee, type and flags), SET replaces the trustee's explicit ACEs, REVOKE
// removes its explicit allow ACEs. The result is in canonical order: explicit
// deny, explicit allow (new entries before old ones), then inherited ACEs.
func (e *Emu) setEntriesInAcl(count uint32, list, old, out uint64, wide bool) uint64 {
	if out == 0 || (count != 0 && list == 0) {
		return errInvalidParameter
	}
	prev, ok := e.aclEntries(old)
	if !ok {
		return errInvalidAcl
	}
	if count == 0 && old == 0 {
		e.Mem.W64(out, 0)
		return 0
	}
	var added []aclEntry
	drop := func(s sid, denyToo bool) { // removes the trustee's explicit allow (and deny) ACEs
		keep := func(l []aclEntry) []aclEntry {
			var r []aclEntry
			for _, x := range l {
				if x.raw == nil && x.flags&aceInherited == 0 && x.s.equal(s) && (x.typ == aceAllowedType || denyToo) {
					continue
				}
				r = append(r, x)
			}
			return r
		}
		prev, added = keep(prev), keep(added)
	}
	merge := func(n aclEntry) {
		for _, l := range [][]aclEntry{added, prev} {
			for i := range l {
				if x := &l[i]; x.raw == nil && x.flags&aceInherited == 0 && x.typ == n.typ && x.flags == n.flags && x.s.equal(n.s) {
					x.mask |= n.mask
					return
				}
			}
		}
		added = append(added, n)
	}
	for i := range count {
		p := list + 48*uint64(i)
		mode := e.Mem.R32(p + 4)
		if mode == modeNotUsed || mode == modeAuditOK || mode == modeAuditNo {
			continue // audit entries belong in a SACL
		}
		if mode > modeRevoke {
			return errInvalidParameter
		}
		s, code := e.trustee(p+16, wide)
		if code != 0 {
			return code
		}
		n := aclEntry{aceSpec: aceSpec{aceAllowedType, uint8(e.Mem.R32(p+8) & 0x0F), e.Mem.R32(p), s}}
		switch mode {
		case modeGrant:
			merge(n)
		case modeSet:
			drop(s, true)
			added = append(added, n)
		case modeDeny:
			n.typ = aceDeniedType
			merge(n)
		case modeRevoke:
			drop(s, false)
		}
	}
	var body []byte
	n := 0
	emit := func(l []aclEntry, want func(aclEntry) bool) {
		for _, x := range l {
			if want(x) {
				if x.raw != nil {
					body = append(body, x.raw...)
				} else {
					body = append(body, x.bytes()...)
				}
				n++
			}
		}
	}
	inherited := func(x aclEntry) bool {
		if x.raw != nil {
			return x.raw[1]&aceInherited != 0
		}
		return x.flags&aceInherited != 0
	}
	deny := func(x aclEntry) bool { return x.raw == nil && !inherited(x) && x.typ == aceDeniedType }
	other := func(x aclEntry) bool { return !inherited(x) && !deny(x) }
	emit(added, deny)
	emit(prev, deny)
	emit(added, other)
	emit(prev, other)
	emit(prev, inherited)
	rev := uint8(aclRevision)
	if old != 0 && e.Mem.R8(old) > rev {
		rev = e.Mem.R8(old)
	}
	b := make([]byte, aclHeaderSize, aclHeaderSize+len(body))
	b[0] = rev
	binary.LittleEndian.PutUint16(b[2:], uint16(aclHeaderSize+len(body)))
	binary.LittleEndian.PutUint16(b[4:], uint16(n))
	b = append(b, body...)
	a := e.heapAllocRaw(uint64(len(b)))
	e.Mem.Write(a, b)
	e.Mem.W64(out, a)
	return 0
}

// effectiveRights evaluates the ACL at p for the trustee s: ACEs apply in
// order, a right denied first stays denied. For the current user, ACEs
// match the user and every enabled group of the effective token; for other
// trustees, the SID itself and Everyone.
func (e *Emu) effectiveRights(p uint64, s sid) (uint32, bool) {
	l, ok := e.aclEntries(p)
	if !ok {
		return 0, false
	}
	match := func(x sid) bool { return x.equal(s) || x.equal(sidEveryone) }
	if s.equal(sidUserAccount) {
		if t := e.token(pseudoEffectiveToken); t != nil {
			t.mu.Lock()
			defer t.mu.Unlock()
			match = t.member
		}
	}
	var granted, denied uint32
	for _, x := range l {
		if x.raw != nil || x.flags&aceInheritOnly != 0 || !match(x.s) {
			continue
		}
		if x.typ == aceDeniedType {
			denied |= x.mask &^ granted
		} else {
			granted |= x.mask &^ denied
		}
	}
	return granted, true
}

func init() {
	a := dAdv
	// SetEntriesInAcl(cCount, pListOfExplicitEntries, OldAcl, *NewAcl)
	regAW(a, "SetEntriesInAcl", func(e *Emu, w bool) uint64 {
		return e.setEntriesInAcl(e.Arg32(0), e.Arg(1), e.Arg(2), e.Arg(3), w)
	})
	// GetEffectiveRightsFromAcl(pacl, pTrustee, pAccessRights)
	regAW(a, "GetEffectiveRightsFromAcl", func(e *Emu, w bool) uint64 {
		if e.Arg(0) == 0 || e.Arg(1) == 0 || e.Arg(2) == 0 {
			return errInvalidParameter
		}
		s, code := e.trustee(e.Arg(1), w)
		if code != 0 {
			return code
		}
		r, ok := e.effectiveRights(e.Arg(0), s)
		if !ok {
			return errInvalidAcl
		}
		e.Mem.W32(e.Arg(2), r)
		return 0
	})
}

func init() {
	a := dAdv
	// GetSecurityInfo(handle, type, info, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSD)
	reg(a, "GetSecurityInfo", func(e *Emu) uint64 {
		if !e.validObjectHandle(e.Arg(0)) {
			return errInvalidHandle
		}
		return e.objectSecurity(e.Arg32(1), e.Arg32(2), e.Arg(3), e.Arg(4), e.Arg(5), e.Arg(6), e.Arg(7))
	})
	regAW(a, "GetNamedSecurityInfo", func(e *Emu, w bool) uint64 {
		if e.Arg(0) == 0 {
			return errInvalidParameter
		}
		if r := e.namedObject(e.strArg(0, w), e.Arg32(1)); r != 0 {
			return r
		}
		return e.objectSecurity(e.Arg32(1), e.Arg32(2), e.Arg(3), e.Arg(4), e.Arg(5), e.Arg(6), e.Arg(7))
	})
	// SetSecurityInfo(handle, type, info, psidOwner, psidGroup, pDacl, pSacl)
	reg(a, "SetSecurityInfo", func(e *Emu) uint64 {
		if !e.validObjectHandle(e.Arg(0)) {
			return errInvalidHandle
		}
		return e.setObjectSecurity(e.Arg32(2), e.Arg(3), e.Arg(4), e.Arg(5))
	})
	regAW(a, "SetNamedSecurityInfo", func(e *Emu, w bool) uint64 {
		if e.Arg(0) == 0 {
			return errInvalidParameter
		}
		if r := e.namedObject(e.strArg(0, w), e.Arg32(1)); r != 0 {
			return r
		}
		return e.setObjectSecurity(e.Arg32(2), e.Arg(3), e.Arg(4), e.Arg(5))
	})
}
