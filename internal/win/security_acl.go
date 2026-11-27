package win

// Access control lists and (absolute) security descriptors, in guest memory.
//
//	ACL        { BYTE AclRevision; BYTE Sbz1; WORD AclSize; WORD AceCount; WORD Sbz2 }   // 8 bytes
//	ACE_HEADER { BYTE AceType; BYTE AceFlags; WORD AceSize }
//	ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE { ACE_HEADER; ACCESS_MASK Mask; SID (SidStart) }
//	SECURITY_DESCRIPTOR (absolute, x64) { BYTE Revision; BYTE Sbz1; WORD Control;
//	    PSID Owner @8; PSID Group @16; PACL Sacl @24; PACL Dacl @32 }  // 40 bytes

import "encoding/binary"

const (
	aclRevision    = 2
	aclRevisionDS  = 4
	aclHeaderSize  = 8
	aceAllowedType = 0
	aceDeniedType  = 1

	sdRevision       = 1
	sdSize           = 40
	sdOwnerDefaulted = 0x0001
	sdGroupDefaulted = 0x0002
	sdDaclPresent    = 0x0004
	sdDaclDefaulted  = 0x0008
	sdSelfRelative   = 0x8000
)

type aceSpec struct {
	typ, flags uint8
	mask       uint32
	s          sid
}

func (a aceSpec) bytes() []byte {
	sb := a.s.bytes()
	b := make([]byte, 8, 8+len(sb))
	b[0], b[1] = a.typ, a.flags
	binary.LittleEndian.PutUint16(b[2:], uint16(8+len(sb)))
	binary.LittleEndian.PutUint32(b[4:], a.mask)
	return append(b, sb...)
}

// buildAcl encodes a complete ACL (revision 2) holding aces.
func buildAcl(aces ...aceSpec) []byte {
	var body []byte
	for _, a := range aces {
		body = append(body, a.bytes()...)
	}
	b := make([]byte, aclHeaderSize, aclHeaderSize+len(body))
	b[0] = aclRevision
	binary.LittleEndian.PutUint16(b[2:], uint16(aclHeaderSize+len(body)))
	binary.LittleEndian.PutUint16(b[4:], uint16(len(aces)))
	return append(b, body...)
}

// aclWalk validates the ACL at p and returns its size, ACE count and the
// offsets of its ACEs; ok is false for an invalid ACL (IsValidAcl rules).
func (e *Emu) aclWalk(p uint64) (size, used int, offs []int, ok bool) {
	if p == 0 || !e.Mem.Valid(p) || !e.Mem.Valid(p+aclHeaderSize-1) {
		return 0, 0, nil, false
	}
	rev := e.Mem.R8(p)
	size = int(e.Mem.R16(p + 2))
	n := int(e.Mem.R16(p + 4))
	if rev < aclRevision || rev > aclRevisionDS || size < aclHeaderSize || size%4 != 0 || !e.Mem.Valid(p+uint64(size)-1) {
		return 0, 0, nil, false
	}
	off := aclHeaderSize
	for range n {
		if off+4 > size {
			return 0, 0, nil, false
		}
		as := int(e.Mem.R16(p + uint64(off) + 2))
		if as < 4 || as%4 != 0 || off+as > size {
			return 0, 0, nil, false
		}
		offs = append(offs, off)
		off += as
	}
	return size, off, offs, true
}

// readAcl returns the bytes in use of a valid guest ACL (nil, true for NULL).
func (e *Emu) readAcl(p uint64) ([]byte, bool) {
	if p == 0 {
		return nil, true
	}
	_, used, _, ok := e.aclWalk(p)
	if !ok {
		return nil, false
	}
	b := e.Mem.ReadBytes(p, used)
	binary.LittleEndian.PutUint16(b[2:], uint16(used))
	return b, true
}

// aclInsert inserts the ACE bytes list at ACE index idx (MAXDWORD or past
// the end appends) into the ACL at p.
func (e *Emu) aclInsert(p uint64, rev uint32, idx uint32, list []byte, count int) uint64 {
	size, used, offs, ok := e.aclWalk(p)
	if !ok {
		return e.fail(errInvalidAcl)
	}
	if rev < aclRevision || rev > aclRevisionDS {
		return e.fail(errInvalidParameter)
	}
	if used+len(list) > size {
		return e.fail(errAllottedSpace)
	}
	at := used
	if int(idx) < len(offs) {
		at = offs[idx]
	}
	e.Mem.Move(p+uint64(at+len(list)), p+uint64(at), uint64(used-at))
	e.Mem.Write(p+uint64(at), list)
	e.Mem.W16(p+4, uint16(len(offs)+count))
	if uint8(rev) > e.Mem.R8(p) {
		e.Mem.W8(p, uint8(rev))
	}
	return 1
}

func (e *Emu) addAce(p uint64, rev uint32, typ, flags uint8, mask uint32, sidPtr uint64) uint64 {
	s, ok := e.readSid(sidPtr)
	if !ok {
		return e.fail(errInvalidSid)
	}
	if flags&^0x1F != 0 { // only inheritance flags are valid here
		return e.fail(errInvalidParameter)
	}
	return e.aclInsert(p, rev, ^uint32(0), aceSpec{typ, flags, mask, s}.bytes(), 1)
}

// sdCheck reports whether p is an absolute revision-1 security
// descriptor; otherwise it sets the matching last error.
func (e *Emu) sdCheck(p uint64) bool {
	if p == 0 || !e.Mem.Valid(p) {
		e.SetLastError(errInvalidSecDesc)
		return false
	}
	if e.Mem.R8(p) != sdRevision {
		e.SetLastError(errUnknownRev)
		return false
	}
	if e.Mem.R16(p+2)&sdSelfRelative != 0 {
		e.SetLastError(errInvalidSecDesc)
		return false
	}
	return true
}

func init() {
	a := dAdv
	reg(a, "InitializeAcl", func(e *Emu) uint64 {
		p, n, rev := e.Arg(0), e.Arg32(1)&^3, e.Arg32(2)
		if rev < aclRevision || rev > aclRevisionDS || e.Arg32(1) > 0xFFFF || p == 0 {
			return e.fail(errInvalidParameter)
		}
		if n < aclHeaderSize {
			return e.fail(errInsufficientBuf)
		}
		e.Mem.Write(p, []byte{byte(rev), 0, byte(n), byte(n >> 8), 0, 0, 0, 0})
		return 1
	})
	reg(a, "IsValidAcl", func(e *Emu) uint64 {
		_, _, _, ok := e.aclWalk(e.Arg(0))
		return b2u(ok)
	})
	reg(a, "GetAce", func(e *Emu) uint64 {
		_, _, offs, ok := e.aclWalk(e.Arg(0))
		if !ok {
			return e.fail(errInvalidAcl)
		}
		if e.Arg32(1) >= uint32(len(offs)) || e.Arg(2) == 0 {
			return e.fail(errInvalidParameter)
		}
		e.Mem.W64(e.Arg(2), e.Arg(0)+uint64(offs[e.Arg32(1)]))
		return 1
	})
	reg(a, "AddAce", func(e *Emu) uint64 {
		list, n := e.Arg(3), int(e.Arg32(4))
		if list == 0 && n != 0 {
			return e.fail(errInvalidParameter)
		}
		b := e.Mem.ReadBytes(list, n)
		count := 0
		for off := 0; off < n; count++ { // the list must be a whole number of well-formed ACEs
			if off+4 > n {
				return e.fail(errInvalidParameter)
			}
			as := int(binary.LittleEndian.Uint16(b[off+2:]))
			if as < 4 || as%4 != 0 || off+as > n {
				return e.fail(errInvalidParameter)
			}
			off += as
		}
		return e.aclInsert(e.Arg(0), e.Arg32(1), e.Arg32(2), b, count)
	})
	reg(a, "AddAccessAllowedAce", func(e *Emu) uint64 {
		return e.addAce(e.Arg(0), e.Arg32(1), aceAllowedType, 0, e.Arg32(2), e.Arg(3))
	})
	reg(a, "AddAccessAllowedAceEx", func(e *Emu) uint64 {
		return e.addAce(e.Arg(0), e.Arg32(1), aceAllowedType, uint8(e.Arg32(2)), e.Arg32(3), e.Arg(4))
	})
	reg(a, "AddAccessDeniedAce", func(e *Emu) uint64 {
		return e.addAce(e.Arg(0), e.Arg32(1), aceDeniedType, 0, e.Arg32(2), e.Arg(3))
	})
	reg(a, "AddAccessDeniedAceEx", func(e *Emu) uint64 {
		return e.addAce(e.Arg(0), e.Arg32(1), aceDeniedType, uint8(e.Arg32(2)), e.Arg32(3), e.Arg(4))
	})
	reg(a, "GetAclInformation", func(e *Emu) uint64 {
		size, used, offs, ok := e.aclWalk(e.Arg(0))
		if !ok {
			return e.fail(errInvalidAcl)
		}
		out, n := e.Arg(1), e.Arg32(2)
		switch e.Arg32(3) {
		case 1: // AclRevisionInformation: ACL_REVISION_INFORMATION { DWORD AclRevision }
			if n < 4 || out == 0 {
				return e.fail(errInsufficientBuf)
			}
			e.Mem.W32(out, uint32(e.Mem.R8(e.Arg(0))))
		case 2: // AclSizeInformation: { DWORD AceCount, AclBytesInUse, AclBytesFree }
			if n < 12 || out == 0 {
				return e.fail(errInsufficientBuf)
			}
			e.Mem.W32(out, uint32(len(offs)))
			e.Mem.W32(out+4, uint32(used))
			e.Mem.W32(out+8, uint32(size-used))
		default:
			return e.fail(errInvalidParameter)
		}
		return 1
	})

	// ---- security descriptors (absolute form) ----
	reg(a, "InitializeSecurityDescriptor", func(e *Emu) uint64 {
		if e.Arg32(1) != sdRevision {
			return e.fail(errUnknownRev)
		}
		if e.Arg(0) == 0 {
			return e.fail(errInvalidParameter)
		}
		e.Mem.Fill(e.Arg(0), 0, sdSize)
		e.Mem.W8(e.Arg(0), sdRevision)
		return 1
	})
	reg(a, "IsValidSecurityDescriptor", func(e *Emu) uint64 {
		p := e.Arg(0)
		if !e.sdReadable(p) {
			return 0
		}
		if d := e.sdPart(p, 3); e.Mem.R16(p+2)&sdDaclPresent != 0 && d != 0 {
			if _, ok := e.readAcl(d); !ok {
				return e.fail(errInvalidSecDesc)
			}
		}
		for _, i := range []int{0, 1} {
			if o := e.sdPart(p, i); o != 0 {
				if _, ok := e.readSid(o); !ok {
					return e.fail(errInvalidSecDesc)
				}
			}
		}
		return 1
	})
	reg(a, "SetSecurityDescriptorDacl", func(e *Emu) uint64 {
		p := e.Arg(0)
		if !e.sdCheck(p) {
			return 0
		}
		ctl := e.Mem.R16(p+2) &^ (sdDaclPresent | sdDaclDefaulted)
		dacl := uint64(0)
		if e.Arg32(1) != 0 {
			ctl |= sdDaclPresent
			dacl = e.Arg(2)
			if e.Arg32(3) != 0 {
				ctl |= sdDaclDefaulted
			}
		}
		e.Mem.W16(p+2, ctl)
		e.Mem.W64(p+32, dacl)
		return 1
	})
	reg(a, "GetSecurityDescriptorDacl", func(e *Emu) uint64 {
		p := e.Arg(0)
		if !e.sdReadable(p) {
			return 0
		}
		if e.Arg(1) == 0 || e.Arg(2) == 0 || e.Arg(3) == 0 {
			return e.fail(errNoAccess)
		}
		ctl := e.Mem.R16(p + 2)
		e.Mem.W32(e.Arg(1), uint32(b2u(ctl&sdDaclPresent != 0)))
		if ctl&sdDaclPresent != 0 {
			e.Mem.W64(e.Arg(2), e.sdPart(p, 3))
			e.Mem.W32(e.Arg(3), uint32(b2u(ctl&sdDaclDefaulted != 0)))
		}
		return 1
	})
	setSid := func(off uint64, flag uint16) Fn {
		return func(e *Emu) uint64 {
			p := e.Arg(0)
			if !e.sdCheck(p) {
				return 0
			}
			ctl := e.Mem.R16(p+2) &^ flag
			if e.Arg32(2) != 0 {
				ctl |= flag
			}
			e.Mem.W16(p+2, ctl)
			e.Mem.W64(p+off, e.Arg(1))
			return 1
		}
	}
	reg(a, "SetSecurityDescriptorOwner", setSid(8, sdOwnerDefaulted))
	reg(a, "SetSecurityDescriptorGroup", setSid(16, sdGroupDefaulted))
}
