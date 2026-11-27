package win

// Identity APIs: user names, account lookup (advapi32/secur32), netapi32
// user info and userenv profile directories, all derived from the account
// model in security_sid.go (one local user on the stand-alone machine
// secComputerName, member of the workgroup "WORKGROUP").

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

const (
	nameSamCompatible = 2
	nameDisplay       = 3
	workgroupName     = "WORKGROUP"
)

func profilesDir() string             { return `C:\Users` }
func (e *Emu) userProfileDir() string { return profilesDir() + `\` + e.fs.user }

// isLocalSystem reports whether a system/server name argument names this
// machine ("" / NULL, ".", the computer name, optionally with a \\ prefix).
func isLocalSystem(s string) bool {
	s = strings.TrimPrefix(s, `\\`)
	return s == "" || s == "." || strings.EqualFold(s, secComputerName) || strings.EqualFold(s, "localhost")
}

// fits reports whether s plus its NUL fits in the *pcch-character buffer
// (A: bytes, W: UTF-16 units).
func (e *Emu) fits(pcch uint64, s string, wide bool) bool {
	n := len(s)
	if wide {
		n = len(utf16.Encode([]rune(s)))
	}
	return e.Mem.R32(pcch) > uint32(n)
}

func strLen(s string, wide bool) uint32 {
	if wide {
		return uint32(len(utf16.Encode([]rune(s))))
	}
	return uint32(len(s))
}

func (e *Emu) writeStr(wide bool, buf uint64, s string) {
	if wide {
		e.Mem.WriteWStr(buf, s)
	} else {
		e.Mem.WriteCStr(buf, s)
	}
}

// userName returns the current user's name in EXTENDED_NAME_FORMAT f.
func (e *Emu) userName(f uint32) (string, uint32) {
	switch f {
	case nameSamCompatible:
		return secComputerName + `\` + e.fs.user, 0
	case nameDisplay:
		return e.fs.user, 0 // the full name of the local account
	case 1, 6, 7, 8, 9, 10, 12, 13, 14: // directory-service formats: not on a stand-alone machine
		return "", errNoneMapped
	}
	return "", errInvalidParameter
}

// ---- netapi32 USER_INFO_* encoding ----

// netField is one member of a USER_INFO_n structure: a string pointer
// (str, nil pointer if !set), a SID pointer, or a DWORD.
type netField struct {
	kind byte // 's' LPWSTR, 'S' PSID, 'd' DWORD
	str  string
	set  bool
	sid  sid
	v    uint32
}

func nStr(s string) netField { return netField{kind: 's', str: s, set: true} }
func nNull() netField        { return netField{kind: 's'} }
func nDw(v uint32) netField  { return netField{kind: 'd', v: v} }

// netBuffer lays out fields with natural x64 alignment, appends the
// strings/SIDs after the struct and returns the heap block (freed by
// NetApiBufferFree).
func (e *Emu) netBuffer(fields []netField) uint64 {
	off := 0
	offs := make([]int, len(fields))
	for i, f := range fields {
		sz := 8
		if f.kind == 'd' {
			sz = 4
		}
		off = (off + sz - 1) &^ (sz - 1)
		offs[i] = off
		off += sz
	}
	off = (off + 7) &^ 7
	b := make([]byte, off)
	var tail [][]byte
	tailOff := off
	ptrs := make([]int, len(fields))
	for i, f := range fields {
		var d []byte
		switch {
		case f.kind == 'S':
			d = f.sid.bytes()
		case f.kind == 's' && f.set:
			for _, u := range append(utf16.Encode([]rune(f.str)), 0) {
				d = binary.LittleEndian.AppendUint16(d, u)
			}
		}
		ptrs[i] = -1
		if d != nil {
			ptrs[i] = tailOff
			tail = append(tail, d)
			tailOff += (len(d) + 7) &^ 7
		}
	}
	a := e.heapAllocRaw(uint64(tailOff))
	for i, f := range fields {
		if f.kind == 'd' {
			binary.LittleEndian.PutUint32(b[offs[i]:], f.v)
		} else if ptrs[i] >= 0 {
			binary.LittleEndian.PutUint64(b[offs[i]:], a+uint64(ptrs[i]))
		}
	}
	e.Mem.Write(a, b)
	p := off
	for _, d := range tail {
		e.Mem.Write(a+uint64(p), d)
		p += (len(d) + 7) &^ 7
	}
	return a
}

func (e *Emu) userInfo(level uint32, ac account) ([]netField, bool) {
	const (
		userPrivUser = 1
		ufFlags      = 0x0001 | 0x0200 | 0x10000 // UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD
		timeqForever = 0xFFFFFFFF
		userMaxStor  = 0xFFFFFFFF
	)
	name, full, home := nStr(ac.name), nStr(ac.name), nStr("")
	rid := ac.s.subs[len(ac.s.subs)-1]
	switch level {
	case 0:
		return []netField{name}, true
	case 1:
		return []netField{name, nNull(), nDw(0), nDw(userPrivUser), home, nStr(""), nDw(ufFlags), nStr("")}, true
	case 4:
		return []netField{name, nNull(), nDw(0), nDw(userPrivUser), home, nStr(""), nDw(ufFlags), nStr(""),
			nDw(0), full, nStr(""), nStr(""), nStr(""), nDw(0), nDw(0), nDw(timeqForever), nDw(userMaxStor),
			nDw(168), nNull(), nDw(0), nDw(0), nStr(`\\*`), nDw(0), nDw(0),
			{kind: 'S', sid: ac.s}, nDw(ridNone), nStr(""), nStr(""), nDw(0)}, true
	case 10:
		return []netField{name, nStr(""), nStr(""), full}, true
	case 20:
		return []netField{name, full, nStr(""), nDw(ufFlags), nDw(rid)}, true
	case 23:
		return []netField{name, full, nStr(""), nDw(ufFlags), {kind: 'S', sid: ac.s}}, true
	}
	return nil, false
}

func init() {
	a := dAdv
	regAW(a, "GetUserName", func(e *Emu, w bool) uint64 {
		pn := e.Arg(1)
		if pn == 0 {
			return e.fail(errInvalidParameter)
		}
		if e.Arg(0) == 0 || !e.fits(pn, e.fs.user, w) {
			e.Mem.W32(pn, strLen(e.fs.user, w)+1)
			return e.fail(errInsufficientBuf)
		}
		e.writeStr(w, e.Arg(0), e.fs.user)
		e.Mem.W32(pn, strLen(e.fs.user, w)+1)
		return 1
	})
	regAW("secur32.dll", "GetUserNameEx", func(e *Emu, w bool) uint64 {
		pn := e.Arg(2)
		if pn == 0 {
			return e.fail(errInvalidParameter)
		}
		s, code := e.userName(e.Arg32(0))
		if code != 0 {
			return e.fail(code)
		}
		if e.Arg(1) == 0 || !e.fits(pn, s, w) {
			e.Mem.W32(pn, strLen(s, w)+1)
			return e.fail(errMoreData)
		}
		e.writeStr(w, e.Arg(1), s)
		e.Mem.W32(pn, strLen(s, w))
		return 1
	})
	regAW("secur32.dll", "TranslateName", func(e *Emu, w bool) uint64 {
		pn := e.Arg(4)
		if e.Arg(0) == 0 || pn == 0 {
			return e.fail(errInvalidParameter)
		}
		in, inF, outF := e.strArg(0, w), e.Arg32(1), e.Arg32(2)
		ac, ok := e.accountByName(in)
		if inF != nameSamCompatible || !strings.Contains(in, `\`) || !ok || ac.use != sidTypeUser {
			return e.fail(errNoneMapped)
		}
		var s string
		switch outF {
		case nameSamCompatible:
			s = ac.domain + `\` + ac.name
		case nameDisplay:
			s = ac.name
		default:
			return e.fail(errNoneMapped)
		}
		if e.Arg(3) == 0 || !e.fits(pn, s, w) {
			e.Mem.W32(pn, strLen(s, w)+1)
			return e.fail(errInsufficientBuf)
		}
		e.writeStr(w, e.Arg(3), s)
		e.Mem.W32(pn, strLen(s, w)+1)
		return 1
	})
	regAW(a, "LookupAccountSid", func(e *Emu, w bool) uint64 {
		if !isLocalSystem(e.strArg(0, w)) {
			return e.fail(errNoneMapped)
		}
		s, ok := e.readSid(e.Arg(1))
		if !ok {
			return e.fail(errInvalidSid)
		}
		pName, pDom := e.Arg(3), e.Arg(5)
		if pName == 0 || pDom == 0 {
			return e.fail(errNoAccess)
		}
		ac, ok := e.accountBySid(s)
		if !ok {
			return e.fail(errNoneMapped)
		}
		if e.Arg(2) == 0 || e.Arg(4) == 0 || !e.fits(pName, ac.name, w) || !e.fits(pDom, ac.domain, w) {
			e.Mem.W32(pName, strLen(ac.name, w)+1)
			e.Mem.W32(pDom, strLen(ac.domain, w)+1)
			return e.fail(errInsufficientBuf)
		}
		e.writeStr(w, e.Arg(2), ac.name)
		e.writeStr(w, e.Arg(4), ac.domain)
		e.Mem.W32(pName, strLen(ac.name, w))
		e.Mem.W32(pDom, strLen(ac.domain, w))
		if e.Arg(6) != 0 {
			e.Mem.W32(e.Arg(6), ac.use)
		}
		return 1
	})
	regAW(a, "LookupAccountName", func(e *Emu, w bool) uint64 {
		if !isLocalSystem(e.strArg(0, w)) {
			return e.fail(errNoneMapped)
		}
		if e.Arg(1) == 0 {
			return e.fail(errInvalidParameter)
		}
		pcb, pDom := e.Arg(3), e.Arg(5)
		if pcb == 0 || pDom == 0 {
			return e.fail(errNoAccess)
		}
		ac, ok := e.accountByName(e.strArg(1, w))
		if !ok {
			return e.fail(errNoneMapped)
		}
		if e.Arg(2) == 0 || e.Arg(4) == 0 || e.Mem.R32(pcb) < uint32(ac.s.size()) || !e.fits(pDom, ac.domain, w) {
			e.Mem.W32(pcb, uint32(ac.s.size()))
			e.Mem.W32(pDom, strLen(ac.domain, w)+1)
			return e.fail(errInsufficientBuf)
		}
		e.Mem.Write(e.Arg(2), ac.s.bytes())
		e.writeStr(w, e.Arg(4), ac.domain)
		e.Mem.W32(pcb, uint32(ac.s.size()))
		e.Mem.W32(pDom, strLen(ac.domain, w))
		if e.Arg(6) != 0 {
			e.Mem.W32(e.Arg(6), ac.use)
		}
		return 1
	})

	// ---- netapi32 (return NET_API_STATUS) ----
	n := "netapi32.dll"
	reg(n, "NetApiBufferFree", func(e *Emu) uint64 {
		if p := e.Arg(0); p != 0 && !e.heap.freeBlock(p) {
			return errInvalidParameter
		}
		return 0
	})
	reg(n, "NetGetJoinInformation", func(e *Emu) uint64 {
		if !isLocalSystem(e.strArg(0, true)) {
			return errBadNetPath
		}
		if e.Arg(1) == 0 || e.Arg(2) == 0 {
			return errInvalidParameter
		}
		e.Mem.W64(e.Arg(1), e.allocWStr(workgroupName))
		e.Mem.W32(e.Arg(2), 2) // NetSetupWorkgroupName
		return 0
	})
	reg(n, "NetUserGetInfo", func(e *Emu) uint64 {
		if !isLocalSystem(e.strArg(0, true)) {
			return errBadNetPath
		}
		if e.Arg(1) == 0 || e.Arg(3) == 0 {
			return errInvalidParameter
		}
		ac, ok := e.accountByName(e.strArg(1, true))
		if !ok || ac.use != sidTypeUser || strings.Contains(e.strArg(1, true), `\`) {
			return nerrUserNotFound
		}
		f, ok := e.userInfo(e.Arg32(2), ac)
		if !ok {
			return errInvalidLevel
		}
		e.Mem.W64(e.Arg(3), e.netBuffer(f))
		return 0
	})

	// ---- userenv ----
	u := "userenv.dll"
	putPath := func(e *Emu, w bool, buf, pn uint64, s string) uint64 {
		if pn == 0 {
			return e.fail(errInvalidParameter)
		}
		need := strLen(s, w) + 1
		if buf == 0 || !e.fits(pn, s, w) {
			e.Mem.W32(pn, need)
			return e.fail(errInsufficientBuf)
		}
		e.writeStr(w, buf, s)
		e.Mem.W32(pn, need)
		return 1
	}
	regAW(u, "GetUserProfileDirectory", func(e *Emu, w bool) uint64 {
		if e.token(e.Arg(0)) == nil {
			return e.fail(errInvalidHandle)
		}
		return putPath(e, w, e.Arg(1), e.Arg(2), e.userProfileDir())
	})
	regAW(u, "GetProfilesDirectory", func(e *Emu, w bool) uint64 {
		return putPath(e, w, e.Arg(0), e.Arg(1), profilesDir())
	})
}
