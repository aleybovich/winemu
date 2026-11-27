package win

// Security identifiers (SIDs): one Go model (sid) used by every security API
// (tokens, ACLs, account lookup), encoded in guest memory with the documented
// layout:
//
//	BYTE  Revision            // SID_REVISION = 1
//	BYTE  SubAuthorityCount   // <= SID_MAX_SUB_AUTHORITIES (15)
//	BYTE  IdentifierAuthority[6] (big-endian 48-bit value)
//	DWORD SubAuthority[SubAuthorityCount]

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	sidRevision       = 1
	sidMaxSubAuth     = 15
	errInvalidSid     = 1337
	errNoneMapped     = 1332
	errInvalidAcl     = 1336
	errNoToken        = 1008
	errBadLength      = 24
	errInvalidLevel   = 124
	errNoAccess       = 998
	errNotAllAssigned = 1300
	errNoSuchPriv     = 1313
	errPrivNotHeld    = 1314
	errInvalidOwner   = 1307
	errInvalidPrimGrp = 1308
	errNoImpersonTok  = 1309
	errUnknownRev     = 1305
	errInvalidSecDesc = 1338
	errAllottedSpace  = 1344
	errBadImpersonLvl = 1346
	nerrUserNotFound  = 2221
	errBadNetPath     = 53
)

type sid struct {
	auth uint64 // 48-bit identifier authority
	subs []uint32
}

func newSid(auth uint64, subs ...uint32) sid { return sid{auth: auth, subs: subs} }

func (s sid) size() int { return 8 + 4*len(s.subs) }

func (s sid) bytes() []byte {
	b := make([]byte, s.size())
	b[0], b[1] = sidRevision, byte(len(s.subs))
	for i := range 6 {
		b[2+i] = byte(s.auth >> (8 * (5 - i)))
	}
	for i, v := range s.subs {
		binary.LittleEndian.PutUint32(b[8+4*i:], v)
	}
	return b
}

func (s sid) equal(o sid) bool {
	if s.auth != o.auth || len(s.subs) != len(o.subs) {
		return false
	}
	for i := range s.subs {
		if s.subs[i] != o.subs[i] {
			return false
		}
	}
	return true
}

// String formats the SID in its standard string form (S-1-5-21-...).
func (s sid) String() string {
	var b strings.Builder
	b.WriteString("S-1-")
	if s.auth < 1<<32 {
		b.WriteString(strconv.FormatUint(s.auth, 10))
	} else {
		fmt.Fprintf(&b, "0x%012X", s.auth)
	}
	for _, v := range s.subs {
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// sddlSidAliases are the SDDL two-letter SID abbreviations accepted by
// ConvertStringSidToSid.
var sddlSidAliases = map[string]sid{
	"WD": newSid(1, 0),       // Everyone
	"CO": newSid(3, 0),       // CREATOR OWNER
	"CG": newSid(3, 1),       // CREATOR GROUP
	"IU": newSid(5, 4),       // INTERACTIVE
	"AU": newSid(5, 11),      // Authenticated Users
	"SY": newSid(5, 18),      // LocalSystem
	"LS": newSid(5, 19),      // LocalService
	"NS": newSid(5, 20),      // NetworkService
	"BA": newSid(5, 32, 544), // BUILTIN\Administrators
	"BU": newSid(5, 32, 545), // BUILTIN\Users
	"BG": newSid(5, 32, 546), // BUILTIN\Guests
	"PU": newSid(5, 32, 547), // BUILTIN\Power Users
	"LW": newSid(16, 4096),   // Low Mandatory Level
	"ME": newSid(16, 8192),   // Medium Mandatory Level
	"HI": newSid(16, 12288),  // High Mandatory Level
	"SI": newSid(16, 16384),  // System Mandatory Level
}

// parseSid parses "S-1-<auth>-<sub>..." (auth decimal or 0x-hex) or an SDDL
// alias.
func parseSid(str string) (sid, bool) {
	if s, ok := sddlSidAliases[strings.ToUpper(str)]; ok && len(str) == 2 {
		return s, true
	}
	parts := strings.Split(str, "-")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "S") || parts[1] != "1" {
		return sid{}, false
	}
	var s sid
	var err error
	if a := parts[2]; strings.HasPrefix(a, "0x") || strings.HasPrefix(a, "0X") {
		s.auth, err = strconv.ParseUint(a[2:], 16, 48)
	} else {
		s.auth, err = strconv.ParseUint(a, 10, 32)
	}
	if err != nil || len(parts)-3 > sidMaxSubAuth {
		return sid{}, false
	}
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil || p == "" || p[0] == '+' {
			return sid{}, false
		}
		s.subs = append(s.subs, uint32(v))
	}
	return s, true
}

// readSid decodes and validates a SID in guest memory (IsValidSid rules:
// readable, revision 1, at most 15 sub-authorities).
func (e *Emu) readSid(p uint64) (sid, bool) {
	if p == 0 || !e.Mem.Valid(p) || !e.Mem.Valid(p+7) {
		return sid{}, false
	}
	n := int(e.Mem.R8(p + 1))
	if e.Mem.R8(p) != sidRevision || n > sidMaxSubAuth || !e.Mem.Valid(p+uint64(8+4*n)-1) {
		return sid{}, false
	}
	b := e.Mem.ReadBytes(p, 8+4*n)
	s := sid{subs: make([]uint32, n)}
	for i := range 6 {
		s.auth = s.auth<<8 | uint64(b[2+i])
	}
	for i := range n {
		s.subs[i] = binary.LittleEndian.Uint32(b[8+4*i:])
	}
	return s, true
}

// allocSid copies s into a new process-heap block (also valid for
// LocalFree/FreeSid, which free heap blocks).
func (e *Emu) allocSid(s sid) uint64 {
	a := e.heapAllocRaw(uint64(s.size()))
	e.Mem.Write(a, s.bytes())
	return a
}

// ---------------------------------------------------------------------------
// Local accounts. The machine is a stand-alone workstation (workgroup member)
// named like GetComputerName; the interactive user is a local, non-admin
// account whose primary group is the machine's "None" group (RID 513).

const (
	sidTypeUser           = 1
	sidTypeGroup          = 2
	sidTypeDomain         = 3
	sidTypeAlias          = 4
	sidTypeWellKnownGroup = 5
	sidTypeLabel          = 10

	ridNone = 513
	ridUser = 1000
)

const secComputerName = "WINEMU" // must match GetComputerName

// machine sub-authorities of S-1-5-21-a-b-c
var machineSubs = []uint32{1180699209, 877415012, 3182924384}

func machineSid(rid ...uint32) sid {
	return newSid(5, append(append([]uint32{21}, machineSubs...), rid...)...)
}

var (
	sidEveryone      = newSid(1, 0)
	sidLocal         = newSid(2, 0)
	sidInteractive   = newSid(5, 4)
	sidAuthUsers     = newSid(5, 11)
	sidThisOrg       = newSid(5, 15)
	sidSystem        = newSid(5, 18)
	sidBuiltinUsers  = newSid(5, 32, 545)
	sidAdmins        = newSid(5, 32, 544)
	sidMediumLabel   = newSid(16, 8192)
	sidLogonSession  = newSid(5, 5, 0, 0x3e7a1)
	sidUserAccount   = machineSid(ridUser)
	sidNoneGroup     = machineSid(ridNone)
	sidMachineDomain = machineSid()
)

type account struct {
	s      sid
	name   string
	domain string
	use    uint32
}

// accounts returns every account known to the lookup APIs.
func (e *Emu) accounts() []account {
	return []account{
		{sidUserAccount, e.fs.user, secComputerName, sidTypeUser},
		{sidNoneGroup, "None", secComputerName, sidTypeGroup},
		{sidMachineDomain, secComputerName, secComputerName, sidTypeDomain},
		{sidEveryone, "Everyone", "", sidTypeWellKnownGroup},
		{sidLocal, "LOCAL", "", sidTypeWellKnownGroup},
		{newSid(3, 0), "CREATOR OWNER", "", sidTypeWellKnownGroup},
		{newSid(3, 1), "CREATOR GROUP", "", sidTypeWellKnownGroup},
		{sidInteractive, "INTERACTIVE", "NT AUTHORITY", sidTypeWellKnownGroup},
		{sidAuthUsers, "Authenticated Users", "NT AUTHORITY", sidTypeWellKnownGroup},
		{sidThisOrg, "This Organization", "NT AUTHORITY", sidTypeWellKnownGroup},
		{sidSystem, "SYSTEM", "NT AUTHORITY", sidTypeWellKnownGroup},
		{newSid(5, 19), "LOCAL SERVICE", "NT AUTHORITY", sidTypeWellKnownGroup},
		{newSid(5, 20), "NETWORK SERVICE", "NT AUTHORITY", sidTypeWellKnownGroup},
		{newSid(5, 32), "BUILTIN", "BUILTIN", sidTypeDomain},
		{sidAdmins, "Administrators", "BUILTIN", sidTypeAlias},
		{sidBuiltinUsers, "Users", "BUILTIN", sidTypeAlias},
		{newSid(5, 32, 546), "Guests", "BUILTIN", sidTypeAlias},
		{newSid(5, 32, 547), "Power Users", "BUILTIN", sidTypeAlias},
		{newSid(16, 4096), "Low Mandatory Level", "Mandatory Label", sidTypeLabel},
		{sidMediumLabel, "Medium Mandatory Level", "Mandatory Label", sidTypeLabel},
		{newSid(16, 12288), "High Mandatory Level", "Mandatory Label", sidTypeLabel},
		{newSid(16, 16384), "System Mandatory Level", "Mandatory Label", sidTypeLabel},
	}
}

func (e *Emu) accountBySid(s sid) (account, bool) {
	for _, a := range e.accounts() {
		if a.s.equal(s) {
			return a, true
		}
	}
	return account{}, false
}

// accountByName accepts "name", "domain\name" (case-insensitive) and the
// local-machine forms ".\name" and "<computer>\name".
func (e *Emu) accountByName(name string) (account, bool) {
	dom, n, qualified := strings.Cut(name, `\`)
	if !qualified {
		n, dom = dom, ""
	} else if dom == "." {
		dom = secComputerName
	}
	if n == "" && qualified { // "DOMAIN\" names the domain itself
		n = dom
	}
	for _, a := range e.accounts() {
		if strings.EqualFold(a.name, n) && (!qualified || strings.EqualFold(a.domain, dom)) {
			return a, true
		}
	}
	return account{}, false
}

// ---------------------------------------------------------------------------

func init() {
	a := dAdv
	reg(a, "IsValidSid", func(e *Emu) uint64 {
		_, ok := e.readSid(e.Arg(0))
		return b2u(ok)
	})
	reg(a, "GetLengthSid", func(e *Emu) uint64 { return uint64(8 + 4*uint32(e.Mem.R8(e.Arg(0)+1))) })
	reg(a, "GetSidLengthRequired", func(e *Emu) uint64 { return uint64(8 + 4*uint32(uint8(e.Arg(0)))) })
	reg(a, "GetSidIdentifierAuthority", func(e *Emu) uint64 { return e.Arg(0) + 2 })
	reg(a, "GetSidSubAuthorityCount", func(e *Emu) uint64 { return e.Arg(0) + 1 })
	reg(a, "GetSidSubAuthority", func(e *Emu) uint64 { return e.Arg(0) + 8 + 4*uint64(e.Arg32(1)) })
	reg(a, "InitializeSid", func(e *Emu) uint64 {
		n := uint8(e.Arg(2))
		if n > sidMaxSubAuth || e.Arg(0) == 0 || e.Arg(1) == 0 {
			return e.fail(errInvalidParameter)
		}
		e.Mem.W8(e.Arg(0), sidRevision)
		e.Mem.W8(e.Arg(0)+1, n)
		e.Mem.Write(e.Arg(0)+2, e.Mem.ReadBytes(e.Arg(1), 6))
		return 1
	})
	reg(a, "CopySid", func(e *Emu) uint64 {
		s, ok := e.readSid(e.Arg(2))
		if !ok {
			return e.fail(errInvalidSid)
		}
		if e.Arg32(0) < uint32(s.size()) || e.Arg(1) == 0 {
			return e.fail(errInsufficientBuf)
		}
		e.Mem.Write(e.Arg(1), s.bytes())
		return 1
	})
	reg(a, "EqualSid", func(e *Emu) uint64 {
		s1, ok1 := e.readSid(e.Arg(0))
		s2, ok2 := e.readSid(e.Arg(1))
		if !ok1 || !ok2 {
			return e.fail(errInvalidSid)
		}
		e.SetLastError(0)
		return b2u(s1.equal(s2))
	})
	reg(a, "EqualPrefixSid", func(e *Emu) uint64 {
		s1, ok1 := e.readSid(e.Arg(0))
		s2, ok2 := e.readSid(e.Arg(1))
		if !ok1 || !ok2 {
			return e.fail(errInvalidSid)
		}
		e.SetLastError(0)
		if len(s1.subs) != len(s2.subs) || len(s1.subs) == 0 {
			return b2u(len(s1.subs) == len(s2.subs) && s1.auth == s2.auth)
		}
		return b2u(sid{s1.auth, s1.subs[:len(s1.subs)-1]}.equal(sid{s2.auth, s2.subs[:len(s2.subs)-1]}))
	})
	reg(a, "AllocateAndInitializeSid", func(e *Emu) uint64 {
		n := int(uint8(e.Arg(1)))
		if n > 8 || e.Arg(0) == 0 {
			return e.fail(errInvalidSid)
		}
		if e.Arg(10) == 0 {
			return e.fail(errInvalidParameter)
		}
		var s sid
		for _, b := range e.Mem.ReadBytes(e.Arg(0), 6) {
			s.auth = s.auth<<8 | uint64(b)
		}
		for i := range n {
			s.subs = append(s.subs, e.Arg32(2+i))
		}
		e.Mem.W64(e.Arg(10), e.allocSid(s))
		return 1
	})
	reg(a, "FreeSid", func(e *Emu) uint64 {
		if e.Arg(0) != 0 && !e.heap.freeBlock(e.Arg(0)) {
			return e.Arg(0)
		}
		return 0
	})
	regAW(a, "ConvertSidToStringSid", func(e *Emu, w bool) uint64 {
		s, ok := e.readSid(e.Arg(0))
		if !ok {
			return e.fail(errInvalidSid)
		}
		if e.Arg(1) == 0 {
			return e.fail(errInvalidParameter)
		}
		if w {
			e.Mem.W64(e.Arg(1), e.allocWStr(s.String()))
		} else {
			e.Mem.W64(e.Arg(1), e.allocCStr(s.String()))
		}
		return 1
	})
	regAW(a, "ConvertStringSidToSid", func(e *Emu, w bool) uint64 {
		if e.Arg(0) == 0 || e.Arg(1) == 0 {
			return e.fail(errInvalidParameter)
		}
		s, ok := parseSid(e.strArg(0, w))
		if !ok {
			return e.fail(errInvalidSid)
		}
		e.Mem.W64(e.Arg(1), e.allocSid(s))
		return 1
	})
}
