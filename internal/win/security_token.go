package win

// Access tokens. The process has one primary token (shared by every handle
// OpenProcessToken returns, so SetTokenInformation through one handle is seen
// through the others); threads may carry an impersonation token
// (ImpersonateSelf, SetThreadToken, ImpersonateLoggedOnUser). Token contents
// use the account model of security_sid.go: a non-elevated local user at
// medium integrity.

import (
	"encoding/binary"
	"strings"
	"sync"
)

const (
	tokenPrimary       = 1
	tokenImpersonation = 2

	seGroupMandatory   = 0x1
	seGroupDefault     = 0x2
	seGroupEnabled     = 0x4
	seGroupOwner       = 0x8
	seGroupDenyOnly    = 0x10
	seGroupIntegrity   = 0x20
	seGroupIntegrityOn = 0x40
	seGroupLogonID     = 0xC0000000
	seGroupStd         = seGroupMandatory | seGroupDefault | seGroupEnabled

	sePrivEnabledDefault = 0x1
	sePrivEnabled        = 0x2
	sePrivRemoved        = 0x4

	pseudoProcessToken   = ^uint64(3) // GetCurrentProcessToken()
	pseudoThreadToken    = ^uint64(4) // GetCurrentThreadToken()
	pseudoEffectiveToken = ^uint64(5) // GetCurrentThreadEffectiveToken()

	privChangeNotify = 23

	errBadTokenType = 1349
)

var privilegeNames = []string{2: "SeCreateTokenPrivilege", "SeAssignPrimaryTokenPrivilege", "SeLockMemoryPrivilege",
	"SeIncreaseQuotaPrivilege", "SeMachineAccountPrivilege", "SeTcbPrivilege", "SeSecurityPrivilege",
	"SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
	"SeProfileSingleProcessPrivilege", "SeIncreaseBasePriorityPrivilege", "SeCreatePagefilePrivilege",
	"SeCreatePermanentPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeShutdownPrivilege",
	"SeDebugPrivilege", "SeAuditPrivilege", "SeSystemEnvironmentPrivilege", "SeChangeNotifyPrivilege",
	"SeRemoteShutdownPrivilege", "SeUndockPrivilege", "SeSyncAgentPrivilege", "SeEnableDelegationPrivilege",
	"SeManageVolumePrivilege", "SeImpersonatePrivilege", "SeCreateGlobalPrivilege",
	"SeTrustedCredManAccessPrivilege", "SeRelabelPrivilege", "SeIncreaseWorkingSetPrivilege",
	"SeTimeZonePrivilege", "SeCreateSymbolicLinkPrivilege", "SeDelegateSessionUserImpersonatePrivilege"}

func privilegeValue(name string) (uint32, bool) {
	for i, n := range privilegeNames {
		if n != "" && strings.EqualFold(n, name) {
			return uint32(i), true
		}
	}
	return 0, false
}

type sidAttr struct {
	s    sid
	attr uint32
}

type privAttr struct{ luid, attr uint32 }

// tokenObj is a kernel object: a handle to it can be held by several
// processes (OpenProcessToken on another process, DuplicateHandle), so its
// mutable state (groups, privs, owner, primary, dacl, modified) is accessed
// under mu. The other fields are fixed once the token is published.
type tokenObj struct {
	mu         sync.Mutex
	user       sidAttr
	groups     []sidAttr
	privs      []privAttr
	owner      sid
	primary    sid
	dacl       []byte // nil: no default DACL
	typ        uint32
	level      uint32 // SECURITY_IMPERSONATION_LEVEL (impersonation tokens)
	restricted []sidAttr
	id, authID uint64
	modified   uint64
}

type secState struct {
	threads map[*Thread]*tokenObj // impersonation tokens
}

func (e *Emu) secState() *secState {
	if e.sec == nil {
		e.sec = &secState{threads: map[*Thread]*tokenObj{}}
	}
	return e.sec
}

// primaryToken is the process's primary token, created on first use. It is
// reachable from other processes (OpenProcessToken on a process handle).
func (p *Process) primaryToken() *tokenObj {
	p.tokenOnce.Do(func() {
		k := p.k
		t := &tokenObj{
			user: sidAttr{sidUserAccount, 0},
			groups: []sidAttr{
				{sidNoneGroup, seGroupStd},
				{sidEveryone, seGroupStd},
				{sidBuiltinUsers, seGroupStd},
				{sidInteractive, seGroupStd},
				{sidAuthUsers, seGroupStd},
				{sidThisOrg, seGroupStd},
				{sidLocal, seGroupStd},
				{sidLogonSession, seGroupStd | seGroupLogonID},
				{sidMediumLabel, seGroupIntegrity | seGroupIntegrityOn},
			},
			privs: []privAttr{{19, 0}, {privChangeNotify, sePrivEnabledDefault | sePrivEnabled}, {25, 0}, {33, 0}, {34, 0}},
			owner: sidUserAccount, primary: sidNoneGroup,
			dacl: buildAcl(aceSpec{aceAllowedType, 0, 0x10000000, sidUserAccount}, // GENERIC_ALL
				aceSpec{aceAllowedType, 0, 0x10000000, sidSystem},
				aceSpec{aceAllowedType, 0, 0xA0000000, sidLogonSession}), // GENERIC_READ|GENERIC_EXECUTE
			typ: tokenPrimary, id: k.newLuid(), authID: 0x3e7a1,
		}
		t.modified = k.newLuid()
		p.token = t
	})
	return p.token
}

// newLuid allocates a locally unique id (unique across the session).
func (k *Kernel) newLuid() uint64 { return k.luid.Add(1) }

func (e *Emu) newLuid() uint64 { return e.k.newLuid() }

func (t *tokenObj) clone(e *Emu) *tokenObj {
	t.mu.Lock()
	defer t.mu.Unlock()
	return &tokenObj{
		user:       t.user,
		groups:     append([]sidAttr(nil), t.groups...),
		privs:      append([]privAttr(nil), t.privs...),
		owner:      t.owner,
		primary:    t.primary,
		dacl:       append([]byte(nil), t.dacl...),
		typ:        t.typ,
		level:      t.level,
		restricted: append([]sidAttr(nil), t.restricted...),
		id:         e.newLuid(),
		authID:     t.authID,
		modified:   e.newLuid(),
	}
}

// token resolves a token handle, including the pseudo handles.
func (e *Emu) token(h uint64) *tokenObj {
	s := e.secState()
	switch h {
	case pseudoProcessToken:
		return e.proc.primaryToken()
	case pseudoThreadToken:
		return s.threads[e.Cur]
	case pseudoEffectiveToken:
		if t := s.threads[e.Cur]; t != nil {
			return t
		}
		return e.proc.primaryToken()
	}
	t, _ := e.handles.get(h).(*tokenObj)
	return t
}

func (t *tokenObj) integrity() sidAttr {
	for _, g := range t.groups {
		if g.attr&seGroupIntegrity != 0 {
			return g
		}
	}
	return sidAttr{sidMediumLabel, seGroupIntegrity | seGroupIntegrityOn}
}

func (t *tokenObj) hasSid(s sid, need uint32) bool {
	if t.user.s.equal(s) && t.user.attr&seGroupDenyOnly == 0 {
		return true
	}
	for _, g := range t.groups {
		if g.s.equal(s) && g.attr&need == need && g.attr&seGroupDenyOnly == 0 {
			return true
		}
	}
	return false
}

// member implements the CheckTokenMembership access check.
func (t *tokenObj) member(s sid) bool {
	if !t.hasSid(s, seGroupEnabled) {
		return false
	}
	if len(t.restricted) == 0 {
		return true
	}
	for _, r := range t.restricted {
		if r.s.equal(s) {
			return true
		}
	}
	return false
}

// sidAttrBlob encodes n SID_AND_ATTRIBUTES (16 bytes each) followed by the
// SIDs, placed at base+off; prefix bytes precede the array.
func sidAttrBlob(base uint64, prefix []byte, list []sidAttr) []byte {
	b := append([]byte(nil), prefix...)
	arr := len(b)
	b = append(b, make([]byte, 16*len(list))...)
	for i, g := range list {
		binary.LittleEndian.PutUint64(b[arr+16*i:], base+uint64(len(b)))
		binary.LittleEndian.PutUint32(b[arr+16*i+8:], g.attr)
		b = append(b, g.s.bytes()...)
	}
	return b
}

func tokenGroupsBlob(base uint64, list []sidAttr) []byte {
	p := make([]byte, 8)
	binary.LittleEndian.PutUint32(p, uint32(len(list)))
	return sidAttrBlob(base, p, list)
}

func ptrBlob(base uint64, data []byte) []byte {
	b := make([]byte, 8, 8+len(data))
	if data != nil {
		binary.LittleEndian.PutUint64(b, base+8)
	}
	return append(b, data...)
}

func dword(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// info encodes TOKEN_INFORMATION_CLASS c as it would sit at address base.
func (t *tokenObj) info(c uint32, base uint64) ([]byte, bool) {
	switch c {
	case 1: // TokenUser: TOKEN_USER { SID_AND_ATTRIBUTES User }
		return sidAttrBlob(base, nil, []sidAttr{t.user}), true
	case 2: // TokenGroups
		return tokenGroupsBlob(base, t.groups), true
	case 3: // TokenPrivileges: { DWORD Count; LUID_AND_ATTRIBUTES[Count] (12 bytes) }
		b := dword(uint32(len(t.privs)))
		for _, p := range t.privs {
			b = binary.LittleEndian.AppendUint32(b, p.luid)
			b = binary.LittleEndian.AppendUint32(b, 0)
			b = binary.LittleEndian.AppendUint32(b, p.attr)
		}
		return b, true
	case 4: // TokenOwner
		return ptrBlob(base, t.owner.bytes()), true
	case 5: // TokenPrimaryGroup
		return ptrBlob(base, t.primary.bytes()), true
	case 6: // TokenDefaultDacl
		return ptrBlob(base, t.dacl), true
	case 7: // TokenSource { CHAR SourceName[8]; LUID SourceIdentifier }
		return append([]byte("User32  "), make([]byte, 8)...), true
	case 8: // TokenType
		return dword(t.typ), true
	case 9: // TokenImpersonationLevel
		if t.typ != tokenImpersonation {
			return nil, false
		}
		return dword(t.level), true
	case 10: // TokenStatistics (56 bytes)
		b := binary.LittleEndian.AppendUint64(nil, t.id)
		b = binary.LittleEndian.AppendUint64(b, t.authID)
		b = binary.LittleEndian.AppendUint64(b, 0x7FFFFFFFFFFFFFFF) // ExpirationTime: never
		b = binary.LittleEndian.AppendUint32(b, t.typ)
		b = binary.LittleEndian.AppendUint32(b, t.level)
		b = binary.LittleEndian.AppendUint32(b, 4096)
		b = binary.LittleEndian.AppendUint32(b, uint32(4096-len(t.dacl)))
		b = binary.LittleEndian.AppendUint32(b, uint32(len(t.groups)))
		b = binary.LittleEndian.AppendUint32(b, uint32(len(t.privs)))
		return binary.LittleEndian.AppendUint64(b, t.modified), true
	case 11: // TokenRestrictedSids
		return tokenGroupsBlob(base, t.restricted), true
	case 12: // TokenSessionId
		return dword(1), true
	case 18: // TokenElevationType: TokenElevationTypeDefault
		return dword(1), true
	case 20: // TokenElevation { DWORD TokenIsElevated }
		return dword(0), true
	case 25: // TokenIntegrityLevel: TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label }
		return sidAttrBlob(base, nil, []sidAttr{t.integrity()}), true
	case 29: // TokenIsAppContainer
		return dword(0), true
	}
	return nil, false
}

// readSidAttrs reads n SID_AND_ATTRIBUTES at p.
func (e *Emu) readSidAttrs(p uint64, n uint32) ([]sidAttr, bool) {
	var out []sidAttr
	for i := range uint64(n) {
		s, ok := e.readSid(e.Mem.R64(p + 16*i))
		if !ok {
			return nil, false
		}
		out = append(out, sidAttr{s, e.Mem.R32(p + 16*i + 8)})
	}
	return out, true
}

func (e *Emu) duplicateToken(src uint64, level, typ uint32, out uint64) uint64 {
	t := e.token(src)
	if t == nil {
		return e.fail(errInvalidHandle)
	}
	if typ != tokenPrimary && typ != tokenImpersonation {
		return e.fail(errInvalidParameter)
	}
	if level > 3 {
		return e.fail(errBadImpersonLvl)
	}
	if out == 0 {
		return e.fail(errNoAccess)
	}
	n := t.clone(e)
	n.typ, n.level = typ, level
	e.Mem.W64(out, e.handles.add(n))
	return 1
}

func (e *Emu) setThreadToken(th *Thread, t *tokenObj) {
	s := e.secState()
	if t == nil {
		delete(s.threads, th)
		return
	}
	s.threads[th] = t
}

func init() {
	a := dAdv
	reg(a, "OpenProcessToken", func(e *Emu) uint64 {
		p := e.processOf(e.Arg(0)) // own or another process's handle
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		if e.Arg(2) == 0 {
			return e.fail(errNoAccess)
		}
		e.Mem.W64(e.Arg(2), e.handles.add(p.primaryToken()))
		return 1
	})
	reg(a, "OpenThreadToken", func(e *Emu) uint64 {
		th := e.threadOf(e.Arg(0))
		if th == nil {
			return e.fail(errInvalidHandle)
		}
		if e.Arg(3) == 0 {
			return e.fail(errNoAccess)
		}
		t := e.secState().threads[th]
		if t == nil {
			return e.fail(errNoToken)
		}
		e.Mem.W64(e.Arg(3), e.handles.add(t))
		return 1
	})
	reg(a, "GetTokenInformation", func(e *Emu) uint64 {
		t := e.token(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		buf, n, retLen := e.Arg(2), e.Arg32(3), e.Arg(4)
		t.mu.Lock()
		b, ok := t.info(e.Arg32(1), buf)
		t.mu.Unlock()
		if !ok {
			return e.fail(errInvalidParameter)
		}
		if retLen != 0 {
			e.Mem.W32(retLen, uint32(len(b)))
		}
		if n < uint32(len(b)) || buf == 0 {
			return e.fail(errInsufficientBuf)
		}
		e.Mem.Write(buf, b)
		return 1
	})
	reg(a, "SetTokenInformation", func(e *Emu) uint64 {
		t := e.token(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		p, n := e.Arg(2), e.Arg32(3)
		need := map[uint32]uint32{4: 8, 5: 8, 6: 8, 12: 4, 25: 16}[e.Arg32(1)]
		if need == 0 {
			return e.fail(errInvalidParameter)
		}
		if n < need || p == 0 {
			return e.fail(errBadLength)
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		switch e.Arg32(1) {
		case 4: // TokenOwner: the user or a group with SE_GROUP_OWNER
			s, ok := e.readSid(e.Mem.R64(p))
			if !ok {
				return e.fail(errInvalidSid)
			}
			if !t.user.s.equal(s) && !t.hasSid(s, seGroupOwner) {
				return e.fail(errInvalidOwner)
			}
			t.owner = s
		case 5: // TokenPrimaryGroup: the user or one of the token's groups
			s, ok := e.readSid(e.Mem.R64(p))
			if !ok {
				return e.fail(errInvalidSid)
			}
			if !t.user.s.equal(s) && !t.hasSid(s, 0) {
				return e.fail(errInvalidPrimGrp)
			}
			t.primary = s
		case 6: // TokenDefaultDacl (NULL removes it)
			acl, ok := e.readAcl(e.Mem.R64(p))
			if !ok {
				return e.fail(errInvalidAcl)
			}
			t.dacl = acl
		case 12: // TokenSessionId needs SeTcbPrivilege
			return e.fail(errPrivNotHeld)
		case 25: // TokenIntegrityLevel: may only be lowered
			s, ok := e.readSid(e.Mem.R64(p))
			if !ok || s.auth != 16 || len(s.subs) != 1 {
				return e.fail(errInvalidSid)
			}
			cur := t.integrity()
			if s.subs[0] > cur.s.subs[0] {
				return e.fail(errPrivNotHeld)
			}
			for i, g := range t.groups {
				if g.attr&seGroupIntegrity != 0 {
					t.groups[i].s = s
				}
			}
		}
		t.modified = e.newLuid()
		return 1
	})
	reg(a, "DuplicateTokenEx", func(e *Emu) uint64 {
		return e.duplicateToken(e.Arg(0), e.Arg32(3), e.Arg32(4), e.Arg(5))
	})
	reg(a, "DuplicateToken", func(e *Emu) uint64 {
		return e.duplicateToken(e.Arg(0), e.Arg32(1), tokenImpersonation, e.Arg(2))
	})
	reg(a, "CreateRestrictedToken", func(e *Emu) uint64 {
		t := e.token(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		if e.Arg(8) == 0 {
			return e.fail(errNoAccess)
		}
		if e.Arg32(1)&^0xF != 0 {
			return e.fail(errInvalidParameter)
		}
		disable, ok1 := e.readSidAttrs(e.Arg(3), e.Arg32(2))
		restrict, ok2 := e.readSidAttrs(e.Arg(7), e.Arg32(6))
		if !ok1 || !ok2 {
			return e.fail(errInvalidSid)
		}
		n := t.clone(e)
		for _, d := range disable { // deny-only: still matches deny ACEs, never grants
			if n.user.s.equal(d.s) {
				n.user.attr |= seGroupDenyOnly
			}
			for i, g := range n.groups {
				if g.s.equal(d.s) && g.attr&seGroupIntegrity == 0 {
					n.groups[i].attr = g.attr&^(seGroupEnabled|seGroupDefault|seGroupMandatory|seGroupOwner) | seGroupDenyOnly
				}
			}
		}
		del := map[uint32]bool{}
		for i := range uint64(e.Arg32(4)) {
			del[e.Mem.R32(e.Arg(5)+12*i)] = true
		}
		const disableMaxPrivilege, luaToken = 0x1, 0x4
		keep := n.privs[:0]
		for _, p := range n.privs {
			if !del[p.luid] && (e.Arg32(1)&(disableMaxPrivilege|luaToken) == 0 || p.luid == privChangeNotify) {
				keep = append(keep, p)
			}
		}
		n.privs = keep
		for _, r := range restrict {
			n.restricted = append(n.restricted, sidAttr{r.s, seGroupStd})
		}
		e.Mem.W64(e.Arg(8), e.handles.add(n))
		return 1
	})
	reg(a, "IsTokenRestricted", func(e *Emu) uint64 {
		t := e.token(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		e.SetLastError(0)
		return b2u(len(t.restricted) > 0)
	})
	reg(a, "CheckTokenMembership", func(e *Emu) uint64 {
		var t *tokenObj
		if e.Arg(0) == 0 {
			t = e.token(pseudoEffectiveToken)
		} else if t = e.token(e.Arg(0)); t == nil {
			return e.fail(errInvalidHandle)
		} else if t.typ != tokenImpersonation {
			return e.fail(errNoImpersonTok)
		}
		s, ok := e.readSid(e.Arg(1))
		if !ok {
			return e.fail(errInvalidSid)
		}
		if e.Arg(2) == 0 {
			return e.fail(errNoAccess)
		}
		t.mu.Lock()
		m := t.member(s)
		t.mu.Unlock()
		e.Mem.W32(e.Arg(2), uint32(b2u(m)))
		return 1
	})
	reg(a, "ImpersonateSelf", func(e *Emu) uint64 {
		if e.Arg32(0) > 3 {
			return e.fail(errBadImpersonLvl)
		}
		n := e.proc.primaryToken().clone(e)
		n.typ, n.level = tokenImpersonation, e.Arg32(0)
		e.setThreadToken(e.Cur, n)
		return 1
	})
	reg(a, "RevertToSelf", func(e *Emu) uint64 { e.setThreadToken(e.Cur, nil); return 1 })
	reg(a, "ImpersonateLoggedOnUser", func(e *Emu) uint64 {
		t := e.token(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		if t.typ == tokenPrimary {
			t = t.clone(e)
			t.typ, t.level = tokenImpersonation, 2 // SecurityImpersonation
		}
		e.setThreadToken(e.Cur, t)
		return 1
	})
	reg(a, "SetThreadToken", func(e *Emu) uint64 {
		th := e.Cur
		if p := e.Arg(0); p != 0 {
			if th = e.threadOf(e.Mem.R64(p)); th == nil {
				return e.fail(errInvalidHandle)
			}
		}
		if e.Arg(1) == 0 {
			e.setThreadToken(th, nil)
			return 1
		}
		t := e.token(e.Arg(1))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		if t.typ != tokenImpersonation {
			return e.fail(errBadTokenType)
		}
		e.setThreadToken(th, t)
		return 1
	})
	regAW(a, "LookupPrivilegeValue", func(e *Emu, w bool) uint64 {
		v, ok := privilegeValue(e.strArg(1, w))
		if !ok {
			return e.fail(errNoSuchPriv)
		}
		if e.Arg(2) == 0 {
			return e.fail(errNoAccess)
		}
		e.Mem.W64(e.Arg(2), uint64(v))
		return 1
	})
	regAW(a, "LookupPrivilegeName", func(e *Emu, w bool) uint64 {
		if e.Arg(1) == 0 || e.Arg(3) == 0 {
			return e.fail(errNoAccess)
		}
		l := e.Mem.R64(e.Arg(1))
		if l >= uint64(len(privilegeNames)) || privilegeNames[l] == "" {
			return e.fail(errNoSuchPriv)
		}
		r := e.putStr(w, e.Arg(2), e.Mem.R32(e.Arg(3)), privilegeNames[l])
		e.Mem.W32(e.Arg(3), uint32(r))
		if r > uint64(len(privilegeNames[l])) {
			return e.fail(errInsufficientBuf)
		}
		return 1
	})
	reg(a, "AdjustTokenPrivileges", func(e *Emu) uint64 {
		t := e.token(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		disableAll, ns, bufLen, prev, retLen := e.Arg32(1) != 0, e.Arg(2), e.Arg32(3), e.Arg(4), e.Arg(5)
		t.mu.Lock()
		defer t.mu.Unlock()
		want := map[uint32]uint32{} // luid -> new attributes (enabled bit or removed)
		missing := false
		if disableAll {
			for _, p := range t.privs {
				want[p.luid] = 0
			}
		} else {
			if ns == 0 {
				return e.fail(errInvalidParameter)
			}
			for i := range uint64(e.Mem.R32(ns)) {
				l, at := e.Mem.R32(ns+4+12*i), e.Mem.R32(ns+4+12*i+8)
				if e.Mem.R32(ns+4+12*i+4) != 0 || !t.holds(l) {
					missing = true
					continue
				}
				want[l] = at & (sePrivEnabled | sePrivRemoved)
			}
		}
		var changed []privAttr
		for _, p := range t.privs {
			if w, ok := want[p.luid]; ok && (w&sePrivRemoved != 0 || p.attr&sePrivEnabled != w&sePrivEnabled) {
				changed = append(changed, p)
			}
		}
		if prev != 0 {
			need := uint32(4 + 12*len(changed))
			if retLen != 0 {
				e.Mem.W32(retLen, need)
			}
			if bufLen < need {
				return e.fail(errInsufficientBuf)
			}
			e.Mem.W32(prev, uint32(len(changed)))
			for i, p := range changed {
				e.Mem.W32(prev+4+12*uint64(i), p.luid)
				e.Mem.W32(prev+8+12*uint64(i), 0)
				e.Mem.W32(prev+12+12*uint64(i), p.attr)
			}
		}
		keep := t.privs[:0]
		for _, p := range t.privs {
			if w, ok := want[p.luid]; ok {
				if w&sePrivRemoved != 0 {
					continue
				}
				p.attr = p.attr&^sePrivEnabled | w&sePrivEnabled
			}
			keep = append(keep, p)
		}
		t.privs = keep
		if len(changed) > 0 {
			t.modified = e.newLuid()
		}
		if missing {
			e.SetLastError(errNotAllAssigned)
		} else {
			e.SetLastError(0)
		}
		return 1
	})
}

func (t *tokenObj) holds(luid uint32) bool {
	for _, p := range t.privs {
		if p.luid == luid {
			return true
		}
	}
	return false
}
