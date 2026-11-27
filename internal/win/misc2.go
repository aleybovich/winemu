package win

// Assorted runtime-library APIs (WS-C): msvcrt locks, UCRT stat variants,
// NLS/geo queries, resource enumeration, crypt32/advapi32 crypto stubs.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// BuiltinHas reports whether an import dll!name (or ordinal, as "#n") is
// implemented by winemu's builtin DLLs, resolving DLL aliases and API sets
// the way the loader does. Used by tools/peimports.
func BuiltinHas(dll, name string) bool {
	canon, _ := canonicalBuiltin(normDLL(dll))
	if strings.HasPrefix(canon, "api-ms-") || strings.HasPrefix(canon, "ext-ms-") {
		for _, d := range apisetOrder {
			if t := registry[d]; t != nil && t.funcs[name] != nil {
				return true
			}
		}
		return false
	}
	t := registry[canon]
	if t == nil {
		return false
	}
	if ord, err := strconv.ParseUint(strings.TrimPrefix(name, "#"), 10, 32); err == nil && strings.HasPrefix(name, "#") {
		n, ok := t.ords[uint32(ord)]
		return ok && t.funcs[n] != nil
	}
	return t.funcs[name] != nil
}

// ---------------------------------------------------------------------------
// msvcrt.dll internal locks (_lock/_unlock, used by MinGW-built code):
// recursive per-thread locks numbered 0.._TOTAL_LOCKS-1.

const crtTotalLocks = 36

type crtLock struct {
	owner *Thread
	count int
}

// amsgExit is _amsg_exit: report CRT runtime error R60nn and _exit(255).
func (e *Emu) amsgExit(code uint32) {
	msgs := map[uint32]string{2: "floating point support not loaded", 8: "not enough space for arguments",
		9: "not enough space for environment", 16: "not enough space for thread data", 17: "unexpected multithread lock error",
		18: "unexpected heap error", 19: "unable to open console device", 24: "not enough space for _onexit/atexit table"}
	e.crt.flushAll()
	fmt.Fprintf(e.Opt.Stderr, "\r\nruntime error R60%02d\r\n", code)
	if m, ok := msgs[code]; ok {
		fmt.Fprintf(e.Opt.Stderr, "- %s\r\n", m)
	}
	e.exitProcess(255)
}

func init() {
	reg(dMsvc, "_amsg_exit", func(e *Emu) uint64 { e.amsgExit(e.Arg32(0)); return 0 })
	reg(dMsvc, "_lock", func(e *Emu) uint64 {
		n := int32(e.Arg32(0))
		if n < 0 || n >= crtTotalLocks {
			e.amsgExit(17) // _RT_LOCK
		}
		locks := e.rtl().crtLocks
		l := locks[n]
		if l == nil {
			l = &crtLock{}
			locks[n] = l
		}
		if l.owner != nil && l.owner != e.Cur {
			e.block(func() bool { return l.owner == nil }, infinite)
			return 0
		}
		e.endWaitIf()
		l.owner = e.Cur
		l.count++
		return 0
	})
	reg(dMsvc, "_unlock", func(e *Emu) uint64 {
		if l := e.rtl().crtLocks[int32(e.Arg32(0))]; l != nil && l.owner == e.Cur {
			if l.count--; l.count == 0 {
				l.owner = nil
			}
		}
		return 0
	})
}

// ---------------------------------------------------------------------------
// NLS: GetNLSVersionEx, geographical locations (the emulated user is in the
// United States, GEOID 244).

const (
	errInvalidFlags  = 1004
	geoIDUS          = 244
	geoIDNorthAmeric = 39070 // "Northern America", the parent region of 244
)

var geoInfoUS = map[uint32]string{
	1: "244", 2: "39.45", 3: "-98.908", 4: "US", 5: "USA", 6: "en-US", 7: "00000409",
	8: "United States", 9: "United States of America", 11: "en", 12: "840", 13: "39070",
	14: "1", 15: "USD", 16: "$", 17: "US", 18: "244",
}

// geoInfo implements GetGeoInfoA/W; the result is copied with its NUL.
func (e *Emu) geoInfo(geo, typ uint32, buf uint64, n uint32, wide bool) uint64 {
	if geo != geoIDUS {
		return e.fail(errInvalidParameter)
	}
	s, ok := geoInfoUS[typ]
	if !ok {
		return e.fail(errInvalidFlags)
	}
	need := uint64(len(utf16.Encode([]rune(s))) + 1)
	if !wide {
		need = uint64(len(s) + 1)
	}
	if n == 0 {
		return need
	}
	if buf == 0 || uint64(n) < need {
		return e.fail(errInsufficientBuf)
	}
	if wide {
		e.Mem.WriteWStr(buf, s)
	} else {
		e.Mem.WriteCStr(buf, s)
	}
	return need
}

func init() {
	k := dK32
	// BOOL GetNLSVersionEx(NLS_FUNCTION, LPCWSTR, LPNLSVERSIONINFOEX):
	// NLSVERSIONINFOEX { dwNLSVersionInfoSize; dwNLSVersion; dwDefinedVersion;
	// dwEffectiveId; GUID guidCustomVersion; } (32 bytes).
	reg(k, "GetNLSVersionEx", func(e *Emu) uint64 {
		fn, info := e.Arg32(0), e.Arg(2)
		if fn != 1 { // COMPARE_STRING
			return e.fail(errInvalidFlags)
		}
		if info == 0 {
			return e.fail(errInvalidParameter)
		}
		m := e.Mem
		if m.R32(info) != 32 {
			return e.fail(errInsufficientBuf)
		}
		const ver = 0x60305 // NLS sorting version 6.3.5 (major << 8 | minor)
		m.W32(info+4, ver)
		m.W32(info+8, ver)
		m.W32(info+12, userLCID)
		m.Write(info+16, []byte{0x05, 0, 0, 0, 0xEE, 0x57, 0x5C, 0x1E, 0x00, 0xB4, 0xD0, 0x00, 0x0B, 0xB1, 0xE1, 0x1E})
		return 1
	})
	reg(k, "GetUserGeoID", func(e *Emu) uint64 {
		switch e.Arg32(0) {
		case 16: // GEOCLASS_NATION
			return geoIDUS
		case 14: // GEOCLASS_REGION
			return geoIDNorthAmeric
		}
		return 0xFFFFFFFF // GEOID_NOT_AVAILABLE
	})
	reg(k, "GetGeoInfoW", func(e *Emu) uint64 { return e.geoInfo(e.Arg32(0), e.Arg32(1), e.Arg(2), e.Arg32(3), true) })
	reg(k, "GetGeoInfoA", func(e *Emu) uint64 { return e.geoInfo(e.Arg32(0), e.Arg32(1), e.Arg(2), e.Arg32(3), false) })
}

// ---------------------------------------------------------------------------
// Resources: EnumResourceLanguages* walk the resource directory
// (IMAGE_DIRECTORY_ENTRY_RESOURCE) of the module as mapped in memory.

const (
	errResDataNotFound = 1812
	errResTypeNotFound = 1813
	errResNameNotFound = 1814
	errResEnumUserStop = 15106
)

// resKey is a resource type or name: an integer id, or a string matched
// case-insensitively ("#123" is the id 123).
type resKey struct {
	id    uint32
	name  string
	isStr bool
}

func (e *Emu) resKeyArg(p uint64, wide bool) resKey {
	if p < 0x10000 {
		return resKey{id: uint32(p)}
	}
	s := e.CStr(p)
	if wide {
		s = e.WStr(p)
	}
	if strings.HasPrefix(s, "#") {
		if n, err := strconv.ParseUint(s[1:], 10, 16); err == nil {
			return resKey{id: uint32(n)}
		}
	}
	return resKey{name: s, isStr: true}
}

// resourceSection returns the address of the module's resource directory.
func (e *Emu) resourceSection(hmod uint64) (uint64, uint32) {
	var mod *Module
	if hmod == 0 {
		mod = e.exe
	} else {
		for _, m := range e.modules {
			if m.Base == hmod&^3 { // low bits: LoadLibraryEx data-file mappings
				mod = m
				break
			}
		}
	}
	if mod == nil {
		return 0, errModNotFound
	}
	m, b := e.Mem, mod.Base
	opt := b + uint64(m.R32(b+0x3C)) + 24
	if m.R16(opt) != 0x20B || m.R32(opt+108) < 3 {
		return 0, errResDataNotFound
	}
	rva, size := m.R32(opt+112+16), m.R32(opt+112+20)
	if rva == 0 || size == 0 {
		return 0, errResDataNotFound
	}
	return b + uint64(rva), 0
}

// resEntries calls f(name field, offset field) for each entry of the
// directory at dir (named entries first, as stored).
func (e *Emu) resEntries(dir uint64, f func(name, off uint32) bool) {
	m := e.Mem
	n := uint64(m.R16(dir+12)) + uint64(m.R16(dir+14))
	for i := range n {
		if !f(m.R32(dir+16+8*i), m.R32(dir+20+8*i)) {
			return
		}
	}
}

// resFind returns the subdirectory of dir matching k.
func (e *Emu) resFind(rs, dir uint64, k resKey) (uint64, bool) {
	var found uint64
	e.resEntries(dir, func(name, off uint32) bool {
		if off&0x80000000 == 0 {
			return true
		}
		var match bool
		if name&0x80000000 != 0 {
			s := rs + uint64(name&0x7FFFFFFF)
			n := int(e.Mem.R16(s))
			u := make([]uint16, n)
			for i := range u {
				u[i] = e.Mem.R16(s + 2 + 2*uint64(i))
			}
			match = k.isStr && strings.EqualFold(string(utf16.Decode(u)), k.name)
		} else {
			match = !k.isStr && name&0xFFFF == k.id
		}
		if match {
			found = rs + uint64(off&0x7FFFFFFF)
		}
		return !match
	})
	return found, found != 0
}

// enumResourceLanguages implements EnumResourceLanguages(Ex)A/W.
func (e *Emu) enumResourceLanguages(wide bool) uint64 {
	hmod, typ, name, fn, lp := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4)
	rs, errc := e.resourceSection(hmod)
	if errc != 0 {
		return e.fail(errc)
	}
	td, ok := e.resFind(rs, rs, e.resKeyArg(typ, wide))
	if !ok {
		return e.fail(errResTypeNotFound)
	}
	nd, ok := e.resFind(rs, td, e.resKeyArg(name, wide))
	if !ok {
		return e.fail(errResNameNotFound)
	}
	var langs []uint64
	e.resEntries(nd, func(n, _ uint32) bool { langs = append(langs, uint64(n&0xFFFF)); return true })
	for _, l := range langs {
		if uint32(e.CallGuest(fn, hmod, typ, name, l, lp)) == 0 {
			return e.fail(errResEnumUserStop)
		}
	}
	return 1
}

func init() {
	reg(dK32, "EnumResourceLanguagesW", func(e *Emu) uint64 { return e.enumResourceLanguages(true) })
	reg(dK32, "EnumResourceLanguagesExW", func(e *Emu) uint64 { return e.enumResourceLanguages(true) })
	reg(dK32, "EnumResourceLanguagesA", func(e *Emu) uint64 { return e.enumResourceLanguages(false) })
	reg(dK32, "EnumResourceLanguagesExA", func(e *Emu) uint64 { return e.enumResourceLanguages(false) })
}

// ---------------------------------------------------------------------------
// crypt32 / advapi32 crypto. There are no certificates and no CSP keys:
// stores open empty, searches report CRYPT_E_NOT_FOUND, and key/hash
// operations fail with the documented NTE_* codes.

const (
	cryptENotFound  = 0x80092004
	cryptENoMatch   = 0x80092009
	cryptEASN1Tag   = 0x8009310B
	eInvalidArg     = 0x80070057
	nteBadHash      = 0x80090002
	nteBadKey       = 0x80090003
	nteBadData      = 0x80090005
	nteBadAlgid     = 0x80090008
	nteBadType      = 0x8009000A
	nteNoKey        = 0x8009000D
	nteNotSupported = 0x80090029
	certStoreMagic  = 0x524F5453 // "STOR"
)

// certStoreProvider reports whether CertOpenStore supports the provider
// (an integer CERT_STORE_PROV_* or its string name).
func (e *Emu) certStoreProvider(p uint64) bool {
	if p < 0x10000 {
		switch p {
		case 2, 9, 10, 11, 12, 13: // MEMORY, SYSTEM_A/W, COLLECTION, SYSTEM_REGISTRY_A/W
			return true
		}
		return false
	}
	switch lower(e.CStr(p)) {
	case "memory", "system", "system registry", "collection":
		return true
	}
	return false
}

// base64Body extracts the base64 text between PEM "-----BEGIN"/"-----END" lines.
func base64Body(s string) (string, bool) {
	i := strings.Index(s, "-----BEGIN")
	if i < 0 {
		return "", false
	}
	nl := strings.IndexByte(s[i:], '\n')
	if nl < 0 {
		return "", false
	}
	body := s[i+nl+1:]
	j := strings.Index(body, "-----END")
	if j < 0 {
		return "", false
	}
	return body[:j], true
}

func decodeCryptString(s string, flags uint32) ([]byte, uint32, bool) {
	b64 := func(t string) ([]byte, bool) {
		t = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, t)
		b, err := base64.StdEncoding.DecodeString(t)
		return b, err == nil && len(t) > 0
	}
	switch flags {
	case 0, 3, 9: // BASE64HEADER, BASE64REQUESTHEADER, BASE64X509CRLHEADER
		if body, ok := base64Body(s); ok {
			b, ok := b64(body)
			return b, flags, ok
		}
	case 1:
		b, ok := b64(s)
		return b, 1, ok
	case 2:
		return []byte(s), 2, true
	case 4, 8: // HEX, HEX_ANY
		b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
		return b, 4, err == nil
	case 6, 7: // BASE64_ANY, ANY
		if b, f, ok := decodeCryptString(s, 0); ok {
			return b, f, true
		}
		if b, ok := b64(s); ok {
			return b, 1, true
		}
		if flags == 7 {
			return []byte(s), 2, true
		}
	}
	return nil, 0, false
}

func (e *Emu) cryptStringToBinary(wide bool) uint64 {
	m := e.Mem
	p, n, flags, out, pcb, skip, pflags := e.Arg(0), e.Arg32(1), e.Arg32(2), e.Arg(3), e.Arg(4), e.Arg(5), e.Arg(6)
	if p == 0 || pcb == 0 {
		return e.fail(errInvalidParameter)
	}
	var s string
	switch {
	case wide && n == 0:
		s = e.WStr(p)
	case wide:
		u := make([]uint16, n)
		for i := range u {
			u[i] = m.R16(p + 2*uint64(i))
		}
		s = string(utf16.Decode(u))
	case n == 0:
		s = e.CStr(p)
	default:
		s = string(m.ReadBytes(p, int(n)))
	}
	b, used, ok := decodeCryptString(s, flags)
	if !ok {
		return e.fail(errInvalidData)
	}
	if skip != 0 {
		m.W32(skip, 0)
	}
	if pflags != 0 {
		m.W32(pflags, used)
	}
	if out != 0 && uint64(m.R32(pcb)) < uint64(len(b)) {
		m.W32(pcb, uint32(len(b)))
		return e.fail(errMoreData)
	}
	if out != 0 {
		m.Write(out, b)
	}
	m.W32(pcb, uint32(len(b)))
	return 1
}

func init() {
	c := "crypt32.dll"
	reg(c, "CertOpenStore", func(e *Emu) uint64 {
		if !e.certStoreProvider(e.Arg(0)) {
			return e.fail(errFileNotFound) // no such store provider
		}
		st := e.heapAlloc(16, true)
		e.Mem.W32(st, certStoreMagic)
		return st
	})
	reg(c, "CertOpenSystemStoreW", func(e *Emu) uint64 {
		st := e.heapAlloc(16, true)
		e.Mem.W32(st, certStoreMagic)
		return st
	})
	reg(c, "CertOpenSystemStoreA", func(e *Emu) uint64 { return e.callAPI(c, "CertOpenSystemStoreW") })
	reg(c, "CertCloseStore", func(e *Emu) uint64 {
		if st := e.Arg(0); st != 0 && e.Mem.R32(st) == certStoreMagic {
			e.Mem.W32(st, 0)
			e.heap.freeBlock(st)
		}
		return 1
	})
	reg(c, "CertEnumCertificatesInStore", func(e *Emu) uint64 { return e.fail(cryptENotFound) })
	reg(c, "CertFindCertificateInStore", func(e *Emu) uint64 { return e.fail(cryptENotFound) })
	reg(c, "CertDuplicateCertificateContext", func(e *Emu) uint64 { return e.Arg(0) })
	reg(c, "CertFreeCertificateContext", retTrue)
	reg(c, "CertGetCertificateContextProperty", func(e *Emu) uint64 { return e.fail(cryptENotFound) })
	// No certificate context can exist, so any context argument is invalid.
	reg(c, "CertAddCertificateContextToStore", func(e *Emu) uint64 { return e.fail(eInvalidArg) })
	reg(c, "CertCreateCertificateChainEngine", func(e *Emu) uint64 {
		if e.Arg(1) == 0 {
			return e.fail(eInvalidArg)
		}
		e.Mem.W64(e.Arg(1), e.heapAlloc(16, true))
		return 1
	})
	reg(c, "CertFreeCertificateChainEngine", func(e *Emu) uint64 {
		if h := e.Arg(0); h > 1 { // HCCE_CURRENT_USER (0), HCCE_LOCAL_MACHINE (1)
			e.heap.freeBlock(h)
		}
		return 0
	})
	reg(c, "CertGetCertificateChain", func(e *Emu) uint64 { return e.fail(eInvalidArg) })
	reg(c, "CertFreeCertificateChain", retZero)
	// PCERT_EXTENSION CertFindExtension(LPCSTR oid, DWORD n, CERT_EXTENSION rg[]):
	// CERT_EXTENSION { LPSTR pszObjId; BOOL fCritical; CRYPT_OBJID_BLOB Value; } (32 bytes).
	reg(c, "CertFindExtension", func(e *Emu) uint64 {
		oid, n, arr := e.CStr(e.Arg(0)), e.Arg32(1), e.Arg(2)
		for i := range uint64(n) {
			if p := e.Mem.R64(arr + 32*i); p != 0 && e.CStr(p) == oid {
				return arr + 32*i
			}
		}
		return e.fail(cryptENotFound)
	})
	// No name: an empty string, count 1 (the NUL).
	certName := func(wide bool) Fn {
		return func(e *Emu) uint64 {
			if buf, n := e.Arg(4), e.Arg32(5); buf != 0 && n > 0 {
				if wide {
					e.Mem.W16(buf, 0)
				} else {
					e.Mem.W8(buf, 0)
				}
			}
			return 1
		}
	}
	reg(c, "CertGetNameStringA", certName(false))
	reg(c, "CertGetNameStringW", certName(true))
	reg(c, "CryptDecodeObjectEx", func(e *Emu) uint64 { return e.fail(cryptEASN1Tag) })
	reg(c, "CryptQueryObject", func(e *Emu) uint64 { return e.fail(cryptENoMatch) })
	reg(c, "PFXImportCertStore", func(e *Emu) uint64 { return e.fail(nteBadData) })
	reg(c, "CryptStringToBinaryA", func(e *Emu) uint64 { return e.cryptStringToBinary(false) })
	reg(c, "CryptStringToBinaryW", func(e *Emu) uint64 { return e.cryptStringToBinary(true) })

	a := dAdv
	failWith := func(code uint32) Fn { return func(e *Emu) uint64 { return e.fail(code) } }
	reg(a, "CryptCreateHash", failWith(nteBadAlgid))
	for _, n := range []string{"CryptDestroyHash", "CryptHashData", "CryptGetHashParam", "CryptSetHashParam", "CryptSignHashW", "CryptSignHashA"} {
		reg(a, n, failWith(nteBadHash))
	}
	for _, n := range []string{"CryptDestroyKey", "CryptExportKey", "CryptEncrypt", "CryptDecrypt"} {
		reg(a, n, failWith(nteBadKey))
	}
	reg(a, "CryptGetUserKey", failWith(nteNoKey))
	reg(a, "CryptImportKey", failWith(nteNotSupported))
	reg(a, "CryptGetProvParam", func(e *Emu) uint64 {
		switch e.Arg32(1) {
		case 1, 2, 22: // PP_ENUMALGS, PP_ENUMCONTAINERS, PP_ENUMALGS_EX
			return e.fail(errNoMoreItems)
		}
		return e.fail(nteBadType)
	})
	reg(a, "CryptEnumProvidersW", failWith(errNoMoreItems))
	reg(a, "CryptEnumProvidersA", failWith(errNoMoreItems))
}
