package win

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"winemu/internal/mem"
)

func TestCrtLock(t *testing.T) {
	h := newTestEmu(t)
	h.call(dMsvc, "_lock", 5)
	h.call(dMsvc, "_lock", 5) // recursive for the owning thread
	flag := h.alloc(8)
	worker := h.code(0, gcall{fn: h.export(dMsvc, "_lock"), args: []uint64{5}}, h.setByte(flag, 1),
		gcall{fn: h.export(dMsvc, "_unlock"), args: []uint64{5}})
	th := h.call(dK32, "CreateThread", 0, 0, worker, 0, 0, 0)
	h.call(dK32, "Sleep", 30)
	h.call(dMsvc, "_unlock", 5)
	h.call(dK32, "Sleep", 30)
	if h.r32(flag) != 0 {
		t.Fatal("worker got a lock still held once")
	}
	h.call(dMsvc, "_unlock", 5)
	if r := h.call(dK32, "WaitForSingleObject", th, 2000); r != waitObject0 || h.r32(flag) != 1 {
		t.Fatalf("worker: wait %#x flag %d", r, h.r32(flag))
	}
	if _, exited, code := h.tryCall(dMsvc, "_lock", 36); !exited || code != 255 || !strings.Contains(h.stderr(), "R6017") {
		t.Fatalf("_lock(36): exited %v code %d stderr %q", exited, code, h.stderr())
	}
}

func TestAmsgExit(t *testing.T) {
	h := newTestEmu(t)
	if _, exited, code := h.tryCall(dMsvc, "_amsg_exit", 8); !exited || code != 255 || !strings.Contains(h.stderr(), "runtime error R6008") {
		t.Fatalf("_amsg_exit(8): exited %v code %d stderr %q", exited, code, h.stderr())
	}
}

func TestWstat64i32(t *testing.T) {
	h := newTestEmu(t)
	path := tempFilePath(t, h, "st.txt")
	fh := h.call(dK32, "CreateFileW", h.wstr(path), qaGenericRW, 0, 0, qaCreateAlways, qaFileAttrNormal, 0)
	h.call(dK32, "WriteFile", fh, h.astr("12345"), 5, h.alloc(4), 0)
	h.call(dK32, "CloseHandle", fh)
	st := h.alloc(48)
	if r := h.call(dUcrt, "_wstat64i32", h.wstr(path), st); r != 0 || h.r32(st+20) != 5 || h.r16(st+6)&0xF000 != 0x8000 {
		t.Fatalf("_wstat64i32 = %d size %d mode %#o", r, h.r32(st+20), h.r16(st+6))
	}
	if r := h.call(dUcrt, "_wstat64i32", h.wstr(path+".missing"), st); int32(r) != -1 || h.r32(h.call(dUcrt, "_errno")) != 2 {
		t.Fatalf("missing: ret %d errno %d", int32(r), h.r32(h.call(dUcrt, "_errno")))
	}
}

func TestGetNLSVersionEx(t *testing.T) {
	h := newTestEmu(t)
	v := h.alloc(32)
	h.w32(v, 32)
	if r := h.call(dK32, "GetNLSVersionEx", 1, h.wstr("en-US"), v); r != 1 || h.r32(v+4) == 0 || h.r32(v+8) == 0 || h.r32(v+12) != 0x409 || h.r64(v+16) == 0 {
		t.Fatalf("GetNLSVersionEx = %d %x", r, h.read(v, 32))
	}
	if r := h.call(dK32, "GetNLSVersionEx", 1, 0, v); r != 1 {
		t.Fatalf("default locale: %d", r)
	}
	h.w32(v, 12)
	if r := h.call(dK32, "GetNLSVersionEx", 1, h.wstr("en-US"), v); r != 0 || h.lastError() != errInsufficientBuf {
		t.Fatalf("small struct: %d %d", r, h.lastError())
	}
	h.w32(v, 32)
	if r := h.call(dK32, "GetNLSVersionEx", 2, 0, v); r != 0 || h.lastError() != 1004 {
		t.Fatalf("bad function: %d %d", r, h.lastError())
	}
	if r := h.call(dK32, "GetNLSVersionEx", 1, 0, 0); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("null info: %d %d", r, h.lastError())
	}
}

func TestGeoInfo(t *testing.T) {
	h := newTestEmu(t)
	if g := h.call(dK32, "GetUserGeoID", 16); g != 244 {
		t.Fatalf("GetUserGeoID(GEOCLASS_NATION) = %d", g)
	}
	if g := uint32(h.call(dK32, "GetUserGeoID", 5)); g != 0xFFFFFFFF {
		t.Fatalf("GetUserGeoID(bad class) = %d, want GEOID_NOT_AVAILABLE", int32(g))
	}
	if n := h.call(dK32, "GetGeoInfoW", 244, 4, 0, 0, 0); n != 3 {
		t.Fatalf("GetGeoInfoW probe = %d", n)
	}
	buf := h.alloc(64)
	for typ, want := range map[uint64]string{4: "US", 5: "USA", 8: "United States", 7: "00000409", 1: "244", 15: "USD"} {
		if n := h.call(dK32, "GetGeoInfoW", 244, typ, buf, 32, 0); n != uint64(len(want)+1) || h.readWStr(buf) != want {
			t.Fatalf("GetGeoInfoW(type %d) = %d %q, want %q", typ, n, h.readWStr(buf), want)
		}
	}
	if n := h.call(dK32, "GetGeoInfoA", 244, 5, buf, 32, 0); n != 4 || h.readAStr(buf) != "USA" {
		t.Fatalf("GetGeoInfoA = %d %q", n, h.readAStr(buf))
	}
	if n := h.call(dK32, "GetGeoInfoW", 244, 4, buf, 3, 0); n != 3 || h.readWStr(buf) != "US" { // exact size
		t.Fatalf("exact buffer: %d %q", n, h.readWStr(buf))
	}
	if n := h.call(dK32, "GetGeoInfoW", 244, 4, buf, 2, 0); n != 0 || h.lastError() != errInsufficientBuf {
		t.Fatalf("small buffer: %d %d", n, h.lastError())
	}
	if n := h.call(dK32, "GetGeoInfoW", 12345, 4, buf, 32, 0); n != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("bad geo id: %d %d", n, h.lastError())
	}
	if n := h.call(dK32, "GetGeoInfoW", 244, 10, buf, 32, 0); n != 0 || h.lastError() != 1004 {
		t.Fatalf("unsupported type: %d %d", n, h.lastError())
	}
}

// resImage builds a minimal PE image with a resource directory:
//
//	"MYTYPE" / "NAME1" / lang 0
//	16 (RT_VERSION) / 1 / langs 0x409, 0x407
func resImage(t *testing.T, h *testEmu) uint64 {
	r, err := h.E.Mem.Alloc(0x3000, mem.PageReadWrite, mem.MemImage, "res.dll")
	if err != nil {
		t.Fatal(err)
	}
	b, rs := r.Base, uint64(0x1000)
	h.w16(b, 0x5A4D)
	h.w32(b+0x3C, 0x80)
	h.w32(b+0x80, 0x4550)
	h.w16(b+0x98, 0x20B)
	h.w32(b+0x98+108, 16)        // NumberOfRvaAndSizes
	h.w32(b+0x98+112+16, 0x1000) // resource directory RVA
	h.w32(b+0x98+112+20, 0x400)
	at := b + rs
	next := uint64(0)
	take := func(n uint64) uint64 { o := next; next += (n + 7) &^ 7; return o }
	str := func(s string) uint64 {
		u := utf16.Encode([]rune(s))
		o := take(2 + 2*uint64(len(u)))
		h.w16(at+o, uint16(len(u)))
		for i, c := range u {
			h.w16(at+o+2+2*uint64(i), c)
		}
		return o
	}
	type ent struct{ name, off uint32 }
	dir := func(named, ids int) (uint64, func(i int, e ent)) {
		o := take(16 + 8*uint64(named+ids))
		h.w16(at+o+12, uint16(named))
		h.w16(at+o+14, uint16(ids))
		return o, func(i int, e ent) { h.w32(at+o+16+8*uint64(i), e.name); h.w32(at+o+20+8*uint64(i), e.off) }
	}
	data := func() uint32 { o := take(16); h.w32(at+o, 0x2000); h.w32(at+o+4, 4); return uint32(o) }
	const sub = 0x80000000
	root, setRoot := dir(1, 1)
	_ = root
	my, setMy := dir(1, 0)
	myName, setMyName := dir(0, 1)
	ver, setVer := dir(0, 1)
	verName, setVerName := dir(0, 2)
	setRoot(0, ent{sub | uint32(str("MYTYPE")), sub | uint32(my)})
	setRoot(1, ent{16, sub | uint32(ver)})
	setMy(0, ent{sub | uint32(str("NAME1")), sub | uint32(myName)})
	setMyName(0, ent{0, data()})
	setVer(0, ent{1, sub | uint32(verName)})
	setVerName(0, ent{0x407, data()})
	setVerName(1, ent{0x409, data()})
	h.E.modules = append(h.E.modules, &Module{Name: "res.dll", Base: b, Size: 0x3000, Native: true})
	return b
}

var resCBSeq int

// resCallback returns an EnumResLangProc that records its calls; it returns
// FALSE (stop) after stopAfter calls if stopAfter > 0.
func resCallback(h *testEmu, calls *[]string, stopAfter int) uint64 {
	resCBSeq++
	return h.E.stub("test", fmt.Sprintf("enumres%d", resCBSeq), func(e *Emu) uint64 {
		*calls = append(*calls, fmt.Sprintf("%#x/%#x/%#x/%#x/%d", e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3)&0xFFFF, e.Arg(4)))
		return b2u(stopAfter == 0 || len(*calls) < stopAfter)
	})
}

func TestEnumResourceLanguages(t *testing.T) {
	h := newTestEmu(t)
	mod := resImage(t, h)
	var calls []string
	cb := resCallback(h, &calls, 0)
	if r := h.call(dK32, "EnumResourceLanguagesW", mod, 16, 1, cb, 7); r != 1 || len(calls) != 2 ||
		calls[0] != fmt.Sprintf("%#x/0x10/0x1/0x407/7", mod) || !strings.HasSuffix(calls[1], "/0x409/7") {
		t.Fatalf("EnumResourceLanguagesW(16, 1) = %d %v", r, calls)
	}
	for _, tc := range []struct {
		fn        string
		typ, name uint64
		wantLangs int
		wantErr   uint32
	}{
		{"EnumResourceLanguagesW", h.wstr("mytype"), h.wstr("Name1"), 1, 0},
		{"EnumResourceLanguagesW", h.wstr("#16"), h.wstr("#1"), 2, 0},
		{"EnumResourceLanguagesA", h.astr("MYTYPE"), h.astr("NAME1"), 1, 0},
		{"EnumResourceLanguagesExW", 16, 1, 2, 0},
		{"EnumResourceLanguagesW", 6, 1, 0, 1813},
		{"EnumResourceLanguagesW", 16, 2, 0, 1814},
		{"EnumResourceLanguagesA", h.astr("NOPE"), 1, 0, 1813},
	} {
		calls = nil
		h.setLastError(0)
		r := h.call(dK32, tc.fn, mod, tc.typ, tc.name, cb, 0, 0, 0)
		if len(calls) != tc.wantLangs || (tc.wantErr == 0) != (r == 1) || (tc.wantErr != 0 && h.lastError() != tc.wantErr) {
			t.Fatalf("%s(%#x, %#x) = %d lastError %d calls %v", tc.fn, tc.typ, tc.name, r, h.lastError(), calls)
		}
	}
	calls = nil
	stop := resCallback(h, &calls, 1)
	if r := h.call(dK32, "EnumResourceLanguagesW", mod, 16, 1, stop, 0); r != 0 || len(calls) != 1 || h.lastError() != 15106 {
		t.Fatalf("stopped enumeration = %d calls %d lastError %d", r, len(calls), h.lastError())
	}
	k32 := h.call(dK32, "GetModuleHandleW", h.wstr("kernel32.dll"))
	if r := h.call(dK32, "EnumResourceLanguagesW", k32, 16, 1, cb, 0); r != 0 || h.lastError() != 1812 {
		t.Fatalf("module without resources = %d lastError %d", r, h.lastError())
	}
}

func TestCertStore(t *testing.T) {
	h := newTestEmu(t)
	const crypt = "crypt32.dll"
	st := h.call(crypt, "CertOpenStore", 10, 0, 0, 1<<16, h.wstr("ROOT")) // CERT_STORE_PROV_SYSTEM_W, CURRENT_USER
	if st == 0 {
		t.Fatalf("CertOpenStore(system) failed: %#x", h.lastError())
	}
	if r := h.call(crypt, "CertEnumCertificatesInStore", st, 0); r != 0 || h.lastError() != cryptENotFound {
		t.Fatalf("enum = %#x lastError %#x", r, h.lastError())
	}
	if r := h.call(crypt, "CertFindCertificateInStore", st, 1, 0, 0, 0, 0); r != 0 || h.lastError() != cryptENotFound {
		t.Fatalf("find = %#x lastError %#x", r, h.lastError())
	}
	if h.call(crypt, "CertCloseStore", st, 0) != 1 || h.call(crypt, "CertCloseStore", 0, 0) != 1 {
		t.Fatal("CertCloseStore")
	}
	if r := h.call(crypt, "CertOpenStore", 999, 0, 0, 0, 0); r != 0 || h.lastError() != errFileNotFound {
		t.Fatalf("unknown provider = %#x lastError %d", r, h.lastError())
	}
	mst := h.call(crypt, "CertOpenStore", 2, 0, 0, 0, 0) // CERT_STORE_PROV_MEMORY
	if mst == 0 || h.call(crypt, "CertDuplicateCertificateContext", 0) != 0 || h.call(crypt, "CertFreeCertificateContext", 0) != 1 {
		t.Fatal("memory store / context refcounting")
	}
	if r := h.call(crypt, "CertGetCertificateContextProperty", 0, 2, 0, h.alloc(4)); r != 0 {
		t.Fatalf("property of null context = %d", r)
	}
	// CertFindExtension searches a CERT_EXTENSION array.
	exts := h.alloc(64)
	h.w64(exts, h.astr("2.5.29.19"))
	h.w64(exts+32, h.astr("2.5.29.15"))
	if r := h.call(crypt, "CertFindExtension", h.astr("2.5.29.15"), 2, exts); r != exts+32 {
		t.Fatalf("CertFindExtension = %#x, want %#x", r, exts+32)
	}
	if r := h.call(crypt, "CertFindExtension", h.astr("1.2.3"), 2, exts); r != 0 {
		t.Fatalf("CertFindExtension(missing) = %#x", r)
	}
	if n := h.call(crypt, "CertGetNameStringA", 0, 4, 0, 0, 0, 0); n != 1 {
		t.Fatalf("CertGetNameStringA probe = %d", n)
	}
}

func TestCryptStringToBinaryA(t *testing.T) {
	h := newTestEmu(t)
	const crypt = "crypt32.dll"
	in := h.astr("-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n")
	n := h.alloc(4)
	if r := h.call(crypt, "CryptStringToBinaryA", in, 0, 0, 0, n, 0, 0); r != 1 || h.r32(n) != 5 { // CRYPT_STRING_BASE64HEADER
		t.Fatalf("probe = %d len %d", r, h.r32(n))
	}
	buf := h.alloc(16)
	h.w32(n, 3)
	if r := h.call(crypt, "CryptStringToBinaryA", in, 0, 0, buf, n, 0, 0); r != 0 || h.lastError() != errMoreData {
		t.Fatalf("small buffer = %d lastError %d", r, h.lastError())
	}
	h.w32(n, 16)
	if r := h.call(crypt, "CryptStringToBinaryA", in, 0, 0, buf, n, 0, 0); r != 1 || string(h.read(buf, 5)) != "hello" {
		t.Fatalf("decode = %d %q", r, h.read(buf, int(h.r32(n))))
	}
	if r := h.call(crypt, "CryptStringToBinaryA", h.astr("aGk="), 4, 1, buf, n, 0, 0); r != 1 || h.r32(n) != 2 { // BASE64
		t.Fatalf("base64 = %d len %d", r, h.r32(n))
	}
	if r := h.call(crypt, "CryptStringToBinaryA", h.astr("!!!"), 0, 1, buf, n, 0, 0); r != 0 || h.lastError() != errInvalidData {
		t.Fatalf("bad base64 = %d lastError %d", r, h.lastError())
	}
	if r := h.call(crypt, "CryptStringToBinaryA", h.astr("0a ff"), 0, 4, buf, n, 0, 0); r != 1 || h.r32(n) != 2 || h.r16(buf) != 0xFF0A { // HEX
		t.Fatalf("hex = %d len %d %x", r, h.r32(n), h.read(buf, 2))
	}
}

func TestCryptoAPIFailures(t *testing.T) {
	h := newTestEmu(t)
	prov := h.alloc(8)
	if h.call(dAdv, "CryptAcquireContextW", prov, 0, 0, 1, 0xF0000000) != 1 {
		t.Fatal("CryptAcquireContextW")
	}
	p, out := h.r64(prov), h.alloc(64)
	for _, c := range []struct {
		fn   string
		args []uint64
		err  uint32
	}{
		{"CryptCreateHash", []uint64{p, 0x800C, 0, 0, out}, nteBadAlgid},
		{"CryptGetUserKey", []uint64{p, 1, out}, nteNoKey},
		{"CryptDestroyKey", []uint64{0x99}, nteBadKey},
		{"CryptDestroyHash", []uint64{0x99}, nteBadHash},
		{"CryptHashData", []uint64{0x99, out, 4, 0}, nteBadHash},
		{"CryptExportKey", []uint64{0x99, 0, 6, 0, 0, out}, nteBadKey},
		{"CryptDecrypt", []uint64{0x99, 0, 1, 0, out, out}, nteBadKey},
		{"CryptSignHashW", []uint64{0x99, 1, 0, 0, 0, out}, nteBadHash},
		{"CryptGetProvParam", []uint64{p, 2, out, out, 1}, errNoMoreItems},
		{"CryptEnumProvidersW", []uint64{0, 0, 0, out, 0, out}, errNoMoreItems},
	} {
		h.setLastError(0)
		if r := h.call(dAdv, c.fn, c.args...); r != 0 || h.lastError() != c.err {
			t.Fatalf("%s = %d lastError %#x, want 0 / %#x", c.fn, r, h.lastError(), c.err)
		}
	}
}
