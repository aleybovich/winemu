package win

import "testing"

func sspiExpect(t *testing.T, name string, got, want uint64) {
	t.Helper()
	if uint32(got) != uint32(want) {
		t.Fatalf("%s = %#x, want %#x", name, uint32(got), uint32(want))
	}
}

func TestSspiNoPackages(t *testing.T) {
	h := newTestEmu(t)
	for _, dll := range []string{"secur32.dll", "sspicli.dll"} {
		cnt, pp := h.alloc(4), h.alloc(8)
		h.w32(cnt, 99)
		sspiExpect(t, "EnumerateSecurityPackagesW", h.call(dll, "EnumerateSecurityPackagesW", cnt, pp), secEOK)
		if h.r32(cnt) != 0 || h.r64(pp) == 0 {
			t.Fatalf("%s: count %d buf %#x", dll, h.r32(cnt), h.r64(pp))
		}
		sspiExpect(t, "FreeContextBuffer", h.call(dll, "FreeContextBuffer", h.r64(pp)), secEOK)
		sspiExpect(t, "EnumerateSecurityPackagesA(NULL)", h.call(dll, "EnumerateSecurityPackagesA", 0, pp), secEInvalidParameter)
		sspiExpect(t, "FreeContextBuffer(NULL)", h.call(dll, "FreeContextBuffer", 0), secEOK)

		h.w64(pp, 0x1234)
		sspiExpect(t, "QuerySecurityPackageInfoW", h.call(dll, "QuerySecurityPackageInfoW", h.wstr("Negotiate"), pp), secESecpkgNotFound)
		if h.r64(pp) != 0 {
			t.Fatalf("QuerySecurityPackageInfoW left %#x", h.r64(pp))
		}
		sspiExpect(t, "QuerySecurityPackageInfoA", h.call(dll, "QuerySecurityPackageInfoA", h.astr("NTLM"), pp), secESecpkgNotFound)
		sspiExpect(t, "QuerySecurityPackageInfoA(NULL out)", h.call(dll, "QuerySecurityPackageInfoA", h.astr("NTLM"), 0), secESecpkgNotFound)

		cred, exp := h.alloc(16), h.alloc(8)
		sspiExpect(t, "AcquireCredentialsHandleA", h.call(dll, "AcquireCredentialsHandleA", 0, h.astr("SSPI"), 1, 0, 0, 0, 0, cred, exp), secESecpkgNotFound)
		sspiExpect(t, "AcquireCredentialsHandleW", h.call(dll, "AcquireCredentialsHandleW", 0, h.wstr("Kerberos"), 2, 0, 0, 0, 0, cred, 0), secESecpkgNotFound)
		sspiExpect(t, "AcquireCredentialsHandleW(NULL pkg)", h.call(dll, "AcquireCredentialsHandleW", 0, 0, 2, 0, 0, 0, 0, cred, 0), secESecpkgNotFound)
	}
}

func TestSspiInvalidHandles(t *testing.T) {
	h := newTestEmu(t)
	d := "secur32.dll"
	bogus := h.alloc(16)
	h.w64(bogus, 0x1111)
	h.w64(bogus+8, 0x2222)
	ctx, out, attr, exp, tok := h.alloc(16), h.alloc(32), h.alloc(4), h.alloc(8), h.alloc(8)
	for _, fn := range []string{"InitializeSecurityContextA", "InitializeSecurityContextW"} {
		sspiExpect(t, fn, h.call(d, fn, bogus, 0, h.astr("host"), 0, 0, 0, 0, 0, ctx, out, attr, exp), secEInvalidHandle)
		sspiExpect(t, fn+"(NULL, NULL)", h.call(d, fn, 0, 0, 0, 0, 0, 0, 0, 0, ctx, out, attr, exp), secEInvalidHandle)
		sspiExpect(t, fn+"(continue)", h.call(d, fn, 0, bogus, 0, 0, 0, 0, 0, 0, ctx, out, attr, exp), secEInvalidHandle)
	}
	sspiExpect(t, "AcceptSecurityContext", h.call(d, "AcceptSecurityContext", bogus, 0, 0, 0, 0, ctx, out, attr, exp), secEInvalidHandle)
	sspiExpect(t, "AcceptSecurityContext(NULL)", h.call(d, "AcceptSecurityContext", 0, 0, 0, 0, 0, 0, 0, 0, 0), secEInvalidHandle)
	for _, fn := range []string{"DeleteSecurityContext", "FreeCredentialsHandle"} {
		sspiExpect(t, fn, h.call(d, fn, bogus), secEInvalidHandle)
		sspiExpect(t, fn+"(NULL)", h.call(d, fn, 0), secEInvalidHandle)
	}
	h.w64(tok, 0x77)
	sspiExpect(t, "QuerySecurityContextToken", h.call(d, "QuerySecurityContextToken", bogus, tok), secEInvalidHandle)
	if h.r64(tok) != 0x77 {
		t.Fatalf("QuerySecurityContextToken wrote %#x", h.r64(tok))
	}
	sspiExpect(t, "QuerySecurityContextToken(NULL)", h.call(d, "QuerySecurityContextToken", 0, 0), secEInvalidHandle)
	for _, fn := range []string{"QueryContextAttributesA", "QueryContextAttributesW"} {
		sspiExpect(t, fn, h.call(d, fn, bogus, 0, out), secEInvalidHandle)
		sspiExpect(t, fn+"(NULL)", h.call(d, fn, 0, 0, 0), secEInvalidHandle)
	}
}

func TestCredentialManagerEmpty(t *testing.T) {
	h := newTestEmu(t)
	out := h.alloc(8)
	h.w64(out, 0x55)
	secExpectFail(t, h, "CredReadW", h.call(dAdv, "CredReadW", h.wstr("svc"), 1, 0, out), errNotFound)
	if h.r64(out) != 0x55 {
		t.Fatalf("CredReadW wrote %#x", h.r64(out))
	}
	secExpectFail(t, h, "CredReadW(NULL target)", h.call(dAdv, "CredReadW", 0, 1, 0, out), errInvalidParameter)
	secExpectFail(t, h, "CredReadW(NULL out)", h.call(dAdv, "CredReadW", h.wstr("svc"), 1, 0, 0), errInvalidParameter)
	cred := h.alloc(80)
	h.w32(cred+4, 1)                // CRED_TYPE_GENERIC
	h.w64(cred+8, h.wstr("target")) // TargetName
	secExpectFail(t, h, "CredWriteW", h.call(dAdv, "CredWriteW", cred, 0), errNoSuchLogonSession)
	secExpectFail(t, h, "CredWriteW(NULL)", h.call(dAdv, "CredWriteW", 0, 0), errInvalidParameter)
	secExpectFail(t, h, "CredDeleteW", h.call(dAdv, "CredDeleteW", h.wstr("svc"), 1, 0), errNotFound)
	secExpectFail(t, h, "CredDeleteW(NULL)", h.call(dAdv, "CredDeleteW", 0, 1, 0), errInvalidParameter)
	h.call(dAdv, "CredFree", 0)
	h.call(dAdv, "CredFree", h.call(dK32, "LocalAlloc", 0, 16))
}
