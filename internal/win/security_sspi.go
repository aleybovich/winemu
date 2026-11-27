package win

// Security Support Provider Interface (secur32/sspicli) and the credential
// manager (advapi32 Cred*).
//
// The machine has no security packages installed: EnumerateSecurityPackages
// reports an empty package list, so every package name is unknown
// (SEC_E_SECPKG_NOT_FOUND) and no credential or context handle can ever be
// created; every call taking one fails with SEC_E_INVALID_HANDLE. Callers
// see a well-defined "authentication package unavailable" failure rather
// than a fake handshake. Out parameters are left untouched on failure (MSDN:
// their content is undefined) and are never dereferenced when NULL.
//
// The credential manager is equally empty: reads and deletes report
// ERROR_NOT_FOUND, and writes fail with ERROR_NO_SUCH_LOGON_SESSION (no
// credential set is associated with the logon session).

const (
	secEOK               = 0
	secEInvalidHandle    = 0x80090301
	secESecpkgNotFound   = 0x80090305
	secEInvalidParameter = 0x8009035D

	errNoSuchLogonSession = 1312
)

func init() {
	s := "secur32.dll,sspicli.dll"

	// EnumerateSecurityPackages(PULONG pcPackages, PSecPkgInfo *ppPackageInfo):
	// zero packages; the (empty) buffer is a real block for FreeContextBuffer.
	regAW(s, "EnumerateSecurityPackages", func(e *Emu, _ bool) uint64 {
		if e.Arg(0) == 0 || e.Arg(1) == 0 {
			return secEInvalidParameter
		}
		e.Mem.W32(e.Arg(0), 0)
		e.Mem.W64(e.Arg(1), e.heapAllocRaw(8))
		return secEOK
	})
	// QuerySecurityPackageInfo(name, PSecPkgInfo *ppPackageInfo)
	regAW(s, "QuerySecurityPackageInfo", func(e *Emu, _ bool) uint64 {
		if e.Arg(1) != 0 {
			e.Mem.W64(e.Arg(1), 0)
		}
		return secESecpkgNotFound
	})
	reg(s, "FreeContextBuffer", func(e *Emu) uint64 {
		if p := e.Arg(0); p != 0 {
			e.heap.freeBlock(p)
		}
		return secEOK
	})
	regAW(s, "AcquireCredentialsHandle", func(*Emu, bool) uint64 { return secESecpkgNotFound })
	for _, n := range []string{"InitializeSecurityContextA", "InitializeSecurityContextW", "AcceptSecurityContext",
		"DeleteSecurityContext", "FreeCredentialsHandle", "QuerySecurityContextToken",
		"QueryContextAttributesA", "QueryContextAttributesW"} {
		reg(s, n, ret(secEInvalidHandle))
	}

	// ---- credential manager (advapi32) ----
	a := dAdv
	// CredRead(target, type, flags, PCREDENTIAL *cred)
	regAW(a, "CredRead", func(e *Emu, _ bool) uint64 {
		if e.Arg(0) == 0 || e.Arg(3) == 0 {
			return e.fail(errInvalidParameter)
		}
		return e.fail(errNotFound)
	})
	// CredWrite(PCREDENTIAL cred, flags)
	regAW(a, "CredWrite", func(e *Emu, _ bool) uint64 {
		if e.Arg(0) == 0 {
			return e.fail(errInvalidParameter)
		}
		return e.fail(errNoSuchLogonSession)
	})
	// CredDelete(target, type, flags)
	regAW(a, "CredDelete", func(e *Emu, _ bool) uint64 {
		if e.Arg(0) == 0 {
			return e.fail(errInvalidParameter)
		}
		return e.fail(errNotFound)
	})
	reg(a, "CredFree", func(e *Emu) uint64 {
		if p := e.Arg(0); p != 0 {
			e.heap.freeBlock(p)
		}
		return 0
	})
}
