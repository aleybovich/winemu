package win

import "testing"

func TestOpenSCManagerAccess(t *testing.T) {
	h := newTestEmu(t)
	for _, fn := range []string{"OpenSCManagerA", "OpenSCManagerW"} {
		str := h.astr
		if fn[len(fn)-1] == 'W' {
			str = h.wstr
		}
		// what a non-admin user is granted: connect, enumerate, read
		for _, acc := range []uint64{scManagerConnect, scManagerEnumerate, 0x80000000 /*GENERIC_READ*/, 0x02000000 /*MAXIMUM_ALLOWED*/, 0} {
			sc := h.call(dAdv, fn, 0, 0, acc)
			if sc == 0 {
				t.Fatalf("%s(%#x) failed, lastError %d", fn, acc, h.lastError())
			}
			if h.call(dAdv, "CloseServiceHandle", sc) != 1 {
				t.Fatalf("CloseServiceHandle failed")
			}
			secExpectFail(t, h, "CloseServiceHandle twice", h.call(dAdv, "CloseServiceHandle", sc), errInvalidHandle)
		}
		if h.call(dAdv, fn, str("."), str("ServicesActive"), scManagerConnect) == 0 {
			t.Fatalf("%s(local, ServicesActive) failed", fn)
		}
		for _, acc := range []uint64{scManagerAllAccess, scManagerCreateService, 0x40000000 /*GENERIC_WRITE*/, 0x10000000 /*GENERIC_ALL*/} {
			secExpectFail(t, h, fn+" admin access", h.call(dAdv, fn, 0, 0, acc), errAccessDenied)
		}
		secExpectFail(t, h, fn+" bad db", h.call(dAdv, fn, 0, str("NoSuchDb"), scManagerConnect), errDatabaseNotExist)
	}
	secExpectFail(t, h, "CloseServiceHandle(NULL)", h.call(dAdv, "CloseServiceHandle", 0), errInvalidHandle)
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	secExpectFail(t, h, "CloseServiceHandle(event)", h.call(dAdv, "CloseServiceHandle", ev), errInvalidHandle)
}

func TestServicesEmptyDatabase(t *testing.T) {
	h := newTestEmu(t)
	sc := h.call(dAdv, "OpenSCManagerA", 0, 0, scManagerConnect)
	name := h.astr("NoSuchService")
	secExpectFail(t, h, "OpenServiceA", h.call(dAdv, "OpenServiceA", sc, name, 0xF01FF), errServiceNotExist)
	secExpectFail(t, h, "OpenServiceW", h.call(dAdv, "OpenServiceW", sc, h.wstr("NoSuchService"), 4), errServiceNotExist)
	secExpectFail(t, h, "OpenServiceA(NULL name)", h.call(dAdv, "OpenServiceA", sc, 0, 4), errInvalidName)
	secExpectFail(t, h, "OpenServiceA(bad scm)", h.call(dAdv, "OpenServiceA", 0x4321, name, 4), errInvalidHandle)
	for _, fn := range []string{"CreateServiceA", "CreateServiceW"} {
		secExpectFail(t, h, fn, h.call(dAdv, fn, sc, name, name, 0xF01FF, 0x10, 3, 1, name, 0, 0, 0, 0, 0), errAccessDenied)
		secExpectFail(t, h, fn+"(bad scm)", h.call(dAdv, fn, 0, name, name, 0xF01FF, 0x10, 3, 1, name, 0, 0, 0, 0, 0), errInvalidHandle)
	}
	st := h.alloc(64)
	need := h.alloc(4)
	// no service handle can exist: every service-handle API rejects any handle (incl. the SCM's)
	for _, hs := range []uint64{0, sc, 0x4321} {
		secExpectFail(t, h, "DeleteService", h.call(dAdv, "DeleteService", hs), errInvalidHandle)
		secExpectFail(t, h, "StartServiceA", h.call(dAdv, "StartServiceA", hs, 0, 0), errInvalidHandle)
		secExpectFail(t, h, "StartServiceW", h.call(dAdv, "StartServiceW", hs, 0, 0), errInvalidHandle)
		secExpectFail(t, h, "QueryServiceStatus", h.call(dAdv, "QueryServiceStatus", hs, st), errInvalidHandle)
		secExpectFail(t, h, "QueryServiceStatusEx", h.call(dAdv, "QueryServiceStatusEx", hs, 0, st, 64, need), errInvalidHandle)
		secExpectFail(t, h, "ControlService", h.call(dAdv, "ControlService", hs, 1, st), errInvalidHandle)
		secExpectFail(t, h, "ChangeServiceConfig2A", h.call(dAdv, "ChangeServiceConfig2A", hs, 1, st), errInvalidHandle)
		secExpectFail(t, h, "ChangeServiceConfig2W", h.call(dAdv, "ChangeServiceConfig2W", hs, 1, st), errInvalidHandle)
	}
	if h.call(dAdv, "CloseServiceHandle", sc) != 1 {
		t.Fatal("CloseServiceHandle failed")
	}
}

func TestServiceProcessNotStartedBySCM(t *testing.T) {
	h := newTestEmu(t)
	table := h.alloc(32)
	h.w64(table, h.astr("NoSuchService"))
	h.w64(table+8, 0x1000)
	for _, fn := range []string{"StartServiceCtrlDispatcherA", "StartServiceCtrlDispatcherW"} {
		secExpectFail(t, h, fn, h.call(dAdv, fn, table), errFailedServiceCtrlConnect)
		secExpectFail(t, h, fn+"(NULL)", h.call(dAdv, fn, 0), errInvalidParameter)
	}
	for _, fn := range []string{"RegisterServiceCtrlHandlerA", "RegisterServiceCtrlHandlerW", "RegisterServiceCtrlHandlerExA", "RegisterServiceCtrlHandlerExW"} {
		secExpectFail(t, h, fn, h.call(dAdv, fn, h.astr("NoSuchService"), 0x1000, 0), errServiceNotInExe)
		secExpectFail(t, h, fn+"(NULL handler)", h.call(dAdv, fn, h.astr("NoSuchService"), 0, 0), errInvalidParameter)
	}
	st := h.alloc(28)
	secExpectFail(t, h, "SetServiceStatus", h.call(dAdv, "SetServiceStatus", 0x1234, st), errInvalidHandle)
	secExpectFail(t, h, "SetServiceStatus(NULL)", h.call(dAdv, "SetServiceStatus", 0, 0), errInvalidHandle)
}

func TestRegCreateKey(t *testing.T) {
	h := newTestEmu(t)
	out := h.alloc(8)
	for _, fn := range []string{"RegCreateKeyA", "RegCreateKeyW"} {
		sub := h.astr(`SYSTEM\CurrentControlSet\Services\EventLog\Application\x`)
		if fn[len(fn)-1] == 'W' {
			sub = h.wstr(`SYSTEM\CurrentControlSet\Services\EventLog\Application\x`)
		}
		h.w64(out, 0)
		if r := h.call(dAdv, fn, 0x80000002, sub, out); r != 0 || h.r64(out) == 0 {
			t.Fatalf("%s = %d, key %#x", fn, r, h.r64(out))
		}
		if h.call(dAdv, "RegCloseKey", h.r64(out)) != 0 {
			t.Fatal("RegCloseKey failed")
		}
		if r := h.call(dAdv, fn, 0x80000002, 0, out); r != 0 || h.r64(out) == 0 {
			t.Fatalf("%s(NULL subkey) = %d", fn, r)
		}
		if r := h.call(dAdv, fn, 0x80000002, sub, 0); r != errInvalidParameter {
			t.Fatalf("%s(NULL out) = %d, want %d", fn, r, errInvalidParameter)
		}
	}
}

// Only the local machine (".", its name, with or without "\\") has an SCM.
func TestOpenSCManagerMachine(t *testing.T) {
	h := newTestEmu(t)
	for _, m := range []string{".", secComputerName, `\\` + secComputerName} {
		if sc := h.call(dAdv, "OpenSCManagerW", h.wstr(m), 0, scManagerConnect); sc == 0 {
			t.Fatalf("OpenSCManagerW(%q) failed, lastError %d", m, h.lastError())
		}
	}
	secExpectFail(t, h, "remote", h.call(dAdv, "OpenSCManagerW", h.wstr(`\\OTHERHOST`), 0, scManagerConnect), 1722)
}
