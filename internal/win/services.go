package win

// Service control manager (advapi32), as seen by a non-administrator on a
// machine with no installed services.
//
// OpenSCManager succeeds for the rights Windows grants Authenticated Users
// on the SCM (SC_MANAGER_CONNECT | ENUMERATE_SERVICE | QUERY_LOCK_STATUS |
// READ_CONTROL, i.e. GENERIC_READ/EXECUTE-style access) and fails with
// ERROR_ACCESS_DENIED for anything else (SC_MANAGER_ALL_ACCESS,
// CREATE_SERVICE, GENERIC_WRITE/ALL), exactly like a non-elevated user on
// Windows. The database is empty: OpenService reports
// ERROR_SERVICE_DOES_NOT_EXIST, CreateService needs SC_MANAGER_CREATE_SERVICE
// (never granted), so no service handle can exist and every API taking one
// fails with ERROR_INVALID_HANDLE. The process was not started by the SCM:
// StartServiceCtrlDispatcher fails with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
// and RegisterServiceCtrlHandler(Ex) with ERROR_SERVICE_NOT_IN_EXE (no
// dispatcher table registered the name).

import "strings"

const (
	scManagerConnect       = 0x0001
	scManagerCreateService = 0x0002
	scManagerEnumerate     = 0x0004
	scManagerQueryLock     = 0x0010
	scManagerAllAccess     = 0xF003F
	readControl            = 0x00020000
	maximumAllowed         = 0x02000000

	// rights of Authenticated Users on the SCM object
	scmUserRights = scManagerConnect | scManagerEnumerate | scManagerQueryLock | readControl

	errServiceNotExist          = 1060
	errFailedServiceCtrlConnect = 1063
	errDatabaseNotExist         = 1065
	errServiceNotInExe          = 1083
)

// scmObj is an SC_HANDLE for the service control manager.
type scmObj struct{ access uint32 }

// scmMapGeneric maps GENERIC_* bits onto SCM-specific rights.
func scmMapGeneric(acc uint32) uint32 {
	m := acc & 0x0FFFFFFF
	if acc&0x80000000 != 0 { // GENERIC_READ
		m |= readControl | scManagerEnumerate | scManagerQueryLock
	}
	if acc&0x40000000 != 0 { // GENERIC_WRITE
		m |= readControl | scManagerCreateService | 0x20 // MODIFY_BOOT_CONFIG
	}
	if acc&0x20000000 != 0 { // GENERIC_EXECUTE
		m |= readControl | scManagerConnect | 0x8 // LOCK
	}
	if acc&0x10000000 != 0 { // GENERIC_ALL
		m |= scManagerAllAccess
	}
	return m
}

func (e *Emu) scm(h uint64) *scmObj {
	o, _ := e.handles.get(h).(*scmObj)
	return o
}

func init() {
	a := dAdv
	// OpenSCManager(machine, database, access)
	regAW(a, "OpenSCManager", func(e *Emu, w bool) uint64 {
		if e.Arg(0) != 0 {
			if m := strings.TrimPrefix(e.strArg(0, w), `\\`); m != "" && m != "." && !strings.EqualFold(m, secComputerName) {
				return e.fail(1722) // RPC_S_SERVER_UNAVAILABLE: no remote machines
			}
		}
		if e.Arg(1) != 0 && !strings.EqualFold(e.strArg(1, w), "ServicesActive") {
			return e.fail(errDatabaseNotExist)
		}
		acc := e.Arg32(2)
		granted := scmMapGeneric(acc&^maximumAllowed) | scManagerConnect
		if acc&maximumAllowed != 0 {
			granted |= scmUserRights
		}
		if granted&^scmUserRights != 0 {
			return e.fail(errAccessDenied)
		}
		return e.handles.add(&scmObj{access: granted})
	})
	reg(a, "CloseServiceHandle", func(e *Emu) uint64 {
		if e.scm(e.Arg(0)) == nil {
			return e.fail(errInvalidHandle)
		}
		e.handles.close(e.Arg(0))
		return 1
	})
	// OpenService(scm, name, access)
	regAW(a, "OpenService", func(e *Emu, w bool) uint64 {
		if e.scm(e.Arg(0)) == nil {
			return e.fail(errInvalidHandle)
		}
		if e.Arg(1) == 0 || e.strArg(1, w) == "" {
			return e.fail(errInvalidName)
		}
		return e.fail(errServiceNotExist)
	})
	// CreateService(scm, name, display, access, type, start, errctl, path, ...)
	regAW(a, "CreateService", func(e *Emu, _ bool) uint64 {
		if e.scm(e.Arg(0)) == nil {
			return e.fail(errInvalidHandle)
		}
		return e.fail(errAccessDenied) // SC_MANAGER_CREATE_SERVICE is never granted
	})
	for _, n := range []string{"DeleteService", "StartServiceA", "StartServiceW", "QueryServiceStatus", "QueryServiceStatusEx",
		"ControlService", "ChangeServiceConfig2A", "ChangeServiceConfig2W", "SetServiceStatus"} {
		reg(a, n, func(e *Emu) uint64 { return e.fail(errInvalidHandle) })
	}
	regAW(a, "StartServiceCtrlDispatcher", func(e *Emu, _ bool) uint64 {
		if e.Arg(0) == 0 {
			return e.fail(errInvalidParameter)
		}
		return e.fail(errFailedServiceCtrlConnect)
	})
	ctrlHandler := func(e *Emu, _ bool) uint64 {
		if e.Arg(1) == 0 {
			return e.fail(errInvalidParameter)
		}
		return e.fail(errServiceNotInExe)
	}
	regAW(a, "RegisterServiceCtrlHandler", ctrlHandler)
	regAW(a, "RegisterServiceCtrlHandlerEx", ctrlHandler)
}
