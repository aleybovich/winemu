package win

import (
	"crypto/rand"
	"hash/fnv"
	"os"
	"strings"
	"unicode/utf16"

	"winemu/internal/cpu"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func init() {
	// ---- advapi32 ----
	a := dAdv
	reg(a+","+dNt+","+dK32, "SystemFunction036", func(e *Emu) uint64 {
		e.Mem.Write(e.Arg(0), randomBytes(int(e.Arg32(1))))
		return 1
	})
	reg(a, "CryptAcquireContextW", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 0x1234); return 1 })
	reg(a, "CryptAcquireContextA", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 0x1234); return 1 })
	reg(a, "CryptGenRandom", func(e *Emu) uint64 { e.Mem.Write(e.Arg(2), randomBytes(int(e.Arg32(1)))); return 1 })
	reg(a, "CryptReleaseContext", retTrue)
	for _, n := range []string{"EventRegister", "EventUnregister", "EventSetInformation", "EventWriteTransfer", "EventWrite", "EventWriteString", "EventActivityIdControl"} {
		reg(a, n, retZero)
	}
	reg(a, "RegisterEventSourceW", ret(0x1234))
	reg(a, "RegisterEventSourceA", ret(0x1234))
	reg(a, "ReportEventW", retTrue)
	reg(a, "ReportEventA", retTrue)
	reg(a, "DeregisterEventSource", retTrue)
	// registry: an empty registry (opens fail, creates succeed but store nothing)
	regOpen := func(e *Emu, out uint64) uint64 { return errFileNotFound }
	reg(a, "RegOpenKeyExW", func(e *Emu) uint64 { return regOpen(e, e.Arg(4)) })
	reg(a, "RegOpenKeyExA", func(e *Emu) uint64 { return regOpen(e, e.Arg(4)) })
	reg(a, "RegOpenKeyW", func(e *Emu) uint64 { return regOpen(e, e.Arg(2)) })
	reg(a, "RegOpenKeyA", func(e *Emu) uint64 { return regOpen(e, e.Arg(2)) })
	reg(a, "RegOpenCurrentUser", func(e *Emu) uint64 { e.Mem.W64(e.Arg(1), 0x80000001); return 0 })
	reg(a, "RegCreateKeyExW", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(7), e.handles.add(&regKeyObj{path: e.WStr(e.Arg(1))}))
		if e.Arg(8) != 0 {
			e.Mem.W32(e.Arg(8), 1)
		}
		return 0
	})
	reg(a, "RegCreateKeyExA", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(7), e.handles.add(&regKeyObj{path: e.CStr(e.Arg(1))}))
		if e.Arg(8) != 0 {
			e.Mem.W32(e.Arg(8), 1)
		}
		return 0
	})
	// RegCreateKey(hKey, lpSubKey, phkResult): NULL/empty subkey returns hKey itself
	regAW(a, "RegCreateKey", func(e *Emu, w bool) uint64 {
		if e.Arg(2) == 0 {
			return errInvalidParameter
		}
		if e.Arg(1) == 0 || e.strArg(1, w) == "" {
			e.Mem.W64(e.Arg(2), e.Arg(0))
			return 0
		}
		e.Mem.W64(e.Arg(2), e.handles.add(&regKeyObj{path: e.strArg(1, w)}))
		return 0
	})
	for _, n := range []string{"RegQueryValueExW", "RegQueryValueExA", "RegGetValueW", "RegGetValueA", "RegEnumKeyExW", "RegEnumKeyExA",
		"RegEnumValueW", "RegEnumValueA", "RegDeleteValueW", "RegDeleteValueA", "RegDeleteKeyW", "RegDeleteKeyA", "RegDeleteTreeW",
		"RegQueryValueW", "RegEnumKeyW"} {
		reg(a, n, func(e *Emu) uint64 { return errFileNotFound })
	}
	reg(a, "RegQueryInfoKeyW", func(e *Emu) uint64 {
		for i := 2; i <= 10; i++ {
			if p := e.Arg(i); p != 0 && i != 3 {
				e.Mem.W32(p, 0)
			}
		}
		return 0
	})
	reg(a, "RegSetValueExW", retZero)
	reg(a, "RegSetValueExA", retZero)
	reg(a, "RegCloseKey", func(e *Emu) uint64 { e.handles.close(e.Arg(0)); return 0 })
	reg(a, "RegFlushKey", retZero)
	reg(a, "RegNotifyChangeKeyValue", retZero)
	reg(a, "GetCurrentHwProfileW", retZero)

	// ---- bcrypt / random ----
	reg("bcrypt.dll", "BCryptGenRandom", func(e *Emu) uint64 {
		e.Mem.Write(e.Arg(1), randomBytes(int(e.Arg32(2))))
		return 0
	})
	reg("bcrypt.dll", "BCryptOpenAlgorithmProvider", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 0x4321); return 0 })
	reg("bcrypt.dll", "BCryptCloseAlgorithmProvider", retZero)
	reg("bcryptprimitives.dll", "ProcessPrng", func(e *Emu) uint64 {
		e.Mem.Write(e.Arg(0), randomBytes(int(e.Arg(1))))
		return 1
	})
	reg("bcryptprimitives.dll", "GetProcessPrng", func(e *Emu) uint64 {
		m, _ := e.LoadDLL("bcryptprimitives.dll")
		a, _ := e.GetExport(m, "ProcessPrng", 0, false)
		return a
	})

	// ---- user32 (console programs only use a few) ----
	u := dUser
	regAW(u, "MessageBox", func(e *Emu, w bool) uint64 {
		e.crt.flushAll()
		title, text := e.strArg(2, w), e.strArg(1, w)
		e.logf("[MessageBox] %s: %s", title, text)
		return 1
	})
	regAW(u, "MessageBoxEx", func(e *Emu, w bool) uint64 {
		e.crt.flushAll()
		e.logf("[MessageBox] %s: %s", e.strArg(2, w), e.strArg(1, w))
		return 1
	})
	reg(u, "MessageBeep", retTrue)
	reg(u, "GetSystemMetrics", func(e *Emu) uint64 {
		switch e.Arg32(0) {
		case 0:
			return 1920
		case 1:
			return 1080
		}
		return 0
	})
	for _, n := range []string{"GetDesktopWindow", "GetForegroundWindow", "GetActiveWindow", "GetShellWindow", "GetFocus"} {
		reg(u, n, retZero)
	}
	reg(u, "ShowWindow", retTrue)
	reg(u, "GetWindowThreadProcessId", func(e *Emu) uint64 {
		if e.Arg(1) != 0 {
			e.Mem.W32(e.Arg(1), e.proc.pid)
		}
		return uint64(e.threads[0].ID)
	})
	reg(u, "GetKeyState", retZero)
	reg(u, "GetAsyncKeyState", retZero)
	reg(u, "GetKeyboardLayout", ret(0x04090409))
	reg(u, "GetKeyboardState", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, 256); return 1 })
	reg(u, "MapVirtualKeyW", retZero)
	reg(u, "GetProcessWindowStation", ret(0x1000))
	reg(u, "GetUserObjectInformationW", func(e *Emu) uint64 {
		// report a visible window station
		if e.Arg32(1) == 1 && e.Arg32(3) >= 12 {
			e.Mem.W32(e.Arg(2)+8, 1)
		}
		if e.Arg(4) != 0 {
			e.Mem.W32(e.Arg(4), 12)
		}
		return 1
	})
	reg(u, "SetProcessDPIAware", retTrue)
	reg(u, "SetProcessDpiAwarenessContext", retTrue)
	reg(u, "GetDpiForSystem", ret(96))
	reg(u, "PeekMessageW", retZero)
	reg(u, "PeekMessageA", retZero)
	reg(u, "GetMessageW", retZero)
	reg(u, "TranslateMessage", retZero)
	reg(u, "DispatchMessageW", retZero)
	reg(u, "PostQuitMessage", retZero)
	reg(u, "PostThreadMessageW", retTrue)
	reg(u, "LoadStringW", retZero)
	reg(u, "LoadStringA", retZero)
	reg(u, "OpenClipboard", retZero)
	reg(u, "CloseClipboard", retTrue)
	reg(u, "GetClipboardData", retZero)
	reg(u, "IsWindowVisible", retZero)
	reg(u, "FindWindowW", retZero)
	reg(u, "FindWindowA", retZero)
	reg(u, "SendMessageW", retZero)
	reg(u, "GetWindowLongPtrW", retZero)
	reg(u, "RegisterClassExW", ret(0xC001))
	reg(u, "RegisterClassW", ret(0xC001))
	reg(u, "CreateWindowExW", func(e *Emu) uint64 { return e.fail(errNotSupported) })
	reg(u, "DefWindowProcW", retZero)
	reg(u, "DestroyWindow", retTrue)

	// ---- shell32 ----
	s := dShell
	reg(s, "CommandLineToArgvW", func(e *Emu) uint64 {
		args := splitCmdLine(e.WStr(e.Arg(0)))
		if e.Mem.R16(e.Arg(0)) == 0 {
			args = []string{e.exeWin}
		}
		size := 8 * (len(args) + 1)
		for _, a := range args {
			size += 2*len(utf16.Encode([]rune(a))) + 2
		}
		blk := e.heapAllocRaw(uint64(size))
		p := blk + uint64(8*(len(args)+1))
		for i, a := range args {
			e.Mem.W64(blk+uint64(8*i), p)
			n := e.Mem.WriteWStr(p, a)
			p += uint64(2*n + 2)
		}
		e.Mem.W32(e.Arg(1), uint32(len(args)))
		return blk
	})
	folder := func(e *Emu, csidl uint32) string {
		up := e.fs.userProfile()
		switch csidl & 0xFF {
		case 0x1A: // APPDATA
			return up + `\AppData\Roaming`
		case 0x1C: // LOCAL_APPDATA
			return up + `\AppData\Local`
		case 0x23: // COMMON_APPDATA
			return `C:\ProgramData`
		case 0x05: // MY_DOCUMENTS / PERSONAL
			return up + `\Documents`
		case 0x10, 0x00: // DESKTOPDIRECTORY / DESKTOP
			return up + `\Desktop`
		case 0x28: // PROFILE
			return up
		case 0x24: // WINDOWS
			return `C:\windows`
		case 0x25, 0x29: // SYSTEM
			return `C:\windows\system32`
		case 0x26: // PROGRAM_FILES
			return `C:\Program Files`
		case 0x2A:
			return `C:\Program Files (x86)`
		}
		return up
	}
	reg(s, "SHGetFolderPathW", func(e *Emu) uint64 { e.Mem.WriteWStr(e.Arg(4), folder(e, e.Arg32(1))); return 0 })
	reg(s, "SHGetFolderPathA", func(e *Emu) uint64 { e.Mem.WriteCStr(e.Arg(4), folder(e, e.Arg32(1))); return 0 })
	reg(s, "SHGetSpecialFolderPathW", func(e *Emu) uint64 { e.Mem.WriteWStr(e.Arg(1), folder(e, e.Arg32(2))); return 1 })
	reg(s, "SHGetSpecialFolderPathA", func(e *Emu) uint64 { e.Mem.WriteCStr(e.Arg(1), folder(e, e.Arg32(2))); return 1 })
	reg(s, "SHGetKnownFolderPath", func(e *Emu) uint64 {
		g := e.Mem.ReadBytes(e.Arg(0), 16)
		known := map[string]uint32{
			"3eb685db65f9cb4ca2d1af1d2a1e3e5b": 0x1A, // placeholder
		}
		_ = known
		var csidl uint32 = 0x28
		switch strings.ToUpper(guidString(g)) {
		case "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}":
			csidl = 0x1A // RoamingAppData
		case "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}":
			csidl = 0x1C // LocalAppData
		case "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}":
			csidl = 0x23 // ProgramData
		case "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}":
			csidl = 0x05 // Documents
		case "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}":
			csidl = 0x10 // Desktop
		case "{5E6C858F-0E22-4760-9AFE-EA3317B67173}":
			csidl = 0x28 // Profile
		case "{F38BF404-1D43-42F2-9305-67DE0B28FC23}":
			csidl = 0x24 // Windows
		case "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}":
			csidl = 0x25 // System
		case "{905E63B6-C1BF-494E-B29C-65B732D3D21A}":
			csidl = 0x26 // ProgramFiles
		case "{374DE290-123F-4565-9164-39C4925E467B}":
			csidl = 0x28
			p := e.allocWStr(e.fs.userProfile() + `\Downloads`)
			e.Mem.W64(e.Arg(3), p)
			return 0
		}
		e.Mem.W64(e.Arg(3), e.allocWStr(folder(e, csidl)))
		return 0
	})
	reg(s, "SHCreateDirectoryExW", func(e *Emu) uint64 {
		if err := os.MkdirAll(e.fs.toHost(e.WStr(e.Arg(1))), 0o755); err != nil {
			return uint64(winErr(err))
		}
		return 0
	})
	reg(s, "ShellExecuteW", func(e *Emu) uint64 { return 2 })
	reg(s, "ShellExecuteA", func(e *Emu) uint64 { return 2 })
	reg(s, "ShellExecuteExW", func(e *Emu) uint64 { return e.fail(errFileNotFound) })
	reg(s, "SHFileOperationW", ret(1))
	reg(s, "DragQueryFileW", retZero)

	// ---- ole32 / oleaut32 ----
	o := "ole32.dll"
	reg(o, "CoInitialize", retZero)
	reg(o, "CoInitializeEx", retZero)
	reg(o, "CoUninitialize", retZero)
	reg(o, "OleInitialize", retZero)
	reg(o, "OleUninitialize", retZero)
	reg(o, "CoInitializeSecurity", retZero)
	reg(o, "CoCreateInstance", func(e *Emu) uint64 {
		if e.Arg(4) != 0 {
			e.Mem.W64(e.Arg(4), 0)
		}
		return 0x80040154 // REGDB_E_CLASSNOTREG
	})
	reg(o, "CoTaskMemAlloc", func(e *Emu) uint64 { return e.heapAlloc(e.Arg(0), false) })
	reg(o, "CoTaskMemRealloc", func(e *Emu) uint64 { return e.heap.realloc(e.heap.processHeap, e.Arg(0), e.Arg(1), false) })
	reg(o, "CoTaskMemFree", func(e *Emu) uint64 { e.heap.freeBlock(e.Arg(0)); return 0 })
	reg(o, "CoCreateGuid", func(e *Emu) uint64 {
		g := randomBytes(16)
		g[7] = g[7]&0x0F | 0x40
		g[8] = g[8]&0x3F | 0x80
		e.Mem.Write(e.Arg(0), g)
		return 0
	})
	reg(o, "StringFromGUID2", func(e *Emu) uint64 {
		s := guidString(e.Mem.ReadBytes(e.Arg(0), 16))
		if e.Arg32(2) < 39 {
			return 0
		}
		e.Mem.WriteWStr(e.Arg(1), s)
		return 39
	})
	reg(o, "CoGetApartmentType", func(e *Emu) uint64 { return 0x800401F0 })
	ol := "oleaut32.dll"
	reg(ol, "SysAllocString", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return sysAlloc(e, e.Mem.WStrUnits(e.Arg(0)))
	})
	reg(ol, "SysAllocStringLen", func(e *Emu) uint64 {
		n := e.Arg32(1)
		u := make([]uint16, n)
		if e.Arg(0) != 0 {
			u = e.wunits(e.Arg(0), uint64(n))
		}
		return sysAlloc(e, u)
	})
	reg(ol, "SysFreeString", func(e *Emu) uint64 {
		if e.Arg(0) != 0 {
			e.heap.freeBlock(e.Arg(0) - 4)
		}
		return 0
	})
	reg(ol, "SysStringLen", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return uint64(e.Mem.R32(e.Arg(0)-4) / 2)
	})
	reg(ol, "SysStringByteLen", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return uint64(e.Mem.R32(e.Arg(0) - 4))
	})
	reg(ol, "VariantInit", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, 24); return 0 })
	reg(ol, "VariantClear", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, 24); return 0 })
	reg(ol, "SetErrorInfo", retZero)
	reg(ol, "GetErrorInfo", func(e *Emu) uint64 { e.Mem.W64(e.Arg(1), 0); return 1 })

	// ---- misc small DLLs ----
	regAW("version.dll", "GetFileVersionInfoSize", func(e *Emu, w bool) uint64 { return e.fail(1813) })
	regAW("version.dll", "GetFileVersionInfo", func(e *Emu, w bool) uint64 { return e.fail(1813) })
	regAW("version.dll", "VerQueryValue", func(e *Emu, w bool) uint64 { return 0 })
	for _, n := range []string{"SymInitialize", "SymInitializeW", "SymCleanup", "SymFromAddr", "SymFromAddrW", "SymGetLineFromAddr64",
		"SymGetLineFromAddrW64", "SymSetOptions", "SymGetOptions", "SymLoadModuleExW", "SymGetModuleBase64", "SymFunctionTableAccess64",
		"StackWalk64", "StackWalkEx", "SymGetSearchPathW", "SymSetSearchPathW", "SymAddrIncludeInlineTrace", "SymQueryInlineTrace",
		"SymFromInlineContextW", "SymGetLineFromInlineContextW", "MiniDumpWriteDump"} {
		reg("dbghelp.dll", n, retZero)
	}
	reg("dbghelp.dll", "UnDecorateSymbolName", func(e *Emu) uint64 {
		e.Mem.WriteCStr(e.Arg(1), e.CStr(e.Arg(0)))
		return uint64(len(e.CStr(e.Arg(0))))
	})
	reg("powrprof.dll", "CallNtPowerInformation", func(e *Emu) uint64 { return 0xC0000002 })
	reg("winmm.dll", "timeGetTime", func(e *Emu) uint64 { return uint64(uint32(e.tickMs())) })
	reg("winmm.dll", "timeBeginPeriod", retZero)
	reg("winmm.dll", "timeEndPeriod", retZero)
	reg("winmm.dll", "PlaySoundW", retZero)
	reg("iphlpapi.dll", "GetAdaptersAddresses", func(e *Emu) uint64 { return 232 })
	reg("iphlpapi.dll", "GetAdaptersInfo", func(e *Emu) uint64 { return 232 })
	reg("shlwapi.dll", "PathFileExistsW", func(e *Emu) uint64 {
		_, err := os.Stat(e.fs.toHost(e.WStr(e.Arg(0))))
		return b2u(err == nil)
	})
	reg("shlwapi.dll", "PathFileExistsA", func(e *Emu) uint64 {
		_, err := os.Stat(e.fs.toHost(e.CStr(e.Arg(0))))
		return b2u(err == nil)
	})
	reg("shlwapi.dll", "PathIsRelativeW", func(e *Emu) uint64 {
		p := e.WStr(e.Arg(0))
		return b2u(!(len(p) > 1 && p[1] == ':' || strings.HasPrefix(p, `\`)))
	})

	// ---- ntdll extras ----
	n := dNt
	reg(n, "RtlInitUnicodeString", func(e *Emu) uint64 {
		d, s := e.Arg(0), e.Arg(1)
		l := uint64(0)
		if s != 0 {
			l = 2 * e.wlen(s)
		}
		e.Mem.W16(d, uint16(l))
		e.Mem.W16(d+2, uint16(l+2))
		e.Mem.W64(d+8, s)
		return 0
	})
	reg(n, "RtlInitAnsiString", func(e *Emu) uint64 {
		d, s := e.Arg(0), e.Arg(1)
		l := uint64(0)
		if s != 0 {
			l = uint64(len(e.Mem.CStrBytes(s)))
		}
		e.Mem.W16(d, uint16(l))
		e.Mem.W16(d+2, uint16(l+1))
		e.Mem.W64(d+8, s)
		return 0
	})
	reg(n, "RtlFreeUnicodeString", func(e *Emu) uint64 { e.heap.freeBlock(e.Mem.R64(e.Arg(0) + 8)); return 0 })
	reg(n, "RtlFreeAnsiString", func(e *Emu) uint64 { e.heap.freeBlock(e.Mem.R64(e.Arg(0) + 8)); return 0 })
	reg(n, "NtClose", func(e *Emu) uint64 { e.handles.close(e.Arg(0)); return 0 })
	reg(n, "NtQueryInformationProcess", func(e *Emu) uint64 {
		switch e.Arg32(1) {
		case 0: // ProcessBasicInformation
			b := e.Arg(2)
			e.Mem.Fill(b, 0, 48)
			e.Mem.W64(b+8, e.peb)
			e.Mem.W64(b+32, uint64(e.proc.pid))
			if e.Arg(4) != 0 {
				e.Mem.W32(e.Arg(4), 48)
			}
			return 0
		case 7: // ProcessDebugPort
			e.Mem.W64(e.Arg(2), 0)
			return 0
		}
		return 0xC0000003
	})
	reg(n, "NtQueryInformationThread", func(e *Emu) uint64 { return 0xC0000003 })
	reg(n, "NtSetInformationThread", retZero)
	reg(n, "NtQuerySystemInformation", func(e *Emu) uint64 { return 0xC0000003 })
	reg(n, "NtQueryVirtualMemory", func(e *Emu) uint64 {
		if e.Arg32(2) != 0 {
			return 0xC0000003
		}
		e.virtualQuery(e.Arg(1), e.Arg(3), e.Arg(4))
		if e.Arg(5) != 0 {
			e.Mem.W64(e.Arg(5), 48)
		}
		return 0
	})
	reg(n, "RtlGetCurrentPeb", func(e *Emu) uint64 { return e.peb })
	reg(n, "RtlGetNtGlobalFlags", retZero)
	reg(n, "NtSetInformationProcess", retZero)
	reg(n, "LdrGetDllHandle", func(e *Emu) uint64 {
		name := e.Mem.WStrN(e.Mem.R64(e.Arg(2)+8), int(e.Mem.R16(e.Arg(2))/2))
		if m := e.modByName[normDLL(name)]; m != nil {
			e.Mem.W64(e.Arg(3), m.Base)
			return 0
		}
		return 0xC0000135
	})
	reg(n, "LdrGetProcedureAddress", func(e *Emu) uint64 {
		m := e.moduleAt(e.Arg(0))
		if m == nil {
			return 0xC0000135
		}
		var addr uint64
		var ok bool
		if e.Arg(1) != 0 {
			name := string(e.Mem.ReadBytes(e.Mem.R64(e.Arg(1)+8), int(e.Mem.R16(e.Arg(1)))))
			addr, ok = e.GetExport(m, name, 0, false)
		} else {
			addr, ok = e.GetExport(m, "", e.Arg32(2), true)
		}
		if !ok {
			return 0xC0000139
		}
		e.Mem.W64(e.Arg(3), addr)
		return 0
	})
	reg(n, "RtlUnicodeToMultiByteN", func(e *Emu) uint64 {
		b := unitsToUTF8(e.wunits(e.Arg(3), uint64(e.Arg32(4)/2)))
		k := min(len(b), int(e.Arg32(1)))
		e.Mem.Write(e.Arg(0), b[:k])
		if e.Arg(2) != 0 {
			e.Mem.W32(e.Arg(2), uint32(k))
		}
		return 0
	})
	reg(n, "RtlMultiByteToUnicodeN", func(e *Emu) uint64 {
		u := utf8ToUnits(e.Mem.ReadBytes(e.Arg(3), int(e.Arg32(4))))
		k := min(len(u), int(e.Arg32(1)/2))
		e.Mem.WriteUnits(e.Arg(0), u[:k])
		if e.Arg(2) != 0 {
			e.Mem.W32(e.Arg(2), uint32(2*k))
		}
		return 0
	})
	reg(n, "RtlIsProcessorFeaturePresent", func(e *Emu) uint64 { return e.callAPI(dK32, "IsProcessorFeaturePresent") })
	reg(n, "RtlGetProcessHeaps", func(e *Emu) uint64 {
		if e.Arg32(0) >= 1 {
			e.Mem.W64(e.Arg(1), e.heap.processHeap)
		}
		return 1
	})
	reg(n, "NtGetTickCount", func(e *Emu) uint64 { return uint64(uint32(e.tickMs())) })
	reg(n, "RtlGetCurrentProcessorNumber", retZero)
	reg(n, "RtlRandomEx", func(e *Emu) uint64 {
		v := uint32(randomBytes(4)[0]) | uint32(randomBytes(4)[1])<<8 | uint32(randomBytes(4)[2])<<16
		v &= 0x7FFFFFFF
		e.Mem.W32(e.Arg(0), v)
		return uint64(v)
	})

	// ---- vcruntime140 ----
	v := dVc + "," + dUcrt + "," + dMsvc
	reg(v, "__std_exception_copy", func(e *Emu) uint64 {
		src, dst := e.Arg(0), e.Arg(1)
		what := e.Mem.R64(src)
		dofree := e.Mem.R8(src+8) != 0
		if dofree && what != 0 {
			what = e.allocCStr(e.CStr(what))
		}
		e.Mem.W64(dst, what)
		e.Mem.W8(dst+8, uint8(b2u(dofree)))
		return 0
	})
	reg(v, "__std_exception_destroy", func(e *Emu) uint64 {
		d := e.Arg(0)
		if e.Mem.R8(d+8) != 0 {
			e.heap.freeBlock(e.Mem.R64(d))
		}
		e.Mem.W64(d, 0)
		e.Mem.W8(d+8, 0)
		return 0
	})
	reg(v, "__std_type_info_name", func(e *Emu) uint64 {
		ti := e.Arg(0)
		if p := e.Mem.R64(ti); p != 0 {
			return p
		}
		dec := e.CStr(ti + 8)
		p := e.allocCStr(undecorateTypeName(dec))
		e.Mem.W64(ti, p)
		return p
	})
	reg(v, "__std_type_info_compare", func(e *Emu) uint64 {
		a, b := e.Arg(0), e.Arg(1)
		if a == b {
			return 0
		}
		return sign(strings.Compare(e.CStr(a+9), e.CStr(b+9)))
	})
	reg(v, "__std_type_info_hash", func(e *Emu) uint64 {
		h := fnv.New64a()
		h.Write([]byte(e.CStr(e.Arg(0) + 9)))
		return h.Sum64()
	})
	reg(v, "__std_type_info_destroy_list", retZero)
	reg(v, "__std_terminate", func(e *Emu) uint64 {
		e.crt.flushAll()
		e.logf("std::terminate called")
		e.exitProcess(3)
		return 0
	})
	reg(v, "_purecall", func(e *Emu) uint64 {
		e.crt.flushAll()
		e.logf("pure virtual function call")
		e.exitProcess(3)
		return 0
	})
	reg(v, "__current_exception", func(e *Emu) uint64 { return e.excSlots() })
	reg(v, "__current_exception_context", func(e *Emu) uint64 { return e.excSlots() + 8 })
	reg(v, "__processing_throw", func(e *Emu) uint64 { return e.excSlots() + 16 })
	reg(v, "__uncaught_exception", retZero)
	reg(v, "__uncaught_exceptions", retZero)
	reg(v, "_CxxThrowException", func(e *Emu) uint64 {
		obj, ti := e.Arg(0), e.Arg(1)
		var base uint64
		if m := e.moduleAt(ti); m != nil {
			base = m.Base
		}
		x := e.callerContext()
		e.raiseGuest(&guestException{code: 0xE06D7363, flags: excNoncontinuable,
			params: []uint64{0x19930520, obj, ti, base}, addr: x.Rip, ctx: x})
		return 0
	})
	cxxHandler := func(e *Emu) uint64 {
		e.warnOnce("cxxeh", "C++ exception reached __CxxFrameHandler: MSVC C++ exception handling (catch/unwind) "+
			"is not implemented yet; the exception is not caught by this frame")
		return 1
	}
	reg(v+",vcruntime140_1.dll", "__CxxFrameHandler4", cxxHandler)
	reg(v, "__CxxFrameHandler3", cxxHandler)
	reg(v, "__CxxFrameHandler", cxxHandler)
	reg(v, "__GSHandlerCheck_EH4", cxxHandler)
	reg(v, "__NLG_Notify", retZero)
	reg(v, "__NLG_Return2", retZero)
	reg(v, "_local_unwind", func(e *Emu) uint64 {
		e.unwindTo(e.Arg(0), e.Mem.R64(e.Cur.CPU.R[cpu.RSP]), 0, 0, e.unwindStart())
		return 0
	})
	reg(v, "__telemetry_main_invoke_trigger", retZero)
	reg(v, "__telemetry_main_return_trigger", retZero)
	reg(v, "__vcrt_InitializeCriticalSectionEx", func(e *Emu) uint64 {
		e.Mem.Fill(e.Arg(0), 0, 40)
		return 1
	})
	reg(v, "_set_se_translator", retZero)
	reg(v, "__intrinsic_setjmp", setjmp)
	reg(v, "__intrinsic_setjmpex", setjmp)
	reg(v, "_is_exception_typeof", retZero)
	reg(v, "__unDName", func(e *Emu) uint64 {
		s := e.CStr(e.Arg(1))
		if e.Arg(0) == 0 {
			return e.allocCStr(s)
		}
		e.Mem.WriteCStr(e.Arg(0), s)
		return e.Arg(0)
	})
}

func sysAlloc(e *Emu, u []uint16) uint64 {
	blk := e.heapAlloc(uint64(4+2*len(u)+2), false)
	e.Mem.W32(blk, uint32(2*len(u)))
	e.Mem.WriteUnits(blk+4, append(u, 0))
	return blk + 4
}

func bswap32(v uint32) uint32 { return v>>24 | v>>8&0xFF00 | v<<8&0xFF0000 | v<<24 }

func guidString(g []byte) string {
	h := func(b []byte) string {
		const d = "0123456789ABCDEF"
		out := make([]byte, 0, 2*len(b))
		for _, x := range b {
			out = append(out, d[x>>4], d[x&15])
		}
		return string(out)
	}
	rev := func(b []byte) []byte {
		r := make([]byte, len(b))
		for i := range b {
			r[i] = b[len(b)-1-i]
		}
		return r
	}
	return "{" + h(rev(g[0:4])) + "-" + h(rev(g[4:6])) + "-" + h(rev(g[6:8])) + "-" + h(g[8:10]) + "-" + h(g[10:16]) + "}"
}

// undecorateTypeName turns ".?AVfoo@ns@@" into "class ns::foo".
func undecorateTypeName(d string) string {
	if !strings.HasPrefix(d, ".?A") || len(d) < 5 {
		return strings.TrimPrefix(d, ".")
	}
	kind := "class "
	switch d[3] {
	case 'U':
		kind = "struct "
	case 'T':
		kind = "union "
	case 'W':
		kind = "enum "
	}
	body := strings.TrimSuffix(d[4:], "@@")
	parts := strings.Split(body, "@")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return kind + strings.Join(parts, "::")
}

func init() {
	k := dK32
	reg(k, "WerGetFlags", func(e *Emu) uint64 {
		if e.Arg(1) != 0 {
			e.Mem.W32(e.Arg(1), 0)
		}
		return 0
	})
	reg(k, "WerSetFlags", retZero)
	reg(k, "WerRegisterRuntimeExceptionModule", retZero)
	reg(k, "WerUnregisterRuntimeExceptionModule", retZero)
	reg(k, "timeBeginPeriod", retZero)
}

// excSlots returns the current thread's vcruntime exception slots
// (__current_exception, __current_exception_context, __processing_throw),
// allocated on first use in this process's heap.
func (e *Emu) excSlots() uint64 {
	if e.excStore == nil {
		e.excStore = map[*Thread]uint64{}
	}
	a := e.excStore[e.Cur]
	if a == 0 {
		a = e.heapAllocRaw(32)
		e.excStore[e.Cur] = a
	}
	return a
}
