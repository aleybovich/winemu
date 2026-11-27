package win

import (
	"errors"
	"math"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"winemu/internal/cpu"
	"winemu/internal/mem"
)

// Windows error codes
const (
	errSuccess          = 0
	errFileNotFound     = 2
	errPathNotFound     = 3
	errTooManyFiles     = 4
	errAccessDenied     = 5
	errInvalidHandle    = 6
	errNotEnoughMemory  = 8
	errInvalidData      = 13
	errNoMoreFiles      = 18
	errSharing          = 32
	errHandleEOF        = 38
	errNotSupported     = 50
	errFileExists       = 80
	errInvalidParameter = 87
	errBrokenPipe       = 109
	errCallNotImpl      = 120
	errInsufficientBuf  = 122
	errInvalidName      = 123
	errModNotFound      = 126
	errProcNotFound     = 127
	errDirNotEmpty      = 145
	errAlreadyExists    = 183
	errEnvVarNotFound   = 203
	errMoreData         = 234
	errNoMoreItems      = 259
	errNoUnicodeTrans   = 1113
	errTimeout          = 1460
	errNotFound         = 1168
)

func f64frombits(b uint64) float64 { return math.Float64frombits(b) }
func f32frombits(b uint32) float32 { return math.Float32frombits(b) }
func nowNano() int64               { return time.Now().UnixNano() }

// winErr maps a Go error to a Windows error code.
func winErr(err error) uint32 {
	if err == nil {
		return 0
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		err = le.Err
	}
	var se *os.SyscallError
	if errors.As(err, &se) {
		err = se.Err
	}
	switch {
	case errors.Is(err, syscall.ENOENT):
		return errFileNotFound
	case errors.Is(err, syscall.ENOTDIR):
		return errPathNotFound
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EISDIR), errors.Is(err, syscall.EROFS):
		return errAccessDenied
	case errors.Is(err, syscall.EEXIST):
		return errAlreadyExists
	case errors.Is(err, syscall.ENOTEMPTY):
		return errDirNotEmpty
	case errors.Is(err, syscall.ENOSPC):
		return 112
	case errors.Is(err, syscall.EMFILE):
		return errTooManyFiles
	case errors.Is(err, syscall.ENAMETOOLONG):
		return 206
	case errors.Is(err, syscall.EPIPE):
		return errBrokenPipe
	case errors.Is(err, syscall.EINVAL):
		return errInvalidParameter
	}
	return errAccessDenied
}

// ---------------------------------------------------------------------------
// string helpers for A/W APIs

// putStrA writes s (with NUL) into buf of size n chars. Returns length
// written (excl. NUL) or, if too small, the required size including NUL.
func (e *Emu) putStrA(buf uint64, n uint32, s string) uint64 {
	if uint32(len(s)) >= n || buf == 0 {
		return uint64(len(s) + 1)
	}
	e.Mem.WriteCStr(buf, s)
	return uint64(len(s))
}

func (e *Emu) putStrW(buf uint64, n uint32, s string) uint64 {
	u := utf16.Encode([]rune(s))
	if uint32(len(u)) >= n || buf == 0 {
		return uint64(len(u) + 1)
	}
	e.Mem.WriteUnits(buf, append(u, 0))
	return uint64(len(u))
}

// truncStrA writes as much as fits (GetModuleFileName style).
func (e *Emu) truncStrA(buf uint64, n uint32, s string) uint64 {
	if n == 0 {
		e.SetLastError(errInsufficientBuf)
		return 0
	}
	if uint32(len(s)) >= n {
		e.Mem.WriteCStr(buf, s[:n-1])
		e.SetLastError(errInsufficientBuf)
		return uint64(n)
	}
	e.Mem.WriteCStr(buf, s)
	e.SetLastError(0)
	return uint64(len(s))
}

func (e *Emu) truncStrW(buf uint64, n uint32, s string) uint64 {
	u := utf16.Encode([]rune(s))
	if n == 0 {
		e.SetLastError(errInsufficientBuf)
		return 0
	}
	if uint32(len(u)) >= n {
		e.Mem.WriteUnits(buf, append(u[:n-1], 0))
		e.SetLastError(errInsufficientBuf)
		return uint64(n)
	}
	e.Mem.WriteUnits(buf, append(u, 0))
	e.SetLastError(0)
	return uint64(len(u))
}

// strArg reads an A or W string argument.
func (e *Emu) strArg(i int, wide bool) string {
	a := e.Arg(i)
	if a == 0 {
		return ""
	}
	if wide {
		return e.Mem.WStr(a)
	}
	return e.Mem.CStr(a)
}

// regAW registers name+"A" and name+"W" implementations sharing one body.
func regAW(dlls, name string, fn func(e *Emu, wide bool) uint64) {
	reg(dlls, name+"A", func(e *Emu) uint64 { return fn(e, false) })
	reg(dlls, name+"W", func(e *Emu) uint64 { return fn(e, true) })
}

func (e *Emu) putStr(wide bool, buf uint64, n uint32, s string) uint64 {
	if wide {
		return e.putStrW(buf, n, s)
	}
	return e.putStrA(buf, n, s)
}

func (e *Emu) truncStr(wide bool, buf uint64, n uint32, s string) uint64 {
	if wide {
		return e.truncStrW(buf, n, s)
	}
	return e.truncStrA(buf, n, s)
}

func ret(v uint64) Fn     { return func(*Emu) uint64 { return v } }
func retTrue(*Emu) uint64 { return 1 }
func retZero(*Emu) uint64 { return 0 }

func init() {
	k := dK32
	// ---- process / environment ----
	reg(k, "ExitProcess", func(e *Emu) uint64 {
		e.exitProcess(e.Arg32(0))
		return 0
	})
	reg(k+","+dNt, "RtlExitUserProcess", func(e *Emu) uint64 {
		e.exitProcess(e.Arg32(0))
		return 0
	})
	reg(k, "FatalExit", func(e *Emu) uint64 { e.exitProcess(e.Arg32(0)); return 0 })
	reg(k, "FatalAppExitA", func(e *Emu) uint64 {
		e.logf("FatalAppExit: %s", e.CStr(e.Arg(1)))
		e.exitProcess(255)
		return 0
	})
	reg(k, "FatalAppExitW", func(e *Emu) uint64 {
		e.logf("FatalAppExit: %s", e.WStr(e.Arg(1)))
		e.exitProcess(255)
		return 0
	})
	reg(k, "GetCurrentProcess", ret(pseudoProcess))
	reg(k, "GetCurrentThread", ret(pseudoThread))
	reg(k, "GetCurrentProcessId", func(e *Emu) uint64 { return uint64(e.proc.pid) })
	reg(k, "GetCurrentThreadId", func(e *Emu) uint64 { return uint64(e.Cur.ID) })
	reg(k, "GetThreadId", func(e *Emu) uint64 {
		if t := e.anyThreadOf(e.Arg(0)); t != nil {
			return uint64(t.ID)
		}
		return 0
	})
	reg(k, "GetCommandLineA", func(e *Emu) uint64 {
		if e.crt.cmdA == 0 {
			e.crt.cmdA = e.allocCStr(e.cmdLine)
		}
		return e.crt.cmdA
	})
	reg(k, "GetCommandLineW", func(e *Emu) uint64 {
		return e.Mem.R64(e.params + 0x78)
	})
	reg(k, "GetEnvironmentStringsW", func(e *Emu) uint64 {
		n := 0
		for _, kv := range e.env {
			n += 2*mem.UTF16Len(kv) + 2
		}
		a := e.heapAlloc(uint64(n+4), true)
		e.writeEnvBlock(a)
		return a
	})
	reg(k, "GetEnvironmentStringsA", func(e *Emu) uint64 {
		n := 0
		for _, kv := range e.env {
			n += len(kv) + 1
		}
		a := e.heapAlloc(uint64(n+2), true)
		p := a
		for _, kv := range e.env {
			e.Mem.WriteCStr(p, kv)
			p += uint64(len(kv) + 1)
		}
		e.Mem.W8(p, 0)
		return a
	})
	reg(k, "GetEnvironmentStrings", func(e *Emu) uint64 {
		return e.callAPI(dK32, "GetEnvironmentStringsA")
	})
	reg(k, "FreeEnvironmentStringsW", func(e *Emu) uint64 { e.heap.freeBlock(e.Arg(0)); return 1 })
	reg(k, "FreeEnvironmentStringsA", func(e *Emu) uint64 { e.heap.freeBlock(e.Arg(0)); return 1 })
	regAW(k, "GetEnvironmentVariable", func(e *Emu, w bool) uint64 {
		name := e.strArg(0, w)
		v, ok := e.getEnv(name)
		if !ok {
			return e.fail(errEnvVarNotFound)
		}
		e.SetLastError(0)
		return e.putStr(w, e.Arg(1), e.Arg32(2), v)
	})
	regAW(k, "SetEnvironmentVariable", func(e *Emu, w bool) uint64 {
		name := e.strArg(0, w)
		if e.Arg(1) == 0 {
			e.unsetEnv(name)
		} else {
			e.setEnv(name, e.strArg(1, w))
		}
		return 1
	})
	regAW(k, "ExpandEnvironmentStrings", func(e *Emu, w bool) uint64 {
		s := e.expandEnv(e.strArg(0, w))
		r := e.putStr(w, e.Arg(1), e.Arg32(2), s)
		if r <= uint64(len(s)) && e.Arg(1) != 0 && e.Arg32(2) > uint32(len(s)) {
			return r + 1
		}
		return r
	})
	regAW(k, "GetStartupInfo", func(e *Emu, w bool) uint64 {
		a := e.Arg(0)
		e.Mem.Fill(a, 0, 104)
		e.Mem.W32(a, 104)
		e.Mem.W64(a+80, stdInputHandle)
		e.Mem.W64(a+88, stdOutputHandle)
		e.Mem.W64(a+96, stdErrorHandle)
		return 0
	})

	// ---- errors ----
	reg(k, "GetLastError", func(e *Emu) uint64 { return uint64(e.LastError()) })
	reg(k, "SetLastError", func(e *Emu) uint64 { e.SetLastError(e.Arg32(0)); return 0 })
	reg(k, "RestoreLastError", func(e *Emu) uint64 { e.SetLastError(e.Arg32(0)); return 0 })
	reg(k, "SetErrorMode", func(e *Emu) uint64 { return 0 })
	reg(k, "GetErrorMode", func(e *Emu) uint64 { return 0 })
	reg(k, "SetThreadErrorMode", func(e *Emu) uint64 {
		if e.Arg(1) != 0 {
			e.Mem.W32(e.Arg(1), 0)
		}
		return 1
	})
	reg(k, "GetThreadErrorMode", retZero)
	reg(dNt, "RtlGetLastWin32Error", func(e *Emu) uint64 { return uint64(e.LastError()) })
	reg(dNt, "RtlSetLastWin32Error", func(e *Emu) uint64 { e.SetLastError(e.Arg32(0)); return 0 })
	reg(dNt, "RtlNtStatusToDosError", func(e *Emu) uint64 { return uint64(ntToWin(e.Arg32(0))) })

	// ---- modules ----
	regAW(k, "GetModuleHandle", func(e *Emu, w bool) uint64 {
		if e.Arg(0) == 0 {
			return e.exe.Base
		}
		if m := e.modByName[normDLL(e.strArg(0, w))]; m != nil {
			return m.Base
		}
		return e.fail(errModNotFound)
	})
	regAW(k, "GetModuleHandleEx", func(e *Emu, w bool) uint64 {
		flags, out := e.Arg32(0), e.Arg(2)
		var m *Module
		if flags&4 != 0 { // FROM_ADDRESS
			m = e.moduleAt(e.Arg(1))
		} else if e.Arg(1) == 0 {
			m = e.exe
		} else {
			m = e.modByName[normDLL(e.strArg(1, w))]
		}
		if m == nil {
			if out != 0 {
				e.Mem.W64(out, 0)
			}
			return e.fail(errModNotFound)
		}
		if out != 0 {
			e.Mem.W64(out, m.Base)
		}
		return 1
	})
	regAW(k, "GetModuleFileName", func(e *Emu, w bool) uint64 {
		m := e.exe
		if h := e.Arg(0); h != 0 {
			m = e.moduleAt(h)
			if m == nil {
				return e.fail(errModNotFound)
			}
		}
		p := m.WinPath
		if p == "" {
			p = `C:\windows\system32\` + m.Name
		}
		return e.truncStr(w, e.Arg(1), e.Arg32(2), p)
	})
	regAW(k, "LoadLibrary", func(e *Emu, w bool) uint64 { return e.loadLibrary(e.strArg(0, w)) })
	regAW(k, "LoadLibraryEx", func(e *Emu, w bool) uint64 {
		flags := e.Arg32(2)
		if e.Arg(0) == 0 || e.Arg(1) != 0 || // hFile is reserved, must be NULL
			flags&loadWithAlteredSearchPath != 0 && flags&loadLibrarySearchMask != 0 {
			return e.fail(errInvalidParameter)
		}
		return e.loadLibraryEx(e.strArg(0, w), flags)
	})
	reg(k, "FreeLibrary", retTrue)
	reg(k, "FreeLibraryAndExitThread", func(e *Emu) uint64 { e.exitThread(e.Arg32(1)); return 0 })
	reg(k, "DisableThreadLibraryCalls", func(e *Emu) uint64 {
		if m := e.moduleAt(e.Arg(0)); m != nil {
			m.noThreadCB = true
		}
		return 1
	})
	reg(k, "GetProcAddress", func(e *Emu) uint64 {
		m := e.moduleAt(e.Arg(0))
		if m == nil {
			for _, mm := range e.modules {
				if mm.Base == e.Arg(0) {
					m = mm
				}
			}
		}
		if m == nil {
			return e.fail(errModNotFound)
		}
		n := e.Arg(1)
		var a uint64
		var ok bool
		if n>>16 == 0 {
			a, ok = e.GetExport(m, "", uint32(n), true)
		} else {
			a, ok = e.GetExport(m, e.CStr(n), 0, false)
		}
		if !ok {
			return e.fail(errProcNotFound)
		}
		return a
	})
	reg(k, "AddDllDirectory", func(e *Emu) uint64 { return 1 })
	reg(k, "RemoveDllDirectory", retTrue)
	reg(k, "SetDefaultDllDirectories", retTrue)
	regAW(k, "SetDllDirectory", func(e *Emu, w bool) uint64 { return 1 })
	reg(k, "FindResourceA", func(e *Emu) uint64 { return e.fail(1813) })
	reg(k, "FindResourceW", func(e *Emu) uint64 { return e.findResource(e.Arg(0), e.Arg(1), e.Arg(2), true) })
	reg(k, "FindResourceExW", func(e *Emu) uint64 { return e.findResource(e.Arg(0), e.Arg(2), e.Arg(1), true) })
	reg(k, "LoadResource", func(e *Emu) uint64 { return e.Arg(1) })
	reg(k, "LockResource", func(e *Emu) uint64 { return e.Mem.R64(e.Arg(0)) })
	reg(k, "SizeofResource", func(e *Emu) uint64 { return uint64(e.Mem.R32(e.Arg(1) + 8)) })
	reg(k, "FreeResource", retTrue)

	// ---- system information ----
	sysinfo := func(e *Emu) uint64 {
		a := e.Arg(0)
		m := e.Mem
		m.Fill(a, 0, 48)
		m.W16(a, 9) // AMD64
		m.W32(a+4, 0x1000)
		m.W64(a+8, 0x10000)
		m.W64(a+16, 0x7FFFFFFEFFFF)
		m.W64(a+24, 0xF)
		m.W32(a+32, 4)
		m.W32(a+36, 8664)
		m.W32(a+40, 0x10000)
		m.W16(a+44, 6)
		m.W16(a+46, 0x9E0A)
		return 0
	}
	reg(k, "GetSystemInfo", sysinfo)
	reg(k, "GetNativeSystemInfo", sysinfo)
	reg(k, "GetVersion", func(e *Emu) uint64 { return 19045<<16 | 0<<8 | 10 })
	regAW(k, "GetVersionEx", func(e *Emu, w bool) uint64 {
		a := e.Arg(0)
		e.Mem.W32(a+4, 10)
		e.Mem.W32(a+8, 0)
		e.Mem.W32(a+12, 19045)
		e.Mem.W32(a+16, 2)
		sz := e.Mem.R32(a)
		if w {
			if sz >= 284 {
				e.Mem.W16(a+276, 0)
				e.Mem.W16(a+278, 0)
				e.Mem.W16(a+280, 0x100)
				e.Mem.W8(a+282, 1)
			}
		} else if sz >= 156 {
			e.Mem.W8(a+154, 1)
		}
		return 1
	})
	reg(dNt, "RtlGetVersion", func(e *Emu) uint64 {
		a := e.Arg(0)
		e.Mem.W32(a+4, 10)
		e.Mem.W32(a+8, 0)
		e.Mem.W32(a+12, 19045)
		e.Mem.W32(a+16, 2)
		return 0
	})
	reg(dNt, "RtlGetNtVersionNumbers", func(e *Emu) uint64 {
		if e.Arg(0) != 0 {
			e.Mem.W32(e.Arg(0), 10)
		}
		if e.Arg(1) != 0 {
			e.Mem.W32(e.Arg(1), 0)
		}
		if e.Arg(2) != 0 {
			e.Mem.W32(e.Arg(2), 0xF0000000|19045)
		}
		return 0
	})
	reg(k, "VerifyVersionInfoW", retTrue)
	reg(k, "VerSetConditionMask", func(e *Emu) uint64 { return e.Arg(0) })
	reg(k, "IsProcessorFeaturePresent", func(e *Emu) uint64 {
		switch e.Arg32(0) {
		case 2, 3, 6, 7, 8, 9, 10, 12, 13, 17, 20, 23, 36, 37, 38:
			return 1
		}
		return 0
	})
	reg(k, "IsWow64Process", func(e *Emu) uint64 { e.Mem.W32(e.Arg(1), 0); return 1 })
	reg(k, "IsWow64Process2", func(e *Emu) uint64 {
		e.Mem.W16(e.Arg(1), 0)
		if e.Arg(2) != 0 {
			e.Mem.W16(e.Arg(2), 0x8664)
		}
		return 1
	})
	reg(k, "GetActiveProcessorCount", ret(4))
	reg(k, "GetMaximumProcessorCount", ret(4))
	reg(k, "GetActiveProcessorGroupCount", ret(1))
	reg(k, "GetMaximumProcessorGroupCount", ret(1))
	reg(k, "GetCurrentProcessorNumber", retZero)
	reg(k, "GetCurrentProcessorNumberEx", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), 0); return 0 })
	reg(k, "GetLogicalProcessorInformation", func(e *Emu) uint64 {
		// one entry per core (RelationProcessorCore)
		buf, lenp := e.Arg(0), e.Arg(1)
		need := uint32(4 * 32)
		if e.Mem.R32(lenp) < need || buf == 0 {
			e.Mem.W32(lenp, need)
			return e.fail(errInsufficientBuf)
		}
		for i := 0; i < 4; i++ {
			p := buf + uint64(32*i)
			e.Mem.Fill(p, 0, 32)
			e.Mem.W64(p, 1<<i)
			e.Mem.W32(p+8, 0)
		}
		e.Mem.W32(lenp, need)
		return 1
	})
	reg(k, "GetLogicalProcessorInformationEx", func(e *Emu) uint64 {
		rel, buf, lenp := e.Arg32(0), e.Arg(1), e.Arg(2)
		_ = rel
		const entry = 48
		need := uint32(4 * entry)
		if e.Mem.R32(lenp) < need || buf == 0 {
			e.Mem.W32(lenp, need)
			return e.fail(errInsufficientBuf)
		}
		for i := 0; i < 4; i++ {
			p := buf + uint64(entry*i)
			e.Mem.Fill(p, 0, entry)
			e.Mem.W32(p, 0) // RelationProcessorCore
			e.Mem.W32(p+4, entry)
			e.Mem.W16(p+30, 1) // GroupCount
			e.Mem.W64(p+32, 1<<i)
		}
		e.Mem.W32(lenp, need)
		return 1
	})
	reg(k, "GetProcessAffinityMask", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(1), 0xF)
		e.Mem.W64(e.Arg(2), 0xF)
		return 1
	})
	reg(k, "SetProcessAffinityMask", retTrue)
	reg(k, "SetThreadAffinityMask", ret(0xF))
	reg(k, "GlobalMemoryStatusEx", func(e *Emu) uint64 {
		a := e.Arg(0)
		e.Mem.W32(a+4, 30)
		e.Mem.W64(a+8, 8<<30)
		e.Mem.W64(a+16, 6<<30)
		e.Mem.W64(a+24, 16<<30)
		e.Mem.W64(a+32, 14<<30)
		e.Mem.W64(a+40, 128<<40)
		e.Mem.W64(a+48, 127<<40)
		e.Mem.W64(a+56, 0)
		return 1
	})
	reg(k, "GetPhysicallyInstalledSystemMemory", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 8<<20); return 1 })
	regAW(k, "GetComputerName", func(e *Emu, w bool) uint64 {
		n := e.Mem.R32(e.Arg(1))
		r := e.putStr(w, e.Arg(0), n, "WINEMU")
		if r > 6 {
			e.Mem.W32(e.Arg(1), uint32(r))
			return e.fail(111)
		}
		e.Mem.W32(e.Arg(1), uint32(r))
		return 1
	})
	regAW(k, "GetComputerNameEx", func(e *Emu, w bool) uint64 {
		n := e.Mem.R32(e.Arg(2))
		r := e.putStr(w, e.Arg(1), n, "WINEMU")
		if r > 6 {
			e.Mem.W32(e.Arg(2), uint32(r))
			return e.fail(errMoreData)
		}
		e.Mem.W32(e.Arg(2), uint32(r))
		return 1
	})
	regAW(k, "GetWindowsDirectory", func(e *Emu, w bool) uint64 { return e.putStr(w, e.Arg(0), e.Arg32(1), `C:\windows`) })
	regAW(k, "GetSystemWindowsDirectory", func(e *Emu, w bool) uint64 { return e.putStr(w, e.Arg(0), e.Arg32(1), `C:\windows`) })
	regAW(k, "GetSystemDirectory", func(e *Emu, w bool) uint64 {
		return e.putStr(w, e.Arg(0), e.Arg32(1), `C:\windows\system32`)
	})
	regAW(k, "GetSystemWow64Directory", func(e *Emu, w bool) uint64 { return e.fail(errCallNotImpl) })

	// ---- time ----
	reg(k, "GetTickCount", func(e *Emu) uint64 { return uint64(uint32(e.tickMs())) })
	reg(k, "GetTickCount64", func(e *Emu) uint64 { return e.tickMs() })
	reg(k, "QueryPerformanceCounter", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(0), uint64(time.Since(e.started).Nanoseconds()/100)+1000000)
		return 1
	})
	reg(k, "QueryPerformanceFrequency", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 10000000); return 1 })
	reg(dNt, "RtlQueryPerformanceCounter", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(0), uint64(time.Since(e.started).Nanoseconds()/100)+1000000)
		return 1
	})
	reg(dNt, "RtlQueryPerformanceFrequency", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 10000000); return 1 })
	reg(dNt, "NtQueryPerformanceCounter", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(0), uint64(time.Since(e.started).Nanoseconds()/100)+1000000)
		if e.Arg(1) != 0 {
			e.Mem.W64(e.Arg(1), 10000000)
		}
		return 0
	})
	reg(k, "QueryUnbiasedInterruptTime", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(0), uint64(time.Since(e.started).Nanoseconds()/100))
		return 1
	})
	reg(k, "QueryInterruptTime", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(0), uint64(time.Since(e.started).Nanoseconds()/100))
		return 0
	})
	reg(k, "QueryInterruptTimePrecise", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(0), uint64(time.Since(e.started).Nanoseconds()/100))
		return 0
	})
	ft := func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), unixToFiletime(time.Now())); return 0 }
	reg(k, "GetSystemTimeAsFileTime", ft)
	reg(k, "GetSystemTimePreciseAsFileTime", ft)
	reg(dNt, "NtQuerySystemTime", ft)
	reg(dNt, "RtlGetSystemTimePrecise", func(e *Emu) uint64 { return unixToFiletime(time.Now()) })
	reg(k, "GetSystemTime", func(e *Emu) uint64 { e.writeSystemTime(e.Arg(0), time.Now().UTC()); return 0 })
	reg(k, "GetLocalTime", func(e *Emu) uint64 { e.writeSystemTime(e.Arg(0), time.Now()); return 0 })
	reg(k, "SetLocalTime", func(e *Emu) uint64 { return e.fail(errAccessDenied) })
	reg(k, "SetSystemTime", func(e *Emu) uint64 { return e.fail(errAccessDenied) })
	reg(k, "FileTimeToSystemTime", func(e *Emu) uint64 {
		e.writeSystemTime(e.Arg(1), filetimeToUnix(e.Mem.R64(e.Arg(0))).UTC())
		return 1
	})
	reg(k, "SystemTimeToFileTime", func(e *Emu) uint64 {
		t := e.readSystemTime(e.Arg(0), time.UTC)
		e.Mem.W64(e.Arg(1), unixToFiletime(t))
		return 1
	})
	reg(k, "FileTimeToLocalFileTime", func(e *Emu) uint64 {
		t := filetimeToUnix(e.Mem.R64(e.Arg(0)))
		_, off := t.Zone()
		e.Mem.W64(e.Arg(1), e.Mem.R64(e.Arg(0))+uint64(int64(off)*10000000))
		return 1
	})
	reg(k, "LocalFileTimeToFileTime", func(e *Emu) uint64 {
		t := filetimeToUnix(e.Mem.R64(e.Arg(0)))
		_, off := t.Zone()
		e.Mem.W64(e.Arg(1), e.Mem.R64(e.Arg(0))-uint64(int64(off)*10000000))
		return 1
	})
	reg(k, "SystemTimeToTzSpecificLocalTime", func(e *Emu) uint64 {
		t := e.readSystemTime(e.Arg(1), time.UTC)
		e.writeSystemTime(e.Arg(2), t.Local())
		return 1
	})
	reg(k, "TzSpecificLocalTimeToSystemTime", func(e *Emu) uint64 {
		t := e.readSystemTime(e.Arg(1), time.Local)
		e.writeSystemTime(e.Arg(2), t.UTC())
		return 1
	})
	reg(k, "GetTimeZoneInformation", func(e *Emu) uint64 {
		e.writeTZI(e.Arg(0))
		return 0 // TIME_ZONE_ID_UNKNOWN
	})
	reg(k, "GetDynamicTimeZoneInformation", func(e *Emu) uint64 {
		e.Mem.Fill(e.Arg(0), 0, 432)
		e.writeTZI(e.Arg(0))
		return 0
	})
	reg(k, "CompareFileTime", func(e *Emu) uint64 {
		a, b := e.Mem.R64(e.Arg(0)), e.Mem.R64(e.Arg(1))
		switch {
		case a < b:
			return ^uint64(0)
		case a > b:
			return 1
		}
		return 0
	})
	reg(k, "GetProcessTimes", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(1), unixToFiletime(e.started))
		e.Mem.W64(e.Arg(2), 0)
		e.Mem.W64(e.Arg(3), 0)
		e.Mem.W64(e.Arg(4), uint64(time.Since(e.started)/100))
		return 1
	})
	reg(k, "GetThreadTimes", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(1), unixToFiletime(e.started))
		e.Mem.W64(e.Arg(2), 0)
		e.Mem.W64(e.Arg(3), 0)
		e.Mem.W64(e.Arg(4), uint64(time.Since(e.started)/100))
		return 1
	})
	reg(k, "GetSystemTimes", func(e *Emu) uint64 {
		for i := 0; i < 3; i++ {
			if e.Arg(i) != 0 {
				e.Mem.W64(e.Arg(i), uint64(time.Since(e.started)/100))
			}
		}
		return 1
	})
	reg(k, "QueryThreadCycleTime", func(e *Emu) uint64 { e.Mem.W64(e.Arg(1), e.Cur.CPU.ICount); return 1 })
	reg(k, "QueryProcessCycleTime", func(e *Emu) uint64 { e.Mem.W64(e.Arg(1), e.Cur.CPU.ICount); return 1 })
	reg(k, "GetSystemTimeAdjustment", func(e *Emu) uint64 {
		e.Mem.W32(e.Arg(0), 156250)
		e.Mem.W32(e.Arg(1), 156250)
		e.Mem.W32(e.Arg(2), 1)
		return 1
	})

	// ---- memory ----
	reg(k, "VirtualAlloc", func(e *Emu) uint64 { return e.virtualAlloc(e.Arg(0), e.Arg(1), e.Arg32(2), e.Arg32(3)) })
	reg(k, "VirtualAlloc2", func(e *Emu) uint64 { return e.virtualAlloc(e.Arg(1), e.Arg(2), e.Arg32(3), e.Arg32(4)) })
	reg(k, "VirtualFree", func(e *Emu) uint64 { return e.virtualFree(e.Arg(0), e.Arg(1), e.Arg32(2)) })
	reg(k, "VirtualProtect", func(e *Emu) uint64 {
		r := e.Mem.FindRegion(e.Arg(0))
		if r == nil {
			return e.fail(487)
		}
		if e.Arg(3) != 0 {
			e.Mem.W32(e.Arg(3), r.Prot)
		}
		return 1
	})
	reg(k, "VirtualQuery", func(e *Emu) uint64 { return e.virtualQuery(e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(k, "VirtualLock", retTrue)
	reg(k, "VirtualUnlock", retTrue)
	reg(k, "FlushInstructionCache", func(e *Emu) uint64 {
		for _, t := range e.threads {
			t.CPU.InvalidateCode()
		}
		return 1
	})
	reg(k, "GetLargePageMinimum", retZero)
	reg(k, "GetWriteWatch", func(e *Emu) uint64 { return 1 })
	reg(k, "PrefetchVirtualMemory", retTrue)
	reg(k, "DiscardVirtualMemory", retZero)
	reg(k, "OfferVirtualMemory", retZero)
	reg(k, "SetProcessWorkingSetSize", retTrue)
	reg(k, "GetProcessWorkingSetSize", func(e *Emu) uint64 {
		e.Mem.W64(e.Arg(1), 1<<20)
		e.Mem.W64(e.Arg(2), 64<<20)
		return 1
	})
	reg(k, "IsBadReadPtr", func(e *Emu) uint64 { return b2u(!e.Mem.Valid(e.Arg(0))) })
	reg(k, "IsBadWritePtr", func(e *Emu) uint64 { return b2u(!e.Mem.Valid(e.Arg(0))) })
	reg(k, "IsBadCodePtr", func(e *Emu) uint64 { return b2u(!e.Mem.Valid(e.Arg(0))) })

	// heap
	reg(k, "GetProcessHeap", func(e *Emu) uint64 { return e.heap.processHeap })
	reg(k, "GetProcessHeaps", func(e *Emu) uint64 {
		if e.Arg32(0) >= 1 {
			e.Mem.W64(e.Arg(1), e.heap.processHeap)
		}
		return 1
	})
	reg(k, "HeapCreate", func(e *Emu) uint64 {
		r, err := e.Mem.Alloc(0x10000, mem.PageReadWrite, mem.MemPrivate, "heap-handle")
		if err != nil {
			return 0
		}
		e.heap.heaps[r.Base] = true
		return r.Base
	})
	reg(k, "HeapDestroy", func(e *Emu) uint64 {
		h := e.Arg(0)
		if h == e.heap.processHeap {
			return 1
		}
		e.heap.destroy(h)
		e.Mem.Unmap(h)
		return 1
	})
	reg(k+","+dNt, "HeapAlloc", func(e *Emu) uint64 {
		a := e.heap.alloc(e.Arg(0), e.Arg(2), e.Arg32(1)&8 != 0)
		if a == 0 {
			e.SetLastError(errNotEnoughMemory)
		}
		return a
	})
	reg(dNt, "RtlAllocateHeap", func(e *Emu) uint64 { return e.heap.alloc(e.Arg(0), e.Arg(2), e.Arg32(1)&8 != 0) })
	reg(k, "HeapReAlloc", func(e *Emu) uint64 {
		if e.Arg32(1)&0x10 != 0 { // IN_PLACE_REALLOC_ONLY
			if s, ok := e.heap.size(e.Arg(2)); ok && e.Arg(3) <= s {
				return e.Arg(2)
			}
			return 0
		}
		return e.heap.realloc(e.Arg(0), e.Arg(2), e.Arg(3), e.Arg32(1)&8 != 0)
	})
	reg(dNt, "RtlReAllocateHeap", func(e *Emu) uint64 {
		return e.heap.realloc(e.Arg(0), e.Arg(2), e.Arg(3), e.Arg32(1)&8 != 0)
	})
	reg(k, "HeapFree", func(e *Emu) uint64 {
		if e.Arg(2) == 0 {
			return 1
		}
		return b2u(e.heap.freeBlock(e.Arg(2)))
	})
	reg(dNt, "RtlFreeHeap", func(e *Emu) uint64 {
		if e.Arg(2) == 0 {
			return 1
		}
		return b2u(e.heap.freeBlock(e.Arg(2)))
	})
	reg(k, "HeapSize", func(e *Emu) uint64 {
		s, ok := e.heap.size(e.Arg(2))
		if !ok {
			return ^uint64(0)
		}
		return s
	})
	reg(dNt, "RtlSizeHeap", func(e *Emu) uint64 {
		s, ok := e.heap.size(e.Arg(2))
		if !ok {
			return ^uint64(0)
		}
		return s
	})
	reg(k, "HeapValidate", retTrue)
	reg(k, "HeapCompact", ret(0x100000))
	reg(k, "HeapLock", retTrue)
	reg(k, "HeapUnlock", retTrue)
	reg(k, "HeapSetInformation", retTrue)
	reg(k, "HeapQueryInformation", func(e *Emu) uint64 {
		if e.Arg(2) != 0 && e.Arg(3) >= 4 {
			e.Mem.W32(e.Arg(2), 2)
		}
		return 1
	})
	reg(k, "HeapWalk", func(e *Emu) uint64 { return e.fail(errNoMoreItems) })
	reg(k, "HeapSummary", func(e *Emu) uint64 { return 1 })
	for _, p := range []string{"Local", "Global"} {
		reg(k, p+"Alloc", func(e *Emu) uint64 { return e.heapAlloc(e.Arg(1), e.Arg32(0)&0x40 != 0) })
		reg(k, p+"ReAlloc", func(e *Emu) uint64 {
			return e.heap.realloc(e.heap.processHeap, e.Arg(0), e.Arg(1), e.Arg32(2)&0x40 != 0)
		})
		reg(k, p+"Free", func(e *Emu) uint64 {
			if e.Arg(0) != 0 && !e.heap.freeBlock(e.Arg(0)) {
				return e.Arg(0)
			}
			return 0
		})
		reg(k, p+"Lock", func(e *Emu) uint64 { return e.Arg(0) })
		reg(k, p+"Unlock", retTrue)
		reg(k, p+"Size", func(e *Emu) uint64 { s, _ := e.heap.size(e.Arg(0)); return s })
		reg(k, p+"Handle", func(e *Emu) uint64 { return e.Arg(0) })
		reg(k, p+"Flags", retZero)
	}

	// ---- misc ----
	reg(k, "EncodePointer", func(e *Emu) uint64 { return e.Arg(0) ^ 0x5A5A5A5A5A5A5A5A })
	reg(k, "DecodePointer", func(e *Emu) uint64 { return e.Arg(0) ^ 0x5A5A5A5A5A5A5A5A })
	reg(k, "EncodeSystemPointer", func(e *Emu) uint64 { return e.Arg(0) ^ 0x3C3C3C3C3C3C3C3C })
	reg(k, "DecodeSystemPointer", func(e *Emu) uint64 { return e.Arg(0) ^ 0x3C3C3C3C3C3C3C3C })
	reg(dNt, "RtlEncodePointer", func(e *Emu) uint64 { return e.Arg(0) ^ 0x5A5A5A5A5A5A5A5A })
	reg(dNt, "RtlDecodePointer", func(e *Emu) uint64 { return e.Arg(0) ^ 0x5A5A5A5A5A5A5A5A })
	reg(k, "IsDebuggerPresent", retZero)
	reg(k, "CheckRemoteDebuggerPresent", func(e *Emu) uint64 { e.Mem.W32(e.Arg(1), 0); return 1 })
	reg(k, "DebugBreak", func(e *Emu) uint64 {
		x := e.callerContext()
		e.raiseGuest(&guestException{code: cpu.ExcBreakpoint, ctx: x, addr: x.Rip})
		return 0
	})
	regAW(k, "OutputDebugString", func(e *Emu, w bool) uint64 {
		if e.Opt.Verbose || os.Getenv("WINEMU_DEBUGSTRING") != "" {
			e.logf("debug: %s", strings.TrimRight(e.strArg(0, w), "\r\n"))
		}
		return 0
	})
	reg(k, "Beep", retTrue)
	reg(k, "SetProcessDEPPolicy", retTrue)
	reg(k, "SetProcessMitigationPolicy", retTrue)
	reg(k, "GetProcessMitigationPolicy", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(2), 0, e.Arg(3)); return 1 })
	reg(k, "SetPriorityClass", retTrue)
	reg(k, "GetPriorityClass", ret(0x20))
	reg(k, "SetProcessPriorityBoost", func(e *Emu) uint64 {
		if e.processOf(e.Arg(0)) == nil {
			return e.fail(errInvalidHandle)
		}
		return 1
	})
	reg(k, "SetProcessShutdownParameters", retTrue)
	reg(k, "GetProcessVersion", ret(0x000A0000))
	reg(k, "SetProcessInformation", retTrue)
	reg(k, "GetProcessInformation", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(2), 0, e.Arg(3)); return 1 })
	reg(k, "GetProcessHandleCount", func(e *Emu) uint64 { e.Mem.W32(e.Arg(1), uint32(e.handles.count())); return 1 })
	reg(k, "GetProcessIoCounters", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(1), 0, 48); return 1 })
	reg(k, "K32GetProcessMemoryInfo", func(e *Emu) uint64 { return processMemInfo(e, e.Arg(1), e.Arg32(2)) })
	reg("psapi.dll", "GetProcessMemoryInfo", func(e *Emu) uint64 { return processMemInfo(e, e.Arg(1), e.Arg32(2)) })
	regAW(k, "QueryFullProcessImageName", func(e *Emu, w bool) uint64 {
		n := e.Mem.R32(e.Arg(3))
		r := e.putStr(w, e.Arg(2), n, e.exeWin)
		if r > uint64(len([]rune(e.exeWin))) {
			return e.fail(errInsufficientBuf)
		}
		e.Mem.W32(e.Arg(3), uint32(r))
		return 1
	})
	regAW(k, "K32GetModuleFileNameEx", func(e *Emu, w bool) uint64 {
		m := e.exe
		if h := e.Arg(1); h != 0 {
			if m = e.moduleAt(h); m == nil {
				return 0
			}
		}
		return e.truncStr(w, e.Arg(2), e.Arg32(3), m.WinPath)
	})
	reg(k, "K32EnumProcessModules", func(e *Emu) uint64 {
		buf, cb, need := e.Arg(1), e.Arg32(2), e.Arg(3)
		var native []*Module
		for _, m := range e.modules {
			native = append(native, m)
		}
		for i, m := range native {
			if uint32(8*(i+1)) <= cb {
				e.Mem.W64(buf+uint64(8*i), m.Base)
			}
		}
		e.Mem.W32(need, uint32(8*len(native)))
		return 1
	})
	reg(k, "K32GetModuleInformation", func(e *Emu) uint64 {
		m := e.moduleAt(e.Arg(1))
		if m == nil {
			return 0
		}
		e.Mem.W64(e.Arg(2), m.Base)
		e.Mem.W32(e.Arg(2)+8, uint32(m.Size))
		e.Mem.W64(e.Arg(2)+16, m.Entry)
		return 1
	})
}

func processMemInfo(e *Emu, a uint64, cb uint32) uint64 {
	e.Mem.Fill(a, 0, uint64(cb))
	e.Mem.W32(a, cb)
	var total uint64
	for _, r := range e.Mem.Regions() {
		total += r.Size
	}
	e.Mem.W64(a+16, total/4)
	e.Mem.W64(a+24, total/4)
	e.Mem.W64(a+64, total/4)
	e.Mem.W64(a+72, total/4)
	return 1
}

func (e *Emu) tickMs() uint64 { return uint64(time.Since(e.started)/time.Millisecond) + 100000 }

func (e *Emu) writeSystemTime(a uint64, t time.Time) {
	m := e.Mem
	m.W16(a, uint16(t.Year()))
	m.W16(a+2, uint16(t.Month()))
	m.W16(a+4, uint16(t.Weekday()))
	m.W16(a+6, uint16(t.Day()))
	m.W16(a+8, uint16(t.Hour()))
	m.W16(a+10, uint16(t.Minute()))
	m.W16(a+12, uint16(t.Second()))
	m.W16(a+14, uint16(t.Nanosecond()/1e6))
}

func (e *Emu) readSystemTime(a uint64, loc *time.Location) time.Time {
	m := e.Mem
	return time.Date(int(m.R16(a)), time.Month(m.R16(a+2)), int(m.R16(a+6)), int(m.R16(a+8)),
		int(m.R16(a+10)), int(m.R16(a+12)), int(m.R16(a+14))*1e6, loc)
}

func (e *Emu) writeTZI(a uint64) {
	m := e.Mem
	m.Fill(a, 0, 172)
	name, off := time.Now().Zone()
	m.W32(a, uint32(int32(-off/60)))
	m.WriteWStr(a+4, name)
	m.WriteWStr(a+88, name)
}

// ---------------------------------------------------------------------------
// environment

func (e *Emu) getEnv(name string) (string, bool) {
	for _, kv := range e.env {
		if i := strings.IndexByte(kv[1:], '='); i >= 0 && strings.EqualFold(kv[:i+1], name) {
			return kv[i+2:], true
		}
	}
	return "", false
}

func (e *Emu) setEnv(name, val string) {
	for i, kv := range e.env {
		if j := strings.IndexByte(kv[1:], '='); j >= 0 && strings.EqualFold(kv[:j+1], name) {
			e.env[i] = name + "=" + val
			e.crt.envChanged()
			return
		}
	}
	e.env = append(e.env, name+"="+val)
	e.crt.envChanged()
}

func (e *Emu) unsetEnv(name string) {
	for i, kv := range e.env {
		if j := strings.IndexByte(kv[1:], '='); j >= 0 && strings.EqualFold(kv[:j+1], name) {
			e.env = append(e.env[:i], e.env[i+1:]...)
			e.crt.envChanged()
			return
		}
	}
}

func (e *Emu) expandEnv(s string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			b.WriteString(s)
			break
		}
		name := s[i+1 : i+1+j]
		if v, ok := e.getEnv(name); ok {
			b.WriteString(s[:i])
			b.WriteString(v)
		} else {
			b.WriteString(s[:i+2+j])
		}
		s = s[i+2+j:]
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// LoadLibrary

// LoadLibraryEx flags
const (
	dontResolveDllReferences  = 0x1
	loadLibraryAsDatafile     = 0x2
	loadWithAlteredSearchPath = 0x8
	loadLibraryAsImageRes     = 0x20
	loadLibraryAsDatafileExcl = 0x40
	loadLibrarySearchMask     = 0x1F00 // LOAD_LIBRARY_SEARCH_*
	loadLibrarySearchSystem32 = 0x800
)

func (e *Emu) loadLibrary(name string) uint64 { return e.loadLibraryEx(name, 0) }

// loadLibraryEx implements LoadLibraryEx: a data-file / image-resource load
// of a module not yet loaded as an image returns the mapping tagged in the
// low bits (1 data file, 2 image resource) without running its entry point,
// as does DONT_RESOLVE_DLL_REFERENCES (untagged); a later ordinary load
// initialises it. LOAD_LIBRARY_SEARCH_SYSTEM32 alone searches only the
// system directory.
func (e *Emu) loadLibraryEx(name string, flags uint32) uint64 {
	if name == "" {
		return e.fail(errInvalidParameter)
	}
	m, err := e.loadDLL(name, flags&loadLibrarySearchMask == loadLibrarySearchSystem32)
	if err != nil {
		e.warnOnce("ll"+name, "LoadLibrary(%s): %v", name, err)
		return e.fail(errModNotFound)
	}
	if m.Native && !m.initDone {
		switch {
		case flags&loadLibraryAsImageRes != 0:
			return m.Base | 2
		case flags&(loadLibraryAsDatafile|loadLibraryAsDatafileExcl) != 0:
			return m.Base | 1
		case flags&dontResolveDllReferences != 0:
			return m.Base
		}
		if err := e.initModule(m); err != nil {
			return e.fail(1114)
		}
	}
	return m.Base
}

// callAPI invokes another registered API implementation directly.
func (e *Emu) callAPI(dll, name string) uint64 {
	if t := registry[dll]; t != nil {
		if d := t.funcs[name]; d != nil && d.fn != nil {
			return d.fn(e)
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// virtual memory

func (e *Emu) virtualAlloc(addr, size uint64, typ, prot uint32) uint64 {
	r, err := vmAlloc(e.Mem, addr, size, typ, prot)
	if err != 0 {
		return e.fail(err)
	}
	return r
}

// vmAlloc is VirtualAlloc on the address space m (any process); it returns
// the base or a Win32 error.
func vmAlloc(m *mem.Memory, addr, size uint64, typ, prot uint32) (uint64, uint32) {
	if size == 0 {
		return 0, errInvalidParameter
	}
	if addr != 0 {
		if r := m.FindRegion(addr); r != nil {
			// commit inside an existing reservation
			if typ&memCommitFlag == 0 {
				return 0, 487
			}
			start, end := addr&^(mem.PageSize-1), (addr+size+mem.PageSize-1)&^(mem.PageSize-1)
			if end > r.Base+r.Size || end < start {
				return 0, 487
			}
			m.SetCommitted(r, start, end-start, true)
			return start, 0
		}
		if typ&memReserveFlag == 0 { // MEM_COMMIT needs a reservation
			return 0, 487
		}
		base := addr &^ 0xFFFF
		end := (addr + size + 0xFFFF) &^ 0xFFFF
		r, err := m.Map(base, end-base, prot, mem.MemPrivate, "virtual")
		if err != nil {
			return 0, 487
		}
		reserve(m, r, addr, size, typ)
		return r.Base, 0
	}
	start := uint64(0x100000)
	if typ&0x100000 != 0 { // MEM_TOP_DOWN
		start = 0x7FF000000000
	}
	r, err := m.AllocFrom(start, size, prot, mem.MemPrivate, "virtual")
	if err != nil {
		return 0, errNotEnoughMemory
	}
	reserve(m, r, r.Base, size, typ)
	return r.Base, 0
}

const (
	memCommitFlag   = 0x1000
	memReserveFlag  = 0x2000
	memDecommitFlag = 0x4000
	memReleaseFlag  = 0x8000
)

// reserve sets the commit state of a new reservation r: the pages of
// [addr, addr+size) are committed if typ has MEM_COMMIT, the rest reserved.
func reserve(m *mem.Memory, r *mem.Region, addr, size uint64, typ uint32) {
	r.Reserve()
	if typ&memCommitFlag != 0 {
		start := addr &^ (mem.PageSize - 1)
		m.SetCommitted(r, start, (addr+size+mem.PageSize-1)&^(mem.PageSize-1)-start, true)
	}
}

func (e *Emu) virtualFree(addr, size uint64, typ uint32) uint64 {
	if err := vmFree(e.Mem, addr, size, typ); err != 0 {
		return e.fail(err)
	}
	for _, t := range e.threads {
		t.CPU.InvalidateCode()
	}
	return 1
}

// vmFree is VirtualFree on the address space m; the caller invalidates the
// code caches of m's threads.
func vmFree(m *mem.Memory, addr, size uint64, typ uint32) uint32 {
	r := m.FindRegion(addr)
	if r == nil {
		return 487
	}
	switch typ & (memDecommitFlag | memReleaseFlag) {
	case memReleaseFlag:
		if size != 0 {
			return errInvalidParameter
		}
		if r.Base != addr {
			return 487
		}
		m.Unmap(addr)
	case memDecommitFlag:
		start, end := addr&^(mem.PageSize-1), r.Base+r.Size
		if size != 0 {
			end = (addr + size + mem.PageSize - 1) &^ (mem.PageSize - 1)
		}
		if end > r.Base+r.Size || end < start {
			return 487
		}
		if r.Section != nil {
			m.Zero(start, end-start)
		} else {
			m.SetCommitted(r, start, end-start, false)
		}
	default:
		return errInvalidParameter
	}
	return 0
}

func (e *Emu) virtualQuery(addr, buf, n uint64) uint64 {
	if n < 48 {
		return e.fail(errInsufficientBuf)
	}
	vmQuery(e.Mem, addr).write(e.Mem, buf)
	return 48
}

// memInfo is a MEMORY_BASIC_INFORMATION (48 bytes).
type memInfo struct {
	base, allocBase, size uint64
	allocProt, state      uint32
	prot, typ             uint32
}

func (i memInfo) write(m *mem.Memory, buf uint64) {
	m.Fill(buf, 0, 48)
	m.W64(buf, i.base)
	m.W64(buf+8, i.allocBase)
	m.W32(buf+16, i.allocProt)
	m.W64(buf+24, i.size)
	m.W32(buf+32, i.state)
	m.W32(buf+36, i.prot)
	m.W32(buf+40, i.typ)
}

// vmQuery is VirtualQuery on the address space m.
func vmQuery(m *mem.Memory, addr uint64) memInfo {
	r := m.FindRegion(addr)
	if r == nil {
		// free region: find extent
		base := addr &^ 0xFFF
		next := uint64(mem.MaxAddr)
		for _, rr := range m.Regions() {
			if rr.Base > addr && rr.Base < next {
				next = rr.Base
			}
		}
		return memInfo{base: base, size: next - base, state: 0x10000, prot: mem.PageNoAccess} // MEM_FREE
	}
	prot := r.Prot
	if r.Kind == mem.MemImage {
		prot = mem.PageExecuteReadWrite
	}
	committed, end := r.CommitRun(addr)
	state := uint32(memCommitFlag)
	if !committed {
		state, prot = memReserveFlag, 0
	}
	return memInfo{base: addr &^ 0xFFF, allocBase: r.Base, allocProt: r.Prot, size: end - (addr &^ 0xFFF),
		state: state, prot: prot, typ: r.Kind}
}

// ---------------------------------------------------------------------------
// resources (minimal: version info etc. are rarely needed by console apps)

func (e *Emu) findResource(hmod, name, typ uint64, wide bool) uint64 {
	return e.fail(1813) // ERROR_RESOURCE_TYPE_NOT_FOUND
}

// NTSTATUS codes stored in OVERLAPPED.Internal / IO_STATUS_BLOCK.
const (
	statusBufferOverflow    = 0x80000005
	statusUnsuccessful      = 0xC0000001
	statusInvalidPipeState  = 0xC00000AD
	statusPipeBusy          = 0xC00000AE
	statusPipeDisconnected  = 0xC00000B0
	statusPipeClosing       = 0xC00000B1
	statusPipeListening     = 0xC00000B3
	statusIOTimeout         = 0xC00000B5
	statusCancelled         = 0xC0000120
	statusLocalDisconnect   = 0xC000013B
	statusRemoteDisconnect  = 0xC000013C
	statusPipeBroken        = 0xC000014B
	statusInvalidAddrComp   = 0xC0000207
	statusAddrAlreadyExists = 0xC000020A
	statusConnReset         = 0xC000020D
	statusConnRefused       = 0xC0000236
	statusGracefulDisc      = 0xC0000237
	statusNetUnreachable    = 0xC000023C
	statusHostUnreachable   = 0xC000023D
	statusConnAborted       = 0xC0000241
)

// ntStatusWin32 is the NTSTATUS -> Win32 error table (RtlNtStatusToDosError)
// used by every caller: RtlNtStatusToDosError, GetOverlappedResult(Ex) and
// GetQueuedCompletionStatus for files, pipes and sockets.
var ntStatusWin32 = map[uint32]uint32{
	0:                       0,
	0x102:                   258, // STATUS_TIMEOUT -> WAIT_TIMEOUT
	0xC0000008:              errInvalidHandle,
	0xC000000D:              errInvalidParameter,
	0xC0000011:              errHandleEOF,
	0xC0000017:              errNotEnoughMemory,
	0xC0000022:              errAccessDenied,
	0xC0000034:              errFileNotFound,
	0xC0000035:              errAlreadyExists,
	0xC000003A:              errPathNotFound,
	statusBufferOverflow:    errMoreData,
	statusCancelled:         errOperationAborted,
	statusPipeBroken:        errBrokenPipe,
	statusPipeClosing:       errNoData,
	statusPipeDisconnected:  errPipeNotConnected,
	statusPipeListening:     errPipeListening,
	statusInvalidPipeState:  errBadPipe,
	statusPipeBusy:          errPipeBusy,
	statusIOTimeout:         errSemTimeout,
	statusConnReset:         64, // ERROR_NETNAME_DELETED
	statusRemoteDisconnect:  64,
	statusLocalDisconnect:   64,
	statusConnAborted:       1236, // ERROR_CONNECTION_ABORTED
	statusConnRefused:       1225, // ERROR_CONNECTION_REFUSED
	statusGracefulDisc:      1226, // ERROR_GRACEFUL_DISCONNECT
	statusNetUnreachable:    1231, // ERROR_NETWORK_UNREACHABLE
	statusHostUnreachable:   1232, // ERROR_HOST_UNREACHABLE
	statusAddrAlreadyExists: 52,   // ERROR_DUP_NAME
	statusInvalidAddrComp:   1214, // ERROR_INVALID_NETNAME
	statusUnsuccessful:      31,   // ERROR_GEN_FAILURE
}

func ntToWin(st uint32) uint32 {
	if code, ok := ntStatusWin32[st]; ok {
		return code
	}
	return 317 // ERROR_MR_MID_NOT_FOUND
}

var winMessages = map[uint32]string{
	0:    "The operation completed successfully.",
	1:    "Incorrect function.",
	2:    "The system cannot find the file specified.",
	3:    "The system cannot find the path specified.",
	4:    "The system cannot open the file.",
	5:    "Access is denied.",
	6:    "The handle is invalid.",
	8:    "Not enough memory resources are available to process this command.",
	18:   "There are no more files.",
	32:   "The process cannot access the file because it is being used by another process.",
	38:   "Reached the end of the file.",
	50:   "The request is not supported.",
	80:   "The file exists.",
	87:   "The parameter is incorrect.",
	109:  "The pipe has been ended.",
	112:  "There is not enough space on the disk.",
	120:  "This function is not supported on this system.",
	122:  "The data area passed to a system call is too small.",
	123:  "The filename, directory name, or volume label syntax is incorrect.",
	126:  "The specified module could not be found.",
	127:  "The specified procedure could not be found.",
	145:  "The directory is not empty.",
	183:  "Cannot create a file when that file already exists.",
	203:  "The system could not find the environment option that was entered.",
	234:  "More data is available.",
	259:  "No more data is available.",
	1460: "This operation returned because the timeout period expired.",
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [24]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func validUTF8(b []byte) bool { return utf8.Valid(b) }
