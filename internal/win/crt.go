package win

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"unicode/utf16"

	"winemu/internal/cpu"
)

// CRT holds the state of the emulated C runtime (ucrtbase/msvcrt).
type CRT struct {
	e *Emu

	files map[uint64]*cfile
	fds   map[int]*fdEntry
	iob   uint64
	stdH  [3]uint64

	cmdA, cmdW              uint64
	argc, argv, wargv       uint64 // addresses of the globals
	environ, wenviron       uint64 // addresses of the globals (char**)
	argsBuilt, envBuilt     bool
	initialEnv, initialWEnv uint64

	atexit []uint64
	doserr map[uint32]uint64

	fmode, commode  uint64
	pctype, pwctype uint64
	lconv           uint64
	localeObj       uint64
	localeName      string
	localeStr       uint64
	mbcurmax        uint64

	randState map[uint32]uint64
	strtok    map[uint32]uint64
	wcstok    map[uint32]uint64
	tmBuf     map[uint32]uint64
	ascBuf    map[uint32]uint64

	signals             map[int]uint64
	newMode             uint64
	newHandler          uint64
	invalidParamHandler uint64

	tzname, timezone, daylight, dstbias uint64
	findHandles                         map[uint64]*findObj
	exiting                             bool
	popen                               map[uint64]*Process
	strerrBuf                           uint64
	tmpnamBuf                           uint64
	nextTmp                             int
}

type fdEntry struct {
	h      uint64
	text   bool
	append bool
	eof    bool
	path   string
}

func newCRT(e *Emu) *CRT {
	c := &CRT{e: e, files: map[uint64]*cfile{}, fds: map[int]*fdEntry{},
		doserr: map[uint32]uint64{}, randState: map[uint32]uint64{},
		strtok: map[uint32]uint64{}, wcstok: map[uint32]uint64{}, tmBuf: map[uint32]uint64{},
		ascBuf: map[uint32]uint64{}, signals: map[int]uint64{}, findHandles: map[uint64]*findObj{},
		localeName: "C", mbcurmax: 1, popen: map[uint64]*Process{}}
	// globals block
	g := e.heapAllocRaw(0x400)
	c.argc, c.argv, c.wargv = g, g+8, g+16
	c.environ, c.wenviron = g+24, g+32
	c.fmode, c.commode = g+40, g+44
	c.timezone, c.daylight, c.dstbias = g+48, g+52, g+56
	c.tzname = g + 64 // char*[2]
	c.newMode = 0
	// stdio streams
	c.iob = e.heapAllocRaw(48 * 20)
	for i := 0; i < 3; i++ {
		c.fds[i] = &fdEntry{h: []uint64{stdInputHandle, stdOutputHandle, stdErrorHandle}[i], text: true}
		f := &cfile{addr: c.iob + uint64(48*i), fd: i, text: true, std: i + 1}
		switch i {
		case 0:
			f.readable = true
		case 1:
			f.writable = true
			f.bufMode = ioFBF
			if isTerminal(e.Opt.Stdout) {
				f.bufMode = ioLBF
			}
		case 2:
			f.writable = true
			f.bufMode = ioNBF
		}
		e.Mem.W32(f.addr+28, uint32(i))
		c.files[f.addr] = f
	}
	c.buildCtype()
	c.initTZ()
	return c
}

// ---------------------------------------------------------------------------
// errno

const (
	eperm     = 1
	enoent    = 2
	eintr     = 4
	eio       = 5
	ebadf     = 9
	eagain    = 11
	enomem    = 12
	eacces    = 13
	eexist    = 17
	enotdir   = 20
	eisdir    = 21
	einval    = 22
	emfile    = 24
	enospc    = 28
	espipe    = 29
	epipe     = 32
	edom      = 33
	erange    = 34
	enotempty = 41
	eilseq    = 42
)

func (c *CRT) errnoAddr() uint64 {
	t := c.e.Cur
	if t.crtErrno == 0 {
		t.crtErrno = c.e.heapAllocRaw(16)
	}
	return t.crtErrno
}

// invalidParameterExit ends the process as the default invalid-parameter
// handler does (STATUS_INVALID_CRT_PARAMETER).
func (c *CRT) invalidParameterExit() {
	e := c.e
	c.flushAll()
	e.logf("invalid parameter passed to a C runtime function (from %s)", e.symbolize(e.Mem.R64(e.Cur.CPU.R[cpu.RSP])))
	e.exitProcess(0xC0000417)
}

func (c *CRT) setErrno(v int) { c.e.Mem.W32(c.errnoAddr(), uint32(v)) }

func errnoOf(err error) int {
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		err = le.Err
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		switch en {
		case syscall.ENOENT:
			return enoent
		case syscall.EACCES, syscall.EPERM, syscall.EROFS:
			return eacces
		case syscall.EEXIST:
			return eexist
		case syscall.ENOTDIR:
			return enotdir
		case syscall.EISDIR:
			return eisdir
		case syscall.ENOTEMPTY:
			return enotempty
		case syscall.ENOSPC:
			return enospc
		case syscall.EMFILE:
			return emfile
		case syscall.EBADF:
			return ebadf
		case syscall.EINVAL:
			return einval
		case syscall.EPIPE:
			return epipe
		}
	}
	return eio
}

func errnoFromWin(code uint32) int {
	switch code {
	case errFileNotFound, errPathNotFound, errModNotFound:
		return enoent
	case errAccessDenied:
		return eacces
	case errFileExists, errAlreadyExists:
		return eexist
	case errInvalidHandle:
		return ebadf
	case errNotEnoughMemory:
		return enomem
	case errDirNotEmpty:
		return enotempty
	case errInvalidParameter:
		return einval
	case errBrokenPipe:
		return epipe
	}
	return einval
}

var errnoMsgs = map[int]string{
	0: "No error", 1: "Operation not permitted", 2: "No such file or directory", 3: "No such process",
	4: "Interrupted function call", 5: "Input/output error", 6: "No such device or address",
	7: "Arg list too long", 8: "Exec format error", 9: "Bad file descriptor", 10: "No child processes",
	11: "Resource temporarily unavailable", 12: "Not enough space", 13: "Permission denied",
	14: "Bad address", 16: "Resource device", 17: "File exists", 18: "Improper link",
	19: "No such device", 20: "Not a directory", 21: "Is a directory", 22: "Invalid argument",
	23: "Too many open files in system", 24: "Too many open files", 25: "Inappropriate I/O control operation",
	27: "File too large", 28: "No space left on device", 29: "Invalid seek", 30: "Read-only file system",
	31: "Too many links", 32: "Broken pipe", 33: "Domain error", 34: "Result too large",
	36: "Resource deadlock avoided", 38: "Filename too long", 39: "No locks available",
	40: "Function not implemented", 41: "Directory not empty", 42: "Illegal byte sequence",
}

func strerror(n int) string {
	if s, ok := errnoMsgs[n]; ok {
		return s
	}
	return "Unknown error"
}

// ---------------------------------------------------------------------------
// argv / environ

func (c *CRT) buildArgs() {
	if c.argsBuilt {
		return
	}
	c.argsBuilt = true
	e := c.e
	args := splitCmdLine(e.cmdLine)
	argv := e.heapAllocRaw(uint64(8 * (len(args) + 1)))
	wargv := e.heapAllocRaw(uint64(8 * (len(args) + 1)))
	for i, a := range args {
		e.Mem.W64(argv+uint64(8*i), e.allocCStr(a))
		e.Mem.W64(wargv+uint64(8*i), e.allocWStr(a))
	}
	e.Mem.W32(c.argc, uint32(len(args)))
	e.Mem.W64(c.argv, argv)
	e.Mem.W64(c.wargv, wargv)
}

func (c *CRT) buildEnv() {
	e := c.e
	env := e.heapAllocRaw(uint64(8 * (len(e.env) + 1)))
	wenv := e.heapAllocRaw(uint64(8 * (len(e.env) + 1)))
	for i, kv := range e.env {
		e.Mem.W64(env+uint64(8*i), e.allocCStr(kv))
		e.Mem.W64(wenv+uint64(8*i), e.allocWStr(kv))
	}
	e.Mem.W64(c.environ, env)
	e.Mem.W64(c.wenviron, wenv)
	if !c.envBuilt {
		c.initialEnv, c.initialWEnv = env, wenv
	}
	c.envBuilt = true
}

func (c *CRT) envChanged() {
	if c != nil && c.envBuilt {
		c.buildEnv()
	}
}

// ---------------------------------------------------------------------------
// exit

func (c *CRT) runAtexit() {
	for len(c.atexit) > 0 {
		f := c.atexit[len(c.atexit)-1]
		c.atexit = c.atexit[:len(c.atexit)-1]
		c.e.CallGuest(f)
	}
}

func (c *CRT) exit(code uint32, handlers bool) {
	e := c.e
	if handlers && !c.exiting {
		c.exiting = true
		c.runAtexit()
	}
	c.flushAll()
	e.detachDLLs()
	e.exitProcess(code)
}

// detachDLLs sends DLL_PROCESS_DETACH to native DLLs (best effort).
func (e *Emu) detachDLLs() {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(processExit); ok {
				panic(r)
			}
		}
	}()
	for i := len(e.modules) - 1; i >= 0; i-- {
		m := e.modules[i]
		if !m.Native || !m.initDone || m == e.exe || !m.PE.IsDLL() {
			continue
		}
		m.initDone = false
		e.callTLSCallbacks(m, dllProcessDetach)
		if m.Entry != 0 {
			e.CallGuest(m.Entry, m.Base, dllProcessDetach, 1)
		}
	}
}

// ---------------------------------------------------------------------------
// ctype / locale

const (
	ctUpper = 0x1
	ctLower = 0x2
	ctDigit = 0x4
	ctSpace = 0x8
	ctPunct = 0x10
	ctCntrl = 0x20
	ctBlank = 0x40
	ctHex   = 0x80
	ctAlpha = 0x100
)

func ctypeOf(c int) uint16 {
	var v uint16
	switch {
	case c >= 'A' && c <= 'Z':
		v = ctUpper | ctAlpha
		if c <= 'F' {
			v |= ctHex
		}
	case c >= 'a' && c <= 'z':
		v = ctLower | ctAlpha
		if c <= 'f' {
			v |= ctHex
		}
	case c >= '0' && c <= '9':
		v = ctDigit | ctHex
	case c == ' ':
		v = ctSpace | ctBlank
	case c == '\t':
		v = ctSpace | ctBlank | ctCntrl
	case c >= 0x0A && c <= 0x0D:
		v = ctSpace | ctCntrl
	case c < 0x20 || c == 0x7F:
		v = ctCntrl
	case c > 0x20 && c < 0x7F:
		v = ctPunct
	}
	return v
}

func (c *CRT) buildCtype() {
	e := c.e
	t := e.heapAllocRaw(2 * 260)
	w := e.heapAllocRaw(2 * 260)
	for i := 0; i < 256; i++ {
		e.Mem.W16(t+2+uint64(2*i), ctypeOf(i))
		e.Mem.W16(w+2+uint64(2*i), ctypeOf(i))
	}
	c.pctype = t + 2
	c.pwctype = w + 2
	// locale object: {locinfo*, mbcinfo*}; locinfo = {pctype*, mb_cur_max, codepage}
	li := e.heapAllocRaw(64)
	e.Mem.W64(li, c.pctype)
	e.Mem.W32(li+8, 1)
	e.Mem.W32(li+12, 65001)
	lo := e.heapAllocRaw(32)
	e.Mem.W64(lo, li)
	e.Mem.W64(lo+8, e.heapAllocRaw(64))
	c.localeObj = lo
	// lconv
	l := e.heapAllocRaw(160)
	dot := e.allocCStr(".")
	empty := e.allocCStr("")
	wdot := e.allocWStr(".")
	wempty := e.allocWStr("")
	e.Mem.W64(l, dot)
	for off := uint64(8); off < 80; off += 8 {
		e.Mem.W64(l+off, empty)
	}
	for off := uint64(80); off < 88; off++ {
		e.Mem.W8(l+off, 127)
	}
	e.Mem.W64(l+88, wdot)
	for off := uint64(96); off < 152; off += 8 {
		e.Mem.W64(l+off, wempty)
	}
	c.lconv = l
}

// ---------------------------------------------------------------------------

func (e *Emu) crtArgPtr(i int) uint64 { return e.Arg(i) }

func init() {
	u := dUcrt + "," + dMsvc
	reg(u, "_set_app_type", retZero)
	reg(u, "__set_app_type", retZero)
	reg(u, "_configure_narrow_argv", func(e *Emu) uint64 { e.crt.buildArgs(); return 0 })
	reg(u, "_configure_wide_argv", func(e *Emu) uint64 { e.crt.buildArgs(); return 0 })
	reg(u, "_initialize_narrow_environment", func(e *Emu) uint64 { e.crt.buildEnv(); return 0 })
	reg(u, "_initialize_wide_environment", func(e *Emu) uint64 { e.crt.buildEnv(); return 0 })
	reg(u, "__p___argc", func(e *Emu) uint64 { e.crt.buildArgs(); return e.crt.argc })
	reg(u, "__p___argv", func(e *Emu) uint64 { e.crt.buildArgs(); return e.crt.argv })
	reg(u, "__p___wargv", func(e *Emu) uint64 { e.crt.buildArgs(); return e.crt.wargv })
	reg(u, "__p__environ", func(e *Emu) uint64 {
		if !e.crt.envBuilt {
			e.crt.buildEnv()
		}
		return e.crt.environ
	})
	reg(u, "__p__wenviron", func(e *Emu) uint64 {
		if !e.crt.envBuilt {
			e.crt.buildEnv()
		}
		return e.crt.wenviron
	})
	reg(u, "_get_initial_narrow_environment", func(e *Emu) uint64 {
		if !e.crt.envBuilt {
			e.crt.buildEnv()
		}
		return e.Mem.R64(e.crt.environ)
	})
	reg(u, "_get_initial_wide_environment", func(e *Emu) uint64 {
		if !e.crt.envBuilt {
			e.crt.buildEnv()
		}
		return e.Mem.R64(e.crt.wenviron)
	})
	reg(u, "__p__pgmptr", func(e *Emu) uint64 {
		a := e.heapAllocRaw(8)
		e.Mem.W64(a, e.allocCStr(e.exeWin))
		return a
	})
	reg(u, "__p__wpgmptr", func(e *Emu) uint64 {
		a := e.heapAllocRaw(8)
		e.Mem.W64(a, e.allocWStr(e.exeWin))
		return a
	})
	reg(u, "_get_pgmptr", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), e.allocCStr(e.exeWin)); return 0 })
	reg(u, "_get_wpgmptr", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), e.allocWStr(e.exeWin)); return 0 })
	reg(u, "_get_narrow_winmain_command_line", func(e *Emu) uint64 {
		return e.allocCStr(skipProgName(e.cmdLine))
	})
	reg(u, "_get_wide_winmain_command_line", func(e *Emu) uint64 {
		return e.allocWStr(skipProgName(e.cmdLine))
	})
	regData(dMsvc, "__argc", 4, func(e *Emu, a uint64) { e.crt.buildArgs(); e.Mem.W32(a, e.Mem.R32(e.crt.argc)) })
	regData(dMsvc, "__argv", 8, func(e *Emu, a uint64) { e.crt.buildArgs(); e.Mem.W64(a, e.Mem.R64(e.crt.argv)) })
	regData(dMsvc, "__wargv", 8, func(e *Emu, a uint64) { e.crt.buildArgs(); e.Mem.W64(a, e.Mem.R64(e.crt.wargv)) })
	regData(dMsvc, "_environ", 8, func(e *Emu, a uint64) { e.crt.buildEnv(); e.Mem.W64(a, e.Mem.R64(e.crt.environ)) })
	regData(dMsvc, "_wenviron", 8, func(e *Emu, a uint64) { e.crt.buildEnv(); e.Mem.W64(a, e.Mem.R64(e.crt.wenviron)) })
	regData(dMsvc, "_fmode", 4, func(e *Emu, a uint64) {})
	regData(dMsvc, "_commode", 4, func(e *Emu, a uint64) {})
	regData(dMsvc, "__initenv", 8, func(e *Emu, a uint64) { e.crt.buildEnv(); e.Mem.W64(a, e.Mem.R64(e.crt.environ)) })
	regData(dMsvc, "__winitenv", 8, func(e *Emu, a uint64) { e.crt.buildEnv(); e.Mem.W64(a, e.Mem.R64(e.crt.wenviron)) })
	regData(dMsvc, "_iob", 48*3, func(e *Emu, a uint64) { e.crt.aliasIob(a) })
	regData(dMsvc, "__mb_cur_max", 4, func(e *Emu, a uint64) { e.Mem.W32(a, 1) })
	regData(dMsvc, "_pctype", 8, func(e *Emu, a uint64) { e.Mem.W64(a, e.crt.pctype) })
	regData(dMsvc, "_wctype", 8, func(e *Emu, a uint64) { e.Mem.W64(a, e.crt.pwctype) })
	regData(dMsvc, "_timezone", 4, func(e *Emu, a uint64) { e.Mem.W32(a, e.Mem.R32(e.crt.timezone)) })
	regData(dMsvc, "_daylight", 4, func(e *Emu, a uint64) { e.Mem.W32(a, e.Mem.R32(e.crt.daylight)) })
	regData(dMsvc, "_tzname", 16, func(e *Emu, a uint64) {
		e.Mem.W64(a, e.Mem.R64(e.crt.tzname))
		e.Mem.W64(a+8, e.Mem.R64(e.crt.tzname+8))
	})
	regData(dMsvc, "_sys_nerr", 4, func(e *Emu, a uint64) { e.Mem.W32(a, 43) })
	reg(dMsvc, "__getmainargs", func(e *Emu) uint64 {
		c := e.crt
		c.buildArgs()
		c.buildEnv()
		e.Mem.W32(e.Arg(0), e.Mem.R32(c.argc))
		e.Mem.W64(e.Arg(1), e.Mem.R64(c.argv))
		e.Mem.W64(e.Arg(2), e.Mem.R64(c.environ))
		return 0
	})
	reg(dMsvc, "__wgetmainargs", func(e *Emu) uint64 {
		c := e.crt
		c.buildArgs()
		c.buildEnv()
		e.Mem.W32(e.Arg(0), e.Mem.R32(c.argc))
		e.Mem.W64(e.Arg(1), e.Mem.R64(c.wargv))
		e.Mem.W64(e.Arg(2), e.Mem.R64(c.wenviron))
		return 0
	})
	reg(dMsvc, "__iob_func", func(e *Emu) uint64 { return e.crt.iob })
	reg(dMsvc, "__p___initenv", func(e *Emu) uint64 { e.crt.buildEnv(); return e.crt.environ })
	reg(u, "__p__fmode", func(e *Emu) uint64 { return e.crt.fmode })
	reg(u, "__p__commode", func(e *Emu) uint64 { return e.crt.commode })
	reg(u, "_set_fmode", func(e *Emu) uint64 { e.Mem.W32(e.crt.fmode, e.Arg32(0)); return 0 })
	reg(u, "_get_fmode", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), e.Mem.R32(e.crt.fmode)); return 0 })
	reg(u, "_initterm", func(e *Emu) uint64 {
		for p := e.Arg(0); p < e.Arg(1); p += 8 {
			if fn := e.Mem.R64(p); fn != 0 {
				e.CallGuest(fn)
			}
		}
		return 0
	})
	reg(u, "_initterm_e", func(e *Emu) uint64 {
		for p := e.Arg(0); p < e.Arg(1); p += 8 {
			if fn := e.Mem.R64(p); fn != 0 {
				if r := uint32(e.CallGuest(fn)); r != 0 {
					return uint64(r)
				}
			}
		}
		return 0
	})
	reg(u, "_crt_atexit", func(e *Emu) uint64 { e.crt.atexit = append(e.crt.atexit, e.Arg(0)); return 0 })
	reg(u, "atexit", func(e *Emu) uint64 { e.crt.atexit = append(e.crt.atexit, e.Arg(0)); return 0 })
	reg(u, "_crt_at_quick_exit", retZero)
	reg(u, "at_quick_exit", retZero)
	reg(u, "_onexit", func(e *Emu) uint64 { e.crt.atexit = append(e.crt.atexit, e.Arg(0)); return e.Arg(0) })
	reg(dMsvc, "__dllonexit", func(e *Emu) uint64 {
		// (func, pbegin, pend): maintain table in guest memory
		fn, pb, pe := e.Arg(0), e.Arg(1), e.Arg(2)
		begin, end := e.Mem.R64(pb), e.Mem.R64(pe)
		n := uint64(0)
		if begin != 0 {
			n = (end - begin) / 8
		}
		nb := e.heapAlloc(8*(n+1), true)
		if n > 0 {
			e.Mem.Move(nb, begin, 8*n)
		}
		e.Mem.W64(nb+8*n, fn)
		e.Mem.W64(pb, nb)
		e.Mem.W64(pe, nb+8*(n+1))
		return fn
	})
	reg(u, "_initialize_onexit_table", func(e *Emu) uint64 {
		t := e.Arg(0)
		e.Mem.W64(t, 0)
		e.Mem.W64(t+8, 0)
		e.Mem.W64(t+16, 0)
		return 0
	})
	reg(u, "_register_onexit_function", func(e *Emu) uint64 {
		t, fn := e.Arg(0), e.Arg(1)
		first, last, end := e.Mem.R64(t), e.Mem.R64(t+8), e.Mem.R64(t+16)
		if last == end {
			n := (end - first) / 8
			nn := n*2 + 8
			nb := e.heapAlloc(8*nn, true)
			if n > 0 {
				e.Mem.Move(nb, first, 8*n)
			}
			first, last, end = nb, nb+8*n, nb+8*nn
		}
		e.Mem.W64(last, fn)
		e.Mem.W64(t, first)
		e.Mem.W64(t+8, last+8)
		e.Mem.W64(t+16, end)
		return 0
	})
	reg(u, "_execute_onexit_table", func(e *Emu) uint64 {
		t := e.Arg(0)
		first, last := e.Mem.R64(t), e.Mem.R64(t+8)
		e.Mem.W64(t, 0)
		e.Mem.W64(t+8, 0)
		e.Mem.W64(t+16, 0)
		for p := last; p > first; {
			p -= 8
			if fn := e.Mem.R64(p); fn != 0 {
				e.CallGuest(fn)
			}
		}
		return 0
	})
	reg(u, "exit", func(e *Emu) uint64 { e.crt.exit(e.Arg32(0), true); return 0 })
	reg(u, "quick_exit", func(e *Emu) uint64 { e.crt.exit(e.Arg32(0), false); return 0 })
	reg(u, "_exit", func(e *Emu) uint64 { e.crt.flushAll(); e.exitProcess(e.Arg32(0)); return 0 })
	reg(u, "_Exit", func(e *Emu) uint64 { e.crt.flushAll(); e.exitProcess(e.Arg32(0)); return 0 })
	reg(u, "_cexit", func(e *Emu) uint64 {
		if !e.crt.exiting {
			e.crt.exiting = true
			e.crt.runAtexit()
		}
		e.crt.flushAll()
		return 0
	})
	reg(u, "_c_exit", func(e *Emu) uint64 { e.crt.flushAll(); return 0 })
	reg(u, "abort", func(e *Emu) uint64 {
		e.crt.flushAll()
		if h := e.crt.signals[22]; h > 1 {
			e.CallGuest(h, 22)
		}
		e.logf("abort() has been called")
		e.exitProcess(3)
		return 0
	})
	reg(u, "terminate", func(e *Emu) uint64 {
		e.crt.flushAll()
		e.logf("terminate() called (unhandled C++ exception or std::terminate)")
		e.exitProcess(3)
		return 0
	})
	reg(u+","+dVc, "_set_abort_behavior", retZero)
	reg(u, "_set_error_mode", retZero)
	reg(u, "__setusermatherr", retZero)
	reg(u, "_set_new_mode", func(e *Emu) uint64 { old := e.crt.newMode; e.crt.newMode = e.Arg(0); return old })
	reg(u, "_query_new_mode", func(e *Emu) uint64 { return e.crt.newMode })
	reg(u, "_set_new_handler", func(e *Emu) uint64 { old := e.crt.newHandler; e.crt.newHandler = e.Arg(0); return old })
	reg(u, "_query_new_handler", func(e *Emu) uint64 { return e.crt.newHandler })
	reg(u, "_callnewh", func(e *Emu) uint64 {
		if e.crt.newHandler != 0 {
			return e.CallGuest(e.crt.newHandler, e.Arg(0))
		}
		return 0
	})
	reg(u, "_configthreadlocale", func(e *Emu) uint64 { return 2 })
	reg(u, "_set_invalid_parameter_handler", func(e *Emu) uint64 {
		old := e.crt.invalidParamHandler
		e.crt.invalidParamHandler = e.Arg(0)
		return old
	})
	reg(u, "_get_invalid_parameter_handler", func(e *Emu) uint64 { return e.crt.invalidParamHandler })
	reg(u, "_set_thread_local_invalid_parameter_handler", retZero)
	reg(u, "_get_thread_local_invalid_parameter_handler", retZero)
	invParam := func(e *Emu) uint64 { e.crt.invalidParameterExit(); return 0 }
	reg(u, "_invalid_parameter_noinfo", invParam)
	reg(u, "_invalid_parameter_noinfo_noreturn", invParam)
	reg(u, "_invalid_parameter", invParam)
	reg(u, "_invoke_watson", invParam)
	reg(u, "_seh_filter_exe", retZero)
	reg(u, "_seh_filter_dll", retZero)
	reg(u, "_XcptFilter", retZero)
	reg(u, "__C_specific_handler_noexcept", cSpecificHandler)
	reg(u, "_crt_debugger_hook", retZero)
	reg(u, "__crtGetShowWindowMode", ret(10))
	reg(u, "_get_heap_handle", func(e *Emu) uint64 { return e.heap.processHeap })
	reg(u, "__threadid", func(e *Emu) uint64 { return uint64(e.Cur.ID) })
	reg(u, "__threadhandle", ret(pseudoThread))
	reg(u, "_getpid", func(e *Emu) uint64 { return uint64(e.proc.pid) })
	reg(u, "_assert", func(e *Emu) uint64 {
		e.crt.flushAll()
		e.logf("Assertion failed: %s, file %s, line %d", e.CStr(e.Arg(0)), e.CStr(e.Arg(1)), e.Arg32(2))
		e.exitProcess(3)
		return 0
	})
	reg(u, "_wassert", func(e *Emu) uint64 {
		e.crt.flushAll()
		e.logf("Assertion failed: %s, file %s, line %d", e.WStr(e.Arg(0)), e.WStr(e.Arg(1)), e.Arg32(2))
		e.exitProcess(3)
		return 0
	})

	// errno
	reg(u, "_errno", func(e *Emu) uint64 { return e.crt.errnoAddr() })
	reg(u, "__doserrno", func(e *Emu) uint64 {
		id := e.Cur.ID
		a := e.crt.doserr[id]
		if a == 0 {
			a = e.heapAllocRaw(8)
			e.crt.doserr[id] = a
		}
		return a
	})
	reg(u, "_get_errno", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), e.Mem.R32(e.crt.errnoAddr())); return 0 })
	reg(u, "_set_errno", func(e *Emu) uint64 { e.crt.setErrno(int(e.Arg32(0))); return 0 })
	reg(u, "_get_doserrno", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), 0); return 0 })
	reg(u, "_set_doserrno", retZero)
	reg(u, "__sys_errlist", func(e *Emu) uint64 {
		a := e.heapAllocRaw(8 * 44)
		for i := 0; i < 43; i++ {
			e.Mem.W64(a+uint64(8*i), e.allocCStr(strerror(i)))
		}
		return a
	})
	reg(u, "__sys_nerr", func(e *Emu) uint64 { a := e.heapAllocRaw(4); e.Mem.W32(a, 43); return a })
	reg(u, "strerror", func(e *Emu) uint64 { return e.crt.strerrorBuf(strerror(int(e.ArgI(0)))) })
	reg(u, "_strerror", func(e *Emu) uint64 {
		s := strerror(int(e.Mem.R32(e.crt.errnoAddr())))
		if e.Arg(0) != 0 {
			s = e.CStr(e.Arg(0)) + ": " + s
		}
		return e.crt.strerrorBuf(s + "\n")
	})
	reg(u, "_wcserror", func(e *Emu) uint64 { return e.allocWStr(strerror(int(e.ArgI(0)))) })
	reg(u, "strerror_s", func(e *Emu) uint64 {
		s := strerror(int(e.ArgI(2)))
		n := e.Arg(1)
		if uint64(len(s)) >= n {
			s = s[:n-1]
		}
		e.Mem.WriteCStr(e.Arg(0), s)
		return 0
	})
	reg(u, "_wcserror_s", func(e *Emu) uint64 {
		e.putStrW(e.Arg(0), uint32(e.Arg(1)), strerror(int(e.ArgI(2))))
		return 0
	})
	reg(u, "perror", func(e *Emu) uint64 {
		s := strerror(int(e.Mem.R32(e.crt.errnoAddr())))
		if p := e.Arg(0); p != 0 && e.Mem.R8(p) != 0 {
			s = e.CStr(p) + ": " + s
		}
		e.crt.flushStd()
		e.crt.writeStd(2, []byte(s+"\n"))
		return 0
	})
	reg(u, "_wperror", func(e *Emu) uint64 {
		s := strerror(int(e.Mem.R32(e.crt.errnoAddr())))
		if p := e.Arg(0); p != 0 {
			s = e.WStr(p) + ": " + s
		}
		e.crt.flushStd()
		e.crt.writeStd(2, []byte(s+"\n"))
		return 0
	})

	// environment
	reg(u, "getenv", func(e *Emu) uint64 {
		v, ok := e.getEnv(e.CStr(e.Arg(0)))
		if !ok {
			return 0
		}
		return e.crt.envValuePtr(e.CStr(e.Arg(0)), v, false)
	})
	reg(u, "_wgetenv", func(e *Emu) uint64 {
		v, ok := e.getEnv(e.WStr(e.Arg(0)))
		if !ok {
			return 0
		}
		return e.crt.envValuePtr(e.WStr(e.Arg(0)), v, true)
	})
	reg(u, "getenv_s", func(e *Emu) uint64 {
		v, ok := e.getEnv(e.CStr(e.Arg(3)))
		if !ok {
			e.Mem.W64(e.Arg(0), 0)
			if e.Arg(1) != 0 && e.Arg(2) > 0 {
				e.Mem.W8(e.Arg(1), 0)
			}
			return 0
		}
		e.Mem.W64(e.Arg(0), uint64(len(v)+1))
		if e.Arg(2) < uint64(len(v)+1) {
			return erange
		}
		e.Mem.WriteCStr(e.Arg(1), v)
		return 0
	})
	reg(u, "_wgetenv_s", func(e *Emu) uint64 {
		v, ok := e.getEnv(e.WStr(e.Arg(3)))
		if !ok {
			e.Mem.W64(e.Arg(0), 0)
			return 0
		}
		n := len(utf16.Encode([]rune(v))) + 1
		e.Mem.W64(e.Arg(0), uint64(n))
		if e.Arg(2) < uint64(n) {
			return erange
		}
		e.Mem.WriteWStr(e.Arg(1), v)
		return 0
	})
	reg(u, "_dupenv_s", func(e *Emu) uint64 {
		v, ok := e.getEnv(e.CStr(e.Arg(2)))
		if !ok {
			e.Mem.W64(e.Arg(0), 0)
			if e.Arg(1) != 0 {
				e.Mem.W64(e.Arg(1), 0)
			}
			return 0
		}
		e.Mem.W64(e.Arg(0), e.allocCStr(v))
		if e.Arg(1) != 0 {
			e.Mem.W64(e.Arg(1), uint64(len(v)+1))
		}
		return 0
	})
	reg(u, "_wdupenv_s", func(e *Emu) uint64 {
		v, ok := e.getEnv(e.WStr(e.Arg(2)))
		if !ok {
			e.Mem.W64(e.Arg(0), 0)
			return 0
		}
		e.Mem.W64(e.Arg(0), e.allocWStr(v))
		if e.Arg(1) != 0 {
			e.Mem.W64(e.Arg(1), uint64(len(utf16.Encode([]rune(v)))+1))
		}
		return 0
	})
	putenv := func(e *Emu, s string) uint64 {
		i := strings.IndexByte(s, '=')
		if i <= 0 {
			return ^uint64(0)
		}
		if i == len(s)-1 {
			e.unsetEnv(s[:i])
		} else {
			e.setEnv(s[:i], s[i+1:])
		}
		return 0
	}
	reg(u, "_putenv", func(e *Emu) uint64 { return putenv(e, e.CStr(e.Arg(0))) })
	reg(u, "_wputenv", func(e *Emu) uint64 { return putenv(e, e.WStr(e.Arg(0))) })
	reg(u, "_putenv_s", func(e *Emu) uint64 { return putenv(e, e.CStr(e.Arg(0))+"="+e.CStr(e.Arg(1))) })
	reg(u, "_wputenv_s", func(e *Emu) uint64 { return putenv(e, e.WStr(e.Arg(0))+"="+e.WStr(e.Arg(1))) })

	// signals
	reg(u, "signal", func(e *Emu) uint64 {
		sig := int(e.ArgI(0))
		old := e.crt.signals[sig]
		e.crt.signals[sig] = e.Arg(1)
		return old
	})
	reg(u, "raise", func(e *Emu) uint64 {
		sig := int(e.ArgI(0))
		h := e.crt.signals[sig]
		switch {
		case h == 1: // SIG_IGN
			return 0
		case h > 1:
			e.crt.signals[sig] = 0
			e.CallGuest(h, uint64(sig))
			return 0
		}
		e.crt.flushAll()
		e.exitProcess(3)
		return 0
	})
	reg(u, "__pxcptinfoptrs", func(e *Emu) uint64 { return e.heapAllocRaw(8) })
	reg(u, "__fpecode", func(e *Emu) uint64 { return e.heapAllocRaw(8) })

	// locale
	reg(u, "setlocale", func(e *Emu) uint64 { return e.crt.setlocale(e.CStr(e.Arg(1)), e.Arg(1) == 0, false) })
	reg(u, "_wsetlocale", func(e *Emu) uint64 { return e.crt.setlocale(e.WStr(e.Arg(1)), e.Arg(1) == 0, true) })
	reg(u, "localeconv", func(e *Emu) uint64 { return e.crt.lconv })
	reg(u, "__pctype_func", func(e *Emu) uint64 { return e.crt.pctype })
	reg(u, "__pwctype_func", func(e *Emu) uint64 { return e.crt.pwctype })
	reg(u, "___mb_cur_max_func", func(e *Emu) uint64 { return e.crt.mbcurmax })
	reg(u, "___mb_cur_max_l_func", func(e *Emu) uint64 { return e.crt.mbcurmax })
	reg(u, "__p___mb_cur_max", func(e *Emu) uint64 { a := e.heapAllocRaw(4); e.Mem.W32(a, uint32(e.crt.mbcurmax)); return a })
	reg(u, "___lc_codepage_func", ret(65001))
	reg(u, "___lc_collate_cp_func", ret(65001))
	reg(u, "___lc_locale_name_func", func(e *Emu) uint64 { return e.heapAllocRaw(8 * 6) })
	reg(u, "_create_locale", func(e *Emu) uint64 { return e.crt.localeObj })
	reg(u, "_wcreate_locale", func(e *Emu) uint64 { return e.crt.localeObj })
	reg(u, "_get_current_locale", func(e *Emu) uint64 { return e.crt.localeObj })
	reg(u, "_free_locale", retZero)
	reg(u, "_lock_locales", retZero)
	reg(u, "_unlock_locales", retZero)
	reg(u, "__crtLCMapStringW", func(e *Emu) uint64 { return lcmapString(e, e.Arg32(1), e.Arg(2), e.ArgI(3), e.Arg(4), e.ArgI(5)) })
	reg(u, "_getmbcp", ret(65001))
	reg(u, "_setmbcp", retZero)
	reg(u, "__p__mbctype", func(e *Emu) uint64 { return e.heapAllocRaw(260) })
	reg(u, "_get_current_locale_name", retZero)

	// heap
	reg(u, "malloc", func(e *Emu) uint64 { return e.crt.malloc(e.Arg(0), false) })
	reg(u, "_malloc_base", func(e *Emu) uint64 { return e.crt.malloc(e.Arg(0), false) })
	reg(u, "calloc", func(e *Emu) uint64 { return e.crt.malloc(e.Arg(0)*e.Arg(1), true) })
	reg(u, "_calloc_base", func(e *Emu) uint64 { return e.crt.malloc(e.Arg(0)*e.Arg(1), true) })
	reg(u, "free", func(e *Emu) uint64 { e.heap.freeBlock(e.Arg(0)); return 0 })
	reg(u, "_free_base", func(e *Emu) uint64 { e.heap.freeBlock(e.Arg(0)); return 0 })
	reg(u, "realloc", func(e *Emu) uint64 { return e.crt.realloc(e.Arg(0), e.Arg(1)) })
	reg(u, "_realloc_base", func(e *Emu) uint64 { return e.crt.realloc(e.Arg(0), e.Arg(1)) })
	reg(u, "_recalloc", func(e *Emu) uint64 {
		return e.heap.realloc(e.heap.processHeap, e.Arg(0), e.Arg(1)*e.Arg(2), true)
	})
	reg(u, "_expand", func(e *Emu) uint64 {
		if s, ok := e.heap.size(e.Arg(0)); ok && e.Arg(1) <= s {
			return e.Arg(0)
		}
		return 0
	})
	reg(u, "_msize", func(e *Emu) uint64 {
		s, ok := e.heap.size(e.Arg(0))
		if !ok {
			return ^uint64(0)
		}
		return s
	})
	reg(u, "_msize_base", func(e *Emu) uint64 { s, _ := e.heap.size(e.Arg(0)); return s })
	reg(u, "_aligned_malloc", func(e *Emu) uint64 { return e.crt.alignedMalloc(e.Arg(0), e.Arg(1), 0) })
	reg(u, "_aligned_offset_malloc", func(e *Emu) uint64 { return e.crt.alignedMalloc(e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "_aligned_free", func(e *Emu) uint64 {
		if p := e.Arg(0); p != 0 {
			e.heap.freeBlock(e.Mem.R64((p &^ 7) - 8))
		}
		return 0
	})
	reg(u, "_aligned_realloc", func(e *Emu) uint64 {
		p, size, al := e.Arg(0), e.Arg(1), e.Arg(2)
		n := e.crt.alignedMalloc(size, al, 0)
		if p != 0 {
			old := e.Mem.R64((p &^ 7) - 8)
			oldSize := e.Mem.R64((p &^ 7) - 16)
			_ = old
			cp := min(oldSize, size)
			e.Mem.Move(n, p, cp)
			e.heap.freeBlock(old)
		}
		return n
	})
	reg(u, "_aligned_msize", func(e *Emu) uint64 { return e.Mem.R64((e.Arg(0) &^ 7) - 16) })
	reg(u, "_heapchk", ret(0xFFFFFFFE))
	reg(u, "_heapmin", retZero)
	reg(u, "_heapset", retZero)
	reg(u, "_set_sbh_threshold", retZero)

	// threads
	reg(u, "_beginthreadex", func(e *Emu) uint64 {
		t, err := e.newThread(e.Arg(2), e.Arg(3), uint64(e.Arg32(1)))
		if err != nil {
			e.crt.setErrno(eagain)
			return 0
		}
		if e.Arg32(4)&4 != 0 {
			t.suspend = 1
		}
		if p := e.Arg(5); p != 0 {
			e.Mem.W32(p, t.ID)
		}
		return t.Handle
	})
	reg(u, "_beginthread", func(e *Emu) uint64 {
		t, err := e.newThread(e.Arg(0), e.Arg(2), uint64(e.Arg32(1)))
		if err != nil {
			return ^uint64(0)
		}
		return t.Handle
	})
	reg(u, "_endthreadex", func(e *Emu) uint64 { e.exitThread(e.Arg32(0)); return 0 })
	reg(u, "_endthread", func(e *Emu) uint64 { e.exitThread(0); return 0 })
	reg(u, "_cwait", func(e *Emu) uint64 { e.crt.setErrno(echild()); return ^uint64(0) })
	for _, n := range []string{"_spawnl", "_spawnv", "_spawnvp", "_spawnlp", "_wspawnv", "_wspawnvp", "_execv", "_execvp"} {
		reg(u, n, func(e *Emu) uint64 {
			e.warnOnce("spawn", "starting child processes is not supported")
			e.crt.setErrno(enoent)
			return ^uint64(0)
		})
	}
}

func echild() int { return 10 }

func skipProgName(cmd string) string {
	s := strings.TrimLeft(cmd, " \t")
	if strings.HasPrefix(s, `"`) {
		if i := strings.IndexByte(s[1:], '"'); i >= 0 {
			s = s[i+2:]
		} else {
			s = ""
		}
	} else if i := strings.IndexAny(s, " \t"); i >= 0 {
		s = s[i:]
	} else {
		s = ""
	}
	return strings.TrimLeft(s, " \t")
}

func (c *CRT) strerrorBuf(s string) uint64 {
	if c.strerrBuf == 0 {
		c.strerrBuf = c.e.heapAllocRaw(512)
	}
	if len(s) > 500 {
		s = s[:500]
	}
	c.e.Mem.WriteCStr(c.strerrBuf, s)
	return c.strerrBuf
}

// envValuePtr returns a stable pointer to the value inside environ.
func (c *CRT) envValuePtr(name, v string, wide bool) uint64 {
	if !c.envBuilt {
		c.buildEnv()
	}
	arr := c.e.Mem.R64(c.environ)
	if wide {
		arr = c.e.Mem.R64(c.wenviron)
	}
	for i := 0; ; i++ {
		p := c.e.Mem.R64(arr + uint64(8*i))
		if p == 0 {
			break
		}
		var kv string
		if wide {
			kv = c.e.Mem.WStr(p)
		} else {
			kv = c.e.Mem.CStr(p)
		}
		if j := strings.IndexByte(kv[1:], '='); j >= 0 && strings.EqualFold(kv[:j+1], name) {
			if wide {
				return p + uint64(2*len(utf16.Encode([]rune(kv[:j+2]))))
			}
			return p + uint64(j+2)
		}
	}
	if wide {
		return c.e.allocWStr(v)
	}
	return c.e.allocCStr(v)
}

func (c *CRT) setlocale(name string, query bool, wide bool) uint64 {
	if !query {
		switch {
		case name == "" || strings.Contains(strings.ToLower(name), "utf"):
			c.localeName = "English_United States.utf8"
			if name == "" {
				c.localeName = "English_United States.utf8"
			}
		case name == "C" || name == "POSIX":
			c.localeName = "C"
		default:
			c.localeName = name
		}
	}
	if wide {
		return c.e.allocWStr(c.localeName)
	}
	if c.localeStr == 0 {
		c.localeStr = c.e.heapAllocRaw(256)
	}
	c.e.Mem.WriteCStr(c.localeStr, c.localeName)
	return c.localeStr
}

func (c *CRT) malloc(n uint64, zero bool) uint64 {
	if n == 0 {
		n = 1
	}
	a := c.e.heapAlloc(n, zero)
	if a == 0 {
		c.setErrno(enomem)
	}
	return a
}

func (c *CRT) realloc(p, n uint64) uint64 {
	if n == 0 && p != 0 {
		c.e.heap.freeBlock(p)
		return 0
	}
	a := c.e.heap.realloc(c.e.heap.processHeap, p, n, false)
	if a == 0 {
		c.setErrno(enomem)
	}
	return a
}

// alignedMalloc layout: [size][orig][...pad...][aligned ptr]
func (c *CRT) alignedMalloc(size, align, offset uint64) uint64 {
	if align < 16 {
		align = 16
	}
	e := c.e
	raw := e.heapAlloc(size+align+16+offset, false)
	if raw == 0 {
		c.setErrno(enomem)
		return 0
	}
	p := ((raw + 16 + offset + align - 1) &^ (align - 1)) - offset
	e.Mem.W64((p&^7)-8, raw)
	e.Mem.W64((p&^7)-16, size)
	return p
}

// aliasIob makes msvcrt's _iob data export refer to the shared streams.
func (c *CRT) aliasIob(a uint64) {
	for i := 0; i < 3; i++ {
		f := c.files[c.iob+uint64(48*i)]
		c.files[a+uint64(48*i)] = f
		c.e.Mem.W32(a+uint64(48*i)+28, uint32(i))
	}
}

func (c *CRT) initTZ() {
	e := c.e
	name, off := nowZone()
	e.Mem.W32(c.timezone, uint32(int32(-off)))
	e.Mem.W32(c.daylight, 0)
	e.Mem.W32(c.dstbias, 0xFFFFF1F0)
	e.Mem.W64(c.tzname, e.allocCStr(name))
	e.Mem.W64(c.tzname+8, e.allocCStr(name))
}
