package win

// msvcp140.dll (MSVC C++ standard library) exports with the MSVC STL ABI,
// and the vcruntime140 RTTI entry points (__RTtypeid, __RTDynamicCast,
// __RTCastToVoid).
//
// Threads (<xthreads.h>, x64): _Mtx_t points to an in-situ
// _Mtx_internal_imp_t of 80 bytes:
//
//	+0  int  _Type        _Mtx_plain 1 | _Mtx_try 2 | _Mtx_timed 4 | _Mtx_recursive 0x100
//	+8   _Stl_critical_section { void* _Unused; SRWLOCK _M_srw_lock (+16) }, 64 bytes of storage
//	+72 long _Thread_id   owner, -1 (or 0 for constexpr-constructed mutexes) when unowned
//	+76 int  _Count       recursion count
//
// _Cnd_t points to a 72-byte _Cnd_internal_imp_t whose CONDITION_VARIABLE is
// at +8 (after the former vptr). A zero-filled object is a valid unlocked
// mutex / condition variable, as for the constexpr std::mutex constructor.
// Results are _Thrd_result: _Thrd_success 0, _Thrd_nomem 1, _Thrd_timedout 2,
// _Thrd_busy 3, _Thrd_error 4.

import (
	"time"

	"winemu/internal/cpu"
	"winemu/internal/mem"
)

const dMsvcp = "msvcp140.dll"

const (
	thrdSuccess  = 0
	thrdNomem    = 1
	thrdTimedout = 2
	thrdBusy     = 3
	thrdError    = 4

	mtxPlain     = 0x01
	mtxRecursive = 0x100

	mtxOffSRW   = 16
	mtxOffOwner = 72
	mtxOffCount = 76
	mtxSize     = 80
	cndOffCV    = 8
	cndSize     = 72
)

// rtState is the per-process state of the runtime-library APIs (WS-C).
type rtState struct {
	cxx      *cxxRuntime
	excPtrs  map[uint64]*excPtrRep // exception_ptr control block -> state
	fibers   map[uint64]*fiber     // fiber address -> saved context
	crtLocks map[int32]*crtLock    // msvcrt _lock numbers
}

func (e *Emu) rtl() *rtState {
	if e.rt == nil {
		e.rt = &rtState{excPtrs: map[uint64]*excPtrRep{}, fibers: map[uint64]*fiber{}, crtLocks: map[int32]*crtLock{}}
	}
	return e.rt
}

// Lock modes of mtxDoLock.
const (
	lockWait  = iota // _Mtx_lock: no target time
	lockTry          // _Mtx_trylock: target time 0
	lockTimed        // _Mtx_timedlock: absolute target time
)

// mtxDoLock follows the MSVC STL mtx_do_lock. It may block (e.block), in
// which case the API call is re-executed later and the result is ignored.
func (e *Emu) mtxDoLock(m uint64, mode int, deadline time.Time) uint64 {
	mm := e.Mem
	typ := mm.R32(m)
	me := e.Cur.ID
	srw := m + mtxOffSRW
	owned := mm.R32(m+mtxOffOwner) == me
	if typ&^mtxRecursive == mtxPlain {
		if !owned {
			if !e.srwAcquire(srw, true, false) {
				return 0 // blocked
			}
			mm.W32(m+mtxOffOwner, me)
		}
		mm.W32(m+mtxOffCount, mm.R32(m+mtxOffCount)+1)
		return thrdSuccess
	}
	acquired := owned
	if !owned {
		switch mode {
		case lockWait:
			if !e.srwAcquire(srw, true, false) {
				return 0
			}
			acquired = true
		case lockTry:
			acquired = e.srwAcquire(srw, true, true)
		case lockTimed:
			if e.srwAcquire(srw, true, true) {
				acquired = true
				break
			}
			if e.inWait() && e.Cur.waitTimedOut {
				e.endWait()
				break
			}
			if d := time.Until(deadline); d > 0 || e.inWait() {
				e.block(func() bool { return mm.R64(srw) == 0 }, uint32(max(d.Milliseconds(), 1)))
				return 0
			}
		}
	}
	if acquired {
		n := mm.R32(m+mtxOffCount) + 1
		if n > 1 && typ&mtxRecursive == 0 {
			acquired = false // relocking a non-recursive mutex
		} else {
			mm.W32(m+mtxOffCount, n)
			if n == 1 {
				mm.W32(m+mtxOffOwner, me)
			}
		}
	}
	switch {
	case acquired:
		return thrdSuccess
	case mode == lockTimed:
		return thrdTimedout
	}
	return thrdBusy
}

func (e *Emu) mtxUnlock(m uint64) uint64 {
	mm := e.Mem
	n := mm.R32(m + mtxOffCount)
	if n == 0 || mm.R32(m+mtxOffOwner) != e.Cur.ID {
		return thrdError // unlock of an unowned mutex
	}
	mm.W32(m+mtxOffCount, n-1)
	if n == 1 {
		mm.W32(m+mtxOffOwner, 0xFFFFFFFF)
		e.srwRelease(m+mtxOffSRW, true)
	}
	return thrdSuccess
}

func (e *Emu) mtxInitInSitu(m uint64, typ uint32) {
	e.Mem.Fill(m, 0, mtxSize)
	e.Mem.W32(m, typ)
	e.Mem.W32(m+mtxOffOwner, 0xFFFFFFFF)
}

// timespec64 reads a _timespec64 {__time64_t tv_sec; long tv_nsec}.
func (e *Emu) timespec64(p uint64) time.Time {
	return time.Unix(int64(e.Mem.R64(p)), int64(int32(e.Mem.R32(p+8))))
}

// cndWait implements _Cnd_wait / _Cnd_timedwait: release the mutex
// ownership (_Mtx_clear_owner), sleep on the condition variable with the
// mutex's SRW lock, then reacquire ownership (_Mtx_reset_owner).
func (e *Emu) cndWait(c, m uint64, timeoutMs uint32) uint64 {
	mm := e.Mem
	if e.cvByThread[e.Cur] == nil {
		mm.W32(m+mtxOffOwner, 0xFFFFFFFF)
		mm.W32(m+mtxOffCount, mm.R32(m+mtxOffCount)-1)
	}
	r := e.sleepCV(c+cndOffCV, m+mtxOffSRW, 1, timeoutMs)
	if e.inWait() {
		return 0 // blocked; re-executed later
	}
	mm.W32(m+mtxOffOwner, e.Cur.ID)
	mm.W32(m+mtxOffCount, mm.R32(m+mtxOffCount)+1)
	if r == 0 {
		return thrdTimedout
	}
	return thrdSuccess
}

func init() {
	p := dMsvcp
	reg(p, "_Mtx_init_in_situ", func(e *Emu) uint64 { e.mtxInitInSitu(e.Arg(0), e.Arg32(1)); return 0 })
	reg(p, "_Mtx_destroy_in_situ", retZero)
	reg(p, "_Mtx_init", func(e *Emu) uint64 {
		m := e.heapAlloc(mtxSize, true)
		if m == 0 {
			e.Mem.W64(e.Arg(0), 0)
			return thrdNomem
		}
		e.mtxInitInSitu(m, e.Arg32(1))
		e.Mem.W64(e.Arg(0), m)
		return thrdSuccess
	})
	reg(p, "_Mtx_destroy", func(e *Emu) uint64 {
		if m := e.Arg(0); m != 0 {
			e.heap.freeBlock(m)
		}
		return 0
	})
	reg(p, "_Mtx_lock", func(e *Emu) uint64 { return e.mtxDoLock(e.Arg(0), lockWait, time.Time{}) })
	reg(p, "_Mtx_trylock", func(e *Emu) uint64 { return e.mtxDoLock(e.Arg(0), lockTry, time.Time{}) })
	reg(p, "_Mtx_timedlock", func(e *Emu) uint64 {
		return e.mtxDoLock(e.Arg(0), lockTimed, e.timespec64(e.Arg(1)))
	})
	reg(p, "_Mtx_unlock", func(e *Emu) uint64 { return e.mtxUnlock(e.Arg(0)) })
	reg(p, "_Mtx_current_owns", func(e *Emu) uint64 {
		m := e.Arg(0)
		return b2u(e.Mem.R32(m+mtxOffCount) != 0 && e.Mem.R32(m+mtxOffOwner) == e.Cur.ID)
	})
	reg(p, "_Mtx_getconcrtcs", func(e *Emu) uint64 { return e.Arg(0) + 8 })
	reg(p, "_Mtx_clear_owner", func(e *Emu) uint64 {
		m := e.Arg(0)
		e.Mem.W32(m+mtxOffOwner, 0xFFFFFFFF)
		e.Mem.W32(m+mtxOffCount, e.Mem.R32(m+mtxOffCount)-1)
		return 0
	})
	reg(p, "_Mtx_reset_owner", func(e *Emu) uint64 {
		m := e.Arg(0)
		e.Mem.W32(m+mtxOffOwner, e.Cur.ID)
		e.Mem.W32(m+mtxOffCount, e.Mem.R32(m+mtxOffCount)+1)
		return 0
	})

	reg(p, "_Cnd_init_in_situ", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, cndSize); return 0 })
	reg(p, "_Cnd_destroy_in_situ", retZero)
	reg(p, "_Cnd_init", func(e *Emu) uint64 {
		c := e.heapAlloc(cndSize, true)
		e.Mem.W64(e.Arg(0), c)
		if c == 0 {
			return thrdNomem
		}
		return thrdSuccess
	})
	reg(p, "_Cnd_destroy", func(e *Emu) uint64 {
		if c := e.Arg(0); c != 0 {
			e.heap.freeBlock(c)
		}
		return 0
	})
	reg(p, "_Cnd_wait", func(e *Emu) uint64 { return e.cndWait(e.Arg(0), e.Arg(1), infinite) })
	// A NULL target waits without a timeout; a timeout counts only once the
	// target time has passed, the wait time is rounded up to milliseconds.
	reg(p, "_Cnd_timedwait", func(e *Emu) uint64 {
		if e.Arg(2) == 0 {
			return e.cndWait(e.Arg(0), e.Arg(1), infinite)
		}
		target := e.timespec64(e.Arg(2))
		ms := uint32(0)
		if d := time.Until(target); d > 0 {
			ms = uint32(min((d+time.Millisecond-1)/time.Millisecond, infinite-1))
		}
		r := e.cndWait(e.Arg(0), e.Arg(1), ms)
		if r == thrdTimedout && time.Now().Before(target) {
			return thrdSuccess
		}
		return r
	})
	reg(p, "_Cnd_signal", func(e *Emu) uint64 { e.wakeCV(e.Arg(0)+cndOffCV, false); return thrdSuccess })
	reg(p, "_Cnd_broadcast", func(e *Emu) uint64 { e.wakeCV(e.Arg(0)+cndOffCV, true); return thrdSuccess })

	// int _Execute_once(once_flag&, int (__stdcall*)(void*, void*, void**), void*):
	// once_flag is an INIT_ONCE; the callback has the PINIT_ONCE_FN shape.
	reg(p, "?_Execute_once@std@@YAHAEAUonce_flag@1@P6AHPEAX1PEAPEAX@Z1@Z", func(e *Emu) uint64 {
		e.Cur.CPU.R[cpu.R9] = 0 // lpContext
		return e.callAPI(dK32, "InitOnceExecuteOnce")
	})
}

// ---------------------------------------------------------------------------
// C++ exceptions thrown by the runtime itself (std::system_error & co.)
//
// The objects use the MSVC layouts: std::exception is { vfptr;
// __std_exception_data { const char* _What; bool _DoFree; } } (24 bytes),
// std::system_error adds error_code { int _Myval; const error_category*
// _Mycat; } at +24 (40 bytes). They are raised as 0xE06D7363 with a
// ThrowInfo / CatchableTypeArray / CatchableType chain and RTTI
// (TypeDescriptor, CompleteObjectLocator, class hierarchy) laid out in a
// private executable region whose start is the throw image base, so every
// RVA is a positive offset from it.

const (
	cxxExceptionCode = 0xE06D7363
	cxxMagic         = 0x19930520
	ctIsSimpleType   = 0x01
	ctHasVirtualBase = 0x04
	ctIsStdBadAlloc  = 0x10
	bcdHasPCHD       = 0x40
)

// stdClasses lists the runtime's exception classes: bases, most derived
// first, and object size.
var stdClasses = map[string]struct {
	bases []string
	size  uint32
}{
	"exception":         {nil, 24},
	"bad_alloc":         {[]string{"exception"}, 24},
	"bad_exception":     {[]string{"exception"}, 24},
	"bad_cast":          {[]string{"exception"}, 24},
	"bad_typeid":        {[]string{"exception"}, 24},
	"__non_rtti_object": {[]string{"bad_typeid", "exception"}, 24},
	"logic_error":       {[]string{"exception"}, 24},
	"length_error":      {[]string{"logic_error", "exception"}, 24},
	"runtime_error":     {[]string{"exception"}, 24},
	"_System_error":     {[]string{"runtime_error", "exception"}, 40},
	"system_error":      {[]string{"_System_error", "runtime_error", "exception"}, 40},
}

type cxxRuntime struct {
	base, next, end uint64
	td, chd, ct     map[string]uint64
	vtbl, ti        map[string]uint64
	cats            map[uint64]uint64 // error_category _Addr -> object
	typeInfoVtbl    uint64
	unknownExc      uint64 // "Unknown exception"
}

func (e *Emu) cxx() *cxxRuntime {
	rt := e.rtl()
	if rt.cxx != nil {
		return rt.cxx
	}
	r, err := e.Mem.Alloc(0x10000, mem.PageExecuteReadWrite, mem.MemPrivate, "msvcp140 eh data")
	if err != nil {
		panic(err)
	}
	x := &cxxRuntime{base: r.Base, next: r.Base + 0x10, end: r.Base + r.Size,
		td: map[string]uint64{}, chd: map[string]uint64{}, ct: map[string]uint64{},
		vtbl: map[string]uint64{}, ti: map[string]uint64{}, cats: map[uint64]uint64{}}
	rt.cxx = x
	x.typeInfoVtbl = x.take(8)
	e.Mem.W64(x.typeInfoVtbl, x.thunk(e, "type_info::`scalar deleting destructor'", func(e *Emu) uint64 { return e.Arg(0) }))
	x.unknownExc = x.take(18)
	e.Mem.WriteCStr(x.unknownExc, "Unknown exception")
	return x
}

func (x *cxxRuntime) take(n uint64) uint64 {
	a := x.next
	x.next += (n + 15) &^ 15
	if x.next > x.end {
		panic("msvcp140: exception metadata region exhausted")
	}
	return a
}

func (x *cxxRuntime) rva(a uint64) uint32 { return uint32(a - x.base) }

// thunk places a hypercall thunk for fn inside the region (RVA-addressable).
func (x *cxxRuntime) thunk(e *Emu, name string, fn Fn) uint64 {
	a := x.take(thunkSize)
	e.writeThunk(a, e.addHLE("msvcp140", name, fn))
	return a
}

// typeDesc returns the TypeDescriptor of std::<cls>.
func (x *cxxRuntime) typeDesc(e *Emu, cls string) uint64 {
	if a, ok := x.td[cls]; ok {
		return a
	}
	name := ".?AV" + cls + "@std@@"
	a := x.take(16 + uint64(len(name)) + 1)
	e.Mem.W64(a, x.typeInfoVtbl)
	e.Mem.WriteCStr(a+16, name)
	x.td[cls] = a
	return a
}

// classDesc returns the RTTI class hierarchy descriptor of std::<cls>.
func (x *cxxRuntime) classDesc(e *Emu, cls string) uint64 {
	if a, ok := x.chd[cls]; ok {
		return a
	}
	m := e.Mem
	chain := append([]string{cls}, stdClasses[cls].bases...)
	chd := x.take(16)
	x.chd[cls] = chd
	arr := x.take(4 * uint64(len(chain)))
	m.W32(chd+8, uint32(len(chain)))
	m.W32(chd+12, x.rva(arr))
	for i, c := range chain {
		bcd := x.take(28)
		m.W32(bcd, x.rva(x.typeDesc(e, c)))
		m.W32(bcd+4, uint32(len(chain)-1-i))
		m.W32(bcd+12, 0xFFFFFFFF) // where = {0, -1, 0}
		m.W32(bcd+20, bcdHasPCHD)
		m.W32(bcd+24, x.rva(x.classDesc(e, c)))
		m.W32(arr+4*uint64(i), x.rva(bcd))
	}
	return chd
}

func isSystemError(cls string) bool { return cls == "system_error" || cls == "_System_error" }

// excDestroy is ~exception: frees _What if _DoFree.
func (e *Emu) excDestroy(obj uint64) {
	if e.Mem.R8(obj+16) != 0 {
		e.heap.freeBlock(e.Mem.R64(obj + 8))
	}
	e.Mem.W64(obj+8, 0)
	e.Mem.W8(obj+16, 0)
}

// vtable returns the vftable of std::<cls>: [-1] CompleteObjectLocator,
// [0] scalar deleting destructor, [1] what().
func (x *cxxRuntime) vtable(e *Emu, cls string) uint64 {
	if a, ok := x.vtbl[cls]; ok {
		return a
	}
	m := e.Mem
	col := x.take(24)
	m.W32(col, 1) // COL_SIG_REV1: image-relative
	m.W32(col+12, x.rva(x.typeDesc(e, cls)))
	m.W32(col+16, x.rva(x.classDesc(e, cls)))
	m.W32(col+20, x.rva(col))
	vt := x.take(24) + 8
	m.W64(vt-8, col)
	m.W64(vt, x.thunk(e, cls+"::`scalar deleting destructor'", func(e *Emu) uint64 {
		obj := e.Arg(0)
		e.excDestroy(obj)
		if e.Arg32(1)&1 != 0 {
			e.heap.freeBlock(obj)
		}
		return obj
	}))
	m.W64(vt+8, x.thunk(e, cls+"::what", func(e *Emu) uint64 {
		if p := e.Mem.R64(e.Arg(0) + 8); p != 0 {
			return p
		}
		return e.cxx().unknownExc
	}))
	x.vtbl[cls] = vt
	return vt
}

// copyExc is the copy constructor of std::<cls>(dst, src).
func (e *Emu) copyExc(cls string, dst, src uint64) {
	m := e.Mem
	m.W64(dst, e.cxx().vtable(e, cls))
	what, free := m.R64(src+8), m.R8(src+16) != 0
	if free && what != 0 {
		what = e.allocCStr(m.CStr(what))
	}
	m.W64(dst+8, what)
	m.W8(dst+16, uint8(b2u(free)))
	if isSystemError(cls) {
		m.Write(dst+24, m.ReadBytes(src+24, 16))
	}
}

// catchableType returns the CatchableType of std::<cls>.
func (x *cxxRuntime) catchableType(e *Emu, cls string) uint64 {
	if a, ok := x.ct[cls]; ok {
		return a
	}
	m := e.Mem
	ct := x.take(28)
	props := uint32(0)
	if cls == "bad_alloc" {
		props = ctIsStdBadAlloc
	}
	m.W32(ct, props)
	m.W32(ct+4, x.rva(x.typeDesc(e, cls)))
	m.W32(ct+12, 0xFFFFFFFF) // thisDisplacement = {0, -1, 0}
	m.W32(ct+20, stdClasses[cls].size)
	m.W32(ct+24, x.rva(x.thunk(e, cls+"::"+cls+"(const "+cls+"&)", func(e *Emu) uint64 {
		e.copyExc(cls, e.Arg(0), e.Arg(1))
		return e.Arg(0)
	})))
	x.ct[cls] = ct
	return ct
}

// throwInfo returns the ThrowInfo for throwing a std::<cls>.
func (x *cxxRuntime) throwInfo(e *Emu, cls string) uint64 {
	if a, ok := x.ti[cls]; ok {
		return a
	}
	m := e.Mem
	chain := append([]string{cls}, stdClasses[cls].bases...)
	cta := x.take(4 + 4*uint64(len(chain)))
	m.W32(cta, uint32(len(chain)))
	for i, c := range chain {
		m.W32(cta+4+4*uint64(i), x.rva(x.catchableType(e, c)))
	}
	ti := x.take(16)
	m.W32(ti+4, x.rva(x.thunk(e, cls+"::~"+cls, func(e *Emu) uint64 { e.excDestroy(e.Arg(0)); return 0 })))
	m.W32(ti+12, x.rva(cta))
	x.ti[cls] = ti
	return ti
}

// throwStd throws a std::<cls> whose what() is msg, from the API's caller.
// For the system_error classes, code and category (error_category _Addr:
// 3 generic, 7 system) form the error_code.
func (e *Emu) throwStd(cls, msg string, code int32, catAddr uint64) {
	x := e.cxx()
	m := e.Mem
	obj := e.heapAlloc(uint64(stdClasses[cls].size), true)
	m.W64(obj, x.vtable(e, cls))
	m.W64(obj+8, e.allocCStr(msg))
	m.W8(obj+16, 1)
	if isSystemError(cls) {
		m.W32(obj+24, uint32(code))
		m.W64(obj+32, x.category(e, catAddr))
	}
	ctx := e.callerContext()
	e.raiseGuest(&guestException{code: cxxExceptionCode, flags: excNoncontinuable,
		params: []uint64{cxxMagic, obj, x.throwInfo(e, cls), x.base}, addr: ctx.Rip, ctx: ctx})
}

// error_category _Addr values of the MSVC STL's built-in categories.
const (
	catGeneric = 3
	catSystem  = 7
)

// genericMessages are generic_category().message() texts (MSVC _Syserror_map).
var genericMessages = map[int32]string{
	1: "operation not permitted", 3: "no such process", 11: "resource unavailable try again",
	12: "not enough memory", 13: "permission denied", 16: "device or resource busy",
	22: "invalid argument", 36: "resource deadlock would occur",
}

func categoryMessage(catAddr uint64, ev int32) string {
	if catAddr == catSystem {
		if s, ok := winMessages[uint32(ev)]; ok {
			return s
		}
	} else if s, ok := genericMessages[ev]; ok {
		return s
	}
	return "unknown error"
}

// writeStdString constructs an MSVC std::string (x64: 16-byte SSO buffer or
// heap pointer at +0, _Mysize at +16, _Myres at +24) holding s at dst.
func (e *Emu) writeStdString(dst uint64, s string) {
	m := e.Mem
	m.Fill(dst, 0, 32)
	if len(s) < 16 {
		m.WriteCStr(dst, s)
		m.W64(dst+24, 15)
	} else {
		m.W64(dst, e.allocCStr(s))
		m.W64(dst+24, uint64(len(s)))
	}
	m.W64(dst+16, uint64(len(s)))
}

// category returns the error_category object { vfptr; uintptr_t _Addr; }
// with vftable [0] destructor, [1] name(), [2] message(int) -> std::string,
// [3] default_error_condition(int), [4] equivalent(const error_code&, int),
// [5] equivalent(int, const error_condition&).
func (x *cxxRuntime) category(e *Emu, addr uint64) uint64 {
	if a, ok := x.cats[addr]; ok {
		return a
	}
	m := e.Mem
	name := map[uint64]string{catGeneric: "generic", catSystem: "system"}[addr]
	nameStr := x.take(uint64(len(name)) + 1)
	m.WriteCStr(nameStr, name)
	obj := x.take(16)
	vt := x.take(7*8) + 8
	m.W64(obj, vt)
	m.W64(obj+8, addr)
	same := func(cat uint64) bool { return cat == obj || (cat != 0 && e.Mem.R64(cat+8) == addr) }
	fns := []Fn{
		func(e *Emu) uint64 { return e.Arg(0) },
		func(e *Emu) uint64 { return nameStr },
		func(e *Emu) uint64 {
			e.writeStdString(e.Arg(1), categoryMessage(addr, int32(e.Arg32(2))))
			return e.Arg(1)
		},
		func(e *Emu) uint64 {
			e.Mem.W64(e.Arg(1), uint64(e.Arg32(2)))
			e.Mem.W64(e.Arg(1)+8, obj)
			return e.Arg(1)
		},
		func(e *Emu) uint64 { c := e.Arg(1); return b2u(same(e.Mem.R64(c+8)) && e.Mem.R32(c) == e.Arg32(2)) },
		func(e *Emu) uint64 { c := e.Arg(2); return b2u(same(e.Mem.R64(c+8)) && e.Mem.R32(c) == e.Arg32(1)) },
	}
	for i, fn := range fns {
		m.W64(vt+8*uint64(i), x.thunk(e, name+"_category vfunc", fn))
	}
	x.cats[addr] = obj
	return obj
}

// throwCppError is std::_Throw_Cpp_error: system_error from the
// generic_category for one of the <xthreads.h> _Thrd error indexes.
func (e *Emu) throwCppError(idx int32) {
	codes := []int32{16, 22, 3, 12, 1, 36, 11} // _DEVICE_OR_RESOURCE_BUSY .. _RESOURCE_UNAVAILABLE_TRY_AGAIN
	if idx < 0 || int(idx) >= len(codes) {
		e.abort()
	}
	ev := codes[idx]
	e.throwStd("system_error", categoryMessage(catGeneric, ev), ev, catGeneric)
}

// abort terminates the process like the CRT's abort().
func (e *Emu) abort() {
	e.crt.flushAll()
	e.exitProcess(3)
}

func init() {
	p := dMsvcp
	reg(p, "?_Throw_Cpp_error@std@@YAXH@Z", func(e *Emu) uint64 { e.throwCppError(int32(e.Arg32(0))); return 0 })
	reg(p, "?_Throw_C_error@std@@YAXH@Z", func(e *Emu) uint64 {
		switch e.Arg32(0) {
		case thrdNomem, thrdTimedout:
			e.throwCppError(6) // _RESOURCE_UNAVAILABLE_TRY_AGAIN
		case thrdBusy:
			e.throwCppError(0) // _DEVICE_OR_RESOURCE_BUSY
		case thrdError:
			e.throwCppError(1) // _INVALID_ARGUMENT
		}
		e.abort()
		return 0
	})
	reg(p, "?_XGetLastError@std@@YAXXZ", func(e *Emu) uint64 {
		ev := int32(e.LastError())
		e.throwStd("system_error", categoryMessage(catSystem, ev), ev, catSystem)
		return 0
	})
	reg(p, "?_Xlength_error@std@@YAXPEBD@Z", func(e *Emu) uint64 {
		e.throwStd("length_error", e.CStr(e.Arg(0)), 0, 0)
		return 0
	})
	reg(p, "?uncaught_exception@std@@YA_NXZ", func(e *Emu) uint64 { return e.callAPI(dVc, "__uncaught_exception") & 1 })
}

// ---------------------------------------------------------------------------
// RTTI (vcruntime140): MSVC x64 layouts, RVAs relative to the image base
// derived from the CompleteObjectLocator's pSelf (signature 1).
//
//	COL  { sig; offset; cdOffset; pTypeDescriptor; pClassDescriptor; pSelf }
//	CHD  { sig; attributes (1 = MI, 2 = VI); numBaseClasses; pBaseClassArray }
//	BCD  { pTypeDescriptor; numContainedBases; PMD where {mdisp, pdisp, vdisp}; attributes; pClassDescriptor }

const (
	bcdNotVisible = 0x01
	bcdAmbiguous  = 0x02
	chdMultInh    = 0x01
	chdVirtInh    = 0x02
)

// rttiSafe runs f, turning a memory fault (no RTTI data) into a thrown
// std::__non_rtti_object, as vcruntime's __try/__except does.
func (e *Emu) rttiSafe(f func() uint64) (r uint64) {
	faulted := false
	func() {
		defer func() {
			if x := recover(); x != nil {
				if _, ok := x.(*mem.Fault); !ok {
					panic(x)
				}
				faulted = true
			}
		}()
		r = f()
	}()
	if faulted {
		e.throwStd("__non_rtti_object", "Access violation - no RTTI data!", 0, 0)
	}
	return r
}

// rttiCOL returns the CompleteObjectLocator of the object whose vfptr is at
// p, and the image base its RVAs are relative to.
func (e *Emu) rttiCOL(p uint64) (col, base uint64) {
	m := e.Mem
	col = m.R64(m.R64(p) - 8)
	if m.R32(col) == 1 {
		return col, col - uint64(m.R32(col+20))
	}
	if mod := e.moduleAt(col); mod != nil {
		return col, mod.Base
	}
	panic(&mem.Fault{Addr: col})
}

// rttiComplete is FindCompleteObject: the address of the complete object
// containing the subobject whose vfptr is at p.
func (e *Emu) rttiComplete(p, col uint64) uint64 {
	m := e.Mem
	obj := p - uint64(m.R32(col+4))
	if cd := m.R32(col + 8); cd != 0 {
		obj += uint64(int64(int32(m.R32(p - uint64(cd)))))
	}
	return obj
}

// pmdOffset is PMDtoOffset: the offset of a base described by the PMD at pmd
// within the complete object obj.
func (e *Emu) pmdOffset(obj, pmd uint64) int64 {
	m := e.Mem
	off := int64(0)
	if pdisp := int32(m.R32(pmd + 4)); pdisp >= 0 {
		vbt := m.R64(obj + uint64(int64(pdisp)))
		off = int64(pdisp) + int64(int32(m.R32(vbt+uint64(int64(int32(m.R32(pmd+8)))))))
	}
	return off + int64(int32(m.R32(pmd)))
}

func (e *Emu) typeidsEqual(a, b uint64) bool {
	return a == b || e.Mem.CStr(a+16) == e.Mem.CStr(b+16)
}

// dynamicCast implements __RTDynamicCast.
func (e *Emu) dynamicCast(in uint64, vfDelta int32, src, dst uint64) uint64 {
	m := e.Mem
	col, base := e.rttiCOL(in)
	obj := e.rttiComplete(in, col)
	srcOff := int64(in-uint64(int64(vfDelta))) - int64(obj)
	chd := base + uint64(m.R32(col+16))
	attrs, n, arr := m.R32(chd+4), m.R32(chd+8), base+uint64(m.R32(chd+12))
	bcd := func(i uint32) uint64 { return base + uint64(m.R32(arr+4*uint64(i))) }
	is := func(b, td uint64) bool { return e.typeidsEqual(base+uint64(m.R32(b)), td) }
	found, ambiguous := uint64(0), false
	pick := func(b uint64) {
		switch {
		case found == 0:
			found = b
		case e.pmdOffset(obj, found+8) != e.pmdOffset(obj, b+8):
			ambiguous = true
		}
	}
	if attrs&chdMultInh == 0 {
		for i := range n {
			if b := bcd(i); is(b, dst) && m.R32(b+20)&bcdNotVisible == 0 {
				return obj + uint64(e.pmdOffset(obj, b+8))
			}
		}
		return 0
	}
	// down-cast: a target base that contains the source subobject
	for i := uint32(0); i < n; i++ {
		b := bcd(i)
		if !is(b, dst) {
			continue
		}
		for j := uint32(0); j < m.R32(b+4) && i+1+j < n; j++ {
			if sb := bcd(i + 1 + j); is(sb, src) && e.pmdOffset(obj, sb+8) == srcOff {
				pick(b)
				break
			}
		}
		if found != 0 && attrs&chdVirtInh == 0 {
			break
		}
	}
	if found == 0 && !ambiguous {
		// cross-cast: a visible, unambiguous target base of the complete object
		for i := range n {
			if b := bcd(i); is(b, dst) && m.R32(b+20)&(bcdNotVisible|bcdAmbiguous) == 0 {
				pick(b)
				if attrs&chdVirtInh == 0 {
					break
				}
			}
		}
	}
	if found == 0 || ambiguous {
		return 0
	}
	return obj + uint64(e.pmdOffset(obj, found+8))
}

func init() {
	v := dVc + "," + dUcrt + "," + dMsvc
	reg(v, "__RTtypeid", func(e *Emu) uint64 {
		p := e.Arg(0)
		if p == 0 {
			e.throwStd("bad_typeid", "Attempted a typeid of nullptr pointer!", 0, 0)
		}
		return e.rttiSafe(func() uint64 {
			col, base := e.rttiCOL(p)
			return base + uint64(e.Mem.R32(col+12))
		})
	})
	reg(v, "__RTDynamicCast", func(e *Emu) uint64 {
		in, delta, src, dst, isRef := e.Arg(0), int32(e.Arg32(1)), e.Arg(2), e.Arg(3), e.Arg32(4) != 0
		if in == 0 {
			return 0
		}
		r := e.rttiSafe(func() uint64 { return e.dynamicCast(in, delta, src, dst) })
		if r == 0 && isRef {
			e.throwStd("bad_cast", "Bad dynamic_cast!", 0, 0)
		}
		return r
	})
	reg(v, "__RTCastToVoid", func(e *Emu) uint64 {
		p := e.Arg(0)
		if p == 0 {
			return 0
		}
		return e.rttiSafe(func() uint64 {
			col, _ := e.rttiCOL(p)
			return e.rttiComplete(p, col)
		})
	})
}

// ---------------------------------------------------------------------------
// std::exception_ptr: 16 bytes { const EXCEPTION_RECORD* _Data1;
// _Ref_count_base* _Data2; } (a shared_ptr<const EXCEPTION_RECORD>). For a
// C++ exception the record owns a copy of the exception object, destroyed
// through ThrowInfo.pmfnUnwind with the last reference. The control block
// is a guest heap block { vfptr (unused, 0); long _Uses; long _Weaks; }.

type excPtrRep struct{ rec uint64 }

const excRecordSize = 0x98

func (e *Emu) isCxxRecord(rec uint64) bool {
	m := e.Mem
	magic := m.R64(rec + 0x20)
	return m.R32(rec) == cxxExceptionCode && m.R32(rec+0x18) >= 4 && magic >= cxxMagic && magic <= cxxMagic+2
}

// throwImageBase returns the image base the RVAs of ThrowInfo ti are relative to.
func (e *Emu) throwImageBase(ti uint64) uint64 {
	if x := e.rtl().cxx; x != nil && ti >= x.base && ti < x.end {
		return x.base
	}
	if mod := e.moduleAt(ti); mod != nil {
		return mod.Base
	}
	return 0
}

// copyCxxObject copies a thrown object using the first CatchableType of its
// ThrowInfo (memcpy for simple types, else the copy constructor).
func (e *Emu) copyCxxObject(obj, ti, base uint64) uint64 {
	m := e.Mem
	cta := base + uint64(m.R32(ti+12))
	ct := base + uint64(m.R32(cta+4))
	props, size, cp := m.R32(ct), m.R32(ct+20), m.R32(ct+24)
	src := obj + uint64(e.pmdOffset(obj, ct+8))
	dst := e.heapAlloc(uint64(max(size, 1)), true)
	switch {
	case props&ctIsSimpleType != 0 || cp == 0:
		m.Write(dst, m.ReadBytes(src, int(size)))
	case props&ctHasVirtualBase != 0:
		e.CallGuest(base+uint64(cp), dst, src, 1)
	default:
		e.CallGuest(base+uint64(cp), dst, src)
	}
	return dst
}

// excPtrSet makes the exception_ptr at p the only reference to rec.
func (e *Emu) excPtrSet(p, rec uint64) {
	rep := e.heapAlloc(16, true)
	e.Mem.W32(rep+8, 1)
	e.Mem.W32(rep+12, 1)
	e.rtl().excPtrs[rep] = &excPtrRep{rec: rec}
	e.Mem.W64(p, rec)
	e.Mem.W64(p+8, rep)
}

func (e *Emu) excPtrAddRef(rep uint64) {
	if e.rtl().excPtrs[rep] != nil {
		e.Mem.W32(rep+8, e.Mem.R32(rep+8)+1)
	}
}

func (e *Emu) excPtrRelease(rep uint64) {
	r := e.rtl().excPtrs[rep]
	if r == nil {
		return
	}
	m := e.Mem
	n := m.R32(rep+8) - 1
	m.W32(rep+8, n)
	if n != 0 {
		return
	}
	delete(e.rtl().excPtrs, rep)
	if e.isCxxRecord(r.rec) {
		obj, ti, base := m.R64(r.rec+0x28), m.R64(r.rec+0x30), m.R64(r.rec+0x38)
		if dtor := m.R32(ti + 4); dtor != 0 {
			e.CallGuest(base+uint64(dtor), obj)
		}
		e.heap.freeBlock(obj)
	}
	e.heap.freeBlock(r.rec)
	e.heap.freeBlock(rep)
}

// newCxxRecord allocates an EXCEPTION_RECORD for a C++ throw of obj.
func (e *Emu) newCxxRecord(obj, ti, base uint64) uint64 {
	m := e.Mem
	rec := e.heapAlloc(excRecordSize, true)
	m.W32(rec, cxxExceptionCode)
	m.W32(rec+4, excNoncontinuable)
	m.W32(rec+0x18, 4)
	m.W64(rec+0x20, cxxMagic)
	m.W64(rec+0x28, obj)
	m.W64(rec+0x30, ti)
	m.W64(rec+0x38, base)
	return rec
}

func init() {
	p := dMsvcp
	reg(p, "?__ExceptionPtrCreate@@YAXPEAX@Z", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, 16); return 0 })
	reg(p, "?__ExceptionPtrDestroy@@YAXPEAX@Z", func(e *Emu) uint64 { e.excPtrRelease(e.Mem.R64(e.Arg(0) + 8)); return 0 })
	reg(p, "?__ExceptionPtrCopy@@YAXPEAXPEBX@Z", func(e *Emu) uint64 {
		dst, src := e.Arg(0), e.Arg(1)
		e.excPtrAddRef(e.Mem.R64(src + 8))
		e.Mem.Write(dst, e.Mem.ReadBytes(src, 16))
		return 0
	})
	reg(p, "?__ExceptionPtrAssign@@YAXPEAXPEBX@Z", func(e *Emu) uint64 {
		dst, src := e.Arg(0), e.Arg(1)
		b := e.Mem.ReadBytes(src, 16)
		e.excPtrAddRef(e.Mem.R64(src + 8))
		e.excPtrRelease(e.Mem.R64(dst + 8))
		e.Mem.Write(dst, b)
		return 0
	})
	reg(p, "?__ExceptionPtrToBool@@YA_NPEBX@Z", func(e *Emu) uint64 { return b2u(e.Mem.R64(e.Arg(0)) != 0) })
	reg(p, "?__ExceptionPtrCompare@@YA_NPEBX0@Z", func(e *Emu) uint64 {
		return b2u(e.Mem.R64(e.Arg(0)) == e.Mem.R64(e.Arg(1)))
	})
	reg(p, "?__ExceptionPtrSwap@@YAXPEAX0@Z", func(e *Emu) uint64 {
		a, b := e.Mem.ReadBytes(e.Arg(0), 16), e.Mem.ReadBytes(e.Arg(1), 16)
		e.Mem.Write(e.Arg(0), b)
		e.Mem.Write(e.Arg(1), a)
		return 0
	})
	reg(p, "?__ExceptionPtrCopyException@@YAXPEAXPEBX1@Z", func(e *Emu) uint64 {
		obj, ti := e.Arg(1), e.Arg(2)
		base := e.throwImageBase(ti)
		e.excPtrSet(e.Arg(0), e.newCxxRecord(e.copyCxxObject(obj, ti, base), ti, base))
		return 0
	})
	// The record of the exception being handled is vcruntime's
	// *__current_exception(), set by the C++ frame handler on catch entry.
	reg(p, "?__ExceptionPtrCurrentException@@YAXPEAX@Z", func(e *Emu) uint64 {
		p := e.Arg(0)
		cur := e.Mem.R64(e.callAPI(dVc, "__current_exception"))
		if cur == 0 {
			e.Mem.Fill(p, 0, 16)
			return 0
		}
		rec := e.heapAlloc(excRecordSize, true)
		e.Mem.Write(rec, e.Mem.ReadBytes(cur, excRecordSize))
		e.Mem.W64(rec+0x08, 0) // ExceptionRecord chain is not kept
		if e.isCxxRecord(rec) {
			e.Mem.W64(rec+0x28, e.copyCxxObject(e.Mem.R64(rec+0x28), e.Mem.R64(rec+0x30), e.Mem.R64(rec+0x38)))
		}
		e.excPtrSet(p, rec)
		return 0
	})
	reg(p, "?__ExceptionPtrRethrow@@YAXPEBX@Z", func(e *Emu) uint64 {
		m := e.Mem
		rec := m.R64(e.Arg(0))
		if rec == 0 {
			e.throwStd("bad_exception", "bad exception", 0, 0)
		}
		n := min(m.R32(rec+0x18), 15)
		params := make([]uint64, n)
		for i := range params {
			params[i] = m.R64(rec + 0x20 + 8*uint64(i))
		}
		if e.isCxxRecord(rec) {
			params[1] = e.copyCxxObject(params[1], params[2], params[3])
		}
		ctx := e.callerContext()
		e.raiseGuest(&guestException{code: m.R32(rec), flags: m.R32(rec + 4), params: params, addr: ctx.Rip, ctx: ctx})
		return 0
	})
}
