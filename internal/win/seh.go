package win

import (
	"fmt"
	"os"
	"sort"

	"winemu/internal/cpu"
)

// Context mirrors the parts of the x64 CONTEXT we care about.
type Context struct {
	R     [16]uint64
	Rip   uint64
	Flags uint64
	Mxcsr uint32
	X     [16]cpu.Vec
	FCW   uint16
}

const (
	ctxSize     = 0x4D0
	ctxFlagsOff = 0x30
	ctxMxcsr    = 0x34
	ctxEFlags   = 0x44
	ctxRegs     = 0x78
	ctxRip      = 0xF8
	ctxFlt      = 0x100
	ctxXmm      = 0x1A0
	contextAll  = 0x10001F

	excNoncontinuable = 1
	excUnwinding      = 2
	excExitUnwind     = 4
	excTargetUnwind   = 0x20
	excCollidedUnwind = 0x40

	unwFlagEHandler = 1
	unwFlagUHandler = 2
	unwFlagChain    = 4

	statusUnwind             = 0xC0000027
	statusNoncontinuable     = 0xC0000025
	statusInvalidDisposition = 0xC0000026
	statusBadStack           = 0xC0000028
)

var sehDebug = os.Getenv("WINEMU_DEBUG_SEH") != ""

func ctxFromCPU(c *cpu.CPU) Context {
	x := Context{R: c.R, Rip: c.RIP, Flags: c.Flags, Mxcsr: c.MXCSR, X: c.X, FCW: c.FPU.CW}
	return x
}

func (x *Context) toCPU(c *cpu.CPU) {
	c.R = x.R
	c.RIP = x.Rip
	c.Flags = x.Flags&0x00244FD5 | 2 | c.Flags&0x200
	c.MXCSR = x.Mxcsr
	c.X = x.X
}

func (e *Emu) writeContext(a uint64, x *Context) {
	m := e.Mem
	m.Fill(a, 0, ctxSize)
	m.W32(a+ctxFlagsOff, contextAll)
	m.W32(a+ctxMxcsr, x.Mxcsr)
	m.W16(a+0x38, 0x33)
	m.W16(a+0x3A, 0x2B)
	m.W16(a+0x3C, 0x2B)
	m.W16(a+0x3E, 0x53)
	m.W16(a+0x40, 0x2B)
	m.W16(a+0x42, 0x2B)
	m.W32(a+ctxEFlags, uint32(x.Flags))
	for i := 0; i < 16; i++ {
		m.W64(a+ctxRegs+uint64(8*i), x.R[i])
	}
	m.W64(a+ctxRip, x.Rip)
	m.W16(a+ctxFlt, x.FCW)
	m.W32(a+ctxFlt+0x18, x.Mxcsr)
	m.W32(a+ctxFlt+0x1C, 0xFFFF)
	for i := 0; i < 16; i++ {
		m.Write(a+ctxXmm+uint64(16*i), x.X[i][:])
	}
}

func (e *Emu) readContext(a uint64) Context {
	m := e.Mem
	var x Context
	x.Mxcsr = m.R32(a + ctxMxcsr)
	x.Flags = uint64(m.R32(a + ctxEFlags))
	for i := 0; i < 16; i++ {
		x.R[i] = m.R64(a + ctxRegs + uint64(8*i))
	}
	x.Rip = m.R64(a + ctxRip)
	x.FCW = m.R16(a + ctxFlt)
	for i := 0; i < 16; i++ {
		m.Read(a+ctxXmm+uint64(16*i), x.X[i][:])
	}
	return x
}

// ---------------------------------------------------------------------------
// function table lookup

type dynFuncTable struct {
	table, count, base uint64
}

// lookupFunction returns (RUNTIME_FUNCTION address, image base) for pc.
func (e *Emu) lookupFunction(pc uint64) (uint64, uint64) {
	m := e.moduleAt(pc)
	if m != nil && m.pdata != 0 {
		rva := uint32(pc - m.Base)
		n := int(m.pdataSize / 12)
		i := sort.Search(n, func(i int) bool {
			return e.Mem.R32(m.pdata+uint64(12*i)+4) > rva
		})
		if i < n {
			f := m.pdata + uint64(12*i)
			if e.Mem.R32(f) <= rva {
				return f, m.Base
			}
		}
		return 0, m.Base
	}
	for _, t := range e.funcTables {
		for i := uint64(0); i < t.count; i++ {
			f := t.table + 12*i
			b, en := t.base+uint64(e.Mem.R32(f)), t.base+uint64(e.Mem.R32(f+4))
			if pc >= b && pc < en {
				return f, t.base
			}
		}
	}
	return 0, 0
}

// virtualUnwind unwinds one frame (RtlVirtualUnwind). It returns the
// language handler (or 0), the handler data pointer and the establisher frame.
func (e *Emu) virtualUnwind(typ int, base, pc, fn uint64, x *Context) (handler, data, frame uint64) {
	m := e.Mem
	frame = x.R[cpu.RSP]
	first := true
	machFrame := false
	for {
		info := base + uint64(m.R32(fn+8))
		if info&1 != 0 { // chained via indirect pointer
			fn = base + (info &^ 1)
			continue
		}
		ver := m.R8(info) & 7
		flags := m.R8(info) >> 3
		prolog := uint64(m.R8(info + 1))
		count := int(m.R8(info + 2))
		frameReg := m.R8(info+3) & 15
		frameOff := uint64(m.R8(info+3) >> 4)
		begin := base + uint64(m.R32(fn))
		_ = ver
		prologOff := ^uint64(0)
		if first && pc >= begin && pc < begin+prolog {
			prologOff = pc - begin
		}
		codes := info + 4
		// does the SET_FPREG op apply?
		if frameReg != 0 {
			applied := false
			for i := 0; i < count; {
				op := m.R8(codes + uint64(2*i) + 1)
				off := uint64(m.R8(codes + uint64(2*i)))
				if op&15 == 3 && (prologOff == ^uint64(0) || prologOff >= off) {
					applied = true
				}
				i += unwindOpSize(op)
			}
			if applied {
				frame = x.R[frameReg] - frameOff*16
			} else {
				frame = x.R[cpu.RSP]
			}
		} else if first {
			frame = x.R[cpu.RSP]
		}
		for i := 0; i < count; {
			off := uint64(m.R8(codes + uint64(2*i)))
			op := m.R8(codes + uint64(2*i) + 1)
			code := op & 15
			opInfo := op >> 4
			sz := unwindOpSize(op)
			if prologOff != ^uint64(0) && prologOff < off {
				i += sz
				continue
			}
			slot := func(k int) uint64 { return uint64(m.R16(codes + uint64(2*(i+k)))) }
			switch code {
			case 0: // PUSH_NONVOL
				x.R[opInfo] = m.R64(x.R[cpu.RSP])
				x.R[cpu.RSP] += 8
			case 1: // ALLOC_LARGE
				if opInfo == 0 {
					x.R[cpu.RSP] += slot(1) * 8
				} else {
					x.R[cpu.RSP] += slot(1) | slot(2)<<16
				}
			case 2: // ALLOC_SMALL
				x.R[cpu.RSP] += uint64(opInfo)*8 + 8
			case 3: // SET_FPREG
				x.R[cpu.RSP] = frame
			case 4: // SAVE_NONVOL
				x.R[opInfo] = m.R64(frame + slot(1)*8)
			case 5: // SAVE_NONVOL_FAR
				x.R[opInfo] = m.R64(frame + (slot(1) | slot(2)<<16))
			case 6: // EPILOG (v2) - informational
			case 8: // SAVE_XMM128
				m.Read(frame+slot(1)*16, x.X[opInfo][:])
			case 9: // SAVE_XMM128_FAR
				m.Read(frame+(slot(1)|slot(2)<<16), x.X[opInfo][:])
			case 10: // PUSH_MACHFRAME
				if opInfo != 0 {
					x.R[cpu.RSP] += 8
				}
				x.Rip = m.R64(x.R[cpu.RSP])
				x.R[cpu.RSP] = m.R64(x.R[cpu.RSP] + 24)
				machFrame = true
			}
			i += sz
		}
		if flags&unwFlagChain != 0 {
			fn = codes + uint64(2*((count+1)&^1))
			first = false
			continue
		}
		if !machFrame {
			x.Rip = m.R64(x.R[cpu.RSP])
			x.R[cpu.RSP] += 8
		}
		if int(flags)&typ != 0 && prologOff == ^uint64(0) {
			hp := codes + uint64(2*((count+1)&^1))
			handler = base + uint64(m.R32(hp))
			data = hp + 4
		}
		return
	}
}

func unwindOpSize(op uint8) int {
	switch op & 15 {
	case 1:
		if op>>4 == 0 {
			return 2
		}
		return 3
	case 4, 8:
		return 2
	case 5, 9:
		return 3
	case 6:
		return 2
	}
	return 1
}

// unwindFrame steps x to its caller, handling leaf functions and callback
// boundaries. ok=false when the walk has to stop.
func (e *Emu) unwindFrame(typ int, x *Context) (fn, base, handler, data, frame uint64, ok bool) {
	pc := x.Rip
	if pc == e.retThunk {
		// boundary of a CallGuest callback: continue in the API's caller
		for i := len(e.Cur.callFrames) - 1; i >= 0; i-- {
			cf := e.Cur.callFrames[i]
			if cf.want == x.R[cpu.RSP] {
				x.Rip = e.Mem.R64(cf.saveSP)
				x.R[cpu.RSP] = cf.saveSP + 8
				return 0, 0, 0, 0, x.R[cpu.RSP], x.Rip != 0
			}
		}
		return 0, 0, 0, 0, 0, false
	}
	if pc == 0 || pc == e.exitThunk || pc == e.bootThunk {
		return 0, 0, 0, 0, 0, false
	}
	t := e.Cur
	if x.R[cpu.RSP] < t.StackLimit || x.R[cpu.RSP] >= t.StackBase {
		return 0, 0, 0, 0, 0, false
	}
	fn, base = e.lookupFunction(pc)
	if fn == 0 {
		frame = x.R[cpu.RSP]
		x.Rip = e.Mem.R64(x.R[cpu.RSP])
		x.R[cpu.RSP] += 8
		return 0, base, 0, 0, frame, true
	}
	handler, data, frame = e.virtualUnwind(typ, base, pc, fn, x)
	return fn, base, handler, data, frame, true
}

// ---------------------------------------------------------------------------
// raising

type guestException struct {
	code   uint32
	flags  uint32
	params []uint64
	addr   uint64
	ctx    Context
	recPtr uint64 // existing record (RtlRaiseException)
	msg    string
}

type activeUnwind struct{ cur Context }

type activeDispatch struct {
	rec     uint64
	origCtx uint64
}

func (e *Emu) raiseFromCPU(ex *cpu.Exception) {
	c := e.Cur.CPU
	g := &guestException{code: ex.Code, params: ex.Params, addr: ex.Addr, ctx: ctxFromCPU(c)}
	if ex.Code == cpu.ExcStackBufOverrun {
		// __fastfail: not dispatchable
		e.fatalException(g, ex.Msg)
	}
	if ex.Code == cpu.ExcIllegalInstr && ex.Msg != "" {
		g.msg = ex.Msg
	}
	if ex.Code == cpu.ExcAccessViolation && ex.Msg != "" {
		g.msg = ex.Msg
	}
	e.dispatchGuest(g)
}

func (e *Emu) dispatchGuest(g *guestException) {
	t := e.Cur
	c := t.CPU
	m := e.Mem
	// build records on the stack below the faulting frame
	sp := (g.ctx.R[cpu.RSP] - 0x2000) &^ 63
	ctxA := sp
	recA := sp + ctxSize + 0x10
	ptrs := recA + 0xA0
	disp := ptrs + 0x10
	e.writeContext(ctxA, &g.ctx)
	if g.recPtr != 0 {
		buf := m.ReadBytes(g.recPtr, 0x98)
		m.Write(recA, buf)
		g.code = m.R32(recA)
		g.flags = m.R32(recA + 4)
	} else {
		m.Fill(recA, 0, 0x98)
		m.W32(recA, g.code)
		m.W32(recA+4, g.flags)
		m.W64(recA+0x10, g.addr)
		n := len(g.params)
		if n > 15 {
			n = 15
		}
		m.W32(recA+0x18, uint32(n))
		for i := 0; i < n; i++ {
			m.W64(recA+0x20+uint64(8*i), g.params[i])
		}
	}
	m.W64(ptrs, recA)
	m.W64(ptrs+8, ctxA)
	c.R[cpu.RSP] = sp - 0x100
	e.Cur.dispatch = append(e.Cur.dispatch, activeDispatch{rec: recA, origCtx: ctxA})
	defer func() { e.Cur.dispatch = e.Cur.dispatch[:len(e.Cur.dispatch)-1] }()

	resume := func() {
		x := e.readContext(ctxA)
		x.toCPU(c)
		panic(contextRestored{})
	}

	// vectored handlers
	for _, h := range append([]uint64{}, e.vectored...) {
		r := e.CallGuest(h, ptrs)
		if int32(r) == -1 {
			resume()
		}
	}
	// frame-based handlers
	x := g.ctx

	for depth := 0; depth < 4096; depth++ {
		pc := x.Rip
		fn, base, handler, data, frame, ok := e.unwindFrame(unwFlagEHandler, &x)
		if sehDebug {
			e.logf("seh: pc=%#x %s fn=%#x handler=%#x frame=%#x -> caller %#x rsp=%#x", pc, e.symbolize(pc), fn, handler, frame, x.Rip, x.R[cpu.RSP])
		}
		if !ok {
			break
		}
		if handler == 0 {
			continue
		}
		// DISPATCHER_CONTEXT
		uctx := disp + 0x60
		e.writeContext(uctx, &x)
		m.Fill(disp, 0, 0x50)
		m.W64(disp, pc)
		m.W64(disp+8, base)
		m.W64(disp+0x10, fn)
		m.W64(disp+0x18, frame)
		m.W64(disp+0x28, uctx)
		m.W64(disp+0x30, handler)
		m.W64(disp+0x38, data)
		r := uint32(e.CallGuest(handler, recA, frame, ctxA, disp))
		switch r {
		case 0: // ExceptionContinueExecution
			if m.R32(recA+4)&excNoncontinuable != 0 {
				e.fatalException(&guestException{code: statusNoncontinuable, ctx: g.ctx}, "handler tried to continue a noncontinuable exception")
			}
			resume()
		case 1: // ExceptionContinueSearch
		default:
		}
	}
	// unhandled
	if e.unhandledFilter != 0 {
		r := int32(e.CallGuest(e.unhandledFilter, ptrs))
		switch r {
		case -1:
			resume()
		case 1:
			e.exitProcess(m.R32(recA))
		}
	}
	g.code = m.R32(recA)
	e.fatalException(g, g.msg)
}

func (e *Emu) fatalException(g *guestException, msg string) {
	e.crt.flushAll()
	desc := excName(g.code)
	where := e.symbolize(g.ctx.Rip)
	e.logf("unhandled exception %#08x (%s) at %#x [%s] in thread %d", g.code, desc, g.ctx.Rip, where, e.Cur.ID)
	if msg != "" {
		e.logf("  %s", msg)
	}
	if g.code == cpu.ExcAccessViolation && len(g.params) >= 2 {
		op := "reading"
		if g.params[0] == 1 {
			op = "writing"
		}
		e.logf("  %s address %#x", op, g.params[1])
	}
	if g.code == 0xE06D7363 {
		e.logf("  (an uncaught C++ exception)")
	}
	if e.Opt.Verbose {
		c := g.ctx
		e.logf("  rax=%#x rbx=%#x rcx=%#x rdx=%#x rsi=%#x rdi=%#x", c.R[0], c.R[3], c.R[1], c.R[2], c.R[6], c.R[7])
		e.logf("  rsp=%#x rbp=%#x r8=%#x r9=%#x r10=%#x r11=%#x", c.R[4], c.R[5], c.R[8], c.R[9], c.R[10], c.R[11])
		x := g.ctx
		for i := 0; i < 16; i++ {
			_, _, _, _, _, ok := e.unwindFrame(0, &x)
			if !ok {
				break
			}
			e.logf("  #%d %#x %s", i+1, x.Rip, e.symbolize(x.Rip))
		}
	}
	e.exitProcess(g.code)
}

func excName(code uint32) string {
	switch code {
	case 0xC0000005:
		return "access violation"
	case 0xC0000094:
		return "integer divide by zero"
	case 0xC0000095:
		return "integer overflow"
	case 0xC000001D:
		return "illegal instruction"
	case 0xC0000096:
		return "privileged instruction"
	case 0x80000003:
		return "breakpoint"
	case 0xC00000FD:
		return "stack overflow"
	case 0xC0000409:
		return "fast fail / stack buffer overrun"
	case 0xE06D7363:
		return "C++ exception"
	case 0x20474343:
		return "GCC C++ exception"
	case 0xC0000025:
		return "noncontinuable exception"
	case 0x40010006, 0x4001000A:
		return "debug output"
	}
	return "exception"
}

// ---------------------------------------------------------------------------
// unwinding

// unwindTo implements RtlUnwindEx. start is the context the unwind begins
// from. It never returns normally (it panics with contextRestored).
func (e *Emu) unwindTo(targetFrame, targetIP, recPtr, retval uint64, start Context) {
	m := e.Mem
	t := e.Cur
	scratch := (start.R[cpu.RSP]-0x1000)&^63 - 0x200
	if cur := t.CPU.R[cpu.RSP]; cur < scratch+0x1000 {
		scratch = (cur - 0x1000) &^ 63
	}
	rec := scratch
	ctxA := scratch + 0xC0
	disp := ctxA + ctxSize + 0x10
	if recPtr == 0 {
		m.Fill(rec, 0, 0x98)
		m.W32(rec, statusUnwind)
		m.W64(rec+0x10, t.CPU.RIP)
	} else {
		m.Write(rec, m.ReadBytes(recPtr, 0x98))
	}
	fl := m.R32(rec+4) | excUnwinding
	if targetFrame == 0 {
		fl |= excExitUnwind
	}
	m.W32(rec+4, fl)
	t.CPU.R[cpu.RSP] = scratch - 0x100

	cur := start
	st := &activeUnwind{}
	t.unwinds = append(t.unwinds, st)
	defer func() { t.unwinds = t.unwinds[:len(t.unwinds)-1] }()
	for depth := 0; depth < 8192; depth++ {
		x := cur
		pc := cur.Rip
		fn, base, handler, data, frame, ok := e.unwindFrame(unwFlagUHandler, &x)
		if !ok {
			if targetFrame == 0 {
				break
			}
			e.fatalException(&guestException{code: statusBadStack, ctx: start}, "unwind target frame not found")
		}
		if handler != 0 && fn != 0 {
			if targetFrame != 0 && frame > targetFrame {
				e.fatalException(&guestException{code: 0xC0000029, ctx: start}, "invalid unwind target")
			}
			if frame == targetFrame {
				m.W32(rec+4, m.R32(rec+4)|excTargetUnwind)
			}
			e.writeContext(ctxA, &cur)
			m.Fill(disp, 0, 0x50)
			m.W64(disp, pc)
			m.W64(disp+8, base)
			m.W64(disp+0x10, fn)
			m.W64(disp+0x18, frame)
			m.W64(disp+0x20, targetIP)
			m.W64(disp+0x28, ctxA)
			m.W64(disp+0x30, handler)
			m.W64(disp+0x38, data)
			st.cur = cur
			e.CallGuest(handler, rec, frame, ctxA, disp)
			// handlers may adjust the context of the target frame
			cur = e.readContext(ctxA)
			m.W32(rec+4, m.R32(rec+4)&^(excTargetUnwind|excCollidedUnwind))
		}
		if frame == targetFrame && targetFrame != 0 {
			break
		}
		cur = x
	}
	cur.R[cpu.RAX] = retval
	cur.Rip = targetIP
	cur.toCPU(t.CPU)
	panic(contextRestored{})
}

// unwindStart returns the context RtlUnwindEx should start from when called
// as an API: the frame being processed by an active (outer) unwind when the
// call comes from an unwind handler (a "collided" unwind), else the frame of
// the exception being dispatched, otherwise the API's caller.
func (e *Emu) unwindStart() Context {
	t := e.Cur
	if n := len(t.unwinds); n > 0 {
		return t.unwinds[n-1].cur
	}
	if n := len(t.dispatch); n > 0 {
		return e.readContext(t.dispatch[n-1].origCtx)
	}
	c := t.CPU
	x := ctxFromCPU(c)
	x.Rip = e.Mem.R64(c.R[cpu.RSP])
	x.R[cpu.RSP] += 8
	return x
}

// callerContext is the context of the code that called the current API.
func (e *Emu) callerContext() Context {
	c := e.Cur.CPU
	x := ctxFromCPU(c)
	x.Rip = e.Mem.R64(c.R[cpu.RSP])
	x.R[cpu.RSP] += 8
	return x
}

func init() {
	reg(dK32+","+dNt, "RaiseException", func(e *Emu) uint64 {
		code, flags, n, args := e.Arg32(0), e.Arg32(1), e.Arg32(2), e.Arg(3)
		if n > 15 {
			n = 15
		}
		ps := make([]uint64, n)
		for i := range ps {
			ps[i] = e.Mem.R64(args + uint64(8*i))
		}
		x := e.callerContext()
		g := &guestException{code: code, flags: flags & excNoncontinuable, params: ps, addr: x.Rip, ctx: x}
		e.raiseGuest(g)
		return 0
	})
	reg(dNt, "RtlRaiseException", func(e *Emu) uint64 {
		x := e.callerContext()
		rec := e.Arg(0)
		g := &guestException{recPtr: rec, ctx: x, addr: x.Rip}
		e.Mem.W64(rec+0x10, x.Rip)
		e.raiseGuest(g)
		return 0
	})
	reg(dK32+","+dNt, "RtlUnwindEx", func(e *Emu) uint64 {
		e.unwindTo(e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.unwindStart())
		return 0
	})
	reg(dK32+","+dNt, "RtlUnwind", func(e *Emu) uint64 {
		e.unwindTo(e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.unwindStart())
		return 0
	})
	reg(dK32+","+dNt, "RtlCaptureContext", func(e *Emu) uint64 {
		x := e.callerContext()
		e.writeContext(e.Arg(0), &x)
		return 0
	})
	reg(dNt, "RtlCaptureContext2", func(e *Emu) uint64 {
		x := e.callerContext()
		e.writeContext(e.Arg(0), &x)
		return 0
	})
	reg(dK32+","+dNt, "RtlRestoreContext", func(e *Emu) uint64 {
		x := e.readContext(e.Arg(0))
		x.toCPU(e.Cur.CPU)
		panic(contextRestored{})
	})
	reg(dNt, "NtContinue", func(e *Emu) uint64 {
		x := e.readContext(e.Arg(0))
		x.toCPU(e.Cur.CPU)
		panic(contextRestored{})
	})
	reg(dK32+","+dNt, "RtlLookupFunctionEntry", func(e *Emu) uint64 {
		fn, base := e.lookupFunction(e.Arg(0))
		if e.Arg(1) != 0 {
			e.Mem.W64(e.Arg(1), base)
		}
		return fn
	})
	reg(dK32+","+dNt, "RtlVirtualUnwind", func(e *Emu) uint64 {
		typ, base, pc, fn, ctxA := int(e.Arg32(0)), e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4)
		dataP, frameP := e.Arg(5), e.Arg(6)
		x := e.readContext(ctxA)
		var h, d, fr uint64
		if fn == 0 {
			fr = x.R[cpu.RSP]
			x.Rip = e.Mem.R64(x.R[cpu.RSP])
			x.R[cpu.RSP] += 8
		} else {
			h, d, fr = e.virtualUnwind(typ, base, pc, fn, &x)
		}
		// preserve fields we don't model by writing only what we track
		e.Mem.W64(ctxA+ctxRip, x.Rip)
		for i := 0; i < 16; i++ {
			e.Mem.W64(ctxA+ctxRegs+uint64(8*i), x.R[i])
		}
		for i := 6; i < 16; i++ {
			e.Mem.Write(ctxA+ctxXmm+uint64(16*i), x.X[i][:])
		}
		if dataP != 0 {
			e.Mem.W64(dataP, d)
		}
		if frameP != 0 {
			e.Mem.W64(frameP, fr)
		}
		return h
	})
	reg(dK32+","+dNt, "RtlPcToFileHeader", func(e *Emu) uint64 {
		m := e.moduleAt(e.Arg(0))
		var b uint64
		if m != nil {
			b = m.Base
		}
		e.Mem.W64(e.Arg(1), b)
		return b
	})
	reg(dK32+","+dNt, "RtlAddFunctionTable", func(e *Emu) uint64 {
		e.funcTables = append(e.funcTables, dynFuncTable{e.Arg(0), uint64(e.Arg32(1)), e.Arg(2)})
		return 1
	})
	reg(dK32+","+dNt, "RtlDeleteFunctionTable", func(e *Emu) uint64 {
		for i, t := range e.funcTables {
			if t.table == e.Arg(0) {
				e.funcTables = append(e.funcTables[:i], e.funcTables[i+1:]...)
				return 1
			}
		}
		return 0
	})
	reg(dK32+","+dNt, "RtlInstallFunctionTableCallback", func(e *Emu) uint64 { return 1 })
	reg(dK32+","+dNt, "AddVectoredExceptionHandler", func(e *Emu) uint64 {
		h := e.Arg(1)
		if e.Arg32(0) != 0 {
			e.vectored = append([]uint64{h}, e.vectored...)
		} else {
			e.vectored = append(e.vectored, h)
		}
		return h
	})
	reg(dK32+","+dNt, "AddVectoredContinueHandler", func(e *Emu) uint64 { return e.Arg(1) })
	reg(dK32+","+dNt, "RemoveVectoredContinueHandler", func(e *Emu) uint64 { return 1 })
	reg(dK32+","+dNt, "RemoveVectoredExceptionHandler", func(e *Emu) uint64 {
		for i, h := range e.vectored {
			if h == e.Arg(0) {
				e.vectored = append(e.vectored[:i], e.vectored[i+1:]...)
				return 1
			}
		}
		return 0
	})
	reg(dK32, "SetUnhandledExceptionFilter", func(e *Emu) uint64 {
		old := e.unhandledFilter
		e.unhandledFilter = e.Arg(0)
		return old
	})
	reg(dK32, "UnhandledExceptionFilter", func(e *Emu) uint64 { return 1 })
	reg(dNt+","+dVc+","+dMsvc+","+dUcrt, "__C_specific_handler", cSpecificHandler)
	reg(dVc+","+dUcrt, "_setjmp", setjmp)
	reg(dMsvc+","+dVc+","+dUcrt, "_setjmpex", setjmp)
	reg(dMsvc, "_setjmp", setjmp)
	reg(dMsvc+","+dUcrt+","+dVc, "longjmp", longjmp)
	reg(dNt, "__chkstk", func(e *Emu) uint64 { return e.Cur.CPU.R[cpu.RAX] })
}

func (e *Emu) raiseGuest(g *guestException) {
	panic(g)
}

// cSpecificHandler implements __C_specific_handler for __try/__except/__finally.
func cSpecificHandler(e *Emu) uint64 {
	m := e.Mem
	rec, frame, ctxA, disp := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3)
	base := m.R64(disp + 8)
	scope := m.R64(disp + 0x38)
	pc := m.R64(disp) - base
	count := m.R32(scope)
	flags := m.R32(rec + 4)
	if flags&(excUnwinding|excExitUnwind) == 0 {
		for i := uint32(0); i < count; i++ {
			s := scope + 4 + 16*uint64(i)
			b, en, h, tgt := m.R32(s), m.R32(s+4), m.R32(s+8), m.R32(s+12)
			if uint64(b) > pc || pc >= uint64(en) || tgt == 0 {
				continue
			}
			var filter int32
			if h == 1 {
				filter = 1
			} else {
				ptrs := e.heapAlloc(16, false)
				m.W64(ptrs, rec)
				m.W64(ptrs+8, ctxA)
				filter = int32(e.CallGuest(base+uint64(h), ptrs, frame))
				e.heap.freeBlock(ptrs)
			}
			if filter < 0 {
				return 0
			}
			if filter > 0 {
				code := uint64(m.R32(rec))
				e.unwindTo(frame, base+uint64(tgt), rec, code, e.unwindStart())
			}
		}
		return 1
	}
	targetIP := m.R64(disp + 0x20)
	for i := m.R32(disp + 0x48); i < count; i++ {
		s := scope + 4 + 16*uint64(i)
		b, en, h, tgt := m.R32(s), m.R32(s+4), m.R32(s+8), m.R32(s+12)
		if uint64(b) > pc || pc >= uint64(en) {
			continue
		}
		if flags&excTargetUnwind != 0 && tgt != 0 && base+uint64(tgt) == targetIP {
			break
		}
		if tgt == 0 {
			m.W32(disp+0x48, i+1)
			e.CallGuest(base+uint64(h), 1, frame)
		}
	}
	return 1
}

func setjmp(e *Emu) uint64 {
	c := e.Cur.CPU
	b := e.Arg(0)
	m := e.Mem
	m.W64(b, e.Arg(1))
	m.W64(b+0x08, c.R[cpu.RBX])
	m.W64(b+0x10, c.R[cpu.RSP]+8)
	m.W64(b+0x18, c.R[cpu.RBP])
	m.W64(b+0x20, c.R[cpu.RSI])
	m.W64(b+0x28, c.R[cpu.RDI])
	for i := 0; i < 4; i++ {
		m.W64(b+0x30+uint64(8*i), c.R[12+i])
	}
	m.W64(b+0x50, m.R64(c.R[cpu.RSP]))
	m.W32(b+0x58, c.MXCSR)
	m.W16(b+0x5C, c.FPU.CW)
	for i := 6; i < 16; i++ {
		m.Write(b+0x60+uint64(16*(i-6)), c.X[i][:])
	}
	return 0
}

func longjmp(e *Emu) uint64 {
	c := e.Cur.CPU
	b := e.Arg(0)
	v := e.Arg(1) & 0xFFFFFFFF
	if v == 0 {
		v = 1
	}
	m := e.Mem
	c.R[cpu.RBX] = m.R64(b + 0x08)
	c.R[cpu.RSP] = m.R64(b + 0x10)
	c.R[cpu.RBP] = m.R64(b + 0x18)
	c.R[cpu.RSI] = m.R64(b + 0x20)
	c.R[cpu.RDI] = m.R64(b + 0x28)
	for i := 0; i < 4; i++ {
		c.R[12+i] = m.R64(b + 0x30 + uint64(8*i))
	}
	c.RIP = m.R64(b + 0x50)
	c.MXCSR = m.R32(b + 0x58)
	for i := 6; i < 16; i++ {
		m.Read(b+0x60+uint64(16*(i-6)), c.X[i][:])
	}
	c.R[cpu.RAX] = v
	panic(contextRestored{})
}

var _ = fmt.Sprintf
