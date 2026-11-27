package win

// kernel32 fibers. A fiber is a guest block whose first field is the fiber
// data, as the inline GetFiberData() expects (*(void**)GetCurrentFiber()):
//
//	+0x00 FiberData   +0x08 ExceptionList   +0x10 StackBase
//	+0x18 StackLimit  +0x20 DeallocationStack
//
// The running fiber is NT_TIB.FiberData (TEB+0x20, the inline
// GetCurrentFiber() reads gs:[0x20]); TEB.SameTebFlags.HasFiberData
// (TEB+0x17EE bit 2) marks a thread converted to a fiber. SwitchToFiber
// saves the CPU registers into the current fiber and loads the target's,
// together with the TEB stack fields. Fiber-local storage is still per
// thread.

import "winemu/internal/cpu"

const (
	fiberBlockSize     = 0x40
	tebFiberData       = 0x20
	tebSameTebFlags    = 0x17EE
	tebHasFiberData    = 0x0004
	tebDeallocStack    = 0x1478
	errAlreadyFiber    = 1280
	errAlreadyThread   = 1281
	fiberFlagFloatSwap = 1
)

type fiber struct {
	regs      cpuRegs
	stack     uint64 // allocation base of a CreateFiber stack (0: a converted thread)
	converted bool
}

// cpuRegs is the register state a fiber switch preserves.
type cpuRegs struct {
	R          [16]uint64
	RIP, Flags uint64
	X          [16]cpu.Vec
	MXCSR      uint32
	FPU        cpu.FPU
}

func saveRegs(c *cpu.CPU) cpuRegs {
	return cpuRegs{R: c.R, RIP: c.RIP, Flags: c.Flags, X: c.X, MXCSR: c.MXCSR, FPU: c.FPU}
}

func (r *cpuRegs) load(c *cpu.CPU) {
	c.R, c.RIP, c.Flags, c.X, c.MXCSR, c.FPU = r.R, r.RIP, r.Flags, r.X, r.MXCSR, r.FPU
}

func (e *Emu) isFiberThread() bool {
	return e.Mem.R16(e.Cur.TEB+tebSameTebFlags)&tebHasFiberData != 0
}

func (e *Emu) convertThreadToFiber(param uint64, flags uint32) uint64 {
	if flags&^fiberFlagFloatSwap != 0 {
		return e.fail(errInvalidParameter)
	}
	if e.isFiberThread() {
		return e.fail(errAlreadyFiber)
	}
	m, teb := e.Mem, e.Cur.TEB
	f := e.heapAlloc(fiberBlockSize, true)
	m.W64(f, param)
	m.W64(f+0x10, m.R64(teb+0x08))
	m.W64(f+0x18, m.R64(teb+0x10))
	m.W64(f+0x20, m.R64(teb+tebDeallocStack))
	e.rtl().fibers[f] = &fiber{converted: true}
	m.W64(teb+tebFiberData, f)
	m.W16(teb+tebSameTebFlags, m.R16(teb+tebSameTebFlags)|tebHasFiberData)
	return f
}

// createFiber allocates a fiber whose first switch calls start(param); when
// start returns, the thread exits with its return value.
func (e *Emu) createFiber(reserve uint64, flags uint32, start, param uint64) uint64 {
	if flags&^fiberFlagFloatSwap != 0 {
		return e.fail(errInvalidParameter)
	}
	if reserve == 0 {
		reserve = 1 << 20
	}
	reserve = (reserve + 0xFFFF) &^ 0xFFFF
	r, err := e.Mem.Alloc(reserve, 0x04, 0x20000, "fiber stack") // PAGE_READWRITE, MEM_PRIVATE
	if err != nil {
		return e.fail(errNotEnoughMemory)
	}
	m := e.Mem
	f := e.heapAlloc(fiberBlockSize, true)
	top := r.Base + r.Size
	m.W64(f, param)
	m.W64(f+0x10, top)
	m.W64(f+0x18, r.Base)
	m.W64(f+0x20, r.Base)
	fresh := cpu.New(e.Mem)
	regs := saveRegs(fresh)
	sp := (top-0x40)&^15 - 8 // as if called: rsp = 8 (mod 16)
	m.W64(sp, e.exitThunk)
	regs.R[cpu.RSP] = sp
	regs.R[cpu.RCX] = param
	regs.RIP = start
	e.rtl().fibers[f] = &fiber{regs: regs, stack: r.Base}
	return f
}

func (e *Emu) switchToFiber(target uint64) {
	m, t := e.Mem, e.Cur
	teb := t.TEB
	cur := m.R64(teb + tebFiberData)
	to := e.rtl().fibers[target]
	if to == nil || target == cur {
		return
	}
	if from := e.rtl().fibers[cur]; from != nil {
		from.regs = saveRegs(t.CPU) // resumes at the thunk's ret
		m.W64(cur+0x10, m.R64(teb+0x08))
		m.W64(cur+0x18, m.R64(teb+0x10))
		m.W64(cur+0x20, m.R64(teb+tebDeallocStack))
	}
	m.W64(teb+tebFiberData, target)
	t.StackBase, t.StackLimit = m.R64(target+0x10), m.R64(target+0x18)
	m.W64(teb+0x08, t.StackBase)
	m.W64(teb+0x10, t.StackLimit)
	m.W64(teb+tebDeallocStack, m.R64(target+0x20))
	to.regs.load(t.CPU)
	e.skipRet = true // keep the target's RAX
}

func (e *Emu) deleteFiber(f uint64) {
	fb := e.rtl().fibers[f]
	if fb == nil {
		return
	}
	if f == e.Mem.R64(e.Cur.TEB+tebFiberData) {
		// the running fiber deletes itself: its thread exits
		if e.Cur == e.threads[0] {
			e.exitProcess(1)
		}
		e.exitThread(1)
	}
	if fb.stack != 0 {
		e.Mem.Unmap(fb.stack)
	}
	delete(e.rtl().fibers, f)
	e.heap.freeBlock(f)
}

func init() {
	k := dK32
	reg(k, "ConvertThreadToFiber", func(e *Emu) uint64 { return e.convertThreadToFiber(e.Arg(0), 0) })
	reg(k, "ConvertThreadToFiberEx", func(e *Emu) uint64 { return e.convertThreadToFiber(e.Arg(0), e.Arg32(1)) })
	reg(k, "ConvertFiberToThread", func(e *Emu) uint64 {
		if !e.isFiberThread() {
			return e.fail(errAlreadyThread)
		}
		m, teb := e.Mem, e.Cur.TEB
		if f := m.R64(teb + tebFiberData); e.rtl().fibers[f] != nil && e.rtl().fibers[f].converted {
			delete(e.rtl().fibers, f)
			e.heap.freeBlock(f)
		}
		m.W64(teb+tebFiberData, 0)
		m.W16(teb+tebSameTebFlags, m.R16(teb+tebSameTebFlags)&^tebHasFiberData)
		return 1
	})
	reg(k, "IsThreadAFiber", func(e *Emu) uint64 { return b2u(e.isFiberThread()) })
	reg(k, "CreateFiber", func(e *Emu) uint64 { return e.createFiber(e.Arg(0), 0, e.Arg(1), e.Arg(2)) })
	reg(k, "CreateFiberEx", func(e *Emu) uint64 {
		return e.createFiber(max(e.Arg(0), e.Arg(1)), e.Arg32(2), e.Arg(3), e.Arg(4))
	})
	reg(k, "SwitchToFiber", func(e *Emu) uint64 { e.switchToFiber(e.Arg(0)); return 0 })
	reg(k, "DeleteFiber", func(e *Emu) uint64 { e.deleteFiber(e.Arg(0)); return 0 })
}
