package win

// Virtual memory of another process: VirtualAllocEx & co. and
// Read/WriteProcessMemory. The target is stopped while its address space
// is touched (withProcess, xproc.go).

import "winemu/internal/mem"

// procArg resolves argument i as a process handle.
func (e *Emu) procArg(i int) *Process { return e.processOf(e.Arg(i)) }

func init() {
	k := dK32
	reg(k, "VirtualAllocEx", func(e *Emu) uint64 {
		p := e.procArg(0)
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		var r uint64
		var err uint32
		a, n, typ, prot := e.Arg(1), e.Arg(2), e.Arg32(3), e.Arg32(4)
		e.withProcess(p, func(c *Emu) { r, err = vmAlloc(c.Mem, a, n, typ, prot) })
		if err != 0 {
			return e.fail(err)
		}
		return r
	})
	reg(k, "VirtualFreeEx", func(e *Emu) uint64 {
		p := e.procArg(0)
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		var err uint32
		a, n, typ := e.Arg(1), e.Arg(2), e.Arg32(3)
		e.withProcess(p, func(c *Emu) {
			if err = vmFree(c.Mem, a, n, typ); err == 0 {
				for _, t := range c.threads {
					t.CPU.InvalidateCode()
				}
			}
		})
		if err != 0 {
			return e.fail(err)
		}
		return 1
	})
	reg(k, "VirtualQueryEx", func(e *Emu) uint64 {
		p := e.procArg(0)
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		if e.Arg(3) < 48 {
			return e.fail(errInsufficientBuf)
		}
		var info memInfo
		a := e.Arg(1)
		e.withProcess(p, func(c *Emu) { info = vmQuery(c.Mem, a) })
		info.write(e.Mem, e.Arg(2))
		return 48
	})
	reg(k, "VirtualProtectEx", func(e *Emu) uint64 {
		p := e.procArg(0)
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		var r *mem.Region
		var prot uint32
		a := e.Arg(1)
		e.withProcess(p, func(c *Emu) {
			if r = c.Mem.FindRegion(a); r != nil {
				prot = r.Prot
			}
		})
		if r == nil {
			return e.fail(errInvalidAddress)
		}
		if out := e.Arg(4); out != 0 {
			e.Mem.W32(out, prot)
		}
		return 1
	})
	reg(k, "ReadProcessMemory", func(e *Emu) uint64 {
		p := e.procArg(0)
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		src, dst, n, done := e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4)
		if e.Mem.AccessibleLen(dst, n) < n {
			return e.fail(998) // ERROR_NOACCESS
		}
		var data []byte
		e.withProcess(p, func(c *Emu) { data = c.Mem.ReadBytes(src, int(c.Mem.AccessibleLen(src, n))) })
		e.Mem.Write(dst, data)
		if done != 0 {
			e.Mem.W64(done, uint64(len(data)))
		}
		if uint64(len(data)) < n {
			return e.fail(errPartialCopy)
		}
		return 1
	})
	reg(k, "WriteProcessMemory", func(e *Emu) uint64 {
		p := e.procArg(0)
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		dst, src, n, done := e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4)
		if e.Mem.AccessibleLen(src, n) < n {
			return e.fail(998) // ERROR_NOACCESS
		}
		data := e.Mem.ReadBytes(src, int(n))
		var w uint64
		e.withProcess(p, func(c *Emu) {
			w = c.Mem.AccessibleLen(dst, n)
			c.Mem.Write(dst, data[:w])
			for _, t := range c.threads {
				t.CPU.InvalidateCode()
			}
		})
		if done != 0 {
			e.Mem.W64(done, w)
		}
		if w < n {
			return e.fail(errPartialCopy)
		}
		return 1
	})
}
