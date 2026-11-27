package cpu

// Handlers of predecoded ops. Each performs the side effects of the
// corresponding exec1/exec0F path in the same order (see docs/engine.md).

func (c *CPU) getR(r, sh, sz uint8) uint64 {
	switch sz {
	case 8:
		return c.R[r]
	case 4:
		return c.R[r] & 0xFFFFFFFF
	case 2:
		return c.R[r] & 0xFFFF
	}
	return (c.R[r] >> sh) & 0xFF
}

func (c *CPU) setR(r, sh, sz uint8, v uint64) {
	switch sz {
	case 8:
		c.R[r] = v
	case 4:
		c.R[r] = v & 0xFFFFFFFF
	case 2:
		c.R[r] = c.R[r]&^0xFFFF | v&0xFFFF
	default:
		c.R[r] = c.R[r]&^(0xFF<<sh) | (v&0xFF)<<sh
	}
}

func (c *CPU) leaEA(o *op) uint64 {
	a := o.disp
	if o.base != noReg {
		a += c.R[o.base]
	}
	if o.idx != noReg {
		a += c.R[o.idx] << o.scale
	}
	return a
}

func (c *CPU) opEA(o *op) uint64 {
	a := c.leaEA(o)
	switch o.seg {
	case 1:
		a += c.FSBase
	case 2:
		a += c.GSBase
	}
	return a
}

// stored ends the block after a store that hit decoded code.
func (c *CPU) stored(o *op) bool {
	if c.Mem.CodeWritten {
		c.Mem.CodeWritten = false
		c.RIP = o.next
		return true
	}
	return false
}

func (c *CPU) push64(v uint64) {
	sp := c.R[RSP] - 8
	c.mc.W64(c.Mem, sp, v)
	c.R[RSP] = sp
}

func opFallback(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.flags()
	c.RIP = o.ip
	c.refStep()
	return true
}

func opNop(c *CPU, o *op) bool { return false }

func opHyper(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.flags()
	c.RIP = o.next
	shared := c.sharedSlice
	c.Hyper(c, uint32(o.imm))
	c.sharedSlice = shared // a nested Run may have changed it
	return true
}

// --- ALU / TEST

func opAluRR(c *CPU, o *op) bool {
	r := c.aluL(o.sub, c.getR(o.rm, o.rmSh, o.sz), c.getR(o.r, o.rSh, o.sz), o.sz)
	if o.sub != 7 {
		c.setR(o.rm, o.rmSh, o.sz, r)
	}
	return false
}

func opAluMR(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.opEA(o)
	r := c.aluL(o.sub, c.rdMem(a, o.sz), c.getR(o.r, o.rSh, o.sz), o.sz)
	if o.sub != 7 {
		c.wrMem(a, o.sz, r)
		return c.stored(o)
	}
	return false
}

func opAluRM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	r := c.aluL(o.sub, c.getR(o.r, o.rSh, o.sz), c.rdMem(c.opEA(o), o.sz), o.sz)
	if o.sub != 7 {
		c.setR(o.r, o.rSh, o.sz, r)
	}
	return false
}

func opAluRI(c *CPU, o *op) bool {
	r := c.aluL(o.sub, c.getR(o.rm, o.rmSh, o.sz), o.imm, o.sz)
	if o.sub != 7 {
		c.setR(o.rm, o.rmSh, o.sz, r)
	}
	return false
}

func opAluMI(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.opEA(o)
	r := c.aluL(o.sub, c.rdMem(a, o.sz), o.imm, o.sz)
	if o.sub != 7 {
		c.wrMem(a, o.sz, r)
		return c.stored(o)
	}
	return false
}

func opTestRR(c *CPU, o *op) bool {
	c.logicL(c.getR(o.rm, o.rmSh, o.sz)&c.getR(o.r, o.rSh, o.sz), o.sz)
	return false
}

func opTestMR(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.logicL(c.rdMem(c.opEA(o), o.sz)&c.getR(o.r, o.rSh, o.sz), o.sz)
	return false
}

func opTestRI(c *CPU, o *op) bool {
	c.logicL(c.getR(o.rm, o.rmSh, o.sz)&o.imm, o.sz)
	return false
}

func opTestMI(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.logicL(c.rdMem(c.opEA(o), o.sz)&o.imm, o.sz)
	return false
}

func opNotR(c *CPU, o *op) bool {
	c.setR(o.rm, o.rmSh, o.sz, ^c.getR(o.rm, o.rmSh, o.sz)&sizeMask[o.sz])
	return false
}

func opNotM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.opEA(o)
	c.wrMem(a, o.sz, ^c.rdMem(a, o.sz)&sizeMask[o.sz])
	return c.stored(o)
}

func opNegR(c *CPU, o *op) bool {
	c.setR(o.rm, o.rmSh, o.sz, c.aluL(5, 0, c.getR(o.rm, o.rmSh, o.sz), o.sz))
	return false
}

func opNegM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.opEA(o)
	c.wrMem(a, o.sz, c.aluL(5, 0, c.rdMem(a, o.sz), o.sz))
	return c.stored(o)
}

func opIncDecR(c *CPU, o *op) bool {
	c.setR(o.rm, o.rmSh, o.sz, c.incdecL(o.sub, c.getR(o.rm, o.rmSh, o.sz), o.sz))
	return false
}

func opIncDecM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.opEA(o)
	c.wrMem(a, o.sz, c.incdecL(o.sub, c.rdMem(a, o.sz), o.sz))
	return c.stored(o)
}

func opShiftR(c *CPU, o *op) bool {
	c.setR(o.rm, o.rmSh, o.sz, c.shiftL(o.sub, c.getR(o.rm, o.rmSh, o.sz), o.imm, o.sz))
	return false
}

func opShiftM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.opEA(o)
	c.wrMem(a, o.sz, c.shiftL(o.sub, c.rdMem(a, o.sz), o.imm, o.sz))
	return c.stored(o)
}

func opShiftRCL(c *CPU, o *op) bool {
	c.setR(o.rm, o.rmSh, o.sz, c.shiftL(o.sub, c.getR(o.rm, o.rmSh, o.sz), c.R[RCX]&0xFF, o.sz))
	return false
}

func opShiftMCL(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.opEA(o)
	c.wrMem(a, o.sz, c.shiftL(o.sub, c.rdMem(a, o.sz), c.R[RCX]&0xFF, o.sz))
	return c.stored(o)
}

func opImul2R(c *CPU, o *op) bool {
	c.lf.kind = lfNone // imul2 sets every arithmetic flag
	c.setR(o.r, 0, o.sz, c.imul2(c.getR(o.r, 0, o.sz), c.getR(o.rm, 0, o.sz), o.sz))
	return false
}

func opImul2M(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.flags() // not discarded: the load may fault with the old flags visible
	c.setR(o.r, 0, o.sz, c.imul2(c.getR(o.r, 0, o.sz), c.rdMem(c.opEA(o), o.sz), o.sz))
	return false
}

func opImul3R(c *CPU, o *op) bool {
	c.lf.kind = lfNone // imul2 sets every arithmetic flag
	c.setR(o.r, 0, o.sz, c.imul2(c.getR(o.rm, 0, o.sz), o.imm, o.sz))
	return false
}

func opImul3M(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.flags() // not discarded: the load may fault with the old flags visible
	c.setR(o.r, 0, o.sz, c.imul2(c.rdMem(c.opEA(o), o.sz), o.imm, o.sz))
	return false
}
