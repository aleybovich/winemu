package cpu

// Size- and addressing-form-specialised variants of the hottest handlers.
// "B" variants are for [base+disp] operands without index or segment.

// simpleEA reports a [base+disp] operand without index or segment override.
func simpleEA(o *op) bool { return o.base != noReg && o.idx == noReg && o.seg == 0 }

// sized picks the 64-bit, 32-bit or generic handler.
func sized(sz uint8, f64, f32, gen opFn) opFn {
	switch sz {
	case 8:
		return f64
	case 4:
		return f32
	}
	return gen
}

// sizedEA is sized for memory forms with a [base+disp] fast variant.
func sizedEA(o *op, b64, f64, b32, f32, gen opFn) opFn {
	if simpleEA(o) {
		return sized(o.sz, b64, b32, gen)
	}
	return sized(o.sz, f64, f32, gen)
}

func opMovRR64(c *CPU, o *op) bool { c.R[o.rm] = c.R[o.r]; return false }
func opMovRR32(c *CPU, o *op) bool { c.R[o.rm] = c.R[o.r] & 0xFFFFFFFF; return false }

func opMovRM64(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.R[o.r] = c.mc.R64(c.Mem, c.opEA(o))
	return false
}
func opMovRM32(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.R[o.r] = uint64(c.mc.R32(c.Mem, c.opEA(o)))
	return false
}
func opMovRM64B(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.R[o.r] = c.mc.R64(c.Mem, c.R[o.base]+o.disp)
	return false
}
func opMovRM32B(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.R[o.r] = uint64(c.mc.R32(c.Mem, c.R[o.base]+o.disp))
	return false
}

func opMovMR64(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.mc.W64(c.Mem, c.opEA(o), c.R[o.r])
	return c.stored(o)
}
func opMovMR32(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.mc.W32(c.Mem, c.opEA(o), uint32(c.R[o.r]))
	return c.stored(o)
}
func opMovMR64B(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.mc.W64(c.Mem, c.R[o.base]+o.disp, c.R[o.r])
	return c.stored(o)
}
func opMovMR32B(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.mc.W32(c.Mem, c.R[o.base]+o.disp, uint32(c.R[o.r]))
	return c.stored(o)
}

func opMovRI64(c *CPU, o *op) bool { c.R[o.rm] = o.imm; return false }
func opMovRI32(c *CPU, o *op) bool { c.R[o.rm] = o.imm & 0xFFFFFFFF; return false }

func opMovMI64(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.mc.W64(c.Mem, c.opEA(o), o.imm)
	return c.stored(o)
}
func opMovMI32(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.mc.W32(c.Mem, c.opEA(o), uint32(o.imm))
	return c.stored(o)
}

func opLea64(c *CPU, o *op) bool { c.R[o.r] = c.leaEA(o); return false }
func opLea32(c *CPU, o *op) bool { c.R[o.r] = c.leaEA(o) & 0xFFFFFFFF; return false }
func opLea64B(c *CPU, o *op) bool {
	c.R[o.r] = c.R[o.base] + o.disp
	return false
}

// MOVZX r32/r64, byte (operand size 4 or 8: the result is zero-extended).
func opMovzxM8(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.R[o.r] = uint64(c.mc.R8(c.Mem, c.opEA(o)))
	return false
}
func opMovzxM8B(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.R[o.r] = uint64(c.mc.R8(c.Mem, c.R[o.base]+o.disp))
	return false
}
func opMovzxR8(c *CPU, o *op) bool { c.R[o.r] = (c.R[o.rm] >> o.rmSh) & 0xFF; return false }
func opMovzxM16(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.R[o.r] = uint64(c.mc.R16(c.Mem, c.opEA(o)))
	return false
}

// INC/DEC r32/r64 with lazy flags (CF preserved through lf.cf).
func opInc64R(c *CPU, o *op) bool {
	v := c.R[o.rm]
	c.lf = lazyFlags{kind: lfInc, sz: 8, a: v, r: v + 1, cf: c.carry()}
	c.R[o.rm] = v + 1
	return false
}

func opDec64R(c *CPU, o *op) bool {
	v := c.R[o.rm]
	c.lf = lazyFlags{kind: lfDec, sz: 8, a: v, r: v - 1, cf: c.carry()}
	c.R[o.rm] = v - 1
	return false
}

func opInc32R(c *CPU, o *op) bool {
	v := c.R[o.rm] & 0xFFFFFFFF
	r := (v + 1) & 0xFFFFFFFF
	c.lf = lazyFlags{kind: lfInc, sz: 4, a: v, r: r, cf: c.carry()}
	c.R[o.rm] = r
	return false
}

func opDec32R(c *CPU, o *op) bool {
	v := c.R[o.rm] & 0xFFFFFFFF
	r := (v - 1) & 0xFFFFFFFF
	c.lf = lazyFlags{kind: lfDec, sz: 4, a: v, r: r, cf: c.carry()}
	c.R[o.rm] = r
	return false
}

// SHL/SHR/SAR r32/r64, imm with a non-zero (pre-masked) count in o.imm.
func opShl64RI(c *CPU, o *op) bool {
	a := c.R[o.rm]
	r := a << o.imm
	c.lf = lazyFlags{kind: lfShift, sz: 8, op: 4, a: a, b: o.imm, r: r}
	c.R[o.rm] = r
	return false
}

func opShr64RI(c *CPU, o *op) bool {
	a := c.R[o.rm]
	r := a >> o.imm
	c.lf = lazyFlags{kind: lfShift, sz: 8, op: 5, a: a, b: o.imm, r: r}
	c.R[o.rm] = r
	return false
}

func opSar64RI(c *CPU, o *op) bool {
	a := c.R[o.rm]
	r := uint64(int64(a) >> o.imm)
	c.lf = lazyFlags{kind: lfShift, sz: 8, op: 7, a: a, b: o.imm, r: r}
	c.R[o.rm] = r
	return false
}

func opShl32RI(c *CPU, o *op) bool {
	a := c.R[o.rm] & 0xFFFFFFFF
	r := (a << o.imm) & 0xFFFFFFFF
	c.lf = lazyFlags{kind: lfShift, sz: 4, op: 4, a: a, b: o.imm, r: r}
	c.R[o.rm] = r
	return false
}

func opShr32RI(c *CPU, o *op) bool {
	a := c.R[o.rm] & 0xFFFFFFFF
	r := a >> o.imm
	c.lf = lazyFlags{kind: lfShift, sz: 4, op: 5, a: a, b: o.imm, r: r}
	c.R[o.rm] = r
	return false
}

func opSar32RI(c *CPU, o *op) bool {
	a := c.R[o.rm] & 0xFFFFFFFF
	r := uint64(int32(a)>>o.imm) & 0xFFFFFFFF
	c.lf = lazyFlags{kind: lfShift, sz: 4, op: 7, a: a, b: o.imm, r: r}
	c.R[o.rm] = r
	return false
}

// shiftPick specialises register shifts by an immediate.
func shiftPick(o *op) {
	if o.mem || o.sub < 4 || o.sz < 4 {
		return
	}
	n := o.imm & 31
	if o.sz == 8 {
		n = o.imm & 63
	}
	if n == 0 {
		return
	}
	o.imm = n
	k := [4]int{0, 1, 0, 2}[o.sub-4]
	if o.sz == 8 {
		o.fn = [3]opFn{opShl64RI, opShr64RI, opSar64RI}[k]
	} else {
		o.fn = [3]opFn{opShl32RI, opShr32RI, opSar32RI}[k]
	}
}

// ALU r/m32/64, r with a [base+disp] memory destination.
func opAluMR64B(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.R[o.base] + o.disp
	r := c.aluL(o.sub, c.mc.R64(c.Mem, a), c.R[o.r], 8)
	if o.sub != 7 {
		c.mc.W64(c.Mem, a, r)
		return c.stored(o)
	}
	return false
}

func opAluMR32B(c *CPU, o *op) bool {
	c.IP0 = o.ip
	a := c.R[o.base] + o.disp
	r := c.aluL(o.sub, uint64(c.mc.R32(c.Mem, a)), c.R[o.r], 4)
	if o.sub != 7 {
		c.mc.W32(c.Mem, a, uint32(r))
		return c.stored(o)
	}
	return false
}

// ALU r32/64, r/m with a memory source.
func opAluRM64(c *CPU, o *op) bool {
	c.IP0 = o.ip
	r := c.aluL(o.sub, c.R[o.r], c.mc.R64(c.Mem, c.opEA(o)), 8)
	if o.sub != 7 {
		c.R[o.r] = r
	}
	return false
}

func opAluRM32(c *CPU, o *op) bool {
	c.IP0 = o.ip
	r := c.aluL(o.sub, c.R[o.r], uint64(c.mc.R32(c.Mem, c.opEA(o))), 4)
	if o.sub != 7 {
		c.R[o.r] = r
	}
	return false
}

func opMovMR16(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.mc.W16(c.Mem, c.opEA(o), uint16(c.R[o.r]))
	return c.stored(o)
}

func opMovMR8(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.mc.W8(c.Mem, c.opEA(o), uint8(c.R[o.r]>>o.rSh))
	return c.stored(o)
}

func opTest8RR(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 1, r: (c.R[o.rm] >> o.rmSh) & (c.R[o.r] >> o.rSh) & 0xFF}
	return false
}
