package cpu

// --- moves

func opMovRR(c *CPU, o *op) bool {
	c.setR(o.rm, o.rmSh, o.sz, c.getR(o.r, o.rSh, o.sz))
	return false
}

func opMovMR(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.wrMem(c.opEA(o), o.sz, c.getR(o.r, o.rSh, o.sz))
	return c.stored(o)
}

func opMovRM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.setR(o.r, o.rSh, o.sz, c.rdMem(c.opEA(o), o.sz))
	return false
}

func opMovRI(c *CPU, o *op) bool {
	c.setR(o.rm, o.rmSh, o.sz, o.imm)
	return false
}

func opMovMI(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.wrMem(c.opEA(o), o.sz, o.imm)
	return c.stored(o)
}

func opLea(c *CPU, o *op) bool {
	c.setR(o.r, 0, o.sz, c.leaEA(o))
	return false
}

func movsxd(v uint64, sz uint8) uint64 {
	if sz == 8 {
		return signExt(v, 4)
	}
	return v
}

func opMovsxdR(c *CPU, o *op) bool {
	c.setR(o.r, 0, o.sz, movsxd(c.getR(o.rm, 0, 4), o.sz))
	return false
}

func opMovsxdM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.setR(o.r, 0, o.sz, movsxd(c.rdMem(c.opEA(o), 4), o.sz))
	return false
}

func (c *CPU) movx(o *op, v uint64) {
	s := uint8(o.imm)
	if o.sub != 0 {
		v = signExt(v, s)
	}
	c.setR(o.r, 0, o.sz, v&sizeMask[o.sz])
}

func opMovxR(c *CPU, o *op) bool {
	c.movx(o, c.getR(o.rm, o.rmSh, uint8(o.imm)))
	return false
}

func opMovxM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.movx(o, c.rdMem(c.opEA(o), uint8(o.imm)))
	return false
}

func opCmovR(c *CPU, o *op) bool {
	v := c.getR(o.rm, 0, o.sz)
	if c.lcond(o.sub) {
		c.setR(o.r, 0, o.sz, v)
	} else if o.sz == 4 {
		c.R[o.r] &= 0xFFFFFFFF
	}
	return false
}

func opCmovM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	v := c.rdMem(c.opEA(o), o.sz)
	if c.lcond(o.sub) {
		c.setR(o.r, 0, o.sz, v)
	} else if o.sz == 4 {
		c.R[o.r] &= 0xFFFFFFFF
	}
	return false
}

func (c *CPU) condVal(cc uint8) uint64 {
	if c.lcond(cc) {
		return 1
	}
	return 0
}

func opSetccR(c *CPU, o *op) bool {
	c.setR(o.rm, o.rmSh, 1, c.condVal(o.sub))
	return false
}

func opSetccM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.wrMem(c.opEA(o), 1, c.condVal(o.sub))
	return c.stored(o)
}

func opXchgAX(c *CPU, o *op) bool {
	a := c.getR(RAX, 0, o.sz)
	c.setR(RAX, 0, o.sz, c.getR(o.r, 0, o.sz))
	c.setR(o.r, 0, o.sz, a)
	return false
}

func opCwde(c *CPU, o *op) bool {
	switch o.sz {
	case 8:
		c.R[RAX] = signExt(c.R[RAX], 4)
	case 4:
		c.R[RAX] = signExt(c.R[RAX], 2) & 0xFFFFFFFF
	default:
		c.setReg(RAX, 2, signExt(c.R[RAX], 1))
	}
	return false
}

func opCdq(c *CPU, o *op) bool {
	v := uint64(0)
	if c.getR(RAX, 0, o.sz)&signBit[o.sz] != 0 {
		v = ^uint64(0)
	}
	c.setR(RDX, 0, o.sz, v)
	return false
}

// --- stack

func opPush(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.push64(c.R[o.r])
	return c.stored(o)
}

func opPop(c *CPU, o *op) bool {
	c.IP0 = o.ip
	v := c.mc.R64(c.Mem, c.R[RSP])
	c.R[RSP] += 8
	c.R[o.r] = v
	return false
}

func opPushI(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.push64(o.imm)
	return c.stored(o)
}

func opPushRM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	var v uint64
	if o.mem {
		v = c.mc.R64(c.Mem, c.opEA(o))
	} else {
		v = c.R[o.rm]
	}
	c.push64(v)
	return c.stored(o)
}

func opLeave(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.R[RSP] = c.R[RBP]
	c.R[RBP] = c.Pop()
	return false
}

// --- control transfer (always the last op of a block)

func opJcc(c *CPU, o *op) bool { return c.branch(o) }

// opCallCont is a direct call whose target continues the block.
func opCallCont(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.push64(o.imm)
	return c.stored(o)
}

func opJmp(c *CPU, o *op) bool {
	c.RIP = o.disp
	return true
}

func opCall(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.push64(o.next)
	c.RIP = o.disp
	return true
}

func opRet(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.RIP = c.Pop()
	return true
}

func opRetN(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.RIP = c.Pop()
	c.R[RSP] += o.imm
	return true
}

func opCallIndR(c *CPU, o *op) bool {
	c.IP0 = o.ip
	t := c.R[o.rm]
	c.push64(o.next)
	c.RIP = t
	return true
}

func opCallIndM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	t := c.mc.R64(c.Mem, c.opEA(o))
	c.push64(o.next)
	c.RIP = t
	return true
}

func opJmpIndR(c *CPU, o *op) bool {
	c.RIP = c.R[o.rm]
	return true
}

func opJmpIndM(c *CPU, o *op) bool {
	c.IP0 = o.ip
	c.RIP = c.mc.R64(c.Mem, c.opEA(o))
	return true
}
