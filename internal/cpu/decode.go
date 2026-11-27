package cpu

// decodeModRM reads a ModRM byte (plus SIB/displacement) and computes the
// effective address. immLen is the number of immediate bytes that follow the
// addressing bytes; it is needed for RIP-relative addressing.
func (c *CPU) decodeModRM(immLen int) {
	b := c.f8()
	c.mod = b >> 6
	c.reg = (b>>3)&7 | (c.rex&4)<<1
	rm := b & 7
	if c.mod == 3 {
		c.rm = rm | (c.rex&1)<<3
		c.isMem = false
		return
	}
	c.isMem = true
	var ea uint64
	if rm == 4 {
		sib := c.f8()
		scale := sib >> 6
		idx := (sib>>3)&7 | (c.rex&2)<<2
		base := sib&7 | (c.rex&1)<<3
		if idx != 4 {
			ea = c.R[idx] << scale
		}
		if sib&7 == 5 && c.mod == 0 {
			ea += uint64(int64(int32(c.f32())))
		} else {
			ea += c.R[base]
		}
	} else if rm == 5 && c.mod == 0 {
		disp := uint64(int64(int32(c.f32())))
		ea = c.RIP + uint64(immLen) + disp
		if c.ad32 {
			ea &= 0xFFFFFFFF
		}
		c.ea = ea + c.segB
		return
	} else {
		ea = c.R[rm|(c.rex&1)<<3]
	}
	switch c.mod {
	case 1:
		ea += uint64(int64(int8(c.f8())))
	case 2:
		ea += uint64(int64(int32(c.f32())))
	}
	if c.ad32 {
		ea &= 0xFFFFFFFF
	}
	c.ea = ea + c.segB
}

func (c *CPU) rdRM(sz uint8) uint64 {
	if c.isMem {
		return c.rdMem(c.ea, sz)
	}
	return c.getReg(c.rm, sz)
}

func (c *CPU) wrRM(sz uint8, v uint64) {
	if c.isMem {
		c.wrMem(c.ea, sz, v)
		return
	}
	c.setReg(c.rm, sz, v)
}

// imm reads an immediate of operand size sz (64-bit operands take a
// sign-extended imm32).
func (c *CPU) imm(sz uint8) uint64 {
	switch sz {
	case 1:
		return uint64(c.f8())
	case 2:
		return uint64(c.f16())
	case 4:
		return uint64(c.f32())
	default:
		return uint64(int64(int32(c.f32())))
	}
}

func immLen(sz uint8) int {
	if sz == 8 {
		return 4
	}
	return int(sz)
}

// step decodes and executes one instruction.
func (c *CPU) step() {
	c.IP0 = c.RIP
	c.rex = 0
	c.p66 = false
	c.rep = 0
	c.segB = 0
	c.ad32 = false
	var op uint8
prefix:
	for {
		op = c.f8()
		switch op {
		case 0x66:
			c.p66 = true
		case 0x67:
			c.ad32 = true
		case 0xF2, 0xF3:
			c.rep = op
		case 0xF0, 0x2E, 0x36, 0x3E, 0x26:
			// lock / ignored segment overrides
		case 0x64:
			c.segB = c.FSBase
		case 0x65:
			c.segB = c.GSBase
		default:
			break prefix
		}
	}
	if op&0xF0 == 0x40 {
		c.rex = op
		op = c.f8()
		// a REX not immediately preceding the opcode is ignored; we accept
		// the common case only.
		for op&0xF0 == 0x40 {
			c.rex = op
			op = c.f8()
		}
	}
	switch {
	case c.rex&8 != 0:
		c.osz = 8
	case c.p66:
		c.osz = 2
	default:
		c.osz = 4
	}
	if op == 0x0F {
		c.exec0F()
		return
	}
	c.exec1(op)
}

// stepShared is step for address spaces with shared memory (Run selects it
// per slice, so step itself stays untouched): LOCK-prefixed instructions and
// XCHG (implicitly locked) run through execLocked.
func (c *CPU) stepShared() {
	c.IP0 = c.RIP
	c.rex = 0
	c.p66 = false
	c.rep = 0
	c.segB = 0
	c.ad32 = false
	locked := false
	var op uint8
prefix:
	for {
		op = c.f8()
		switch op {
		case 0x66:
			c.p66 = true
		case 0x67:
			c.ad32 = true
		case 0xF2, 0xF3:
			c.rep = op
		case 0xF0:
			locked = true
		case 0x2E, 0x36, 0x3E, 0x26:
		case 0x64:
			c.segB = c.FSBase
		case 0x65:
			c.segB = c.GSBase
		default:
			break prefix
		}
	}
	for op&0xF0 == 0x40 {
		c.rex = op
		op = c.f8()
	}
	switch {
	case c.rex&8 != 0:
		c.osz = 8
	case c.p66:
		c.osz = 2
	default:
		c.osz = 4
	}
	if locked || op == 0x86 || op == 0x87 {
		c.execLocked(op)
		return
	}
	if op == 0x0F {
		c.exec0F()
		return
	}
	c.exec1(op)
}

// execLocked runs a locked read-modify-write instruction: mem turns the write
// of the shared location read first into a CAS; if the CAS fails, the
// instruction is rolled back (registers, flags, RIP) and re-executed.
func (c *CPU) execLocked(op uint8) {
	regs, flags := c.R, c.Flags
	c.Mem.BeginLocked()
	defer func() {
		if c.Mem.EndLocked() {
			c.R, c.Flags, c.RIP = regs, flags, c.IP0
		}
	}()
	if op == 0x0F {
		c.exec0F()
		return
	}
	c.exec1(op)
}
