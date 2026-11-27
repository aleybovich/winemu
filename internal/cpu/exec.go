package cpu

import (
	"math/bits"
)

func (c *CPU) exec1(op uint8) {
	sz := c.osz
	switch op {
	case 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D:
		// classic ALU block: ADD OR ADC SBB AND SUB XOR CMP
		aop := op >> 3
		switch op & 7 {
		case 0, 1, 2, 3:
			s := sz
			if op&1 == 0 {
				s = 1
			}
			c.decodeModRM(0)
			if op&2 == 0 { // r/m, reg
				r := c.alu(aop, c.rdRM(s), c.getReg(c.reg, s), s)
				if aop != 7 {
					c.wrRM(s, r)
				}
			} else { // reg, r/m
				r := c.alu(aop, c.getReg(c.reg, s), c.rdRM(s), s)
				if aop != 7 {
					c.setReg(c.reg, s, r)
				}
			}
		case 4:
			r := c.alu(aop, c.R[RAX], uint64(c.f8()), 1)
			if aop != 7 {
				c.setReg(RAX, 1, r)
			}
		case 5:
			r := c.alu(aop, c.R[RAX], c.imm(sz), sz)
			if aop != 7 {
				c.setReg(RAX, sz, r)
			}
		}
		return
	case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57:
		r := op&7 | (c.rex&1)<<3
		if c.p66 {
			c.R[RSP] -= 2
			c.mc.W16(c.Mem, c.R[RSP], uint16(c.R[r]))
		} else {
			c.Push(c.R[r])
		}
		return
	case 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F:
		r := op&7 | (c.rex&1)<<3
		if c.p66 {
			v := c.mc.R16(c.Mem, c.R[RSP])
			c.R[RSP] += 2
			c.setReg(r, 2, uint64(v))
		} else {
			c.R[r] = c.Pop()
		}
		return
	case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F:
		d := int8(c.f8())
		if c.cond(op & 15) {
			c.RIP += uint64(int64(d))
		}
		return
	case 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97:
		r := op&7 | (c.rex&1)<<3
		a := c.getReg(RAX, sz)
		c.setReg(RAX, sz, c.getReg(r, sz))
		c.setReg(r, sz, a)
		return
	case 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7:
		c.setReg(op&7|(c.rex&1)<<3, 1, uint64(c.f8()))
		return
	case 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF:
		r := op&7 | (c.rex&1)<<3
		switch sz {
		case 8:
			c.R[r] = c.f64()
		case 4:
			c.R[r] = uint64(c.f32())
		default:
			c.setReg(r, 2, uint64(c.f16()))
		}
		return
	case 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF:
		c.x87(op)
		return
	case 0x63: // MOVSXD
		c.decodeModRM(0)
		v := c.rdRM(4)
		if sz == 8 {
			v = signExt(v, 4)
		}
		c.setReg(c.reg, sz, v)
	case 0x68:
		var v uint64
		if c.p66 {
			v = uint64(c.f16())
		} else {
			v = c.imm(4)
		}
		if c.p66 {
			c.R[RSP] -= 2
			c.mc.W16(c.Mem, c.R[RSP], uint16(v))
		} else {
			c.Push(signExt(v, 4))
		}
	case 0x6A:
		v := signExt(uint64(c.f8()), 1)
		if c.p66 {
			c.R[RSP] -= 2
			c.mc.W16(c.Mem, c.R[RSP], uint16(v))
		} else {
			c.Push(v)
		}
	case 0x69, 0x6B: // IMUL r, r/m, imm
		il := immLen(sz)
		if op == 0x6B {
			il = 1
		}
		c.decodeModRM(il)
		a := c.rdRM(sz)
		var b uint64
		if op == 0x6B {
			b = signExt(uint64(c.f8()), 1)
		} else {
			b = signExt(c.imm(sz), sz)
		}
		c.setReg(c.reg, sz, c.imul2(a, b, sz))
	case 0x80, 0x81, 0x83:
		s := sz
		if op == 0x80 {
			s = 1
		}
		il := immLen(s)
		if op == 0x83 {
			il = 1
		}
		c.decodeModRM(il)
		a := c.rdRM(s)
		var b uint64
		if op == 0x83 {
			b = signExt(uint64(c.f8()), 1)
		} else {
			b = c.imm(s)
		}
		r := c.alu(c.reg&7, a, b, s)
		if c.reg&7 != 7 {
			c.wrRM(s, r)
		}
	case 0x84, 0x85:
		s := sz
		if op == 0x84 {
			s = 1
		}
		c.decodeModRM(0)
		c.logic(c.rdRM(s)&c.getReg(c.reg, s), s)
	case 0x86, 0x87:
		s := sz
		if op == 0x86 {
			s = 1
		}
		c.decodeModRM(0)
		a := c.rdRM(s)
		c.wrRM(s, c.getReg(c.reg, s))
		c.setReg(c.reg, s, a)
	case 0x88:
		c.decodeModRM(0)
		c.wrRM(1, c.getReg(c.reg, 1))
	case 0x89:
		c.decodeModRM(0)
		c.wrRM(sz, c.getReg(c.reg, sz))
	case 0x8A:
		c.decodeModRM(0)
		c.setReg(c.reg, 1, c.rdRM(1))
	case 0x8B:
		c.decodeModRM(0)
		c.setReg(c.reg, sz, c.rdRM(sz))
	case 0x8C: // MOV r/m, Sreg
		c.decodeModRM(0)
		sel := []uint64{0x2b, 0x33, 0x2b, 0x2b, 0x53, 0x2b, 0, 0}[c.reg&7]
		if c.isMem {
			c.wrMem(c.ea, 2, sel)
		} else {
			c.setReg(c.rm, sz, sel)
		}
	case 0x8D: // LEA
		c.decodeModRM(0)
		if !c.isMem {
			c.ud()
		}
		c.setReg(c.reg, sz, c.ea-c.segB)
	case 0x8E:
		c.decodeModRM(0)
	case 0x8F:
		c.decodeModRM(0)
		v := c.Pop()
		c.wrRM(8, v)
	case 0x90:
		if c.rex&1 != 0 {
			a := c.getReg(RAX, sz)
			c.setReg(RAX, sz, c.getReg(8, sz))
			c.setReg(8, sz, a)
		}
	case 0x98: // CBW/CWDE/CDQE
		switch sz {
		case 8:
			c.R[RAX] = signExt(c.R[RAX], 4)
		case 4:
			c.R[RAX] = signExt(c.R[RAX], 2) & 0xFFFFFFFF
		default:
			c.setReg(RAX, 2, signExt(c.R[RAX], 1))
		}
	case 0x99: // CWD/CDQ/CQO
		neg := c.getReg(RAX, sz)&signBit[sz] != 0
		v := uint64(0)
		if neg {
			v = ^uint64(0)
		}
		c.setReg(RDX, sz, v)
	case 0x9B: // FWAIT
	case 0x9C:
		c.Push(c.Flags&0x00FCFFD7 | 2)
	case 0x9D:
		v := c.Pop()
		c.Flags = (c.Flags &^ 0x00244FD5) | (v & 0x00244FD5) | 2
	case 0x9E: // SAHF
		ah := (c.R[RAX] >> 8) & 0xD5
		c.Flags = c.Flags&^0xD5 | ah
	case 0x9F: // LAHF
		c.R[RAX] = c.R[RAX]&^0xFF00 | ((c.Flags&0xD5)|2)<<8
	case 0xA0, 0xA1, 0xA2, 0xA3: // MOV moffs
		var a uint64
		if c.ad32 {
			a = uint64(c.f32())
		} else {
			a = c.f64()
		}
		a += c.segB
		s := sz
		if op&1 == 0 {
			s = 1
		}
		if op < 0xA2 {
			c.setReg(RAX, s, c.rdMem(a, s))
		} else {
			c.wrMem(a, s, c.getReg(RAX, s))
		}
	case 0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF:
		c.stringOp(op)
	case 0xA8:
		c.logic(c.R[RAX]&uint64(c.f8()), 1)
	case 0xA9:
		c.logic(c.R[RAX]&c.imm(sz), sz)
	case 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3:
		s := sz
		if op&1 == 0 {
			s = 1
		}
		il := 0
		if op <= 0xC1 {
			il = 1
		}
		c.decodeModRM(il)
		var n uint64
		switch op {
		case 0xC0, 0xC1:
			n = uint64(c.f8())
		case 0xD0, 0xD1:
			n = 1
		default:
			n = c.R[RCX] & 0xFF
		}
		c.wrRM(s, c.shift(c.reg&7, c.rdRM(s), n, s))
	case 0xC2:
		n := c.f16()
		c.RIP = c.Pop()
		c.R[RSP] += uint64(n)
	case 0xC3:
		c.RIP = c.Pop()
	case 0xC6:
		c.decodeModRM(1)
		c.wrRM(1, uint64(c.f8()))
	case 0xC7:
		c.decodeModRM(immLen(sz))
		c.wrRM(sz, c.imm(sz))
	case 0xC8: // ENTER
		size := uint64(c.f16())
		level := c.f8() & 31
		c.Push(c.R[RBP])
		fp := c.R[RSP]
		for i := uint8(1); i < level; i++ {
			c.R[RBP] -= 8
			c.Push(c.mc.R64(c.Mem, c.R[RBP]))
		}
		if level > 0 {
			c.Push(fp)
		}
		c.R[RBP] = fp
		c.R[RSP] -= size
	case 0xC9:
		c.R[RSP] = c.R[RBP]
		c.R[RBP] = c.Pop()
	case 0xCC:
		c.RIP = c.IP0
		panic(&Exception{Code: ExcBreakpoint, Addr: c.IP0})
	case 0xCD:
		n := c.f8()
		switch n {
		case 0x29:
			c.RIP = c.IP0
			panic(&Exception{Code: ExcStackBufOverrun, Addr: c.IP0, Params: []uint64{c.R[RCX]}, Msg: "__fastfail"})
		case 0x2C:
			c.fault(ExcAssertionFailure, "int 2c")
		case 3:
			c.RIP = c.IP0
			panic(&Exception{Code: ExcBreakpoint, Addr: c.IP0})
		default:
			c.fault(ExcAccessViolation, "int")
		}
	case 0xE0, 0xE1, 0xE2: // LOOPNE LOOPE LOOP
		d := int8(c.f8())
		var cnt uint64
		if c.ad32 {
			cnt = (c.R[RCX] - 1) & 0xFFFFFFFF
			c.R[RCX] = cnt
		} else {
			c.R[RCX]--
			cnt = c.R[RCX]
		}
		take := cnt != 0
		if op == 0xE0 {
			take = take && c.Flags&FlagZF == 0
		} else if op == 0xE1 {
			take = take && c.Flags&FlagZF != 0
		}
		if take {
			c.RIP += uint64(int64(d))
		}
	case 0xE3:
		d := int8(c.f8())
		cnt := c.R[RCX]
		if c.ad32 {
			cnt &= 0xFFFFFFFF
		}
		if cnt == 0 {
			c.RIP += uint64(int64(d))
		}
	case 0xE8:
		d := int64(int32(c.f32()))
		c.Push(c.RIP)
		c.RIP += uint64(d)
	case 0xE9:
		d := int64(int32(c.f32()))
		c.RIP += uint64(d)
	case 0xEB:
		d := int8(c.f8())
		c.RIP += uint64(int64(d))
	case 0xF4:
		c.fault(ExcPrivInstr, "hlt")
	case 0xF5:
		c.Flags ^= FlagCF
	case 0xF6, 0xF7:
		c.group3(op)
	case 0xF8:
		c.Flags &^= FlagCF
	case 0xF9:
		c.Flags |= FlagCF
	case 0xFA, 0xFB:
		// CLI/STI: ignore
	case 0xFC:
		c.Flags &^= FlagDF
	case 0xFD:
		c.Flags |= FlagDF
	case 0xFE, 0xFF:
		c.group45(op)
	default:
		c.ud()
	}
}

func (c *CPU) imul2(a, b uint64, sz uint8) uint64 {
	sa, sb := int64(signExt(a, sz)), int64(signExt(b, sz))
	var r uint64
	var ovf bool
	if sz == 8 {
		hi, lo := bits.Mul64(uint64(sa), uint64(sb))
		if sa < 0 {
			hi -= uint64(sb)
		}
		if sb < 0 {
			hi -= uint64(sa)
		}
		r = lo
		ovf = hi != uint64(int64(lo)>>63)
	} else {
		p := sa * sb
		r = uint64(p) & sizeMask[sz]
		ovf = int64(signExt(r, sz)) != p
	}
	c.setFlags(ovf, ovf, false, r, sz)
	return r
}

func (c *CPU) group3(op uint8) {
	s := c.osz
	if op == 0xF6 {
		s = 1
	}
	il := 0
	// peek at reg field to decide on immediate (TEST has one)
	c.decodeModRMPeekTest(s)
	_ = il
	switch c.reg & 7 {
	case 0, 1: // TEST r/m, imm
		v := c.imm(s)
		c.logic(c.rdRM(s)&v, s)
	case 2: // NOT
		c.wrRM(s, ^c.rdRM(s)&sizeMask[s])
	case 3: // NEG
		v := c.rdRM(s)
		r := c.sub(0, v, 0, s)
		c.wrRM(s, r)
	case 4: // MUL
		v := c.rdRM(s)
		switch s {
		case 1:
			r := (c.R[RAX] & 0xFF) * v
			c.setReg(RAX, 2, r)
			ovf := r>>8 != 0
			c.setFlags(ovf, ovf, false, r, 1)
		case 8:
			hi, lo := bits.Mul64(c.R[RAX], v)
			c.R[RAX], c.R[RDX] = lo, hi
			c.setFlags(hi != 0, hi != 0, false, lo, 8)
		default:
			r := c.getReg(RAX, s) * v
			lo, hi := r&sizeMask[s], r>>(8*s)
			c.setReg(RAX, s, lo)
			c.setReg(RDX, s, hi)
			c.setFlags(hi != 0, hi != 0, false, lo, s)
		}
	case 5: // IMUL one operand
		v := int64(signExt(c.rdRM(s), s))
		switch s {
		case 1:
			r := int64(int8(c.R[RAX])) * v
			c.setReg(RAX, 2, uint64(r))
			ovf := r != int64(int8(r))
			c.setFlags(ovf, ovf, false, uint64(r), 1)
		case 8:
			a := int64(c.R[RAX])
			hi, lo := bits.Mul64(uint64(a), uint64(v))
			if a < 0 {
				hi -= uint64(v)
			}
			if v < 0 {
				hi -= uint64(a)
			}
			c.R[RAX], c.R[RDX] = lo, hi
			ovf := hi != uint64(int64(lo)>>63)
			c.setFlags(ovf, ovf, false, lo, 8)
		default:
			a := int64(signExt(c.getReg(RAX, s), s))
			r := a * v
			lo := uint64(r) & sizeMask[s]
			hi := uint64(r>>(8*s)) & sizeMask[s]
			c.setReg(RAX, s, lo)
			c.setReg(RDX, s, hi)
			ovf := int64(signExt(lo, s)) != r
			c.setFlags(ovf, ovf, false, lo, s)
		}
	case 6: // DIV
		d := c.rdRM(s)
		if d == 0 {
			c.fault(ExcIntDivZero, "")
		}
		switch s {
		case 1:
			n := c.R[RAX] & 0xFFFF
			q := n / d
			if q > 0xFF {
				c.fault(ExcIntOverflow, "")
			}
			c.setReg(RAX, 2, (n%d)<<8|q)
		case 8:
			if c.R[RDX] >= d {
				c.fault(ExcIntOverflow, "")
			}
			q, r := bits.Div64(c.R[RDX], c.R[RAX], d)
			c.R[RAX], c.R[RDX] = q, r
		default:
			n := c.getReg(RDX, s)<<(8*s) | c.getReg(RAX, s)
			q := n / d
			if q > sizeMask[s] {
				c.fault(ExcIntOverflow, "")
			}
			c.setReg(RAX, s, q)
			c.setReg(RDX, s, n%d)
		}
	case 7: // IDIV
		d := int64(signExt(c.rdRM(s), s))
		if d == 0 {
			c.fault(ExcIntDivZero, "")
		}
		switch s {
		case 1:
			n := int64(int16(c.R[RAX]))
			q, r := n/d, n%d
			if q != int64(int8(q)) {
				c.fault(ExcIntOverflow, "")
			}
			c.setReg(RAX, 2, uint64(r&0xFF)<<8|uint64(q&0xFF))
		case 8:
			q, r, ok := idiv128(c.R[RDX], c.R[RAX], d)
			if !ok {
				c.fault(ExcIntOverflow, "")
			}
			c.R[RAX], c.R[RDX] = uint64(q), uint64(r)
		default:
			n := int64(c.getReg(RDX, s)<<(8*s) | c.getReg(RAX, s))
			if s == 2 {
				n = int64(int32(n))
			}
			if d == -1 && n == -n && n != 0 {
				c.fault(ExcIntOverflow, "")
			}
			q, r := n/d, n%d
			if q != int64(signExt(uint64(q), s)) {
				c.fault(ExcIntOverflow, "")
			}
			c.setReg(RAX, s, uint64(q))
			c.setReg(RDX, s, uint64(r))
		}
	}
}

// decodeModRMPeekTest decodes ModRM for group 3, accounting for the TEST
// immediate when computing RIP-relative addresses.
func (c *CPU) decodeModRMPeekTest(s uint8) {
	// Peek the modrm byte to learn the reg field.
	save := c.RIP
	b := c.f8()
	c.RIP = save
	if (b>>3)&7 <= 1 {
		c.decodeModRM(immLen(s))
	} else {
		c.decodeModRM(0)
	}
}

func idiv128(hi, lo uint64, d int64) (int64, int64, bool) {
	neg := int64(hi) < 0
	if neg {
		lo, hi = -lo, ^hi
		if lo == 0 {
			hi++
		}
	}
	ud := uint64(d)
	dneg := d < 0
	if dneg {
		ud = uint64(-d)
	}
	if hi >= ud {
		return 0, 0, false
	}
	q, r := bits.Div64(hi, lo, ud)
	qneg := neg != dneg
	if qneg {
		if q > 1<<63 {
			return 0, 0, false
		}
		q = -q
	} else if q >= 1<<63 {
		return 0, 0, false
	}
	if neg {
		r = -r
	}
	return int64(q), int64(r), true
}

func (c *CPU) group45(op uint8) {
	c.decodeModRM(0)
	r := c.reg & 7
	if op == 0xFE {
		if r > 1 {
			c.ud()
		}
		c.incdec(r, 1)
		return
	}
	switch r {
	case 0, 1:
		c.incdec(r, c.osz)
	case 2: // CALL r/m64
		t := c.rdRM(8)
		c.Push(c.RIP)
		c.RIP = t
	case 4: // JMP r/m64
		c.RIP = c.rdRM(8)
	case 6:
		v := c.rdRM(8)
		c.Push(v)
	default:
		c.ud()
	}
}

func (c *CPU) incdec(r uint8, s uint8) {
	v := c.rdRM(s)
	cf := c.Flags & FlagCF
	var res uint64
	if r == 0 {
		res = c.add(v, 1, 0, s)
	} else {
		res = c.sub(v, 1, 0, s)
	}
	c.Flags = c.Flags&^FlagCF | cf
	c.wrRM(s, res)
}

// stringOp implements MOVS/CMPS/STOS/LODS/SCAS with REP prefixes.
func (c *CPU) stringOp(op uint8) {
	s := c.osz
	if op&1 == 0 {
		s = 1
	}
	step := uint64(s)
	back := c.Flags&FlagDF != 0
	if back {
		step = -step
	}
	srcBase := c.segB
	rep := c.rep != 0
	if !rep {
		c.stringOne(op, s, step, srcBase)
		return
	}
	cnt := c.R[RCX]
	if c.ad32 {
		cnt &= 0xFFFFFFFF
	}
	// fast paths
	if !back && (op == 0xA4 || op == 0xA5) && cnt > 0 {
		n := cnt * uint64(s)
		src, dst := c.R[RSI]+srcBase, c.R[RDI]
		if dst <= src || dst >= src+n {
			c.Mem.Move(dst, src, n)
			c.R[RSI] += n
			c.R[RDI] += n
			c.R[RCX] = 0
			return
		}
	}
	if !back && (op == 0xAA || op == 0xAB) && cnt > 0 {
		n := cnt * uint64(s)
		v := c.R[RAX]
		if s == 1 || v&sizeMask[s] == 0 || allSameBytes(v, s) {
			c.Mem.Fill(c.R[RDI], byte(v), n)
			c.R[RDI] += n
			c.R[RCX] = 0
			return
		}
	}
	for cnt != 0 {
		c.stringOne(op, s, step, srcBase)
		cnt--
		c.R[RCX] = cnt
		if op == 0xA6 || op == 0xA7 || op == 0xAE || op == 0xAF {
			zf := c.Flags&FlagZF != 0
			if c.rep == 0xF3 && !zf || c.rep == 0xF2 && zf {
				break
			}
		}
	}
}

func allSameBytes(v uint64, s uint8) bool {
	b := v & 0xFF
	for i := uint8(1); i < s; i++ {
		if (v>>(8*i))&0xFF != b {
			return false
		}
	}
	return true
}

func (c *CPU) stringOne(op uint8, s uint8, step uint64, srcBase uint64) {
	switch op {
	case 0xA4, 0xA5:
		c.wrMem(c.R[RDI], s, c.rdMem(c.R[RSI]+srcBase, s))
		c.R[RSI] += step
		c.R[RDI] += step
	case 0xA6, 0xA7:
		a := c.rdMem(c.R[RSI]+srcBase, s)
		b := c.rdMem(c.R[RDI], s)
		c.sub(a, b, 0, s)
		c.R[RSI] += step
		c.R[RDI] += step
	case 0xAA, 0xAB:
		c.wrMem(c.R[RDI], s, c.R[RAX])
		c.R[RDI] += step
	case 0xAC, 0xAD:
		c.setReg(RAX, s, c.rdMem(c.R[RSI]+srcBase, s))
		c.R[RSI] += step
	case 0xAE, 0xAF:
		c.sub(c.R[RAX], c.rdMem(c.R[RDI], s), 0, s)
		c.R[RDI] += step
	}
}
