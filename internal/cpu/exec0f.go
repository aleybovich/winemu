package cpu

import (
	"math/bits"
	"time"
)

var tscStart = time.Now()

func (c *CPU) exec0F() {
	op := c.f8()
	sz := c.osz
	switch op {
	case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F: // CMOVcc
		c.decodeModRM(0)
		v := c.rdRM(sz)
		if c.cond(op & 15) {
			c.setReg(c.reg, sz, v)
		} else if sz == 4 {
			c.R[c.reg] &= 0xFFFFFFFF
		}
		return
	case 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F:
		d := int64(int32(c.f32()))
		if c.cond(op & 15) {
			c.RIP += uint64(d)
		}
		return
	case 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F:
		c.decodeModRM(0)
		v := uint64(0)
		if c.cond(op & 15) {
			v = 1
		}
		c.wrRM(1, v)
		return
	case 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF:
		r := op&7 | (c.rex&1)<<3
		switch sz {
		case 8:
			c.R[r] = bits.ReverseBytes64(c.R[r])
		case 4:
			c.R[r] = uint64(bits.ReverseBytes32(uint32(c.R[r])))
		default:
			c.setReg(r, 2, 0) // undefined; zero
		}
		return
	case 0x04: // private hypercall: 0F 04 imm32
		idx := c.f32()
		c.Hyper(c, idx)
	case 0x05:
		c.fault(ExcIllegalInstr, "syscall not supported")
	case 0x01:
		b := c.f8()
		switch b {
		case 0xD0: // XGETBV
			c.R[RAX], c.R[RDX] = 3, 0
		case 0xF9: // RDTSCP
			t := uint64(time.Since(tscStart).Nanoseconds()) * 3
			c.R[RAX], c.R[RDX], c.R[RCX] = t&0xFFFFFFFF, t>>32, 0
		default:
			c.ud()
		}
	case 0x0B:
		c.fault(ExcIllegalInstr, "ud2")
	case 0x0D, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F: // prefetch / hint NOPs / endbr
		c.decodeModRM(0)
	case 0x31: // RDTSC
		t := uint64(time.Since(tscStart).Nanoseconds()) * 3
		c.R[RAX], c.R[RDX] = t&0xFFFFFFFF, t>>32
	case 0xA2:
		c.cpuid()
	case 0xA3, 0xAB, 0xB3, 0xBB: // BT/BTS/BTR/BTC r/m, r
		c.decodeModRM(0)
		off := c.getReg(c.reg, sz)
		c.bitOp(op, off, true)
	case 0xBA:
		c.decodeModRM(1)
		n := uint64(c.f8())
		r := c.reg & 7
		if r < 4 {
			c.ud()
		}
		c.bitOp([]uint8{0xA3, 0xAB, 0xB3, 0xBB}[r-4], n, false)
	case 0xA4, 0xA5, 0xAC, 0xAD: // SHLD/SHRD
		il := 0
		if op == 0xA4 || op == 0xAC {
			il = 1
		}
		c.decodeModRM(il)
		var n uint64
		if il == 1 {
			n = uint64(c.f8())
		} else {
			n = c.R[RCX]
		}
		c.wrRM(sz, c.shiftd(op >= 0xAC, c.rdRM(sz), c.getReg(c.reg, sz), n, sz))
	case 0xAE:
		c.group15()
	case 0xAF:
		c.decodeModRM(0)
		c.setReg(c.reg, sz, c.imul2(c.getReg(c.reg, sz), c.rdRM(sz), sz))
	case 0xB0, 0xB1: // CMPXCHG
		s := sz
		if op == 0xB0 {
			s = 1
		}
		c.decodeModRM(0)
		d := c.rdRM(s)
		a := c.getReg(RAX, s)
		c.sub(a, d, 0, s)
		if a == d {
			c.wrRM(s, c.getReg(c.reg, s))
		} else {
			if c.isMem {
				c.wrRM(s, d) // locked cycle writes back
			}
			c.setReg(RAX, s, d)
		}
	case 0xB6, 0xB7, 0xBE, 0xBF: // MOVZX / MOVSX
		c.decodeModRM(0)
		s := uint8(1)
		if op&1 == 1 {
			s = 2
		}
		v := c.rdRM(s)
		if op >= 0xBE {
			v = signExt(v, s)
		}
		c.setReg(c.reg, sz, v&sizeMask[sz])
	case 0xB8: // POPCNT
		if c.rep != 0xF3 {
			c.ud()
		}
		c.decodeModRM(0)
		v := c.rdRM(sz)
		r := uint64(bits.OnesCount64(v))
		c.Flags &^= arithFlags
		if v == 0 {
			c.Flags |= FlagZF
		}
		c.setReg(c.reg, sz, r)
	case 0xBC, 0xBD: // BSF/BSR, TZCNT/LZCNT
		c.decodeModRM(0)
		v := c.rdRM(sz)
		nb := uint64(sz) * 8
		if c.rep == 0xF3 {
			var r uint64
			if op == 0xBC {
				r = uint64(bits.TrailingZeros64(v))
				if r > nb {
					r = nb
				}
			} else {
				r = uint64(bits.LeadingZeros64(v)) - (64 - nb)
			}
			c.Flags &^= FlagCF | FlagZF
			if v == 0 {
				c.Flags |= FlagCF
			}
			if r == 0 {
				c.Flags |= FlagZF
			}
			c.setReg(c.reg, sz, r)
			return
		}
		if v == 0 {
			c.Flags |= FlagZF
			return
		}
		c.Flags &^= FlagZF
		if op == 0xBC {
			c.setReg(c.reg, sz, uint64(bits.TrailingZeros64(v)))
		} else {
			c.setReg(c.reg, sz, uint64(63-bits.LeadingZeros64(v)))
		}
	case 0xC0, 0xC1: // XADD
		s := sz
		if op == 0xC0 {
			s = 1
		}
		c.decodeModRM(0)
		d := c.rdRM(s)
		r := c.add(d, c.getReg(c.reg, s), 0, s)
		c.setReg(c.reg, s, d)
		c.wrRM(s, r)
	case 0xC3: // MOVNTI
		c.decodeModRM(0)
		c.wrRM(sz, c.getReg(c.reg, sz))
	case 0xC7:
		c.decodeModRM(0)
		switch c.reg & 7 {
		case 1:
			if c.rex&8 != 0 && c.Mem.Shared(c.ea) { // CMPXCHG16B on shared memory
				lo, hi, ok := c.Mem.CAS128(c.ea, c.R[RAX], c.R[RDX], c.R[RBX], c.R[RCX])
				if ok {
					c.Flags |= FlagZF
				} else {
					c.R[RAX], c.R[RDX] = lo, hi
					c.Flags &^= FlagZF
				}
			} else if c.rex&8 != 0 { // CMPXCHG16B
				lo, hi := c.mc.R64(c.Mem, c.ea), c.mc.R64(c.Mem, c.ea+8)
				if lo == c.R[RAX] && hi == c.R[RDX] {
					c.mc.W64(c.Mem, c.ea, c.R[RBX])
					c.mc.W64(c.Mem, c.ea+8, c.R[RCX])
					c.Flags |= FlagZF
				} else {
					c.R[RAX], c.R[RDX] = lo, hi
					c.Flags &^= FlagZF
				}
			} else { // CMPXCHG8B
				v := c.mc.R64(c.Mem, c.ea)
				want := c.R[RDX]<<32 | c.R[RAX]&0xFFFFFFFF
				if v == want {
					c.mc.W64(c.Mem, c.ea, c.R[RCX]<<32|c.R[RBX]&0xFFFFFFFF)
					c.Flags |= FlagZF
				} else {
					c.R[RAX], c.R[RDX] = v&0xFFFFFFFF, v>>32
					c.Flags &^= FlagZF
				}
			}
		case 6, 7: // RDRAND / RDSEED
			c.setReg(c.rm, sz, uint64(time.Now().UnixNano())*0x9E3779B97F4A7C15)
			c.Flags = c.Flags&^arithFlags | FlagCF
		default:
			c.ud()
		}
	default:
		c.sse(op)
	}
}

func (c *CPU) bitOp(op uint8, off uint64, regOff bool) {
	sz := c.osz
	nb := uint64(sz) * 8
	var addr uint64
	var bit uint64
	if c.isMem && regOff {
		so := int64(signExt(off, sz))
		addr = c.ea + uint64((so>>3)&^int64(sz-1))
		bit = uint64(so) & (nb - 1)
	} else {
		addr = c.ea
		bit = off & (nb - 1)
	}
	var v uint64
	if c.isMem {
		v = c.rdMem(addr, sz)
	} else {
		v = c.getReg(c.rm, sz)
	}
	cf := (v >> bit) & 1
	c.Flags = c.Flags&^FlagCF | cf
	var nv uint64
	switch op {
	case 0xA3:
		return
	case 0xAB:
		nv = v | 1<<bit
	case 0xB3:
		nv = v &^ (1 << bit)
	default:
		nv = v ^ 1<<bit
	}
	if c.isMem {
		c.wrMem(addr, sz, nv)
	} else {
		c.setReg(c.rm, sz, nv)
	}
}

func (c *CPU) shiftd(right bool, dst, src, n uint64, sz uint8) uint64 {
	nb := uint64(sz) * 8
	if sz == 8 {
		n &= 63
	} else {
		n &= 31
	}
	if n == 0 {
		return dst
	}
	m := sizeMask[sz]
	dst &= m
	src &= m
	var r uint64
	var cf bool
	if sz == 2 && n > 16 {
		// undefined; approximate
		n &= 15
		if n == 0 {
			return dst
		}
	}
	if !right {
		if sz == 8 {
			r = dst<<n | src>>(64-n)
		} else {
			r = (dst<<n | src<<n>>nb) & m
			if n < nb {
				r = (dst<<n | src>>(nb-n)) & m
			}
		}
		cf = (dst>>(nb-n))&1 != 0
	} else {
		if sz == 8 {
			r = dst>>n | src<<(64-n)
		} else {
			r = (dst>>n | src<<(nb-n)) & m
		}
		cf = (dst>>(n-1))&1 != 0
	}
	of := (r^dst)&signBit[sz] != 0
	c.setFlags(cf, of, false, r, sz)
	return r
}

func (c *CPU) cpuid() {
	leaf := uint32(c.R[RAX])
	sub := uint32(c.R[RCX])
	if c.CPUIDHook != nil {
		if a, b, cc, d, ok := c.CPUIDHook(leaf, sub); ok {
			c.R[RAX], c.R[RBX], c.R[RCX], c.R[RDX] = uint64(a), uint64(b), uint64(cc), uint64(d)
			return
		}
	}
	var a, b, cc, d uint32
	str := func(s string) (uint32, uint32, uint32, uint32) {
		var buf [16]byte
		copy(buf[:], s)
		return le.Uint32(buf[0:]), le.Uint32(buf[4:]), le.Uint32(buf[8:]), le.Uint32(buf[12:])
	}
	switch leaf {
	case 0:
		a = 0xD
		b, d, cc = 0x756e6547, 0x49656e69, 0x6c65746e // GenuineIntel
	case 1:
		a = 0x000906EA // family 6
		b = 0x00010800
		// SSE3 PCLMUL? no; SSSE3, CX16, SSE4.1, SSE4.2, POPCNT
		cc = 1<<0 | 1<<9 | 1<<13 | 1<<19 | 1<<20 | 1<<23
		// FPU TSC CX8 CMOV MMX FXSR SSE SSE2
		d = 1<<0 | 1<<4 | 1<<8 | 1<<15 | 1<<23 | 1<<24 | 1<<25 | 1<<26
	case 7:
		if sub == 0 {
			b = 1 << 9 // ERMS
		}
	case 0x80000000:
		a = 0x80000004
	case 0x80000001:
		cc = 1<<0 | 1<<5 | 1<<8 // LAHF, LZCNT, PREFETCHW
		d = 1<<11 | 1<<20 | 1<<29
	case 0x80000002:
		a, b, cc, d = str("WinEmu Virtual ")
	case 0x80000003:
		a, b, cc, d = str("x86-64 CPU")
	case 0x80000004:
	}
	c.R[RAX], c.R[RBX], c.R[RCX], c.R[RDX] = uint64(a), uint64(b), uint64(cc), uint64(d)
}

func (c *CPU) group15() {
	c.decodeModRM(0)
	r := c.reg & 7
	if !c.isMem {
		// LFENCE / MFENCE / SFENCE and RDFSBASE etc.
		if c.rep == 0xF3 {
			switch r {
			case 0:
				c.setReg(c.rm, c.osz, c.FSBase)
			case 1:
				c.setReg(c.rm, c.osz, c.GSBase)
			default:
				c.ud()
			}
		}
		return
	}
	switch r {
	case 0: // FXSAVE
		c.fxsave(c.ea)
	case 1:
		c.fxrstor(c.ea)
	case 2:
		c.MXCSR = c.mc.R32(c.Mem, c.ea)
	case 3:
		c.mc.W32(c.Mem, c.ea, c.MXCSR)
	case 4: // XSAVE: save legacy region only
		c.fxsave(c.ea)
	case 5: // XRSTOR
		c.fxrstor(c.ea)
	case 6: // XSAVEOPT
		c.fxsave(c.ea)
	case 7: // CLFLUSH
	}
}

func (c *CPU) fxsave(a uint64) {
	m := c.Mem
	m.W16(a, c.FPU.CW)
	m.W16(a+2, c.FPU.status())
	m.W8(a+4, c.FPU.abridgedTag())
	m.W32(a+0x18, c.MXCSR)
	m.W32(a+0x1C, 0xFFFF)
	for i := 0; i < 8; i++ {
		b := f64to80(c.FPU.st(i))
		m.Write(a+0x20+uint64(16*i), b[:])
	}
	for i := 0; i < 16; i++ {
		m.Write(a+0xA0+uint64(16*i), c.X[i][:])
	}
}

func (c *CPU) fxrstor(a uint64) {
	m := c.Mem
	c.FPU.CW = m.R16(a)
	sw := m.R16(a + 2)
	c.FPU.Top = int((sw >> 11) & 7)
	c.FPU.SW = sw &^ (7 << 11)
	tag := m.R8(a + 4)
	c.MXCSR = m.R32(a + 0x18)
	for i := 0; i < 8; i++ {
		var b [10]byte
		m.Read(a+0x20+uint64(16*i), b[:])
		phys := (c.FPU.Top + i) & 7
		c.FPU.Regs[phys] = f80to64(b)
		c.FPU.Valid[phys] = tag&(1<<phys) != 0
	}
	for i := 0; i < 16; i++ {
		m.Read(a+0xA0+uint64(16*i), c.X[i][:])
	}
}
