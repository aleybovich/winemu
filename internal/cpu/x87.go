package cpu

import (
	"math"
)

// FPU is a simplified x87 unit that computes in float64.
type FPU struct {
	Regs  [8]float64
	Valid [8]bool
	Top   int
	CW    uint16
	SW    uint16
}

const (
	swC0 = 1 << 8
	swC1 = 1 << 9
	swC2 = 1 << 10
	swC3 = 1 << 14
)

func (f *FPU) reset() {
	*f = FPU{CW: 0x027F}
}

func (f *FPU) st(i int) float64       { return f.Regs[(f.Top+i)&7] }
func (f *FPU) setSt(i int, v float64) { f.Regs[(f.Top+i)&7] = v; f.Valid[(f.Top+i)&7] = true }
func (f *FPU) push(v float64) {
	f.Top = (f.Top - 1) & 7
	f.Regs[f.Top] = v
	f.Valid[f.Top] = true
}
func (f *FPU) pop() float64 {
	v := f.Regs[f.Top]
	f.Valid[f.Top] = false
	f.Top = (f.Top + 1) & 7
	return v
}
func (f *FPU) status() uint16 { return f.SW&^(7<<11) | uint16(f.Top)<<11 }
func (f *FPU) abridgedTag() uint8 {
	var t uint8
	for i := 0; i < 8; i++ {
		if f.Valid[i] {
			t |= 1 << i
		}
	}
	return t
}

func (f *FPU) round(v float64) float64 {
	switch (f.CW >> 10) & 3 {
	case 0:
		return math.RoundToEven(v)
	case 1:
		return math.Floor(v)
	case 2:
		return math.Ceil(v)
	default:
		return math.Trunc(v)
	}
}

func (f *FPU) compare(a, b float64) {
	f.SW &^= swC0 | swC2 | swC3
	switch {
	case math.IsNaN(a) || math.IsNaN(b):
		f.SW |= swC0 | swC2 | swC3
	case a < b:
		f.SW |= swC0
	case a == b:
		f.SW |= swC3
	}
}

func (c *CPU) fcomi(a, b float64) {
	c.Flags &^= arithFlags
	switch {
	case math.IsNaN(a) || math.IsNaN(b):
		c.Flags |= FlagZF | FlagPF | FlagCF
	case a < b:
		c.Flags |= FlagCF
	case a == b:
		c.Flags |= FlagZF
	}
}

func f64to80(x float64) (b [10]byte) {
	bitsv := math.Float64bits(x)
	sign := uint16(bitsv>>63) << 15
	var e uint16
	var m uint64
	switch {
	case x == 0:
	case math.IsInf(x, 0):
		e, m = 0x7FFF, 1<<63
	case math.IsNaN(x):
		e, m = 0x7FFF, 0xC000000000000000|(bitsv&0xFFFFFFFFFFFFF)<<11
	default:
		fr, ex := math.Frexp(math.Abs(x))
		m = uint64(math.Ldexp(fr, 64))
		e = uint16(ex - 1 + 16383)
	}
	le.PutUint64(b[0:], m)
	le.PutUint16(b[8:], e|sign)
	return
}

func f80to64(b [10]byte) float64 {
	m := le.Uint64(b[0:])
	se := le.Uint16(b[8:])
	e := int(se & 0x7FFF)
	neg := se&0x8000 != 0
	var v float64
	switch {
	case e == 0 && m == 0:
		v = 0
	case e == 0x7FFF:
		if m<<1 == 0 {
			v = math.Inf(1)
		} else {
			v = math.NaN()
		}
	default:
		v = math.Ldexp(float64(m), e-16383-63)
	}
	if neg {
		v = -v
	}
	return v
}

func (c *CPU) fpArith(op uint8, a, b float64) float64 {
	switch op & 7 {
	case 0:
		return a + b
	case 1:
		return a * b
	case 4:
		return a - b
	case 5:
		return b - a
	case 6:
		return a / b
	case 7:
		return b / a
	}
	return a
}

func (c *CPU) fistore(v float64, sz uint8, trunc bool) {
	f := &c.FPU
	var r float64
	if trunc {
		r = math.Trunc(v)
	} else {
		r = f.round(v)
	}
	var out uint64
	var lim float64
	switch sz {
	case 2:
		lim = 32768
	case 4:
		lim = 2147483648
	default:
		lim = 9223372036854775808
	}
	if math.IsNaN(r) || r >= lim || r < -lim {
		out = signBit[sz]
	} else {
		out = uint64(int64(r))
	}
	c.wrMem(c.ea, sz, out)
}

func (c *CPU) x87(op uint8) {
	c.decodeModRM(0)
	f := &c.FPU
	r := c.reg & 7
	i := int(c.rm & 7)
	if c.isMem {
		switch op {
		case 0xD8:
			v := float64(math.Float32frombits(c.mc.R32(c.Mem, c.ea)))
			c.x87memArith(r, v)
		case 0xDC:
			v := math.Float64frombits(c.mc.R64(c.Mem, c.ea))
			c.x87memArith(r, v)
		case 0xDA:
			c.x87memArith(r, float64(int32(c.mc.R32(c.Mem, c.ea))))
		case 0xDE:
			c.x87memArith(r, float64(int16(c.mc.R16(c.Mem, c.ea))))
		case 0xD9:
			switch r {
			case 0:
				f.push(float64(math.Float32frombits(c.mc.R32(c.Mem, c.ea))))
			case 2, 3:
				c.mc.W32(c.Mem, c.ea, math.Float32bits(float32(f.st(0))))
				if r == 3 {
					f.pop()
				}
			case 4: // FLDENV
				f.CW = c.mc.R16(c.Mem, c.ea)
				sw := c.mc.R16(c.Mem, c.ea+4)
				f.Top = int(sw>>11) & 7
				f.SW = sw
			case 5:
				f.CW = c.mc.R16(c.Mem, c.ea)
			case 6: // FNSTENV
				c.Mem.Fill(c.ea, 0, 28)
				c.mc.W16(c.Mem, c.ea, f.CW)
				c.mc.W16(c.Mem, c.ea+4, f.status())
				c.mc.W16(c.Mem, c.ea+8, 0xFFFF)
			case 7:
				c.mc.W16(c.Mem, c.ea, f.CW)
			default:
				c.ud()
			}
		case 0xDB:
			switch r {
			case 0:
				f.push(float64(int32(c.mc.R32(c.Mem, c.ea))))
			case 1:
				c.fistore(f.pop(), 4, true)
			case 2:
				c.fistore(f.st(0), 4, false)
			case 3:
				c.fistore(f.pop(), 4, false)
			case 5:
				var b [10]byte
				c.Mem.Read(c.ea, b[:])
				f.push(f80to64(b))
			case 7:
				b := f64to80(f.pop())
				c.Mem.Write(c.ea, b[:])
			default:
				c.ud()
			}
		case 0xDD:
			switch r {
			case 0:
				f.push(math.Float64frombits(c.mc.R64(c.Mem, c.ea)))
			case 1:
				c.fistore(f.pop(), 8, true)
			case 2, 3:
				c.mc.W64(c.Mem, c.ea, math.Float64bits(f.st(0)))
				if r == 3 {
					f.pop()
				}
			case 4: // FRSTOR
				f.CW = c.mc.R16(c.Mem, c.ea)
				sw := c.mc.R16(c.Mem, c.ea+4)
				f.Top = int(sw>>11) & 7
				for k := 0; k < 8; k++ {
					var b [10]byte
					c.Mem.Read(c.ea+28+uint64(10*k), b[:])
					f.setSt(k, f80to64(b))
				}
			case 6: // FNSAVE
				c.Mem.Fill(c.ea, 0, 28)
				c.mc.W16(c.Mem, c.ea, f.CW)
				c.mc.W16(c.Mem, c.ea+4, f.status())
				for k := 0; k < 8; k++ {
					b := f64to80(f.st(k))
					c.Mem.Write(c.ea+28+uint64(10*k), b[:])
				}
				f.reset()
			case 7:
				c.mc.W16(c.Mem, c.ea, f.status())
			default:
				c.ud()
			}
		case 0xDF:
			switch r {
			case 0:
				f.push(float64(int16(c.mc.R16(c.Mem, c.ea))))
			case 1:
				c.fistore(f.pop(), 2, true)
			case 2:
				c.fistore(f.st(0), 2, false)
			case 3:
				c.fistore(f.pop(), 2, false)
			case 5:
				f.push(float64(int64(c.mc.R64(c.Mem, c.ea))))
			case 7:
				c.fistore(f.pop(), 8, false)
			default:
				c.ud()
			}
		}
		return
	}
	// register forms
	switch op {
	case 0xD8:
		switch r {
		case 2, 3:
			f.compare(f.st(0), f.st(i))
			if r == 3 {
				f.pop()
			}
		default:
			f.setSt(0, c.fpArith(r, f.st(0), f.st(i)))
		}
	case 0xD9:
		modrm := 0xC0 | r<<3 | uint8(i)
		switch {
		case r == 0:
			f.push(f.st(i))
		case r == 1:
			a, b := f.st(0), f.st(i)
			f.setSt(0, b)
			f.setSt(i, a)
		default:
			c.x87d9(modrm)
		}
	case 0xDA:
		switch r {
		case 0:
			if c.Flags&FlagCF != 0 {
				f.setSt(0, f.st(i))
			}
		case 1:
			if c.Flags&FlagZF != 0 {
				f.setSt(0, f.st(i))
			}
		case 2:
			if c.Flags&(FlagCF|FlagZF) != 0 {
				f.setSt(0, f.st(i))
			}
		case 3:
			if c.Flags&FlagPF != 0 {
				f.setSt(0, f.st(i))
			}
		case 5:
			if i == 1 {
				f.compare(f.st(0), f.st(1))
				f.pop()
				f.pop()
			}
		default:
			c.ud()
		}
	case 0xDB:
		switch r {
		case 0:
			if c.Flags&FlagCF == 0 {
				f.setSt(0, f.st(i))
			}
		case 1:
			if c.Flags&FlagZF == 0 {
				f.setSt(0, f.st(i))
			}
		case 2:
			if c.Flags&(FlagCF|FlagZF) == 0 {
				f.setSt(0, f.st(i))
			}
		case 3:
			if c.Flags&FlagPF == 0 {
				f.setSt(0, f.st(i))
			}
		case 4:
			switch i {
			case 2:
				f.SW &= 0x7F00
			case 3:
				f.reset()
			}
		case 5, 6:
			c.fcomi(f.st(0), f.st(i))
		default:
			c.ud()
		}
	case 0xDC:
		switch r {
		case 2, 3:
			f.compare(f.st(0), f.st(i))
			if r == 3 {
				f.pop()
			}
		default:
			f.setSt(i, c.dcArith(r, f.st(i), f.st(0)))
		}
	case 0xDD:
		switch r {
		case 0:
			f.Valid[(f.Top+i)&7] = false
		case 2:
			f.setSt(i, f.st(0))
		case 3:
			f.setSt(i, f.st(0))
			f.pop()
		case 4, 5:
			f.compare(f.st(0), f.st(i))
			if r == 5 {
				f.pop()
			}
		default:
			c.ud()
		}
	case 0xDE:
		switch r {
		case 3:
			f.compare(f.st(0), f.st(1))
			f.pop()
			f.pop()
		case 2:
			f.compare(f.st(0), f.st(i))
			f.pop()
		default:
			f.setSt(i, c.dcArith(r, f.st(i), f.st(0)))
			f.pop()
		}
	case 0xDF:
		switch r {
		case 4:
			if i == 0 {
				c.setReg(RAX, 2, uint64(f.status()))
			}
		case 5, 6:
			c.fcomi(f.st(0), f.st(i))
			f.pop()
		default:
			c.ud()
		}
	}
}

// dcArith handles the DC/DE register forms: dst = st(i), src = st(0).
func (c *CPU) dcArith(r uint8, sti, st0 float64) float64 {
	switch r {
	case 0:
		return sti + st0
	case 1:
		return sti * st0
	case 4: // FSUBR st(i), st0  => st0 - st(i)
		return st0 - sti
	case 5: // FSUB st(i), st0 => st(i) - st0
		return sti - st0
	case 6: // FDIVR => st0 / st(i)
		return st0 / sti
	case 7: // FDIV => st(i) / st0
		return sti / st0
	}
	return sti
}

func (c *CPU) x87memArith(r uint8, v float64) {
	f := &c.FPU
	switch r {
	case 2, 3:
		f.compare(f.st(0), v)
		if r == 3 {
			f.pop()
		}
	default:
		f.setSt(0, c.fpArith(r, f.st(0), v))
	}
}

func (c *CPU) x87d9(modrm uint8) {
	f := &c.FPU
	switch modrm {
	case 0xD0: // FNOP
	case 0xE0:
		f.setSt(0, -f.st(0))
	case 0xE1:
		f.setSt(0, math.Abs(f.st(0)))
	case 0xE4:
		f.compare(f.st(0), 0)
	case 0xE5: // FXAM
		v := f.st(0)
		f.SW &^= swC0 | swC1 | swC2 | swC3
		if math.Signbit(v) {
			f.SW |= swC1
		}
		switch {
		case !f.Valid[f.Top]:
			f.SW |= swC3 | swC0
		case math.IsNaN(v):
			f.SW |= swC0
		case math.IsInf(v, 0):
			f.SW |= swC2 | swC0
		case v == 0:
			f.SW |= swC3
		case math.Abs(v) < 2.2250738585072014e-308:
			f.SW |= swC3 | swC2
		default:
			f.SW |= swC2
		}
	case 0xE8:
		f.push(1)
	case 0xE9:
		f.push(math.Log2(10))
	case 0xEA:
		f.push(math.Log2E)
	case 0xEB:
		f.push(math.Pi)
	case 0xEC:
		f.push(math.Log10(2))
	case 0xED:
		f.push(math.Ln2)
	case 0xEE:
		f.push(0)
	case 0xF0:
		f.setSt(0, math.Exp2(f.st(0))-1)
	case 0xF1: // FYL2X
		v := f.st(1) * math.Log2(f.st(0))
		f.pop()
		f.setSt(0, v)
	case 0xF2:
		f.setSt(0, math.Tan(f.st(0)))
		f.push(1)
	case 0xF3:
		v := math.Atan2(f.st(1), f.st(0))
		f.pop()
		f.setSt(0, v)
	case 0xF4: // FXTRACT
		v := f.st(0)
		fr, e := math.Frexp(v)
		f.setSt(0, float64(e-1))
		f.push(fr * 2)
	case 0xF5, 0xF8: // FPREM1 / FPREM
		a, b := f.st(0), f.st(1)
		r := math.Mod(a, b)
		if modrm == 0xF5 {
			r = math.Remainder(a, b)
		}
		f.setSt(0, r)
		f.SW &^= swC2
	case 0xF6:
		f.Top = (f.Top - 1) & 7
	case 0xF7:
		f.Top = (f.Top + 1) & 7
	case 0xF9:
		v := f.st(1) * math.Log2(f.st(0)+1)
		f.pop()
		f.setSt(0, v)
	case 0xFA:
		f.setSt(0, math.Sqrt(f.st(0)))
	case 0xFB:
		v := f.st(0)
		f.setSt(0, math.Sin(v))
		f.push(math.Cos(v))
	case 0xFC:
		f.setSt(0, f.round(f.st(0)))
	case 0xFD:
		f.setSt(0, math.Ldexp(f.st(0), int(math.Trunc(f.st(1)))))
	case 0xFE:
		f.setSt(0, math.Sin(f.st(0)))
	case 0xFF:
		f.setSt(0, math.Cos(f.st(0)))
	default:
		c.ud()
	}
}
