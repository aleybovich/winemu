package cpu

import (
	"hash/crc32"
	"math"
	"math/bits"
)

// prefix classes for SSE opcodes
const (
	pNone = iota
	p66
	pF3
	pF2
)

func (c *CPU) ssePfx() int {
	switch c.rep {
	case 0xF3:
		return pF3
	case 0xF2:
		return pF2
	}
	if c.p66 {
		return p66
	}
	return pNone
}

// src reads the xmm/m operand; n is the memory width in bytes.
func (c *CPU) src(n int) Vec {
	if !c.isMem {
		return c.X[c.rm]
	}
	var v Vec
	c.Mem.Read(c.ea, v[:n])
	return v
}

func (c *CPU) storeX(v *Vec, n int) {
	if c.isMem {
		c.Mem.Write(c.ea, v[:n])
	} else {
		c.X[c.rm] = *v
	}
}

func mapB(a, b *Vec, f func(x, y uint8) uint8) (r Vec) {
	for i := 0; i < 16; i++ {
		r[i] = f(a[i], b[i])
	}
	return
}
func mapW(a, b *Vec, f func(x, y uint16) uint16) (r Vec) {
	for i := 0; i < 8; i++ {
		r.SetW(i, f(a.W(i), b.W(i)))
	}
	return
}
func mapD(a, b *Vec, f func(x, y uint32) uint32) (r Vec) {
	for i := 0; i < 4; i++ {
		r.SetD(i, f(a.D(i), b.D(i)))
	}
	return
}
func mapQ(a, b *Vec, f func(x, y uint64) uint64) (r Vec) {
	for i := 0; i < 2; i++ {
		r.SetQ(i, f(a.Q(i), b.Q(i)))
	}
	return
}

func satSB(v int32) uint8 {
	if v > 127 {
		return 0x7F
	}
	if v < -128 {
		return 0x80
	}
	return uint8(int8(v))
}
func satUB(v int32) uint8 {
	if v > 255 {
		return 255
	}
	if v < 0 {
		return 0
	}
	return uint8(v)
}
func satSW(v int32) uint16 {
	if v > 32767 {
		return 0x7FFF
	}
	if v < -32768 {
		return 0x8000
	}
	return uint16(int16(v))
}
func satUW(v int32) uint16 {
	if v > 65535 {
		return 0xFFFF
	}
	if v < 0 {
		return 0
	}
	return uint16(v)
}

func bmask(b bool) uint64 {
	if b {
		return ^uint64(0)
	}
	return 0
}

func (c *CPU) rcRound(v float64) float64 {
	switch (c.MXCSR >> 13) & 3 {
	case 0:
		return math.RoundToEven(v)
	case 1:
		return math.Floor(v)
	case 2:
		return math.Ceil(v)
	}
	return math.Trunc(v)
}

func cvtI32(v float64) uint32 {
	if math.IsNaN(v) || v >= 2147483648 || v < -2147483648 {
		return 0x80000000
	}
	return uint32(int32(v))
}
func cvtI64(v float64) uint64 {
	if math.IsNaN(v) || v >= 9223372036854775808 || v < -9223372036854775808 {
		return 0x8000000000000000
	}
	return uint64(int64(v))
}

func fcmp(pred uint8, a, b float64) bool {
	un := math.IsNaN(a) || math.IsNaN(b)
	switch pred & 7 {
	case 0:
		return a == b
	case 1:
		return a < b
	case 2:
		return a <= b
	case 3:
		return un
	case 4:
		return a != b
	case 5:
		return !(a < b)
	case 6:
		return !(a <= b)
	default:
		return !un
	}
}

func fminS(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func fmaxS(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// x86 NaN results, independent of the host FPU: an invalid operation gives
// the default NaN (QNaN floating-point indefinite, sign set); otherwise a NaN
// operand is returned quieted, the first source winning over the second.
const (
	defaultNaN32 = 0xFFC00000
	defaultNaN64 = 0xFFF8000000000000
)

func nanResult64(r, a, b float64) float64 {
	switch {
	case r == r:
		return r
	case a != a:
		return math.Float64frombits(math.Float64bits(a) | 1<<51)
	case b != b:
		return math.Float64frombits(math.Float64bits(b) | 1<<51)
	}
	return math.Float64frombits(defaultNaN64)
}

func nanResult32(r, a, b float32) float32 {
	switch {
	case r == r:
		return r
	case a != a:
		return math.Float32frombits(math.Float32bits(a) | 1<<22)
	case b != b:
		return math.Float32frombits(math.Float32bits(b) | 1<<22)
	}
	return math.Float32frombits(defaultNaN32)
}

func sqrt64(x float64) float64 { return nanResult64(math.Sqrt(x), x, x) }
func sqrt32(x float32) float32 { return nanResult32(float32(math.Sqrt(float64(x))), x, x) }

func farith(op uint8, a, b float64) float64 {
	switch op {
	case 0x58:
		return nanResult64(a+b, a, b)
	case 0x59:
		return nanResult64(a*b, a, b)
	case 0x5C:
		return nanResult64(a-b, a, b)
	case 0x5D:
		return fminS(a, b)
	case 0x5E:
		return nanResult64(a/b, a, b)
	default:
		return fmaxS(a, b)
	}
}

func farith32(op uint8, a, b float32) float32 {
	switch op {
	case 0x58:
		return nanResult32(a+b, a, b)
	case 0x59:
		return nanResult32(a*b, a, b)
	case 0x5C:
		return nanResult32(a-b, a, b)
	case 0x5D:
		if a < b {
			return a
		}
		return b
	case 0x5E:
		return nanResult32(a/b, a, b)
	default:
		if a > b {
			return a
		}
		return b
	}
}

func (c *CPU) sse(op uint8) {
	switch op {
	case 0x38:
		c.sse38()
		return
	case 0x3A:
		c.sse3A()
		return
	}
	pf := c.ssePfx()
	// opcodes with a GPR destination or immediate need special decode
	switch op {
	case 0x70, 0x71, 0x72, 0x73, 0xC2, 0xC4, 0xC5, 0xC6:
		c.decodeModRM(1)
	default:
		c.decodeModRM(0)
	}
	d := &c.X[c.reg&15]
	switch op {
	case 0x10, 0x11:
		switch pf {
		case pNone, p66:
			if op == 0x10 {
				*d = c.src(16)
			} else {
				c.storeX(d, 16)
			}
		case pF3, pF2:
			n := 4
			if pf == pF2 {
				n = 8
			}
			if op == 0x10 {
				if c.isMem {
					*d = c.src(n)
				} else {
					s := c.X[c.rm]
					copy(d[:n], s[:n])
				}
			} else {
				if c.isMem {
					c.Mem.Write(c.ea, d[:n])
				} else {
					copy(c.X[c.rm][:n], d[:n])
				}
			}
		}
	case 0x12:
		switch pf {
		case pNone, p66:
			s := c.src(8)
			if !c.isMem && pf == pNone { // MOVHLPS
				d.SetQ(0, c.X[c.rm].Q(1))
			} else {
				d.SetQ(0, s.Q(0))
			}
		case pF2: // MOVDDUP
			s := c.src(8)
			v := s.Q(0)
			d.SetQ(0, v)
			d.SetQ(1, v)
		case pF3: // MOVSLDUP
			s := c.src(16)
			d.SetD(0, s.D(0))
			d.SetD(1, s.D(0))
			d.SetD(2, s.D(2))
			d.SetD(3, s.D(2))
		}
	case 0x13:
		if c.isMem {
			c.mc.W64(c.Mem, c.ea, d.Q(0))
		}
	case 0x16:
		switch pf {
		case pNone, p66:
			if !c.isMem && pf == pNone { // MOVLHPS
				d.SetQ(1, c.X[c.rm].Q(0))
			} else {
				s := c.src(8)
				d.SetQ(1, s.Q(0))
			}
		case pF3: // MOVSHDUP
			s := c.src(16)
			d.SetD(0, s.D(1))
			d.SetD(1, s.D(1))
			d.SetD(2, s.D(3))
			d.SetD(3, s.D(3))
		default:
			c.ud()
		}
	case 0x17:
		if c.isMem {
			c.mc.W64(c.Mem, c.ea, d.Q(1))
		} else {
			c.X[c.rm].SetQ(0, d.Q(1))
		}
	case 0x14, 0x15:
		s := c.src(16)
		a := *d
		var r Vec
		if pf == p66 {
			h := int(op - 0x14)
			r.SetQ(0, a.Q(h))
			r.SetQ(1, s.Q(h))
		} else {
			h := 2 * int(op-0x14)
			r.SetD(0, a.D(h))
			r.SetD(1, s.D(h))
			r.SetD(2, a.D(h+1))
			r.SetD(3, s.D(h+1))
		}
		*d = r
	case 0x28:
		*d = c.src(16)
	case 0x29, 0x2B:
		c.storeX(d, 16)
	case 0x2A: // CVTSI2SS/SD
		var v float64
		var iv uint64
		if c.rex&8 != 0 {
			iv = c.rdRM(8)
			v = float64(int64(iv))
		} else {
			iv = c.rdRM(4)
			v = float64(int32(iv))
		}
		if pf == pF3 {
			if c.rex&8 != 0 {
				d.SetF32(0, float32(int64(iv)))
			} else {
				d.SetF32(0, float32(int32(iv)))
			}
		} else if pf == pF2 {
			d.SetF64(0, v)
		} else {
			c.ud()
		}
	case 0x2C, 0x2D:
		var v float64
		if pf == pF3 {
			s := c.src(4)
			v = float64(s.F32(0))
		} else if pf == pF2 {
			s := c.src(8)
			v = s.F64(0)
		} else {
			c.ud()
		}
		if op == 0x2C {
			v = math.Trunc(v)
		} else {
			v = c.rcRound(v)
		}
		if c.rex&8 != 0 {
			c.R[c.reg] = cvtI64(v)
		} else {
			c.R[c.reg] = uint64(cvtI32(v))
		}
	case 0x2E, 0x2F:
		var a, b float64
		if pf == p66 {
			s := c.src(8)
			a, b = d.F64(0), s.F64(0)
		} else {
			s := c.src(4)
			a, b = float64(d.F32(0)), float64(s.F32(0))
		}
		c.fcomi(a, b)
	case 0x50:
		s := c.X[c.rm]
		var m uint64
		if pf == p66 {
			m = s.Q(0)>>63 | (s.Q(1)>>63)<<1
		} else {
			for i := 0; i < 4; i++ {
				m |= uint64(s.D(i)>>31) << i
			}
		}
		c.R[c.reg] = m
	case 0x51, 0x52, 0x53:
		fn64 := sqrt64
		fn32 := sqrt32
		if op == 0x52 {
			fn32 = func(x float32) float32 { return nanResult32(float32(1/math.Sqrt(float64(x))), x, x) }
		} else if op == 0x53 {
			fn32 = func(x float32) float32 { return nanResult32(1/x, x, x) }
		}
		switch pf {
		case pNone:
			s := c.src(16)
			for i := 0; i < 4; i++ {
				d.SetF32(i, fn32(s.F32(i)))
			}
		case p66:
			s := c.src(16)
			for i := 0; i < 2; i++ {
				d.SetF64(i, fn64(s.F64(i)))
			}
		case pF3:
			s := c.src(4)
			d.SetF32(0, fn32(s.F32(0)))
		case pF2:
			s := c.src(8)
			d.SetF64(0, fn64(s.F64(0)))
		}
	case 0x54, 0x55, 0x56, 0x57, 0xDB, 0xDF, 0xEB, 0xEF:
		s := c.src(16)
		a := *d
		switch op {
		case 0x54, 0xDB:
			*d = mapQ(&a, &s, func(x, y uint64) uint64 { return x & y })
		case 0x55, 0xDF:
			*d = mapQ(&a, &s, func(x, y uint64) uint64 { return ^x & y })
		case 0x56, 0xEB:
			*d = mapQ(&a, &s, func(x, y uint64) uint64 { return x | y })
		default:
			*d = mapQ(&a, &s, func(x, y uint64) uint64 { return x ^ y })
		}
	case 0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F:
		switch pf {
		case pNone:
			s := c.src(16)
			for i := 0; i < 4; i++ {
				d.SetF32(i, farith32(op, d.F32(i), s.F32(i)))
			}
		case p66:
			s := c.src(16)
			for i := 0; i < 2; i++ {
				d.SetF64(i, farith(op, d.F64(i), s.F64(i)))
			}
		case pF3:
			s := c.src(4)
			d.SetF32(0, farith32(op, d.F32(0), s.F32(0)))
		case pF2:
			s := c.src(8)
			d.SetF64(0, farith(op, d.F64(0), s.F64(0)))
		}
	case 0x5A:
		switch pf {
		case pNone: // CVTPS2PD
			s := c.src(8)
			a, b := s.F32(0), s.F32(1)
			d.SetF64(0, float64(a))
			d.SetF64(1, float64(b))
		case p66: // CVTPD2PS
			s := c.src(16)
			a, b := s.F64(0), s.F64(1)
			d.SetF32(0, float32(a))
			d.SetF32(1, float32(b))
			d.SetQ(1, 0)
		case pF3:
			s := c.src(4)
			d.SetF64(0, float64(s.F32(0)))
		case pF2:
			s := c.src(8)
			d.SetF32(0, float32(s.F64(0)))
		}
	case 0x5B:
		s := c.src(16)
		for i := 0; i < 4; i++ {
			switch pf {
			case pNone:
				d.SetF32(i, float32(int32(s.D(i))))
			case p66:
				d.SetD(i, cvtI32(c.rcRound(float64(s.F32(i)))))
			case pF3:
				d.SetD(i, cvtI32(math.Trunc(float64(s.F32(i)))))
			default:
				c.ud()
			}
		}
	case 0x6E: // MOVD/MOVQ xmm, r/m
		if pf != p66 {
			c.ud()
		}
		var v Vec
		if c.rex&8 != 0 {
			v.SetQ(0, c.rdRM(8))
		} else {
			v.SetD(0, uint32(c.rdRM(4)))
		}
		*d = v
	case 0x6F:
		if pf == pNone {
			c.ud()
		}
		*d = c.src(16)
	case 0x7E:
		switch pf {
		case p66:
			if c.rex&8 != 0 {
				c.wrRM(8, d.Q(0))
			} else {
				c.wrRM(4, uint64(d.D(0)))
			}
		case pF3:
			s := c.src(8)
			var v Vec
			v.SetQ(0, s.Q(0))
			*d = v
		default:
			c.ud()
		}
	case 0x7F:
		if pf == pNone {
			c.ud()
		}
		c.storeX(d, 16)
	case 0xD6:
		if c.isMem {
			c.mc.W64(c.Mem, c.ea, d.Q(0))
		} else {
			var v Vec
			v.SetQ(0, d.Q(0))
			c.X[c.rm] = v
		}
	case 0xE7:
		c.storeX(d, 16)
	case 0xF0: // LDDQU
		*d = c.src(16)
	case 0x77: // EMMS
	case 0x7C, 0x7D: // HADD/HSUB
		s := c.src(16)
		a := *d
		ar := uint8(0x58) // farith op: ADD, or SUB for HSUB
		if op == 0x7D {
			ar = 0x5C
		}
		if pf == p66 {
			f := func(x, y float64) float64 { return farith(ar, x, y) }
			d.SetF64(0, f(a.F64(0), a.F64(1)))
			d.SetF64(1, f(s.F64(0), s.F64(1)))
		} else {
			f := func(x, y float32) float32 { return farith32(ar, x, y) }
			d.SetF32(0, f(a.F32(0), a.F32(1)))
			d.SetF32(1, f(a.F32(2), a.F32(3)))
			d.SetF32(2, f(s.F32(0), s.F32(1)))
			d.SetF32(3, f(s.F32(2), s.F32(3)))
		}
	case 0xD0: // ADDSUB
		s := c.src(16)
		if pf == p66 {
			d.SetF64(0, farith(0x5C, d.F64(0), s.F64(0)))
			d.SetF64(1, farith(0x58, d.F64(1), s.F64(1)))
		} else {
			for i := 0; i < 4; i++ {
				if i&1 == 0 {
					d.SetF32(i, farith32(0x5C, d.F32(i), s.F32(i)))
				} else {
					d.SetF32(i, farith32(0x58, d.F32(i), s.F32(i)))
				}
			}
		}
	case 0xC2:
		var s Vec
		switch pf {
		case pNone, p66:
			s = c.src(16)
		case pF3:
			s = c.src(4)
		default:
			s = c.src(8)
		}
		pred := c.f8()
		switch pf {
		case pNone:
			for i := 0; i < 4; i++ {
				d.SetD(i, uint32(bmask(fcmp(pred, float64(d.F32(i)), float64(s.F32(i))))))
			}
		case p66:
			for i := 0; i < 2; i++ {
				d.SetQ(i, bmask(fcmp(pred, d.F64(i), s.F64(i))))
			}
		case pF3:
			d.SetD(0, uint32(bmask(fcmp(pred, float64(d.F32(0)), float64(s.F32(0))))))
		default:
			d.SetQ(0, bmask(fcmp(pred, d.F64(0), s.F64(0))))
		}
	case 0xC4: // PINSRW
		v := c.rdRM(2)
		i := int(c.f8() & 7)
		d.SetW(i, uint16(v))
	case 0xC5: // PEXTRW r32, xmm
		i := int(c.f8() & 7)
		c.R[c.reg] = uint64(c.X[c.rm].W(i))
	case 0xC6:
		s := c.src(16)
		imm := c.f8()
		a := *d
		var r Vec
		if pf == p66 {
			r.SetQ(0, a.Q(int(imm&1)))
			r.SetQ(1, s.Q(int(imm>>1)&1))
		} else {
			r.SetD(0, a.D(int(imm&3)))
			r.SetD(1, a.D(int(imm>>2)&3))
			r.SetD(2, s.D(int(imm>>4)&3))
			r.SetD(3, s.D(int(imm>>6)&3))
		}
		*d = r
	case 0x70:
		s := c.src(16)
		imm := c.f8()
		var r Vec
		switch pf {
		case p66:
			for i := 0; i < 4; i++ {
				r.SetD(i, s.D(int(imm>>(2*i))&3))
			}
		case pF3:
			r.SetQ(0, s.Q(0))
			for i := 0; i < 4; i++ {
				r.SetW(4+i, s.W(4+int(imm>>(2*i))&3))
			}
		case pF2:
			r.SetQ(1, s.Q(1))
			for i := 0; i < 4; i++ {
				r.SetW(i, s.W(int(imm>>(2*i))&3))
			}
		default:
			c.ud()
		}
		*d = r
	case 0x71, 0x72, 0x73: // shift by immediate (dest is rm)
		if pf != p66 {
			c.ud()
		}
		n := uint64(c.f8())
		x := &c.X[c.rm]
		w := map[uint8]int{0x71: 16, 0x72: 32, 0x73: 64}[op]
		switch c.reg & 7 {
		case 2:
			*x = vshr(x, w, n, false)
		case 4:
			if w == 64 {
				c.ud()
			}
			*x = vshr(x, w, n, true)
		case 6:
			*x = vshl(x, w, n)
		case 3: // PSRLDQ
			*x = byteShiftR(x, int(n))
		case 7: // PSLLDQ
			*x = byteShiftL(x, int(n))
		default:
			c.ud()
		}
	default:
		if op >= 0x60 && op <= 0xFE {
			if pf != p66 && op != 0xE6 {
				c.ud()
			}
			s := c.src(16)
			a := *d
			*d = c.sseInt(op, &a, &s)
			return
		}
		c.ud()
	}
}

func vshl(x *Vec, w int, n uint64) (r Vec) {
	if n >= uint64(w) {
		return
	}
	switch w {
	case 16:
		for i := 0; i < 8; i++ {
			r.SetW(i, x.W(i)<<n)
		}
	case 32:
		for i := 0; i < 4; i++ {
			r.SetD(i, x.D(i)<<n)
		}
	default:
		for i := 0; i < 2; i++ {
			r.SetQ(i, x.Q(i)<<n)
		}
	}
	return
}

func vshr(x *Vec, w int, n uint64, arith bool) (r Vec) {
	if n >= uint64(w) {
		if !arith {
			return
		}
		n = uint64(w - 1)
	}
	switch w {
	case 16:
		for i := 0; i < 8; i++ {
			if arith {
				r.SetW(i, uint16(int16(x.W(i))>>n))
			} else {
				r.SetW(i, x.W(i)>>n)
			}
		}
	case 32:
		for i := 0; i < 4; i++ {
			if arith {
				r.SetD(i, uint32(int32(x.D(i))>>n))
			} else {
				r.SetD(i, x.D(i)>>n)
			}
		}
	default:
		for i := 0; i < 2; i++ {
			if arith {
				r.SetQ(i, uint64(int64(x.Q(i))>>n))
			} else {
				r.SetQ(i, x.Q(i)>>n)
			}
		}
	}
	return
}

func byteShiftR(x *Vec, n int) (r Vec) {
	if n > 16 {
		n = 16
	}
	copy(r[:], x[n:])
	return
}

func byteShiftL(x *Vec, n int) (r Vec) {
	if n > 16 {
		n = 16
	}
	copy(r[n:], x[:16-n])
	return
}

func (c *CPU) sseInt(op uint8, a, s *Vec) Vec {
	switch op {
	case 0x60, 0x61, 0x62, 0x6C, 0x68, 0x69, 0x6A, 0x6D:
		hi := op >= 0x68
		var r Vec
		var w int
		switch op {
		case 0x60, 0x68:
			w = 1
		case 0x61, 0x69:
			w = 2
		case 0x62, 0x6A:
			w = 4
		default:
			w = 8
			hi = op == 0x6D
		}
		off := 0
		if hi {
			off = 8
		}
		for i := 0; i < 8/w; i++ {
			copy(r[2*i*w:], a[off+i*w:off+i*w+w])
			copy(r[2*i*w+w:], s[off+i*w:off+i*w+w])
		}
		return r
	case 0x63: // PACKSSWB
		var r Vec
		for i := 0; i < 8; i++ {
			r[i] = satSB(int32(int16(a.W(i))))
			r[8+i] = satSB(int32(int16(s.W(i))))
		}
		return r
	case 0x67: // PACKUSWB
		var r Vec
		for i := 0; i < 8; i++ {
			r[i] = satUB(int32(int16(a.W(i))))
			r[8+i] = satUB(int32(int16(s.W(i))))
		}
		return r
	case 0x6B: // PACKSSDW
		var r Vec
		for i := 0; i < 4; i++ {
			r.SetW(i, satSW(int32(a.D(i))))
			r.SetW(4+i, satSW(int32(s.D(i))))
		}
		return r
	case 0x64:
		return mapB(a, s, func(x, y uint8) uint8 { return uint8(bmask(int8(x) > int8(y))) })
	case 0x65:
		return mapW(a, s, func(x, y uint16) uint16 { return uint16(bmask(int16(x) > int16(y))) })
	case 0x66:
		return mapD(a, s, func(x, y uint32) uint32 { return uint32(bmask(int32(x) > int32(y))) })
	case 0x74:
		return mapB(a, s, func(x, y uint8) uint8 { return uint8(bmask(x == y)) })
	case 0x75:
		return mapW(a, s, func(x, y uint16) uint16 { return uint16(bmask(x == y)) })
	case 0x76:
		return mapD(a, s, func(x, y uint32) uint32 { return uint32(bmask(x == y)) })
	case 0xD1, 0xD2, 0xD3, 0xE1, 0xE2, 0xF1, 0xF2, 0xF3:
		n := s.Q(0)
		switch op {
		case 0xD1:
			return vshr(a, 16, n, false)
		case 0xD2:
			return vshr(a, 32, n, false)
		case 0xD3:
			return vshr(a, 64, n, false)
		case 0xE1:
			return vshr(a, 16, n, true)
		case 0xE2:
			return vshr(a, 32, n, true)
		case 0xF1:
			return vshl(a, 16, n)
		case 0xF2:
			return vshl(a, 32, n)
		default:
			return vshl(a, 64, n)
		}
	case 0xD4:
		return mapQ(a, s, func(x, y uint64) uint64 { return x + y })
	case 0xFB:
		return mapQ(a, s, func(x, y uint64) uint64 { return x - y })
	case 0xD5:
		return mapW(a, s, func(x, y uint16) uint16 { return x * y })
	case 0xE5:
		return mapW(a, s, func(x, y uint16) uint16 { return uint16((int32(int16(x)) * int32(int16(y))) >> 16) })
	case 0xE4:
		return mapW(a, s, func(x, y uint16) uint16 { return uint16((uint32(x) * uint32(y)) >> 16) })
	case 0xD7: // PMOVMSKB
		var m uint64
		for i := 0; i < 16; i++ {
			m |= uint64(s[i]>>7) << i
		}
		c.R[c.reg] = m
		return *a
	case 0xD8:
		return mapB(a, s, func(x, y uint8) uint8 { return satUB(int32(x) - int32(y)) })
	case 0xD9:
		return mapW(a, s, func(x, y uint16) uint16 { return satUW(int32(x) - int32(y)) })
	case 0xDC:
		return mapB(a, s, func(x, y uint8) uint8 { return satUB(int32(x) + int32(y)) })
	case 0xDD:
		return mapW(a, s, func(x, y uint16) uint16 { return satUW(int32(x) + int32(y)) })
	case 0xDA:
		return mapB(a, s, func(x, y uint8) uint8 { return min(x, y) })
	case 0xDE:
		return mapB(a, s, func(x, y uint8) uint8 { return max(x, y) })
	case 0xEA:
		return mapW(a, s, func(x, y uint16) uint16 { return uint16(min(int16(x), int16(y))) })
	case 0xEE:
		return mapW(a, s, func(x, y uint16) uint16 { return uint16(max(int16(x), int16(y))) })
	case 0xE0:
		return mapB(a, s, func(x, y uint8) uint8 { return uint8((uint16(x) + uint16(y) + 1) >> 1) })
	case 0xE3:
		return mapW(a, s, func(x, y uint16) uint16 { return uint16((uint32(x) + uint32(y) + 1) >> 1) })
	case 0xE6:
		var r Vec
		switch c.ssePfx() {
		case p66: // CVTTPD2DQ
			r.SetD(0, cvtI32(math.Trunc(s.F64(0))))
			r.SetD(1, cvtI32(math.Trunc(s.F64(1))))
		case pF2: // CVTPD2DQ
			r.SetD(0, cvtI32(c.rcRound(s.F64(0))))
			r.SetD(1, cvtI32(c.rcRound(s.F64(1))))
		case pF3: // CVTDQ2PD
			r.SetF64(0, float64(int32(s.D(0))))
			r.SetF64(1, float64(int32(s.D(1))))
		}
		return r
	case 0xE8:
		return mapB(a, s, func(x, y uint8) uint8 { return satSB(int32(int8(x)) - int32(int8(y))) })
	case 0xE9:
		return mapW(a, s, func(x, y uint16) uint16 { return satSW(int32(int16(x)) - int32(int16(y))) })
	case 0xEC:
		return mapB(a, s, func(x, y uint8) uint8 { return satSB(int32(int8(x)) + int32(int8(y))) })
	case 0xED:
		return mapW(a, s, func(x, y uint16) uint16 { return satSW(int32(int16(x)) + int32(int16(y))) })
	case 0xF4: // PMULUDQ
		var r Vec
		r.SetQ(0, uint64(a.D(0))*uint64(s.D(0)))
		r.SetQ(1, uint64(a.D(2))*uint64(s.D(2)))
		return r
	case 0xF5: // PMADDWD
		var r Vec
		for i := 0; i < 4; i++ {
			v := int32(int16(a.W(2*i)))*int32(int16(s.W(2*i))) + int32(int16(a.W(2*i+1)))*int32(int16(s.W(2*i+1)))
			r.SetD(i, uint32(v))
		}
		return r
	case 0xF6: // PSADBW
		var r Vec
		for h := 0; h < 2; h++ {
			var sum uint64
			for i := 0; i < 8; i++ {
				x, y := int(a[8*h+i]), int(s[8*h+i])
				if x > y {
					sum += uint64(x - y)
				} else {
					sum += uint64(y - x)
				}
			}
			r.SetQ(h, sum)
		}
		return r
	case 0xF7: // MASKMOVDQU
		for i := 0; i < 16; i++ {
			if s[i]&0x80 != 0 {
				c.mc.W8(c.Mem, c.R[RDI]+c.segB+uint64(i), a[i])
			}
		}
		return *a
	case 0xF8:
		return mapB(a, s, func(x, y uint8) uint8 { return x - y })
	case 0xF9:
		return mapW(a, s, func(x, y uint16) uint16 { return x - y })
	case 0xFA:
		return mapD(a, s, func(x, y uint32) uint32 { return x - y })
	case 0xFC:
		return mapB(a, s, func(x, y uint8) uint8 { return x + y })
	case 0xFD:
		return mapW(a, s, func(x, y uint16) uint16 { return x + y })
	case 0xFE:
		return mapD(a, s, func(x, y uint32) uint32 { return x + y })
	}
	c.ud()
	return *a
}

// ---------------------------------------------------------------------------
// 0F 38 map (SSSE3 / SSE4.1 / SSE4.2 / MOVBE / CRC32)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func (c *CPU) sse38() {
	op := c.f8()
	if op == 0xF0 || op == 0xF1 {
		c.decodeModRM(0)
		if c.rep == 0xF2 { // CRC32
			sz := uint8(1)
			if op == 0xF1 {
				sz = c.osz
			}
			v := c.rdRM(sz)
			var buf [8]byte
			le.PutUint64(buf[:], v)
			acc := uint32(c.R[c.reg])
			r := ^crc32.Update(^acc, castagnoli, buf[:sz])
			c.R[c.reg] = uint64(r)
			return
		}
		// MOVBE
		sz := c.osz
		if op == 0xF0 {
			v := c.rdMem(c.ea, sz)
			c.setReg(c.reg, sz, bswap(v, sz))
		} else {
			c.wrMem(c.ea, sz, bswap(c.getReg(c.reg, sz), sz))
		}
		return
	}
	if !c.p66 {
		c.ud()
	}
	c.decodeModRM(0)
	d := &c.X[c.reg]
	a := *d
	var s Vec
	switch op {
	case 0x20, 0x23, 0x25, 0x30, 0x33, 0x35:
		s = c.src(8)
	case 0x21, 0x24, 0x31, 0x34:
		s = c.src(4)
	case 0x22, 0x32:
		s = c.src(2)
	default:
		s = c.src(16)
	}
	var r Vec
	switch op {
	case 0x00: // PSHUFB
		for i := 0; i < 16; i++ {
			if s[i]&0x80 == 0 {
				r[i] = a[s[i]&15]
			}
		}
	case 0x01, 0x02, 0x03, 0x05, 0x06, 0x07: // PHADD/PHSUB
		hor := func(x *Vec, i int) uint32 { return 0 }
		_ = hor
		switch op {
		case 0x01, 0x03, 0x05, 0x07:
			f := func(x, y uint16) uint16 {
				switch op {
				case 0x01:
					return x + y
				case 0x05:
					return x - y
				case 0x03:
					return satSW(int32(int16(x)) + int32(int16(y)))
				default:
					return satSW(int32(int16(x)) - int32(int16(y)))
				}
			}
			for i := 0; i < 4; i++ {
				r.SetW(i, f(a.W(2*i), a.W(2*i+1)))
				r.SetW(4+i, f(s.W(2*i), s.W(2*i+1)))
			}
		default:
			f := func(x, y uint32) uint32 {
				if op == 0x02 {
					return x + y
				}
				return x - y
			}
			for i := 0; i < 2; i++ {
				r.SetD(i, f(a.D(2*i), a.D(2*i+1)))
				r.SetD(2+i, f(s.D(2*i), s.D(2*i+1)))
			}
		}
	case 0x04: // PMADDUBSW
		for i := 0; i < 8; i++ {
			v := int32(a[2*i])*int32(int8(s[2*i])) + int32(a[2*i+1])*int32(int8(s[2*i+1]))
			r.SetW(i, satSW(v))
		}
	case 0x08, 0x09, 0x0A: // PSIGN
		switch op {
		case 0x08:
			r = mapB(&a, &s, func(x, y uint8) uint8 {
				switch {
				case int8(y) < 0:
					return -x
				case y == 0:
					return 0
				}
				return x
			})
		case 0x09:
			r = mapW(&a, &s, func(x, y uint16) uint16 {
				switch {
				case int16(y) < 0:
					return -x
				case y == 0:
					return 0
				}
				return x
			})
		default:
			r = mapD(&a, &s, func(x, y uint32) uint32 {
				switch {
				case int32(y) < 0:
					return -x
				case y == 0:
					return 0
				}
				return x
			})
		}
	case 0x0B: // PMULHRSW
		r = mapW(&a, &s, func(x, y uint16) uint16 {
			return uint16((((int32(int16(x)) * int32(int16(y))) >> 14) + 1) >> 1)
		})
	case 0x10, 0x14, 0x15: // PBLENDVB / BLENDVPS / BLENDVPD (mask = XMM0)
		m := c.X[0]
		r = a
		switch op {
		case 0x10:
			for i := 0; i < 16; i++ {
				if m[i]&0x80 != 0 {
					r[i] = s[i]
				}
			}
		case 0x14:
			for i := 0; i < 4; i++ {
				if m.D(i)>>31 != 0 {
					r.SetD(i, s.D(i))
				}
			}
		default:
			for i := 0; i < 2; i++ {
				if m.Q(i)>>63 != 0 {
					r.SetQ(i, s.Q(i))
				}
			}
		}
	case 0x17: // PTEST
		c.Flags &^= arithFlags
		if a.Q(0)&s.Q(0) == 0 && a.Q(1)&s.Q(1) == 0 {
			c.Flags |= FlagZF
		}
		if ^a.Q(0)&s.Q(0) == 0 && ^a.Q(1)&s.Q(1) == 0 {
			c.Flags |= FlagCF
		}
		return
	case 0x1C:
		r = mapB(&a, &s, func(x, y uint8) uint8 {
			if int8(y) < 0 {
				return -y
			}
			return y
		})
	case 0x1D:
		r = mapW(&a, &s, func(x, y uint16) uint16 {
			if int16(y) < 0 {
				return -y
			}
			return y
		})
	case 0x1E:
		r = mapD(&a, &s, func(x, y uint32) uint32 {
			if int32(y) < 0 {
				return -y
			}
			return y
		})
	case 0x20: // PMOVSXBW
		for i := 0; i < 8; i++ {
			r.SetW(i, uint16(int16(int8(s[i]))))
		}
	case 0x21:
		for i := 0; i < 4; i++ {
			r.SetD(i, uint32(int32(int8(s[i]))))
		}
	case 0x22:
		for i := 0; i < 2; i++ {
			r.SetQ(i, uint64(int64(int8(s[i]))))
		}
	case 0x23:
		for i := 0; i < 4; i++ {
			r.SetD(i, uint32(int32(int16(s.W(i)))))
		}
	case 0x24:
		for i := 0; i < 2; i++ {
			r.SetQ(i, uint64(int64(int16(s.W(i)))))
		}
	case 0x25:
		for i := 0; i < 2; i++ {
			r.SetQ(i, uint64(int64(int32(s.D(i)))))
		}
	case 0x30:
		for i := 0; i < 8; i++ {
			r.SetW(i, uint16(s[i]))
		}
	case 0x31:
		for i := 0; i < 4; i++ {
			r.SetD(i, uint32(s[i]))
		}
	case 0x32:
		for i := 0; i < 2; i++ {
			r.SetQ(i, uint64(s[i]))
		}
	case 0x33:
		for i := 0; i < 4; i++ {
			r.SetD(i, uint32(s.W(i)))
		}
	case 0x34:
		for i := 0; i < 2; i++ {
			r.SetQ(i, uint64(s.W(i)))
		}
	case 0x35:
		for i := 0; i < 2; i++ {
			r.SetQ(i, uint64(s.D(i)))
		}
	case 0x28: // PMULDQ
		r.SetQ(0, uint64(int64(int32(a.D(0)))*int64(int32(s.D(0)))))
		r.SetQ(1, uint64(int64(int32(a.D(2)))*int64(int32(s.D(2)))))
	case 0x29:
		r = mapQ(&a, &s, func(x, y uint64) uint64 { return bmask(x == y) })
	case 0x37:
		r = mapQ(&a, &s, func(x, y uint64) uint64 { return bmask(int64(x) > int64(y)) })
	case 0x2A: // MOVNTDQA
		r = s
	case 0x2B: // PACKUSDW
		for i := 0; i < 4; i++ {
			r.SetW(i, satUW(int32(a.D(i))))
			r.SetW(4+i, satUW(int32(s.D(i))))
		}
	case 0x38:
		r = mapB(&a, &s, func(x, y uint8) uint8 { return uint8(min(int8(x), int8(y))) })
	case 0x39:
		r = mapD(&a, &s, func(x, y uint32) uint32 { return uint32(min(int32(x), int32(y))) })
	case 0x3A:
		r = mapW(&a, &s, func(x, y uint16) uint16 { return min(x, y) })
	case 0x3B:
		r = mapD(&a, &s, func(x, y uint32) uint32 { return min(x, y) })
	case 0x3C:
		r = mapB(&a, &s, func(x, y uint8) uint8 { return uint8(max(int8(x), int8(y))) })
	case 0x3D:
		r = mapD(&a, &s, func(x, y uint32) uint32 { return uint32(max(int32(x), int32(y))) })
	case 0x3E:
		r = mapW(&a, &s, func(x, y uint16) uint16 { return max(x, y) })
	case 0x3F:
		r = mapD(&a, &s, func(x, y uint32) uint32 { return max(x, y) })
	case 0x40:
		r = mapD(&a, &s, func(x, y uint32) uint32 { return x * y })
	case 0x41: // PHMINPOSUW
		mi, mv := 0, s.W(0)
		for i := 1; i < 8; i++ {
			if s.W(i) < mv {
				mi, mv = i, s.W(i)
			}
		}
		r.SetW(0, mv)
		r.SetW(1, uint16(mi))
	default:
		c.ud()
	}
	*d = r
}

func bswap(v uint64, sz uint8) uint64 {
	switch sz {
	case 2:
		return uint64(bits.ReverseBytes16(uint16(v)))
	case 4:
		return uint64(bits.ReverseBytes32(uint32(v)))
	}
	return bits.ReverseBytes64(v)
}

// ---------------------------------------------------------------------------
// 0F 3A map

func (c *CPU) sse3A() {
	op := c.f8()
	if !c.p66 {
		c.ud()
	}
	c.decodeModRM(1)
	d := &c.X[c.reg]
	switch op {
	case 0x14, 0x15, 0x16, 0x17: // PEXTRB/W/D/Q, EXTRACTPS
		imm := int(c.f8())
		var v uint64
		var sz uint8
		switch op {
		case 0x14:
			v, sz = uint64(d[imm&15]), 1
		case 0x15:
			v, sz = uint64(d.W(imm&7)), 2
		case 0x16:
			if c.rex&8 != 0 {
				v, sz = d.Q(imm&1), 8
			} else {
				v, sz = uint64(d.D(imm&3)), 4
			}
		default:
			v, sz = uint64(d.D(imm&3)), 4
		}
		if c.isMem {
			c.wrMem(c.ea, sz, v)
		} else {
			c.R[c.rm] = v
		}
		return
	case 0x20: // PINSRB
		v := c.rdRM(1)
		imm := int(c.f8())
		d[imm&15] = uint8(v)
		return
	case 0x22:
		if c.rex&8 != 0 {
			v := c.rdRM(8)
			d.SetQ(int(c.f8())&1, v)
		} else {
			v := c.rdRM(4)
			d.SetD(int(c.f8())&3, uint32(v))
		}
		return
	case 0x21: // INSERTPS
		var sv uint32
		var imm uint8
		if c.isMem {
			sv = c.mc.R32(c.Mem, c.ea)
			imm = c.f8()
		} else {
			imm = c.f8()
			sv = c.X[c.rm].D(int(imm>>6) & 3)
		}
		d.SetD(int(imm>>4)&3, sv)
		for i := 0; i < 4; i++ {
			if imm&(1<<i) != 0 {
				d.SetD(i, 0)
			}
		}
		return
	}
	var s Vec
	switch op {
	case 0x0A:
		s = c.src(4)
	case 0x0B:
		s = c.src(8)
	default:
		s = c.src(16)
	}
	imm := c.f8()
	a := *d
	var r Vec
	switch op {
	case 0x08, 0x09, 0x0A, 0x0B: // ROUNDPS/PD/SS/SD
		rnd := func(v float64) float64 {
			mode := imm & 3
			if imm&4 != 0 {
				mode = uint8(c.MXCSR>>13) & 3
			}
			switch mode {
			case 0:
				return math.RoundToEven(v)
			case 1:
				return math.Floor(v)
			case 2:
				return math.Ceil(v)
			}
			return math.Trunc(v)
		}
		r = a
		switch op {
		case 0x08:
			for i := 0; i < 4; i++ {
				r.SetF32(i, float32(rnd(float64(s.F32(i)))))
			}
		case 0x09:
			for i := 0; i < 2; i++ {
				r.SetF64(i, rnd(s.F64(i)))
			}
		case 0x0A:
			r.SetF32(0, float32(rnd(float64(s.F32(0)))))
		default:
			r.SetF64(0, rnd(s.F64(0)))
		}
	case 0x0C:
		r = a
		for i := 0; i < 4; i++ {
			if imm&(1<<i) != 0 {
				r.SetD(i, s.D(i))
			}
		}
	case 0x0D:
		r = a
		for i := 0; i < 2; i++ {
			if imm&(1<<i) != 0 {
				r.SetQ(i, s.Q(i))
			}
		}
	case 0x0E:
		r = a
		for i := 0; i < 8; i++ {
			if imm&(1<<i) != 0 {
				r.SetW(i, s.W(i))
			}
		}
	case 0x0F: // PALIGNR
		var buf [32]byte
		copy(buf[:16], s[:])
		copy(buf[16:], a[:])
		n := int(imm)
		for i := 0; i < 16; i++ {
			if n+i < 32 {
				r[i] = buf[n+i]
			}
		}
	case 0x40: // DPPS
		var sum float32
		for i := 0; i < 4; i++ {
			if imm&(0x10<<i) != 0 {
				sum += float32(a.F32(i) * s.F32(i))
			}
		}
		for i := 0; i < 4; i++ {
			if imm&(1<<i) != 0 {
				r.SetF32(i, sum)
			}
		}
	case 0x41: // DPPD
		var sum float64
		for i := 0; i < 2; i++ {
			if imm&(0x10<<i) != 0 {
				sum += float64(a.F64(i) * s.F64(i))
			}
		}
		for i := 0; i < 2; i++ {
			if imm&(1<<i) != 0 {
				r.SetF64(i, sum)
			}
		}
	case 0x42: // MPSADBW
		ao := int(imm>>2&1) * 4
		bo := int(imm&3) * 4
		for i := 0; i < 8; i++ {
			var sum uint16
			for k := 0; k < 4; k++ {
				x, y := int(a[ao+i+k]), int(s[bo+k])
				if x > y {
					sum += uint16(x - y)
				} else {
					sum += uint16(y - x)
				}
			}
			r.SetW(i, sum)
		}
	case 0x60, 0x61, 0x62, 0x63:
		c.pcmpstr(op, imm, &a, &s)
		return
	default:
		c.ud()
	}
	*d = r
}

// pcmpstr implements PCMPESTRM/PCMPESTRI/PCMPISTRM/PCMPISTRI.
func (c *CPU) pcmpstr(op, imm uint8, a, b *Vec) {
	words := imm&1 != 0
	signed := imm&2 != 0
	n := 16
	if words {
		n = 8
	}
	elem := func(v *Vec, i int) int32 {
		if words {
			if signed {
				return int32(int16(v.W(i)))
			}
			return int32(v.W(i))
		}
		if signed {
			return int32(int8(v[i]))
		}
		return int32(v[i])
	}
	var la, lb int
	explicit := op == 0x60 || op == 0x61
	if explicit {
		get := func(r int) int {
			var v int64
			if c.rex&8 != 0 {
				v = int64(c.R[r])
			} else {
				v = int64(int32(c.R[r]))
			}
			if v < 0 {
				v = -v
			}
			if v > int64(n) {
				v = int64(n)
			}
			return int(v)
		}
		la, lb = get(RAX), get(RDX)
	} else {
		la, lb = n, n
		for i := 0; i < n; i++ {
			if elem(a, i) == 0 {
				la = i
				break
			}
		}
		for i := 0; i < n; i++ {
			if elem(b, i) == 0 {
				lb = i
				break
			}
		}
	}
	var res uint32
	switch (imm >> 2) & 3 {
	case 0: // equal any
		for j := 0; j < lb; j++ {
			for i := 0; i < la; i++ {
				if elem(a, i) == elem(b, j) {
					res |= 1 << j
					break
				}
			}
		}
	case 1: // ranges
		for j := 0; j < lb; j++ {
			for i := 0; i+1 < la; i += 2 {
				if elem(a, i) <= elem(b, j) && elem(b, j) <= elem(a, i+1) {
					res |= 1 << j
					break
				}
			}
		}
	case 2: // equal each
		for i := 0; i < n; i++ {
			va, vb := i < la, i < lb
			switch {
			case !va && !vb:
				res |= 1 << i
			case va && vb && elem(a, i) == elem(b, i):
				res |= 1 << i
			}
		}
	case 3: // equal ordered
		for j := 0; j < n; j++ {
			ok := true
			for k := 0; k < n-j; k++ {
				if k >= la {
					break
				}
				if j+k >= lb {
					ok = false
					break
				}
				if elem(a, k) != elem(b, j+k) {
					ok = false
					break
				}
			}
			if ok {
				res |= 1 << j
			}
		}
	}
	full := uint32(1)<<n - 1
	switch (imm >> 4) & 3 {
	case 1:
		res ^= full
	case 3:
		res ^= (uint32(1)<<lb - 1) & full
	}
	res &= full
	c.Flags &^= arithFlags
	if res != 0 {
		c.Flags |= FlagCF
	}
	if lb < n {
		c.Flags |= FlagZF
	}
	if la < n {
		c.Flags |= FlagSF
	}
	if res&1 != 0 {
		c.Flags |= FlagOF
	}
	if op == 0x61 || op == 0x63 { // index
		idx := n
		if res != 0 {
			if imm&0x40 != 0 {
				idx = 31 - bits.LeadingZeros32(res)
			} else {
				idx = bits.TrailingZeros32(res)
			}
		}
		c.R[RCX] = uint64(idx)
		return
	}
	var m Vec
	if imm&0x40 != 0 {
		for i := 0; i < n; i++ {
			if res&(1<<i) != 0 {
				if words {
					m.SetW(i, 0xFFFF)
				} else {
					m[i] = 0xFF
				}
			}
		}
	} else {
		m.SetD(0, res)
	}
	c.X[0] = m
}
