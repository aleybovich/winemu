package cpu

// Lazy flags for the block engine: ADD/SUB/CMP/NEG, AND/OR/XOR/TEST and
// INC/DEC record their operands; RFLAGS is computed only when read, by the
// reference helpers (add/sub/logic) on the recorded operands, so the result
// is bit-identical. Pending flags are materialised before any reference code
// runs (fallback, hypercall), when Run returns or panics, and by the checker.

const (
	lfNone uint8 = iota
	lfAdd
	lfSub
	lfLogic
	lfInc
	lfDec
	lfShift // SHL/SHR/SAR with a non-zero count
)

type lazyFlags struct {
	kind, sz uint8
	op       uint8  // lfShift: shift op (4..7)
	a, b, r  uint64 // operands (masked to sz) and result
	cf       uint64 // INC/DEC: the preserved CF (FlagCF or 0)
}

// flags materialises pending lazy flags into c.Flags.
func (c *CPU) flags() {
	if c.lf.kind == lfNone {
		return
	}
	lf := c.lf
	c.lf.kind = lfNone
	switch lf.kind {
	case lfAdd:
		c.add(lf.a, lf.b, 0, lf.sz)
	case lfSub:
		c.sub(lf.a, lf.b, 0, lf.sz)
	case lfLogic:
		c.logic(lf.r, lf.sz)
	case lfInc:
		c.add(lf.a, 1, 0, lf.sz)
		c.Flags = c.Flags&^FlagCF | lf.cf
	case lfDec:
		c.sub(lf.a, 1, 0, lf.sz)
		c.Flags = c.Flags&^FlagCF | lf.cf
	case lfShift:
		c.shift(lf.op, lf.a, lf.b, lf.sz)
	}
}

// carry returns the current CF (FlagCF or 0) without materialising.
func (c *CPU) carry() uint64 {
	lf := &c.lf
	switch lf.kind {
	case lfNone:
		return c.Flags & FlagCF
	case lfAdd:
		return b2f(lf.r < lf.a, FlagCF)
	case lfSub:
		return b2f(lf.a < lf.b, FlagCF)
	case lfLogic:
		return 0
	case lfShift:
		c.flags()
		return c.Flags & FlagCF
	}
	return lf.cf
}

// lcond is cond on possibly lazy flags.
func (c *CPU) lcond(cc uint8) bool {
	lf := &c.lf
	var r bool
	switch lf.kind {
	case lfNone:
		return c.cond(cc)
	case lfSub:
		switch cc >> 1 {
		case 1:
			r = lf.a < lf.b
		case 2:
			r = lf.r == 0
		case 3:
			r = lf.a <= lf.b
		case 4:
			r = lf.r&signBit[lf.sz] != 0
		case 6:
			r = int64(signExt(lf.a, lf.sz)) < int64(signExt(lf.b, lf.sz))
		case 7:
			r = int64(signExt(lf.a, lf.sz)) <= int64(signExt(lf.b, lf.sz))
		default:
			c.flags()
			return c.cond(cc)
		}
	case lfLogic:
		switch cc >> 1 {
		case 0, 1:
			r = false
		case 2, 3:
			r = lf.r == 0
		case 4, 6:
			r = lf.r&signBit[lf.sz] != 0
		case 7:
			r = lf.r == 0 || lf.r&signBit[lf.sz] != 0
		default:
			c.flags()
			return c.cond(cc)
		}
	default: // ADD, INC, DEC, shifts
		switch cc >> 1 {
		case 2:
			r = lf.r == 0
		case 4:
			r = lf.r&signBit[lf.sz] != 0
		default:
			c.flags()
			return c.cond(cc)
		}
	}
	if cc&1 != 0 {
		return !r
	}
	return r
}

// aluL is alu with lazy flags; ADC and SBB (which read CF) stay eager.
func (c *CPU) aluL(op uint8, a, b uint64, sz uint8) uint64 {
	m := sizeMask[sz]
	a &= m
	b &= m
	var r uint64
	switch op {
	case 0:
		r = (a + b) & m
		c.lf = lazyFlags{kind: lfAdd, sz: sz, a: a, b: b, r: r}
	case 5, 7:
		r = (a - b) & m
		c.lf = lazyFlags{kind: lfSub, sz: sz, a: a, b: b, r: r}
	case 1:
		r = a | b
		c.lf = lazyFlags{kind: lfLogic, sz: sz, r: r}
	case 4:
		r = a & b
		c.lf = lazyFlags{kind: lfLogic, sz: sz, r: r}
	case 6:
		r = a ^ b
		c.lf = lazyFlags{kind: lfLogic, sz: sz, r: r}
	default:
		c.flags()
		return c.alu(op, a, b, sz)
	}
	return r
}

func (c *CPU) logicL(r uint64, sz uint8) {
	c.lf = lazyFlags{kind: lfLogic, sz: sz, r: r & sizeMask[sz]}
}

func (c *CPU) incdecL(dec uint8, v uint64, sz uint8) uint64 {
	m := sizeMask[sz]
	v &= m
	cf := c.carry()
	if dec == 0 {
		r := (v + 1) & m
		c.lf = lazyFlags{kind: lfInc, sz: sz, a: v, r: r, cf: cf}
		return r
	}
	r := (v - 1) & m
	c.lf = lazyFlags{kind: lfDec, sz: sz, a: v, r: r, cf: cf}
	return r
}

// shiftL is shift with lazy flags for SHL/SHR/SAR (same result as shift;
// a zero count leaves value and flags alone); rotates stay eager.
func (c *CPU) shiftL(op uint8, a, n uint64, sz uint8) uint64 {
	if op < 4 {
		c.flags()
		return c.shift(op, a, n, sz)
	}
	if sz == 8 {
		n &= 63
	} else {
		n &= 31
	}
	if n == 0 {
		return a
	}
	m := sizeMask[sz]
	a &= m
	var r uint64
	switch op {
	case 4, 6:
		r = (a << n) & m
	case 5:
		r = a >> n
	default:
		r = uint64(int64(signExt(a, sz))>>n) & m
	}
	c.lf = lazyFlags{kind: lfShift, sz: sz, op: op, a: a, b: n, r: r}
	return r
}
