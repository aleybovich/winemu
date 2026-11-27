package cpu

// cmp/test + jcc fusion: the flag-setting op absorbs the following jcc
// (o.sub = condition code, o.disp = target, o.next = the jcc's next).
// The fused op counts as two instructions (op.extra = 1).

func opCmp64RRJ(c *CPU, o *op) bool {
	a, b := c.R[o.rm], c.R[o.r]
	c.lf = lazyFlags{kind: lfSub, sz: 8, a: a, b: b, r: (a - b)}
	return c.branch(o)
}

func opCmp64RIJ(c *CPU, o *op) bool {
	a, b := c.R[o.rm], o.imm
	c.lf = lazyFlags{kind: lfSub, sz: 8, a: a, b: b, r: (a - b)}
	return c.branch(o)
}

func opCmp32RRJ(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, c.R[o.r]&0xFFFFFFFF
	c.lf = lazyFlags{kind: lfSub, sz: 4, a: a, b: b, r: (a - b) & 0xFFFFFFFF}
	return c.branch(o)
}

func opCmp32RIJ(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, o.imm&0xFFFFFFFF
	c.lf = lazyFlags{kind: lfSub, sz: 4, a: a, b: b, r: (a - b) & 0xFFFFFFFF}
	return c.branch(o)
}

func opTest64RRJ(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: (c.R[o.rm] & c.R[o.r])}
	return c.branch(o)
}

func opTest64RIJ(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: (c.R[o.rm] & o.imm)}
	return c.branch(o)
}

func opTest32RRJ(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: (c.R[o.rm] & c.R[o.r]) & 0xFFFFFFFF}
	return c.branch(o)
}

func opTest32RIJ(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: (c.R[o.rm] & o.imm) & 0xFFFFFFFF}
	return c.branch(o)
}

// branch is a side exit: taken leaves the block at the target, not taken
// continues with the next op (or, at the block end, at o.next).
func (c *CPU) branch(o *op) bool {
	if c.lcond(o.sub) {
		c.RIP = o.disp
		return true
	}
	return false
}

const (
	idNone uint8 = iota
	idJcc
	idCmp64RR
	idCmp64RI
	idCmp32RR
	idCmp32RI
	idTest64RR
	idTest64RI
	idTest32RR
	idTest32RI
	idJmp
	idCall
	idNop // no architectural effect besides RIP (NOP, continued JMP)
)

var fusedJcc = [...]opFn{
	idCmp64RR: opCmp64RRJ, idCmp64RI: opCmp64RIJ, idCmp32RR: opCmp32RRJ, idCmp32RI: opCmp32RIJ,
	idTest64RR: opTest64RRJ, idTest64RI: opTest64RIJ, idTest32RR: opTest32RRJ, idTest32RI: opTest32RIJ,
}

// fuse merges every flag-setter + jcc pair into one op.
func fuse(ops []op) []op {
	out := ops[:0]
	for i := 0; i < len(ops); i++ {
		f := ops[i]
		if i+1 < len(ops) && ops[i+1].id == idJcc && f.id >= idCmp64RR && f.id <= idTest32RI {
			j := ops[i+1]
			f.fn, f.sub, f.disp, f.next, f.extra, f.id = fusedJcc[f.id], j.sub, j.disp, j.next, 1, idNone
			i++
		}
		out = append(out, f)
	}
	return out
}

// foldNops drops no-op instructions that are followed by another op: the
// next op counts them (op.pre). The fetch of a NOP cannot fault once decoded.
func foldNops(ops []op) []op {
	out := ops[:0]
	pre := 0
	for i := range ops {
		if ops[i].id == idNop && i+1 < len(ops) && pre < 200 {
			pre++
			continue
		}
		o := ops[i]
		o.pre = uint8(pre)
		pre = 0
		out = append(out, o)
	}
	return out
}
