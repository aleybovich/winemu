package cpu

// Lazy-flag ALU handlers specialised by operation and size (32/64 bit)
// for register and immediate operands; table aluFast picks them.

func opAdd64RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm], c.R[o.r]
	r := (a + b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfAdd, sz: 8, a: a, b: b, r: r}
	return false
}

func opAdd64RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm], o.imm
	r := (a + b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfAdd, sz: 8, a: a, b: b, r: r}
	return false
}

func opAdd32RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, c.R[o.r]&0xFFFFFFFF
	r := (a + b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfAdd, sz: 4, a: a, b: b, r: r}
	return false
}

func opAdd32RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, o.imm&0xFFFFFFFF
	r := (a + b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfAdd, sz: 4, a: a, b: b, r: r}
	return false
}

func opSub64RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm], c.R[o.r]
	r := (a - b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfSub, sz: 8, a: a, b: b, r: r}
	return false
}

func opSub64RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm], o.imm
	r := (a - b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfSub, sz: 8, a: a, b: b, r: r}
	return false
}

func opSub32RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, c.R[o.r]&0xFFFFFFFF
	r := (a - b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfSub, sz: 4, a: a, b: b, r: r}
	return false
}

func opSub32RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, o.imm&0xFFFFFFFF
	r := (a - b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfSub, sz: 4, a: a, b: b, r: r}
	return false
}

func opCmp64RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm], c.R[o.r]
	r := (a - b)
	c.lf = lazyFlags{kind: lfSub, sz: 8, a: a, b: b, r: r}
	return false
}

func opCmp64RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm], o.imm
	r := (a - b)
	c.lf = lazyFlags{kind: lfSub, sz: 8, a: a, b: b, r: r}
	return false
}

func opCmp32RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, c.R[o.r]&0xFFFFFFFF
	r := (a - b) & 0xFFFFFFFF
	c.lf = lazyFlags{kind: lfSub, sz: 4, a: a, b: b, r: r}
	return false
}

func opCmp32RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, o.imm&0xFFFFFFFF
	r := (a - b) & 0xFFFFFFFF
	c.lf = lazyFlags{kind: lfSub, sz: 4, a: a, b: b, r: r}
	return false
}

func opAnd64RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm], c.R[o.r]
	r := (a & b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: r}
	return false
}

func opAnd64RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm], o.imm
	r := (a & b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: r}
	return false
}

func opAnd32RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, c.R[o.r]&0xFFFFFFFF
	r := (a & b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: r}
	return false
}

func opAnd32RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, o.imm&0xFFFFFFFF
	r := (a & b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: r}
	return false
}

func opOr64RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm], c.R[o.r]
	r := (a | b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: r}
	return false
}

func opOr64RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm], o.imm
	r := (a | b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: r}
	return false
}

func opOr32RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, c.R[o.r]&0xFFFFFFFF
	r := (a | b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: r}
	return false
}

func opOr32RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, o.imm&0xFFFFFFFF
	r := (a | b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: r}
	return false
}

func opXor64RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm], c.R[o.r]
	r := (a ^ b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: r}
	return false
}

func opXor64RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm], o.imm
	r := (a ^ b)
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: r}
	return false
}

func opXor32RR(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, c.R[o.r]&0xFFFFFFFF
	r := (a ^ b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: r}
	return false
}

func opXor32RI(c *CPU, o *op) bool {
	a, b := c.R[o.rm]&0xFFFFFFFF, o.imm&0xFFFFFFFF
	r := (a ^ b) & 0xFFFFFFFF
	c.R[o.rm] = r
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: r}
	return false
}

// aluFast[sub][0=64,1=32][0=RR,1=RI]; nil: no specialised handler (ADC/SBB).
var aluFast = [8][2][2]opFn{
	0: {{opAdd64RR, opAdd64RI}, {opAdd32RR, opAdd32RI}},
	1: {{opOr64RR, opOr64RI}, {opOr32RR, opOr32RI}},
	4: {{opAnd64RR, opAnd64RI}, {opAnd32RR, opAnd32RI}},
	5: {{opSub64RR, opSub64RI}, {opSub32RR, opSub32RI}},
	6: {{opXor64RR, opXor64RI}, {opXor32RR, opXor32RI}},
	7: {{opCmp64RR, opCmp64RI}, {opCmp32RR, opCmp32RI}},
}

func opTest64RR(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: (c.R[o.rm] & c.R[o.r])}
	return false
}

func opTest64RI(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 8, r: (c.R[o.rm] & o.imm)}
	return false
}

func opTest32RR(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: (c.R[o.rm] & c.R[o.r]) & 0xFFFFFFFF}
	return false
}

func opTest32RI(c *CPU, o *op) bool {
	c.lf = lazyFlags{kind: lfLogic, sz: 4, r: (c.R[o.rm] & o.imm) & 0xFFFFFFFF}
	return false
}
