package cpu

import "winemu/internal/mem"

const maxBlockOps = 64

type sharedCode struct{}

// decoder reads guest code for predecoding. Reads panic with *mem.Fault on
// unmapped code and sharedCode{} on code in a shared chunk.
type decoder struct {
	m     *mem.Memory
	pos   uint64
	cbase uint64
	chunk *[mem.ChunkSize]byte
	rex   uint8
	osz   uint8
	p66   bool
	rep   uint8
}

func (d *decoder) u8() uint8 {
	if off := d.pos - d.cbase; off < mem.ChunkSize && d.chunk != nil {
		d.pos++
		return d.chunk[off]
	}
	if d.m.Shared(d.pos) {
		panic(sharedCode{})
	}
	d.chunk = d.m.CodeChunk(d.pos)
	d.cbase = d.pos &^ (mem.ChunkSize - 1)
	d.pos++
	return d.chunk[d.pos-1-d.cbase]
}

func (d *decoder) u16() uint16 { lo := uint16(d.u8()); return lo | uint16(d.u8())<<8 }
func (d *decoder) u32() uint32 { lo := uint32(d.u16()); return lo | uint32(d.u16())<<16 }
func (d *decoder) u64() uint64 { lo := uint64(d.u32()); return lo | uint64(d.u32())<<32 }

// imm reads an immediate exactly like CPU.imm.
func (d *decoder) imm(sz uint8) uint64 {
	switch sz {
	case 1:
		return uint64(d.u8())
	case 2:
		return uint64(d.u16())
	case 4:
		return uint64(d.u32())
	}
	return uint64(int64(int32(d.u32())))
}

// modrm mirrors CPU.decodeModRM; immLen is the value the reference passes.
func (d *decoder) modrm(o *op, immLen int) {
	b := d.u8()
	mod := b >> 6
	o.r = (b>>3)&7 | (d.rex&4)<<1
	rm := b & 7
	o.base, o.idx = noReg, noReg
	if mod == 3 {
		o.rm = rm | (d.rex&1)<<3
		return
	}
	o.mem = true
	var disp uint64
	switch {
	case rm == 4:
		sib := d.u8()
		if idx := (sib>>3)&7 | (d.rex&2)<<2; idx != 4 {
			o.idx, o.scale = idx, sib>>6
		}
		if sib&7 == 5 && mod == 0 {
			disp = uint64(int64(int32(d.u32())))
		} else {
			o.base = sib&7 | (d.rex&1)<<3
		}
	case rm == 5 && mod == 0:
		disp = uint64(int64(int32(d.u32())))
		o.disp = d.pos + uint64(immLen) + disp
		return
	default:
		o.base = rm | (d.rex&1)<<3
	}
	switch mod {
	case 1:
		disp += uint64(int64(int8(d.u8())))
	case 2:
		disp += uint64(int64(int32(d.u32())))
	}
	o.disp = disp
}

// byteReg resolves a byte register number like getReg/setReg do.
func (d *decoder) byteReg(r uint8) (uint8, uint8) {
	if d.rex == 0 && r >= 4 && r < 8 {
		return r - 4, 8
	}
	return r, 0
}

// byteRegs resolves r and (non-memory) rm for a byte-sized operation.
func (d *decoder) byteRegs(o *op) {
	o.r, o.rSh = d.byteReg(o.r)
	if !o.mem {
		o.rm, o.rmSh = d.byteReg(o.rm)
	}
}

// byteRM resolves a non-memory rm of a byte-sized operation whose reg field
// is an opcode extension.
func (d *decoder) byteRM(o *op) {
	if o.sz == 1 && !o.mem {
		o.rm, o.rmSh = d.byteReg(o.rm)
	}
}

// decodeBlock predecodes the block at ip; nil if not even its first
// instruction can be predecoded here (the reference then runs it).
func (c *CPU) decodeBlock(ip uint64) *block {
	if c.Mem.Shared(ip) {
		return nil
	}
	d := decoder{m: c.Mem, pos: ip, cbase: ^uint64(0)}
	page := ip &^ (mem.PageSize - 1)
	var ops []op
	for len(ops) < maxBlockOps && d.pos&^(mem.PageSize-1) == page {
		o, end, ok := d.one()
		if !ok {
			break
		}
		if (o.id == idJmp || o.id == idCall) && o.disp&^(mem.PageSize-1) == page {
			// direct jump/call within the page: continue decoding at the target
			if o.id == idCall {
				o.fn, o.imm = opCallCont, o.next
			} else {
				o.fn, o.id = opNop, idNop
			}
			o.next, end = o.disp, false
			if o.id != idNop {
				o.id = idNone
			}
			d.pos = o.disp
		}
		ops = append(ops, o)
		if end {
			break
		}
	}
	if len(ops) == 0 {
		return nil
	}
	n := len(ops)
	ops = foldNops(fuse(ops))
	cnt := 0
	for i := range ops {
		cnt += int(ops[i].pre) + 1 + int(ops[i].extra)
		ops[i].cnt = uint8(cnt)
	}
	return &block{ip: ip, ops: ops, n: n}
}

// one decodes one instruction. end reports a block-ending op; ok is false if
// the code could not be read (the instruction is then left to the reference).
func (d *decoder) one() (o op, end, ok bool) {
	start := d.pos
	defer func() {
		if r := recover(); r != nil {
			switch r.(type) {
			case *mem.Fault, sharedCode:
				ok = false
				d.pos = start
			default:
				panic(r)
			}
		}
	}()
	o.ip = start
	d.rex, d.p66, d.rep = 0, false, 0
	ad32, lock := false, false
	var opc uint8
prefix:
	for {
		opc = d.u8()
		switch opc {
		case 0x66:
			d.p66 = true
		case 0x67:
			ad32 = true
		case 0xF2, 0xF3:
			d.rep = opc
		case 0xF0:
			lock = true
		case 0x2E, 0x36, 0x3E, 0x26:
		case 0x64:
			o.seg = 1
		case 0x65:
			o.seg = 2
		default:
			break prefix
		}
	}
	for opc&0xF0 == 0x40 {
		d.rex = opc
		opc = d.u8()
	}
	switch {
	case d.rex&8 != 0:
		d.osz = 8
	case d.p66:
		d.osz = 2
	default:
		d.osz = 4
	}
	o.sz = d.osz
	known := false
	if !ad32 && !lock {
		if opc == 0x0F {
			known, end = d.op0F(&o)
		} else {
			known, end = d.op1(&o, opc)
		}
	}
	if !known {
		o = op{fn: opFallback, ip: start, next: start + 1, ext: true}
		return o, true, true
	}
	o.next = d.pos
	return o, end, true
}
