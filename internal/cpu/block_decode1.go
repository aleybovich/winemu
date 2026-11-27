package cpu

// Opcode tables of the block decoder. Every form mirrors exec1/exec0F: same
// operand sizes, immediate extension and immLen passed to decodeModRM.

// rmForm picks the register or memory variant of a ModRM instruction.
func rmForm(o *op, reg, mem opFn) {
	o.fn = reg
	if o.mem {
		o.fn = mem
	}
}

// swapRM makes rm the destination for "reg, r/m" forms (register variant).
func swapRM(o *op) { o.r, o.rm, o.rSh, o.rmSh = o.rm, o.r, o.rmSh, o.rSh }

func (d *decoder) op1(o *op, opc uint8) (known, end bool) {
	sz := d.osz
	switch {
	case opc < 0x40 && opc&7 <= 5:
		o.sub = opc >> 3
		switch opc & 7 {
		case 0, 1, 2, 3:
			if opc&1 == 0 {
				o.sz = 1
			}
			d.modrm(o, 0)
			if o.sz == 1 {
				d.byteRegs(o)
			}
			switch {
			case !o.mem:
				if opc&2 != 0 {
					swapRM(o)
				}
				o.fn = aluPick(o, 0, opAluRR)
			case opc&2 == 0:
				o.fn = opAluMR
				if simpleEA(o) && o.sub != 2 && o.sub != 3 {
					o.fn = sized(o.sz, opAluMR64B, opAluMR32B, opAluMR)
				}
			default:
				o.fn = sized(o.sz, opAluRM64, opAluRM32, opAluRM)
			}
		case 4:
			o.sz, o.rm, o.imm, o.fn = 1, RAX, uint64(d.u8()), opAluRI
		case 5:
			o.rm, o.imm = RAX, d.imm(sz)
			o.fn = aluPick(o, 1, opAluRI)
		}
		return true, false
	case opc >= 0x50 && opc <= 0x57 && !d.p66:
		o.r, o.fn = opc&7|(d.rex&1)<<3, opPush
		return true, false
	case opc >= 0x58 && opc <= 0x5F && !d.p66:
		o.r, o.fn = opc&7|(d.rex&1)<<3, opPop
		return true, false
	case opc >= 0x70 && opc <= 0x7F:
		dd := uint64(int64(int8(d.u8())))
		o.sub, o.disp, o.fn, o.id = opc&15, d.pos+dd, opJcc, idJcc
		return true, false // side exit: the fall-through continues the block
	case opc >= 0x91 && opc <= 0x97:
		o.r, o.fn = opc&7|(d.rex&1)<<3, opXchgAX
		return true, false
	case opc >= 0xB0 && opc <= 0xB7:
		o.sz = 1
		o.rm, o.rmSh = d.byteReg(opc&7 | (d.rex&1)<<3)
		o.imm, o.fn = uint64(d.u8()), opMovRI
		return true, false
	case opc >= 0xB8 && opc <= 0xBF:
		o.rm, o.fn = opc&7|(d.rex&1)<<3, sized(sz, opMovRI64, opMovRI32, opMovRI)
		switch sz {
		case 8:
			o.imm = d.u64()
		case 4:
			o.imm = uint64(d.u32())
		default:
			o.imm = uint64(d.u16())
		}
		return true, false
	}
	switch opc {
	case 0x63:
		d.modrm(o, 0)
		rmForm(o, opMovsxdR, opMovsxdM)
	case 0x68, 0x6A:
		if d.p66 {
			return false, false
		}
		if opc == 0x68 {
			o.imm = signExt(uint64(d.u32()), 4)
		} else {
			o.imm = signExt(uint64(d.u8()), 1)
		}
		o.fn = opPushI
	case 0x69, 0x6B:
		il := immLen(sz)
		if opc == 0x6B {
			il = 1
		}
		d.modrm(o, il)
		if opc == 0x6B {
			o.imm = signExt(uint64(d.u8()), 1)
		} else {
			o.imm = signExt(d.imm(sz), sz)
		}
		rmForm(o, opImul3R, opImul3M)
	case 0x80, 0x81, 0x83:
		if opc == 0x80 {
			o.sz = 1
		}
		il := immLen(o.sz)
		if opc == 0x83 {
			il = 1
		}
		d.modrm(o, il)
		o.sub = o.r & 7
		d.byteRM(o)
		if opc == 0x83 {
			o.imm = signExt(uint64(d.u8()), 1)
		} else {
			o.imm = d.imm(o.sz)
		}
		rmForm(o, aluPick(o, 1, opAluRI), opAluMI)
	case 0x84, 0x85:
		if opc == 0x84 {
			o.sz = 1
		}
		d.modrm(o, 0)
		if o.sz == 1 {
			d.byteRegs(o)
		}
		if o.mem {
			o.fn = opTestMR
		} else {
			o.fn = testPick(o, 0, opTestRR)
			if o.sz == 1 {
				o.fn = opTest8RR
			}
		}
	case 0x88, 0x89, 0x8A, 0x8B:
		if opc&1 == 0 {
			o.sz = 1
		}
		d.modrm(o, 0)
		if o.sz == 1 {
			d.byteRegs(o)
		}
		switch {
		case !o.mem:
			if opc&2 != 0 {
				swapRM(o)
			}
			o.fn = sized(o.sz, opMovRR64, opMovRR32, opMovRR)
		case opc&2 == 0:
			o.fn = sizedEA(o, opMovMR64B, opMovMR64, opMovMR32B, opMovMR32, opMovMR)
			switch o.sz {
			case 2:
				o.fn = opMovMR16
			case 1:
				o.fn = opMovMR8
			}
		default:
			o.fn = sizedEA(o, opMovRM64B, opMovRM64, opMovRM32B, opMovRM32, opMovRM)
		}
	case 0x8D:
		d.modrm(o, 0)
		if !o.mem {
			return false, false
		}
		o.fn = sizedEA(o, opLea64B, opLea64, opLea32, opLea32, opLea)
	case 0x90:
		if d.rex&1 != 0 {
			return false, false
		}
		o.fn, o.id = opNop, idNop
	case 0x98:
		o.fn = opCwde
	case 0x99:
		o.fn = opCdq
	case 0xA8, 0xA9:
		if opc == 0xA8 {
			o.sz, o.imm = 1, uint64(d.u8())
		} else {
			o.imm = d.imm(sz)
		}
		o.rm = RAX
		o.fn = testPick(o, 1, opTestRI)
	case 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3:
		if opc&1 == 0 {
			o.sz = 1
		}
		il := 0
		if opc <= 0xC1 {
			il = 1
		}
		d.modrm(o, il)
		o.sub = o.r & 7
		d.byteRM(o)
		switch opc {
		case 0xC0, 0xC1:
			o.imm = uint64(d.u8())
		case 0xD0, 0xD1:
			o.imm = 1
		}
		if opc >= 0xD2 {
			rmForm(o, opShiftRCL, opShiftMCL)
		} else {
			rmForm(o, opShiftR, opShiftM)
			shiftPick(o)
		}
	case 0xC2:
		o.imm, o.fn = uint64(d.u16()), opRetN
		return true, true
	case 0xC3:
		o.fn = opRet
		return true, true
	case 0xC6, 0xC7:
		il := 1
		if opc == 0xC7 {
			il = immLen(sz)
		} else {
			o.sz = 1
		}
		d.modrm(o, il)
		if o.sz == 1 {
			d.byteRegs(o)
		}
		o.imm = d.imm(o.sz)
		if !o.mem {
			o.fn = sized(o.sz, opMovRI64, opMovRI32, opMovRI)
		} else {
			o.fn = sized(o.sz, opMovMI64, opMovMI32, opMovMI)
		}
	case 0xC9:
		o.fn = opLeave
	case 0xE8, 0xE9:
		dd := uint64(int64(int32(d.u32())))
		o.disp, o.fn, o.id = d.pos+dd, opJmp, idJmp
		if opc == 0xE8 {
			o.fn, o.id = opCall, idCall
		}
		return true, true
	case 0xEB:
		dd := uint64(int64(int8(d.u8())))
		o.disp, o.fn, o.id = d.pos+dd, opJmp, idJmp
		return true, true
	case 0xF6, 0xF7:
		if opc == 0xF6 {
			o.sz = 1
		}
		return d.group3(o)
	case 0xFE, 0xFF:
		return d.group45(o, opc)
	default:
		return false, false
	}
	return true, false
}

func (d *decoder) group3(o *op) (known, end bool) {
	save := d.pos
	reg := (d.u8() >> 3) & 7
	d.pos = save
	il := 0
	if reg <= 1 {
		il = immLen(o.sz)
	}
	d.modrm(o, il)
	if o.sz == 1 {
		d.byteRegs(o)
	}
	switch reg {
	case 0, 1:
		o.imm = d.imm(o.sz)
		if o.mem {
			o.fn = opTestMI
		} else {
			o.fn = testPick(o, 1, opTestRI)
		}
	case 2:
		rmForm(o, opNotR, opNotM)
	case 3:
		rmForm(o, opNegR, opNegM)
	default:
		return false, false
	}
	return true, false
}

func (d *decoder) group45(o *op, opc uint8) (known, end bool) {
	d.modrm(o, 0)
	r := o.r & 7
	if opc == 0xFE {
		if r > 1 {
			return false, false
		}
		o.sz = 1
		d.byteRegs(o)
	}
	switch r {
	case 0, 1:
		o.sub = r
		rmForm(o, opIncDecR, opIncDecM)
		if !o.mem && o.sz >= 4 {
			o.fn = [2][2]opFn{{opInc64R, opDec64R}, {opInc32R, opDec32R}}[(8-o.sz)/4][r]
		}
		return true, false
	case 2:
		o.sz = 8
		rmForm(o, opCallIndR, opCallIndM)
		return true, true
	case 4:
		o.sz = 8
		rmForm(o, opJmpIndR, opJmpIndM)
		return true, true
	case 6:
		o.sz = 8
		rmForm(o, opPushRM, opPushRM)
		return true, false
	}
	return false, false
}

func (d *decoder) op0F(o *op) (known, end bool) {
	opc := d.u8()
	switch {
	case opc >= 0x40 && opc <= 0x4F:
		d.modrm(o, 0)
		o.sub = opc & 15
		rmForm(o, opCmovR, opCmovM)
	case opc >= 0x80 && opc <= 0x8F:
		dd := uint64(int64(int32(d.u32())))
		o.sub, o.disp, o.fn, o.id = opc&15, d.pos+dd, opJcc, idJcc
		return true, false // side exit: the fall-through continues the block
	case opc >= 0x90 && opc <= 0x9F:
		d.modrm(o, 0)
		o.sub, o.sz = opc&15, 1
		d.byteRM(o)
		rmForm(o, opSetccR, opSetccM)
	case opc == 0xAF:
		d.modrm(o, 0)
		rmForm(o, opImul2R, opImul2M)
	case opc == 0xB6 || opc == 0xB7 || opc == 0xBE || opc == 0xBF:
		d.modrm(o, 0)
		o.imm = 1 + uint64(opc&1) // source size
		if opc >= 0xBE {
			o.sub = 1
		}
		if o.imm == 1 && !o.mem {
			o.rm, o.rmSh = d.byteReg(o.rm)
		}
		rmForm(o, opMovxR, opMovxM)
		if o.sub == 0 && o.sz >= 4 { // MOVZX into a 32/64-bit register
			switch {
			case o.imm == 1 && !o.mem:
				o.fn = opMovzxR8
			case o.imm == 1:
				o.fn = sizedEA(o, opMovzxM8B, opMovzxM8, opMovzxM8B, opMovzxM8, opMovxM)
			case o.mem:
				o.fn = opMovzxM16
			}
		}
	case opc == 0x04:
		o.imm, o.fn, o.ext = uint64(d.u32()), opHyper, true
		return true, true
	case opc == 0x0D || opc >= 0x18 && opc <= 0x1F:
		d.modrm(o, 0)
		o.fn, o.id = opNop, idNop
	default:
		return false, false
	}
	return true, false
}

// aluPick returns the specialised lazy-flag handler for a 32/64-bit ALU op in
// register (form 0) or immediate (form 1) form, else gen.
func aluPick(o *op, form int, gen opFn) opFn {
	var f opFn
	switch o.sz {
	case 8:
		f = aluFast[o.sub][0][form]
	case 4:
		f = aluFast[o.sub][1][form]
	}
	if f == nil {
		return gen
	}
	if o.sub == 7 && !o.mem {
		o.id = [2][2]uint8{{idCmp64RR, idCmp64RI}, {idCmp32RR, idCmp32RI}}[(8-o.sz)/4][form]
	}
	return f
}

// testPick is sized for TEST in register (form 0) or immediate (form 1) form.
func testPick(o *op, form int, gen opFn) opFn {
	switch o.sz {
	case 8:
		o.id = [2]uint8{idTest64RR, idTest64RI}[form]
		return [2]opFn{opTest64RR, opTest64RI}[form]
	case 4:
		o.id = [2]uint8{idTest32RR, idTest32RI}[form]
		return [2]opFn{opTest32RR, opTest32RI}[form]
	}
	return gen
}
