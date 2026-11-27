// Package cpu is an x86-64 user-mode interpreter.
package cpu

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"

	"winemu/internal/mem"
)

// General purpose register numbers.
const (
	RAX = iota
	RCX
	RDX
	RBX
	RSP
	RBP
	RSI
	RDI
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
)

// RFLAGS bits.
const (
	FlagCF = 1 << 0
	FlagPF = 1 << 2
	FlagAF = 1 << 4
	FlagZF = 1 << 6
	FlagSF = 1 << 7
	FlagTF = 1 << 8
	FlagIF = 1 << 9
	FlagDF = 1 << 10
	FlagOF = 1 << 11
	FlagAC = 1 << 18
	FlagID = 1 << 21

	arithFlags = FlagCF | FlagPF | FlagAF | FlagZF | FlagSF | FlagOF
)

// Windows exception codes raised by the CPU.
const (
	ExcAccessViolation   = 0xC0000005
	ExcIllegalInstr      = 0xC000001D
	ExcPrivInstr         = 0xC0000096
	ExcIntDivZero        = 0xC0000094
	ExcIntOverflow       = 0xC0000095
	ExcBreakpoint        = 0x80000003
	ExcSingleStep        = 0x80000004
	ExcStackBufOverrun   = 0xC0000409 // __fastfail
	ExcAssertionFailure  = 0xC0000420
	ExcFltInvalid        = 0xC0000090
	ExcArrayBoundsExceed = 0xC000008C
)

// Exception is raised (via panic) for CPU-level faults. RIP has been reset to
// the faulting instruction.
type Exception struct {
	Code   uint32
	Addr   uint64
	Params []uint64
	Msg    string
}

func (e *Exception) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("exception %#x at %#x: %s", e.Code, e.Addr, e.Msg)
	}
	return fmt.Sprintf("exception %#x at %#x", e.Code, e.Addr)
}

// Vec is a 128-bit XMM register.
type Vec [16]byte

var le = binary.LittleEndian

func (v *Vec) Q(i int) uint64          { return le.Uint64(v[i*8 : i*8+8]) }
func (v *Vec) SetQ(i int, x uint64)    { le.PutUint64(v[i*8:i*8+8], x) }
func (v *Vec) D(i int) uint32          { return le.Uint32(v[i*4 : i*4+4]) }
func (v *Vec) SetD(i int, x uint32)    { le.PutUint32(v[i*4:i*4+4], x) }
func (v *Vec) W(i int) uint16          { return le.Uint16(v[i*2 : i*2+2]) }
func (v *Vec) SetW(i int, x uint16)    { le.PutUint16(v[i*2:i*2+2], x) }
func (v *Vec) F32(i int) float32       { return math.Float32frombits(v.D(i)) }
func (v *Vec) SetF32(i int, f float32) { v.SetD(i, math.Float32bits(f)) }
func (v *Vec) F64(i int) float64       { return math.Float64frombits(v.Q(i)) }
func (v *Vec) SetF64(i int, f float64) { v.SetQ(i, math.Float64bits(f)) }

// CPU holds one thread's architectural state.
type CPU struct {
	R      [16]uint64
	RIP    uint64
	Flags  uint64
	X      [16]Vec
	MXCSR  uint32
	FSBase uint64
	GSBase uint64
	FPU    FPU

	Mem *mem.Memory
	mc  mem.Cache // this thread's last-chunk cache for the scalar accesses to Mem

	// Hyper is invoked by the private 0F 04 <imm32> "hypercall" opcode.
	Hyper func(c *CPU, idx uint32)

	Stop   bool // breaks out of Run
	ICount uint64

	Engine      Engine    // how Run executes code (block.go)
	sharedSlice bool      // the current slice runs in shared (locked-instruction) mode
	lf          lazyFlags // pending flags of the block engine (block_flags.go)

	// CPUID customisation
	CPUIDHook func(leaf, sub uint32) (a, b, c, d uint32, ok bool)

	// instruction decode state
	IP0    uint64 // address of the current instruction
	rex    byte
	p66    bool
	rep    byte // 0, 0xF2, 0xF3
	segB   uint64
	ad32   bool
	osz    uint8
	mod    uint8
	reg    uint8
	rm     uint8
	isMem  bool
	ea     uint64
	ripRel bool

	// code fetch cache
	codeBase uint64
	code     *[mem.ChunkSize]byte
}

func New(m *mem.Memory) *CPU {
	c := &CPU{Mem: m, Flags: 0x202, MXCSR: 0x1F80, Engine: DefaultEngine}
	c.FPU.reset()
	c.codeBase = noCode
	return c
}

// noCode is the fetch-cache base meaning "no chunk cached": RIP - noCode is
// at least ChunkSize for every user-mode (and every canonical low) address.
// (^0 made every RIP below 64 KiB index the nil chunk.)
const noCode = 1 << 63

// Clone returns a copy suitable for a new thread.
func (c *CPU) InvalidateCode() { c.codeBase = noCode; c.code = nil }

func (c *CPU) String() string {
	return fmt.Sprintf("rip=%#x rax=%#x rbx=%#x rcx=%#x rdx=%#x rsi=%#x rdi=%#x rbp=%#x rsp=%#x r8=%#x r9=%#x r10=%#x r11=%#x r12=%#x r13=%#x r14=%#x r15=%#x fl=%#x",
		c.RIP, c.R[0], c.R[3], c.R[1], c.R[2], c.R[6], c.R[7], c.R[5], c.R[4], c.R[8], c.R[9], c.R[10], c.R[11], c.R[12], c.R[13], c.R[14], c.R[15], c.Flags)
}

// Run executes up to n instructions or until Stop is set.
func (c *CPU) Run(n int) {
	c.Stop = false
	if c.Engine != EngineInterp {
		c.runBlocks(n)
		return
	}
	if c.Mem.HasShared() {
		c.runShared(n)
		return
	}
	for i := 0; i < n; i++ {
		c.step()
		if c.Stop {
			c.ICount += uint64(i + 1)
			return
		}
	}
	c.ICount += uint64(n)
}

func (c *CPU) runShared(n int) {
	for i := 0; i < n; i++ {
		c.stepShared()
		if c.Stop {
			c.ICount += uint64(i + 1)
			return
		}
	}
	c.ICount += uint64(n)
}

func (c *CPU) fault(code uint32, msg string) {
	c.RIP = c.IP0
	panic(&Exception{Code: code, Addr: c.IP0, Msg: msg})
}

func (c *CPU) ud() {
	b := make([]byte, 0, 8)
	for i := uint64(0); i < 8; i++ {
		func() {
			defer func() { recover() }()
			b = append(b, c.mc.R8(c.Mem, c.IP0+i))
		}()
	}
	c.fault(ExcIllegalInstr, fmt.Sprintf("unsupported instruction % x", b))
}

// ---------------------------------------------------------------------------
// instruction fetch

func (c *CPU) f8() uint8 {
	if off := c.RIP - c.codeBase; off < mem.ChunkSize {
		c.RIP++
		return c.code[uint16(off)]
	}
	return c.f8slow()
}

func (c *CPU) f8slow() uint8 {
	ip := c.RIP
	c.code = c.Mem.CodeChunk(ip)
	c.codeBase = ip &^ (mem.ChunkSize - 1)
	c.RIP++
	return c.code[uint16(ip-c.codeBase)]
}

func (c *CPU) f16() uint16 {
	if off := c.RIP - c.codeBase; off < mem.ChunkSize-1 {
		c.RIP += 2
		return uint16(c.code[uint16(off)]) | uint16(c.code[uint16(off+1)])<<8
	}
	lo := uint16(c.f8slow2())
	return lo | uint16(c.f8slow2())<<8
}

func (c *CPU) f32() uint32 {
	if off := c.RIP - c.codeBase; off < mem.ChunkSize-3 {
		c.RIP += 4
		return le.Uint32(c.code[uint16(off):])
	}
	return c.f32slow()
}

func (c *CPU) f32slow() uint32 {
	lo := uint32(c.f8slow2())
	lo |= uint32(c.f8slow2()) << 8
	lo |= uint32(c.f8slow2()) << 16
	return lo | uint32(c.f8slow2())<<24
}

// f8slow2 is f8 without inlining pressure (used by slow multi-byte paths).
func (c *CPU) f8slow2() uint8 {
	if off := c.RIP - c.codeBase; off < mem.ChunkSize {
		c.RIP++
		return c.code[uint16(off)]
	}
	return c.f8slow()
}

func (c *CPU) f64() uint64 {
	lo := uint64(c.f32())
	return lo | uint64(c.f32())<<32
}

// ---------------------------------------------------------------------------
// registers

var sizeMask = [9]uint64{1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
var signBit = [9]uint64{1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}

func (c *CPU) getReg(r uint8, sz uint8) uint64 {
	switch sz {
	case 8:
		return c.R[r]
	case 4:
		return c.R[r] & 0xFFFFFFFF
	case 2:
		return c.R[r] & 0xFFFF
	default:
		if c.rex == 0 && r >= 4 && r < 8 {
			return (c.R[r-4] >> 8) & 0xFF
		}
		return c.R[r] & 0xFF
	}
}

func (c *CPU) setReg(r uint8, sz uint8, v uint64) {
	switch sz {
	case 8:
		c.R[r] = v
	case 4:
		c.R[r] = v & 0xFFFFFFFF
	case 2:
		c.R[r] = c.R[r]&^0xFFFF | v&0xFFFF
	default:
		if c.rex == 0 && r >= 4 && r < 8 {
			c.R[r-4] = c.R[r-4]&^0xFF00 | (v&0xFF)<<8
		} else {
			c.R[r] = c.R[r]&^0xFF | v&0xFF
		}
	}
}

func (c *CPU) rdMem(a uint64, sz uint8) uint64 {
	switch sz {
	case 8:
		return c.mc.R64(c.Mem, a)
	case 4:
		return uint64(c.mc.R32(c.Mem, a))
	case 2:
		return uint64(c.mc.R16(c.Mem, a))
	default:
		return uint64(c.mc.R8(c.Mem, a))
	}
}

func (c *CPU) wrMem(a uint64, sz uint8, v uint64) {
	switch sz {
	case 8:
		c.mc.W64(c.Mem, a, v)
	case 4:
		c.mc.W32(c.Mem, a, uint32(v))
	case 2:
		c.mc.W16(c.Mem, a, uint16(v))
	default:
		c.mc.W8(c.Mem, a, uint8(v))
	}
}

func (c *CPU) Push(v uint64) {
	sp := c.R[RSP] - 8
	c.mc.W64(c.Mem, sp, v)
	c.R[RSP] = sp
}

func (c *CPU) Pop() uint64 {
	v := c.mc.R64(c.Mem, c.R[RSP])
	c.R[RSP] += 8
	return v
}

// ---------------------------------------------------------------------------
// flags

func parity(v uint64) bool { return bits.OnesCount8(uint8(v))&1 == 0 }

func (c *CPU) setSZP(r uint64, sz uint8) {
	f := c.Flags &^ (FlagSF | FlagZF | FlagPF)
	if r&sizeMask[sz] == 0 {
		f |= FlagZF
	}
	if r&signBit[sz] != 0 {
		f |= FlagSF
	}
	if parity(r) {
		f |= FlagPF
	}
	c.Flags = f
}

func b2f(b bool, flag uint64) uint64 {
	if b {
		return flag
	}
	return 0
}

func (c *CPU) setFlags(cf, of, af bool, r uint64, sz uint8) {
	f := c.Flags &^ arithFlags
	f |= b2f(cf, FlagCF) | b2f(of, FlagOF) | b2f(af, FlagAF)
	if r&sizeMask[sz] == 0 {
		f |= FlagZF
	}
	if r&signBit[sz] != 0 {
		f |= FlagSF
	}
	if parity(r) {
		f |= FlagPF
	}
	c.Flags = f
}

func (c *CPU) cf() uint64 { return c.Flags & FlagCF }

func (c *CPU) add(a, b, cin uint64, sz uint8) uint64 {
	m := sizeMask[sz]
	a &= m
	b &= m
	var r uint64
	var cf bool
	if sz == 8 {
		var carry uint64
		r, carry = bits.Add64(a, b, cin)
		cf = carry != 0
	} else {
		s := a + b + cin
		r = s & m
		cf = s > m
	}
	of := (a^r)&(b^r)&signBit[sz] != 0
	c.setFlags(cf, of, (a^b^r)&0x10 != 0, r, sz)
	return r
}

func (c *CPU) sub(a, b, bin uint64, sz uint8) uint64 {
	m := sizeMask[sz]
	a &= m
	b &= m
	var r uint64
	var cf bool
	if sz == 8 {
		var borrow uint64
		r, borrow = bits.Sub64(a, b, bin)
		cf = borrow != 0
	} else {
		r = (a - b - bin) & m
		cf = a < b+bin
	}
	of := (a^b)&(a^r)&signBit[sz] != 0
	c.setFlags(cf, of, (a^b^r)&0x10 != 0, r, sz)
	return r
}

func (c *CPU) logic(r uint64, sz uint8) uint64 {
	r &= sizeMask[sz]
	c.setFlags(false, false, false, r, sz)
	return r
}

// alu performs one of the 8 classic ALU ops. For CMP the result is unused.
func (c *CPU) alu(op uint8, a, b uint64, sz uint8) uint64 {
	switch op {
	case 0:
		return c.add(a, b, 0, sz)
	case 1:
		return c.logic(a|b, sz)
	case 2:
		return c.add(a, b, c.cf(), sz)
	case 3:
		return c.sub(a, b, c.cf(), sz)
	case 4:
		return c.logic(a&b, sz)
	case 5, 7:
		return c.sub(a, b, 0, sz)
	default:
		return c.logic(a^b, sz)
	}
}

func signExt(v uint64, sz uint8) uint64 {
	switch sz {
	case 1:
		return uint64(int64(int8(v)))
	case 2:
		return uint64(int64(int16(v)))
	case 4:
		return uint64(int64(int32(v)))
	}
	return v
}

// cond evaluates condition code cc (0..15).
func (c *CPU) cond(cc uint8) bool {
	f := c.Flags
	var r bool
	switch cc >> 1 {
	case 0:
		r = f&FlagOF != 0
	case 1:
		r = f&FlagCF != 0
	case 2:
		r = f&FlagZF != 0
	case 3:
		r = f&(FlagCF|FlagZF) != 0
	case 4:
		r = f&FlagSF != 0
	case 5:
		r = f&FlagPF != 0
	case 6:
		r = (f&FlagSF != 0) != (f&FlagOF != 0)
	case 7:
		r = f&FlagZF != 0 || (f&FlagSF != 0) != (f&FlagOF != 0)
	}
	if cc&1 != 0 {
		return !r
	}
	return r
}

// shift implements the C0/C1/D0-D3 group. op is the /reg field.
func (c *CPU) shift(op uint8, a uint64, n uint64, sz uint8) uint64 {
	nbits := uint64(sz) * 8
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
	sb := signBit[sz]
	var r uint64
	f := c.Flags
	switch op {
	case 0, 1: // ROL, ROR
		k := n % nbits
		if op == 0 {
			r = (a<<k | a>>((nbits-k)%nbits)) & m
			if k == 0 {
				r = a
			}
			cfb := r & 1
			f = f&^(FlagCF|FlagOF) | cfb*FlagCF
			if (r&sb != 0) != (cfb != 0) {
				f |= FlagOF
			}
		} else {
			r = (a>>k | a<<((nbits-k)%nbits)) & m
			if k == 0 {
				r = a
			}
			msb := r&sb != 0
			msb2 := r&(sb>>1) != 0
			f &^= FlagCF | FlagOF
			if msb {
				f |= FlagCF
			}
			if msb != msb2 {
				f |= FlagOF
			}
		}
		c.Flags = f
		return r
	case 2, 3: // RCL, RCR
		k := n % (nbits + 1)
		cf := c.Flags&FlagCF != 0
		r = a
		for i := uint64(0); i < k; i++ {
			if op == 2 {
				nc := r&sb != 0
				r = (r << 1) & m
				if cf {
					r |= 1
				}
				cf = nc
			} else {
				nc := r&1 != 0
				r >>= 1
				if cf {
					r |= sb
				}
				cf = nc
			}
		}
		f &^= FlagCF | FlagOF
		if cf {
			f |= FlagCF
		}
		if op == 2 {
			if (r&sb != 0) != cf {
				f |= FlagOF
			}
		} else if (r&sb != 0) != (r&(sb>>1) != 0) {
			f |= FlagOF
		}
		c.Flags = f
		return r
	case 4, 6: // SHL
		var cf bool
		if sz == 8 {
			r = a << n
			cf = (a>>(64-n))&1 != 0
		} else {
			w := a << n
			r = w & m
			cf = (w>>nbits)&1 != 0
		}
		of := (r&sb != 0) != cf
		c.setFlags(cf, of, false, r, sz)
		return r
	case 5: // SHR
		cf := (a>>(n-1))&1 != 0
		r = a >> n
		c.setFlags(cf, a&sb != 0, false, r, sz)
		return r
	default: // SAR
		s := int64(signExt(a, sz))
		cf := (s>>(n-1))&1 != 0
		r = uint64(s>>n) & m
		c.setFlags(cf, false, false, r, sz)
		return r
	}
}
