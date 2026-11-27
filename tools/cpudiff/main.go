// Command cpudiff compares the emulator's CPU against the host CPU on random
// instruction tests. It must run on an x86-64 Linux host:
//
//	gcc -O1 -o /tmp/runner tools/cpudiff/native/runner.c && go run ./tools/cpudiff /tmp/runner
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"os/exec"

	"winemu/internal/cpu"
	"winemu/internal/mem"
)

const (
	fCF  = 1
	fPF  = 4
	fAF  = 0x10
	fZF  = 0x40
	fSF  = 0x80
	fOF  = 0x800
	fAll = fCF | fPF | fAF | fZF | fSF | fOF
)

type state struct {
	R     [16]uint64
	Flags uint64
	X     [16][16]byte // only 0..7 used
	Mem   [256]byte
}

type test struct {
	name  string
	code  []byte
	fmask uint64 // flags to compare
	fix   func(s *state)
	xmm   bool
	nanOK bool
}

var rnd = rand.New(rand.NewSource(int64(os.Getpid())))
var nTests = 40000

func rv() uint64 {
	switch rnd.Intn(8) {
	case 0:
		return 0
	case 1:
		return uint64(rnd.Intn(5))
	case 2:
		return ^uint64(0) - uint64(rnd.Intn(3))
	case 3:
		return 1 << uint(rnd.Intn(64))
	case 4:
		return uint64(int64(int32(rnd.Uint32())))
	case 5:
		return 0x7FFFFFFF + uint64(rnd.Intn(3))
	default:
		return rnd.Uint64()
	}
}

func rreg() byte {
	for {
		r := byte(rnd.Intn(16))
		if r != 4 && r != 12 {
			return r
		}
	}
}

// encode builds prefix+REX+opcode+modrm(reg-reg).
func rr(sz int, op []byte, reg, rm byte) []byte {
	var b []byte
	if sz == 2 {
		b = append(b, 0x66)
	}
	rex := byte(0x40)
	if sz == 8 {
		rex |= 8
	}
	if reg&8 != 0 {
		rex |= 4
	}
	if rm&8 != 0 {
		rex |= 1
	}
	if rex != 0x40 || sz == 1 {
		b = append(b, rex)
	}
	b = append(b, op...)
	b = append(b, 0xC0|(reg&7)<<3|rm&7)
	return b
}

// rm12 builds an [r12+disp8] memory form.
func rm12(sz int, op []byte, reg byte, disp byte) []byte {
	var b []byte
	if sz == 2 {
		b = append(b, 0x66)
	}
	rex := byte(0x41)
	if sz == 8 {
		rex |= 8
	}
	if reg&8 != 0 {
		rex |= 4
	}
	b = append(b, rex)
	b = append(b, op...)
	b = append(b, 0x44|(reg&7)<<3, 0x24, disp)
	return b
}

func w(sz int, op byte) byte {
	if sz == 1 {
		return op
	}
	return op | 1
}

func gen() []test {
	var ts []test
	sizes := []int{1, 2, 4, 8}
	for i := 0; i < nTests; i++ {
		sz := sizes[rnd.Intn(4)]
		a, b := rreg(), rreg()
		k := rnd.Intn(30)
		var t test
		switch k {
		case 0, 1: // ALU reg-reg
			op := byte(rnd.Intn(8))<<3 | byte(rnd.Intn(2))<<1
			t = test{"alu", rr(sz, []byte{w(sz, op)}, a, b), fAll &^ fAF, nil, false, false}
			if op>>3 == 0 || op>>3 == 2 || op>>3 == 3 || op>>3 == 5 || op>>3 == 7 {
				t.fmask = fAll
			}
		case 2: // group1 imm
			r := byte(rnd.Intn(8))
			code := rr(sz, []byte{w(sz, 0x80)}, r, b)
			if sz == 1 {
				code = append(code, byte(rnd.Intn(256)))
			} else if rnd.Intn(2) == 0 {
				code = rr(sz, []byte{0x83}, r, b)
				code = append(code, byte(rnd.Intn(256)))
			} else if sz == 2 {
				code = append(code, byte(rnd.Intn(256)), byte(rnd.Intn(256)))
			} else {
				code = binary.LittleEndian.AppendUint32(code, uint32(rv()))
			}
			t = test{"grp1", code, fAll &^ fAF, nil, false, false}
			if r == 0 || r == 2 || r == 3 || r == 5 || r == 7 {
				t.fmask = fAll
			}
		case 3, 4: // shifts
			r := byte(rnd.Intn(8))
			if r == 6 {
				r = 4
			}
			var code []byte
			cnt := rnd.Intn(70)
			switch rnd.Intn(3) {
			case 0:
				code = append(rr(sz, []byte{w(sz, 0xC0)}, r, b), byte(cnt))
			case 1:
				code = rr(sz, []byte{w(sz, 0xD0)}, r, b)
				cnt = 1
			default:
				code = rr(sz, []byte{w(sz, 0xD2)}, r, b)
				cl := cnt
				_ = cl
			}
			mask := uint64(fCF | fOF)
			if r >= 4 {
				mask = fAll &^ fAF
			}
			mc := cnt & 31
			if sz == 8 {
				mc = cnt & 63
			}
			if mc != 1 {
				mask &^= fOF
			}
			if r < 4 && sz < 8 && mc > sz*8 {
				mask = 0
			}
			if r >= 4 && mc > sz*8 {
				mask &^= fCF
			}
			if r == 2 || r == 3 {
				// RCL/RCR
				mask &= fCF | fOF
			}
			cc := cnt
			t = test{"shift", code, mask, func(s *state) { s.R[1] = s.R[1]&^0xFF | uint64(cc) }, false, false}
			if b == 1 {
				t.fix = nil
				t.fmask = 0
			}
		case 5: // F6/F7 group 3 (not div)
			r := []byte{0, 2, 3, 4, 5}[rnd.Intn(5)]
			code := rr(sz, []byte{w(sz, 0xF6)}, r, b)
			if r == 0 {
				if sz == 1 {
					code = append(code, byte(rnd.Intn(256)))
				} else if sz == 2 {
					code = append(code, 1, 2)
				} else {
					code = binary.LittleEndian.AppendUint32(code, uint32(rv()))
				}
			}
			mask := uint64(fAll &^ fAF)
			if r == 3 {
				mask = fAll
			}
			if r == 2 {
				mask = fAll
			}
			if r >= 4 {
				mask = fCF | fOF
			}
			t = test{"grp3", code, mask, nil, false, false}
		case 6: // div / idiv
			r := byte(6 + rnd.Intn(2))
			if b == 0 || b == 2 {
				b = 3
			}
			code := rr(sz, []byte{w(sz, 0xF6)}, r, b)
			bb := b
			t = test{"div", code, 0, func(s *state) {
				m := uint64(1)<<(uint(sz)*8) - 1
				if sz == 8 {
					m = ^uint64(0)
				}
				d := s.R[bb] & m
				if d == 0 {
					d = 7
					s.R[bb] = s.R[bb]&^m | d
				}
				if r == 6 {
					if sz == 1 {
						s.R[0] = s.R[0]&^0xFF00 | uint64(rnd.Intn(int(d)))<<8
					} else {
						s.R[2] = s.R[2]&^m | uint64(rnd.Int63n(int64(min(d, 1<<62))))
					}
				} else {
					// sign-extend dividend, avoid MIN/-1
					switch sz {
					case 1:
						s.R[0] = s.R[0]&^0xFF00 | uint64(uint8(int8(s.R[0])>>7))<<8
						if uint8(s.R[0]) == 0x80 && uint8(d) == 0xFF {
							s.R[0]++
						}
					case 2:
						s.R[2] = s.R[2]&^0xFFFF | uint64(uint16(int16(s.R[0])>>15))
						if uint16(s.R[0]) == 0x8000 && uint16(d) == 0xFFFF {
							s.R[0]++
						}
					case 4:
						s.R[2] = s.R[2]&^0xFFFFFFFF | uint64(uint32(int32(s.R[0])>>31))
						if uint32(s.R[0]) == 0x80000000 && uint32(d) == 0xFFFFFFFF {
							s.R[0]++
						}
					default:
						s.R[2] = uint64(int64(s.R[0]) >> 63)
						if s.R[0] == 1<<63 && d == ^uint64(0) {
							s.R[0]++
						}
					}
				}
			}, false, false}
		case 7: // imul r, r/m and imm
			if sz == 1 {
				sz = 4
			}
			code := rr(sz, []byte{0x0F, 0xAF}, a, b)
			if rnd.Intn(2) == 0 {
				code = append(rr(sz, []byte{0x6B}, a, b), byte(rnd.Intn(256)))
			}
			t = test{"imul", code, fCF | fOF, nil, false, false}
		case 8: // bt family
			if sz == 1 {
				sz = 4
			}
			ops := []byte{0xA3, 0xAB, 0xB3, 0xBB}
			code := rr(sz, []byte{0x0F, ops[rnd.Intn(4)]}, a, b)
			if rnd.Intn(2) == 0 {
				code = append(rr(sz, []byte{0x0F, 0xBA}, byte(4+rnd.Intn(4)), b), byte(rnd.Intn(256)))
			}
			t = test{"bt", code, fCF, nil, false, false}
		case 9: // bsf/bsr/tzcnt/lzcnt/popcnt
			if sz == 1 {
				sz = 4
			}
			ops := []byte{0xBC, 0xBD, 0xB8}
			o := ops[rnd.Intn(3)]
			code := rr(sz, []byte{0x0F, o}, a, b)
			mask := uint64(fZF)
			if o == 0xB8 || rnd.Intn(2) == 0 {
				code = append([]byte{0xF3}, code...)
				mask = fCF | fZF
				if o == 0xB8 {
					mask = fAll
				}
			}
			bb := b
			t = test{"bitscan", code, mask, func(s *state) {
				if s.R[bb] == 0 {
					s.R[bb] = 0x100
				}
			}, false, false}
		case 10: // shld/shrd
			if sz == 1 {
				sz = 4
			}
			o := []byte{0xA4, 0xAC}[rnd.Intn(2)]
			cnt := rnd.Intn(64)
			if sz == 2 {
				cnt = rnd.Intn(17)
			}
			code := append(rr(sz, []byte{0x0F, o}, a, b), byte(cnt))
			mc := cnt & 31
			if sz == 8 {
				mc = cnt & 63
			}
			mask := uint64(fAll &^ fAF &^ fOF)
			if mc == 1 {
				mask |= fOF
			}
			if mc > sz*8 || mc == 0 {
				mask = 0
			}
			t = test{"shxd", code, mask, nil, false, false}
		case 11: // cmov / setcc
			if rnd.Intn(2) == 0 {
				if sz == 1 {
					sz = 4
				}
				t = test{"cmov", rr(sz, []byte{0x0F, 0x40 | byte(rnd.Intn(16))}, a, b), fAll, nil, false, false}
			} else {
				t = test{"setcc", rr(1, []byte{0x0F, 0x90 | byte(rnd.Intn(16))}, 0, b), fAll, nil, false, false}
			}
		case 12: // xadd / cmpxchg
			o := []byte{0xC0, 0xB0}[rnd.Intn(2)]
			if sz != 1 {
				o |= 1
			}
			t = test{"xadd", rr(sz, []byte{0x0F, o}, a, b), fAll, nil, false, false}
		case 13: // movzx/movsx/movsxd/bswap
			switch rnd.Intn(3) {
			case 0:
				if sz == 1 {
					sz = 4
				}
				o := []byte{0xB6, 0xB7, 0xBE, 0xBF}[rnd.Intn(4)]
				t = test{"movx", rr(sz, []byte{0x0F, o}, a, b), fAll, nil, false, false}
			case 1:
				t = test{"movsxd", rr(8, []byte{0x63}, a, b), fAll, nil, false, false}
			default:
				code := []byte{0x48 | (b>>3)&1, 0x0F, 0xC8 | b&7}
				if rnd.Intn(2) == 0 {
					code = []byte{0x40 | (b>>3)&1, 0x0F, 0xC8 | b&7}
				}
				t = test{"bswap", code, fAll, nil, false, false}
			}
		case 14: // inc/dec/not/neg
			r := byte(rnd.Intn(2))
			t = test{"incdec", rr(sz, []byte{w(sz, 0xFE)}, r, b), fAll, nil, false, false}
		case 15: // misc flags ops
			ops := [][]byte{{0xF5}, {0xF8}, {0xF9}, {0x9E}, {0x9F}, {0x98}, {0x48, 0x98}, {0x99}, {0x48, 0x99}, {0x66, 0x98}, {0x66, 0x99}}
			t = test{"misc", ops[rnd.Intn(len(ops))], fAll, nil, false, false}
		case 16: // lea
			base, idx := rreg(), rreg()
			sc := byte(rnd.Intn(4))
			rex := byte(0x48) | (a>>3)<<2 | (idx>>3)<<1 | base>>3
			code := []byte{rex, 0x8D, 0x84 | (a&7)<<3, sc<<6 | (idx&7)<<3 | base&7}
			code = binary.LittleEndian.AppendUint32(code, rnd.Uint32())
			t = test{"lea", code, fAll, nil, false, false}
		case 17: // memory ALU
			op := byte(rnd.Intn(8))<<3 | byte(rnd.Intn(2))<<1
			code := rm12(sz, []byte{w(sz, op)}, a, byte(rnd.Intn(120)))
			t = test{"memalu", code, fAll &^ fAF, nil, false, false}
		case 18: // string ops
			ops := [][]byte{{0xF3, 0xA4}, {0xF3, 0x48, 0xA5}, {0xF3, 0xAA}, {0xF3, 0x48, 0xAB}, {0xF3, 0xA6}, {0xF2, 0xAE}, {0xA4}, {0xAD}}
			t = test{"str", ops[rnd.Intn(len(ops))], fAll, nil, false, false}
		case 19: // rotates by 1/imm in memory
			r := byte(rnd.Intn(4))
			cnt := byte(rnd.Intn(8))
			code := append(rm12(sz, []byte{w(sz, 0xC0)}, r, byte(rnd.Intn(120))), cnt)
			t = test{"memrot", code, fCF, nil, false, false}
			if cnt == 0 {
				t.fmask = fAll
			}
		default:
			t = sseTest()
		}
		ts = append(ts, t)
	}
	return ts
}

func xr() byte { return byte(rnd.Intn(8)) }

func sseTest() test {
	a, b := xr(), xr()
	mk := func(pfx []byte, op ...byte) []byte {
		code := append([]byte{}, pfx...)
		code = append(code, op...)
		return append(code, 0xC0|a<<3|b)
	}
	k := rnd.Intn(8)
	switch k {
	case 0, 1, 2: // 66 0F integer ops
		ops := []byte{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x74, 0x75, 0x76,
			0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4,
			0xE5, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF8, 0xF9, 0xFA,
			0xFB, 0xFC, 0xFD, 0xFE}
		return test{"sse-int", mk([]byte{0x66}, 0x0F, ops[rnd.Intn(len(ops))]), fAll, nil, true, false}
	case 3: // 66 0F 38
		ops := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x17, 0x1C, 0x1D, 0x1E,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2B, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37, 0x38, 0x39,
			0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41}
		return test{"sse38", mk([]byte{0x66}, 0x0F, 0x38, ops[rnd.Intn(len(ops))]), fAll, nil, true, false}
	case 4: // 66 0F 3A imm
		ops := []byte{0x0C, 0x0D, 0x0E, 0x0F, 0x42, 0x60, 0x61, 0x62, 0x63}
		o := ops[rnd.Intn(len(ops))]
		imm := byte(rnd.Intn(256))
		if o >= 0x60 {
			imm &= 0x7F
		}
		return test{"sse3a", append(mk([]byte{0x66}, 0x0F, 0x3A, o), imm), fAll, func(s *state) {
			s.R[0] = uint64(rnd.Intn(20))
			s.R[2] = uint64(rnd.Intn(20))
		}, true, false}
	case 5: // shuffles / imm forms
		switch rnd.Intn(4) {
		case 0:
			return test{"pshufd", append(mk([]byte{0x66}, 0x0F, 0x70), byte(rnd.Intn(256))), fAll, nil, true, false}
		case 1:
			return test{"shufps", append(mk(nil, 0x0F, 0xC6), byte(rnd.Intn(256))), fAll, nil, true, false}
		case 2:
			o := 0x71 + byte(rnd.Intn(3))
			r := []byte{2, 4, 6}[rnd.Intn(3)]
			if o == 0x73 && r == 4 {
				r = 2
			}
			code := []byte{0x66, 0x0F, o, 0xC0 | r<<3 | b, byte(rnd.Intn(70))}
			return test{"pshiftimm", code, fAll, nil, true, false}
		default:
			code := []byte{0x66, 0x0F, 0x73, 0xC0 | []byte{3, 7}[rnd.Intn(2)]<<3 | b, byte(rnd.Intn(20))}
			return test{"pbyteshift", code, fAll, nil, true, false}
		}
	default: // float ops on nice values
		pfx := [][]byte{nil, {0x66}, {0xF3}, {0xF2}}[rnd.Intn(4)]
		ops := []byte{0x51, 0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F, 0x5A, 0x54, 0x55, 0x56, 0x57, 0x14, 0x15, 0x2E, 0x2F, 0xC2}
		o := ops[rnd.Intn(len(ops))]
		if (o >= 0x54 && o <= 0x57 || o == 0x14 || o == 0x15 || o == 0x2E || o == 0x2F) && len(pfx) > 0 && pfx[0] != 0x66 {
			pfx = nil
		}
		code := mk(pfx, 0x0F, o)
		if o == 0xC2 {
			code = append(code, byte(rnd.Intn(8)))
		}
		return test{"sse-fp", code, fAll, nil, true, true}
	}
}

func randState(t *test, memAddr uint64) state {
	var s state
	for i := range s.R {
		s.R[i] = rv()
	}
	s.R[12] = memAddr
	s.Flags = 0x202 | (rnd.Uint64() & fAll)
	for i := 0; i < 8; i++ {
		for j := range s.X[i] {
			s.X[i][j] = byte(rnd.Intn(256))
		}
		if t.nanOK || rnd.Intn(2) == 0 {
			// nice float values
			for j := 0; j < 4; j++ {
				f := float32(rnd.Intn(2000)-1000) / float32(1+rnd.Intn(16))
				binary.LittleEndian.PutUint32(s.X[i][4*j:], math.Float32bits(f))
			}
			if rnd.Intn(2) == 0 {
				for j := 0; j < 2; j++ {
					f := float64(rnd.Intn(2000)-1000) / float64(1+rnd.Intn(16))
					binary.LittleEndian.PutUint64(s.X[i][8*j:], math.Float64bits(f))
				}
			}
		}
	}
	for i := range s.Mem {
		s.Mem[i] = byte(rnd.Intn(256))
	}
	if t.name == "str" {
		s.R[6] = memAddr + uint64(rnd.Intn(64))
		s.R[7] = memAddr + 64 + uint64(rnd.Intn(64))
		s.R[1] = uint64(rnd.Intn(8))
		s.Flags &^= 0x400
	}
	if t.fix != nil {
		t.fix(&s)
	}
	return s
}

func writeState(wr io.Writer, s *state) {
	var buf [8 * (17 + 32)]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint64(buf[8*i:], s.R[i])
	}
	binary.LittleEndian.PutUint64(buf[128:], s.Flags)
	for i := 0; i < 16; i++ {
		copy(buf[136+16*i:], s.X[i][:])
	}
	wr.Write(buf[:])
	wr.Write(s.Mem[:])
}

func readState(rd io.Reader) state {
	var buf [8*(17+32) + 256]byte
	if _, err := io.ReadFull(rd, buf[:]); err != nil {
		panic(err)
	}
	var s state
	for i := 0; i < 16; i++ {
		s.R[i] = binary.LittleEndian.Uint64(buf[8*i:])
	}
	s.Flags = binary.LittleEndian.Uint64(buf[128:])
	for i := 0; i < 16; i++ {
		copy(s.X[i][:], buf[136+16*i:])
	}
	copy(s.Mem[:], buf[8*(17+32):])
	return s
}

func emulate(t *test, in state, memAddr uint64) (out state, err error) {
	m := mem.New()
	const codeBase = 0x10000000
	m.Map(codeBase, 0x10000, 7, mem.MemPrivate, "code")
	m.Map(0x20000000, 0x10000, 7, mem.MemPrivate, "stack")
	mb := memAddr &^ 0xFFFF
	m.Map(mb, 0x20000, 7, mem.MemPrivate, "data")
	m.Write(codeBase, append(append([]byte{}, t.code...), 0xC3))
	m.Write(memAddr, in.Mem[:])
	c := cpu.New(m)
	c.R = in.R
	c.R[4] = 0x2000F000
	c.Push(0x10008000) // return sentinel
	c.Flags = in.Flags
	for i := 0; i < 8; i++ {
		c.X[i] = in.X[i]
	}
	c.RIP = codeBase
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	for n := 0; n < 10000 && c.RIP != 0x10008000; n++ {
		c.Run(1)
	}
	out.R = c.R
	out.R[4] = in.R[4]
	out.Flags = c.Flags
	for i := 0; i < 8; i++ {
		out.X[i] = c.X[i]
	}
	m.Read(memAddr, out.Mem[:])
	return out, nil
}

func main() {
	runner := os.Args[1]
	ts := gen()
	cmd := exec.Command(runner)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	br := bufio.NewReader(stdout)
	var ab [8]byte
	io.ReadFull(br, ab[:])
	memAddr := binary.LittleEndian.Uint64(ab[:])
	ins := make([]state, len(ts))
	go func() {
		bw := bufio.NewWriter(stdin)
		for i := range ts {
			ins[i] = randState(&ts[i], memAddr)
		}
		for i := range ts {
			binary.Write(bw, binary.LittleEndian, uint32(len(ts[i].code)+1))
			bw.Write(ts[i].code)
			bw.WriteByte(0xC3)
			writeState(bw, &ins[i])
		}
		bw.Flush()
		stdin.Close()
	}()
	fails := 0
	byName := map[string]int{}
	for i := range ts {
		if os.Getenv("DBG") != "" {
			fmt.Fprintf(os.Stderr, "case %d %s % x\n", i, ts[i].name, ts[i].code)
		}
		nat := readState(br)
		t := &ts[i]
		emu, err := emulate(t, ins[i], memAddr)
		bad := ""
		if err != nil {
			bad = err.Error()
		} else {
			for r := 0; r < 16; r++ {
				if r != 4 && nat.R[r] != emu.R[r] {
					bad += fmt.Sprintf(" r%d nat=%#x emu=%#x", r, nat.R[r], emu.R[r])
				}
			}
			if (nat.Flags^emu.Flags)&t.fmask != 0 {
				bad += fmt.Sprintf(" flags nat=%#x emu=%#x mask=%#x", nat.Flags&t.fmask, emu.Flags&t.fmask, t.fmask)
			}
			for x := 0; x < 8; x++ {
				if nat.X[x] != emu.X[x] {
					bad += fmt.Sprintf(" xmm%d nat=%x emu=%x", x, nat.X[x], emu.X[x])
				}
			}
			if nat.Mem != emu.Mem {
				bad += " mem differs"
			}
		}
		if bad != "" {
			fails++
			byName[t.name]++
			if byName[t.name] <= 3 {
				fmt.Printf("FAIL %s code=% x in.r=%x in.fl=%#x\n   %s\n", t.name, t.code, ins[i].R, ins[i].Flags, bad)
			}
		}
	}
	cmd.Wait()
	fmt.Printf("%d/%d failed %v\n", fails, len(ts), byName)
}
