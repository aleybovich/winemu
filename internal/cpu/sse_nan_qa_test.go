package cpu

import "testing"

// MIN/MAX return the second operand unchanged (an SNaN is not quieted) when
// either is a NaN or both are zero; CMPPS treats NaN as unordered; packed
// arithmetic applies the NaN rules per lane.
func TestSSENaNMinMaxCmpPacked(t *testing.T) {
	cases := []struct {
		name string
		insn []byte
		a, b [4]uint32
		want [4]uint32
	}{
		{"minss snan,1", []byte{0xF3, 0x0F, 0x5D, 0xC1}, [4]uint32{0x7F800001, 9, 9, 9}, [4]uint32{one32}, [4]uint32{one32, 9, 9, 9}},
		{"minss 1,snan", []byte{0xF3, 0x0F, 0x5D, 0xC1}, [4]uint32{one32, 9, 9, 9}, [4]uint32{0xFF800001}, [4]uint32{0xFF800001, 9, 9, 9}},
		{"maxss -0,+0", []byte{0xF3, 0x0F, 0x5F, 0xC1}, [4]uint32{0x80000000}, [4]uint32{0}, [4]uint32{0}},
		{"maxps qnan lanes", []byte{0x0F, 0x5F, 0xC1}, [4]uint32{0x7FC00001, one32, 0, 0x7FC00002}, [4]uint32{one32, 0x7FC00003, 0x80000000, 0x7F800004},
			[4]uint32{one32, 0x7FC00003, 0x80000000, 0x7F800004}},
		{"cmpps unord", []byte{0x0F, 0xC2, 0xC1, 0x03}, [4]uint32{0x7FC00000, one32, 0x7F800001, one32}, [4]uint32{one32, one32, one32, 0xFFC00000},
			[4]uint32{^uint32(0), 0, ^uint32(0), ^uint32(0)}},
		{"cmpps eq nan", []byte{0x0F, 0xC2, 0xC1, 0x00}, [4]uint32{0x7FC00000, one32, 0, 0}, [4]uint32{0x7FC00000, one32, 0x80000000, one32},
			[4]uint32{0, ^uint32(0), ^uint32(0), 0}},
		{"cmpps neq nan", []byte{0x0F, 0xC2, 0xC1, 0x04}, [4]uint32{0x7FC00000, one32, 0, 0}, [4]uint32{0x7FC00000, one32, 0x80000000, one32},
			[4]uint32{^uint32(0), 0, 0, ^uint32(0)}},
		{"cmpps nlt nan", []byte{0x0F, 0xC2, 0xC1, 0x05}, [4]uint32{0x7FC00000, one32, 0, one32}, [4]uint32{one32, 0x7F800001, one32, 0},
			[4]uint32{^uint32(0), ^uint32(0), 0, ^uint32(0)}},
		{"cmpps nle nan", []byte{0x0F, 0xC2, 0xC1, 0x06}, [4]uint32{0x7FC00000, one32, one32, one32}, [4]uint32{one32, 0xFFC00000, one32, 0},
			[4]uint32{^uint32(0), ^uint32(0), 0, ^uint32(0)}},
		{"addps per lane", []byte{0x0F, 0x58, 0xC1}, [4]uint32{0x7F800001, inf32, one32, 0xFFC00009}, [4]uint32{0x7F800002, ninf32, 0x7F80000A, 0x7FC00008},
			[4]uint32{0x7FC00001, defNaN32, 0x7FC0000A, 0xFFC00009}},
		{"mulps snan both", []byte{0x0F, 0x59, 0xC1}, [4]uint32{0xFF800003, 0, one32, one32}, [4]uint32{0x7F800004, inf32, one32, one32},
			[4]uint32{0xFFC00003, defNaN32, one32, one32}},
	}
	for _, c := range cases {
		cpu := runSSE(t, c.insn, c.a, c.b)
		for i := range 4 {
			if got := cpu.X[0].D(i); got != c.want[i] {
				t.Errorf("%s lane %d: %#08x, want %#08x", c.name, i, got, c.want[i])
			}
		}
	}
	// MINSD/MAXSD: the second operand, unchanged, when either is a NaN
	for _, c := range []struct {
		name string
		insn []byte
		a, b uint64
	}{
		{"minsd qnan,1", []byte{0xF2, 0x0F, 0x5D, 0xC1}, 0x7FF8000000000001, 0x3FF0000000000000},
		{"minsd 1,snan", []byte{0xF2, 0x0F, 0x5D, 0xC1}, 0x3FF0000000000000, 0xFFF0000000000002},
		{"maxsd snan,1", []byte{0xF2, 0x0F, 0x5F, 0xC1}, 0x7FF0000000000003, 0x3FF0000000000000},
		{"maxsd 1,qnan", []byte{0xF2, 0x0F, 0x5F, 0xC1}, 0x3FF0000000000000, 0x7FF8000000000004},
	} {
		cpu := runSSE(t, c.insn, q2d(c.a, 0), q2d(c.b, 0))
		if got := cpu.X[0].Q(0); got != c.b {
			t.Errorf("%s = %#016x, want %#016x", c.name, got, c.b)
		}
	}
	// double: first source wins when both are NaN, sign kept
	cpu := runSSE(t, []byte{0xF2, 0x0F, 0x58, 0xC1}, q2d(0xFFF0000000000001, 0), q2d(0x7FF8000000000002, 0))
	if got := uint64(cpu.X[0].D(0)) | uint64(cpu.X[0].D(1))<<32; got != 0xFFF8000000000001 {
		t.Errorf("addsd snan+qnan = %#x", got)
	}
}

// HSUB subtracts the upper element of each pair from the lower one.
func TestSSE3HsubValues(t *testing.T) {
	cpu := runSSE(t, []byte{0xF2, 0x0F, 0x7D, 0xC1}, [4]uint32{f32b(5), f32b(2), f32b(1), f32b(4)}, [4]uint32{f32b(10), f32b(3), f32b(0), f32b(-1)})
	for i, w := range []float32{3, -3, 7, 1} {
		if got := cpu.X[0].F32(i); got != w {
			t.Errorf("hsubps lane %d = %v, want %v", i, got, w)
		}
	}
	cpu = runSSE(t, []byte{0x66, 0x0F, 0x7D, 0xC1}, q2d(f64b(5), f64b(2)), q2d(f64b(10), f64b(3)))
	if a, b := cpu.X[0].F64(0), cpu.X[0].F64(1); a != 3 || b != 7 {
		t.Errorf("hsubpd = %v %v, want 3 7", a, b)
	}
}
