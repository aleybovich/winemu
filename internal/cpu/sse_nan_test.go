package cpu

import (
	"math"
	"testing"

	"winemu/internal/mem"
)

// runSSE executes one instruction with xmm0 = a, xmm1 = b (bit patterns,
// four dwords each) and returns the CPU afterwards.
func runSSE(t *testing.T, insn []byte, a, b [4]uint32) *CPU {
	t.Helper()
	m := mem.New()
	if _, err := m.Map(codeBase, mem.ChunkSize, mem.PageExecuteReadWrite, mem.MemPrivate, "code"); err != nil {
		t.Fatal(err)
	}
	m.Write(codeBase, append(append([]byte{}, insn...), 0x0F, 0x04, hyperpStop, 0, 0, 0))
	c := New(m)
	c.Hyper = func(c *CPU, idx uint32) { c.Stop = true }
	c.RIP = codeBase
	for i := range 4 {
		c.X[0].SetD(i, a[i])
		c.X[1].SetD(i, b[i])
	}
	c.Run(100)
	return c
}

func q2d(lo, hi uint64) [4]uint32 {
	return [4]uint32{uint32(lo), uint32(lo >> 32), uint32(hi), uint32(hi >> 32)}
}

const (
	defNaN32 = 0xFFC00000         // x86 QNaN floating-point indefinite
	defNaN64 = 0xFFF8000000000000 // ditto, double
	inf32    = 0x7F800000
	ninf32   = 0xFF800000
	one32    = 0x3F800000
	inf64    = 0x7FF0000000000000
	ninf64   = 0xFFF0000000000000
)

func f32b(f float32) uint32 { return math.Float32bits(f) }
func f64b(f float64) uint64 { return math.Float64bits(f) }

// TestSSEScalarSingleNaN covers the x86 NaN rules for single-precision
// scalar ops: invalid operations give the default NaN, a NaN operand is
// returned quieted with the first source winning, upper lanes are kept.
func TestSSEScalarSingleNaN(t *testing.T) {
	const keep = 0x11223344
	cases := []struct {
		name string
		insn []byte
		a, b uint32
		want uint32
	}{
		{"sqrtss -1", []byte{0xF3, 0x0F, 0x51, 0xC1}, 0, f32b(-1), defNaN32},
		{"sqrtss -inf", []byte{0xF3, 0x0F, 0x51, 0xC1}, 0, ninf32, defNaN32},
		{"sqrtss -0", []byte{0xF3, 0x0F, 0x51, 0xC1}, 0, 0x80000000, 0x80000000},
		{"sqrtss 4", []byte{0xF3, 0x0F, 0x51, 0xC1}, 0, f32b(4), f32b(2)},
		{"sqrtss qnan", []byte{0xF3, 0x0F, 0x51, 0xC1}, 0, 0x7FC12345, 0x7FC12345},
		{"sqrtss snan", []byte{0xF3, 0x0F, 0x51, 0xC1}, 0, 0xFF812345, 0xFFC12345},
		{"rsqrtss -1", []byte{0xF3, 0x0F, 0x52, 0xC1}, 0, f32b(-1), defNaN32},
		{"rsqrtss snan", []byte{0xF3, 0x0F, 0x52, 0xC1}, 0, 0x7F800001, 0x7FC00001},
		{"rcpss snan", []byte{0xF3, 0x0F, 0x53, 0xC1}, 0, 0x7F800001, 0x7FC00001},
		{"addss inf+-inf", []byte{0xF3, 0x0F, 0x58, 0xC1}, inf32, ninf32, defNaN32},
		{"subss inf-inf", []byte{0xF3, 0x0F, 0x5C, 0xC1}, inf32, inf32, defNaN32},
		{"mulss 0*inf", []byte{0xF3, 0x0F, 0x59, 0xC1}, 0, inf32, defNaN32},
		{"divss 0/0", []byte{0xF3, 0x0F, 0x5E, 0xC1}, 0, 0, defNaN32},
		{"divss inf/inf", []byte{0xF3, 0x0F, 0x5E, 0xC1}, ninf32, inf32, defNaN32},
		{"addss 1+2", []byte{0xF3, 0x0F, 0x58, 0xC1}, one32, f32b(2), f32b(3)},
		{"addss qnan+snan", []byte{0xF3, 0x0F, 0x58, 0xC1}, 0x7FC00001, 0x7F800002, 0x7FC00001},
		{"mulss snan*qnan", []byte{0xF3, 0x0F, 0x59, 0xC1}, 0xFF800005, 0x7FC00002, 0xFFC00005},
		{"divss 1/snan", []byte{0xF3, 0x0F, 0x5E, 0xC1}, one32, 0xFF800003, 0xFFC00003},
		{"subss qnan-1", []byte{0xF3, 0x0F, 0x5C, 0xC1}, 0x7FC0BEEF, one32, 0x7FC0BEEF},
	}
	for _, c := range cases {
		cpu := runSSE(t, c.insn, [4]uint32{c.a, keep, keep, keep}, [4]uint32{c.b, 7, 7, 7})
		if got := cpu.X[0].D(0); got != c.want {
			t.Errorf("%s: %#08x, want %#08x", c.name, got, c.want)
		}
		for i := 1; i < 4; i++ {
			if got := cpu.X[0].D(i); got != keep {
				t.Errorf("%s: lane %d = %#x, want preserved", c.name, i, got)
			}
		}
	}
}

func TestSSEScalarDoubleNaN(t *testing.T) {
	const keep = 0x1122334455667788
	cases := []struct {
		name string
		insn []byte
		a, b uint64
		want uint64
	}{
		{"sqrtsd -1", []byte{0xF2, 0x0F, 0x51, 0xC1}, 0, f64b(-1), defNaN64},
		{"sqrtsd -0", []byte{0xF2, 0x0F, 0x51, 0xC1}, 0, 1 << 63, 1 << 63},
		{"sqrtsd 9", []byte{0xF2, 0x0F, 0x51, 0xC1}, 0, f64b(9), f64b(3)},
		{"sqrtsd snan", []byte{0xF2, 0x0F, 0x51, 0xC1}, 0, 0x7FF0000000000001, 0x7FF8000000000001},
		{"addsd inf+-inf", []byte{0xF2, 0x0F, 0x58, 0xC1}, inf64, ninf64, defNaN64},
		{"mulsd 0*inf", []byte{0xF2, 0x0F, 0x59, 0xC1}, inf64, 0, defNaN64},
		{"divsd 0/0", []byte{0xF2, 0x0F, 0x5E, 0xC1}, 0, 1 << 63, defNaN64},
		{"subsd qnan-snan", []byte{0xF2, 0x0F, 0x5C, 0xC1}, 0x7FF8000000000009, 0xFFF0000000000001, 0x7FF8000000000009},
		{"addsd 1+snan", []byte{0xF2, 0x0F, 0x58, 0xC1}, f64b(1), 0xFFF0000000000003, 0xFFF8000000000003},
	}
	for _, c := range cases {
		cpu := runSSE(t, c.insn, q2d(c.a, keep), q2d(c.b, 5))
		if got := cpu.X[0].Q(0); got != c.want {
			t.Errorf("%s: %#016x, want %#016x", c.name, got, c.want)
		}
		if got := cpu.X[0].Q(1); got != keep {
			t.Errorf("%s: upper lane = %#x, want preserved", c.name, got)
		}
	}
}

func TestSSEPackedSqrtNaN(t *testing.T) {
	cpu := runSSE(t, []byte{0x0F, 0x51, 0xC1}, [4]uint32{}, [4]uint32{f32b(-4), f32b(16), 0x80000000, 0x7F800009})
	want := [4]uint32{defNaN32, f32b(4), 0x80000000, 0x7FC00009}
	for i := range 4 {
		if got := cpu.X[0].D(i); got != want[i] {
			t.Errorf("sqrtps lane %d: %#08x, want %#08x", i, got, want[i])
		}
	}
	cpu = runSSE(t, []byte{0x66, 0x0F, 0x51, 0xC1}, [4]uint32{}, q2d(f64b(-2), f64b(0.25)))
	if got := cpu.X[0].Q(0); got != defNaN64 {
		t.Errorf("sqrtpd lane 0: %#x", got)
	}
	if got := cpu.X[0].Q(1); got != f64b(0.5) {
		t.Errorf("sqrtpd lane 1: %#x", got)
	}
	cpu = runSSE(t, []byte{0x0F, 0x59, 0xC1}, [4]uint32{0, inf32, one32, 0x7FC00007}, [4]uint32{inf32, 0, f32b(3), one32})
	want = [4]uint32{defNaN32, defNaN32, f32b(3), 0x7FC00007}
	for i := range 4 {
		if got := cpu.X[0].D(i); got != want[i] {
			t.Errorf("mulps lane %d: %#08x, want %#08x", i, got, want[i])
		}
	}
}

func TestSSE3HorizontalNaN(t *testing.T) {
	// haddps xmm0, xmm1 (F2 0F 7C): lanes a0+a1, a2+a3, b0+b1, b2+b3
	cpu := runSSE(t, []byte{0xF2, 0x0F, 0x7C, 0xC1}, [4]uint32{inf32, ninf32, one32, one32}, [4]uint32{0x7F800001, one32, 0, 0})
	want := [4]uint32{defNaN32, f32b(2), 0x7FC00001, 0}
	for i := range 4 {
		if got := cpu.X[0].D(i); got != want[i] {
			t.Errorf("haddps lane %d: %#08x, want %#08x", i, got, want[i])
		}
	}
	// addsubpd xmm0, xmm1 (66 0F D0): a0-b0, a1+b1
	cpu = runSSE(t, []byte{0x66, 0x0F, 0xD0, 0xC1}, q2d(inf64, inf64), q2d(inf64, ninf64))
	if cpu.X[0].Q(0) != defNaN64 || cpu.X[0].Q(1) != defNaN64 {
		t.Errorf("addsubpd: %#x %#x", cpu.X[0].Q(0), cpu.X[0].Q(1))
	}
}

func TestSSECvtNaNIndefinite(t *testing.T) {
	for _, c := range []struct {
		name string
		insn []byte
		b    [4]uint32
		want uint64
	}{
		{"cvttss2si eax", []byte{0xF3, 0x0F, 0x2C, 0xC1}, [4]uint32{0x7FC00000}, 0x80000000},
		{"cvtss2si eax", []byte{0xF3, 0x0F, 0x2D, 0xC1}, [4]uint32{inf32}, 0x80000000},
		{"cvttsd2si rax", []byte{0xF2, 0x48, 0x0F, 0x2C, 0xC1}, q2d(0xFFF8000000000000, 0), 0x8000000000000000},
		{"cvtsd2si eax", []byte{0xF2, 0x0F, 0x2D, 0xC1}, q2d(f64b(3e9), 0), 0x80000000},
	} {
		cpu := runSSE(t, c.insn, [4]uint32{}, c.b)
		if got := cpu.R[RAX]; got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}
}
