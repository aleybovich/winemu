package win

import (
	"math"
	"strings"
	"testing"

	"winemu/internal/mem"
)

// spanStr maps four chunks followed by unmapped memory and places s (plus its
// NUL) so that it starts before bytes ahead of the chunk boundary. With
// before == 0 the terminator is the last mapped byte of the mapping.
func spanStr(h *testEmu, s string, wide bool, before uint64) uint64 {
	h.t.Helper()
	base := uint64(0x6e0000000)
	for !h.E.Mem.IsFree(base, 5*mem.ChunkSize) {
		base += 8 * mem.ChunkSize
	}
	if _, err := h.E.Mem.Map(base, 4*mem.ChunkSize, mem.PageReadWrite, mem.MemPrivate, "span"); err != nil {
		h.t.Fatalf("map: %v", err)
	}
	var b []byte
	if wide {
		for _, r := range s {
			b = append(b, byte(r), byte(r>>8))
		}
		b = append(b, 0, 0)
	} else {
		b = append([]byte(s), 0)
	}
	a := base + mem.ChunkSize - before
	if before == 0 {
		a = base + 4*mem.ChunkSize - uint64(len(b))
	}
	h.write(a, b)
	return a
}

func TestQAStrtoIntBoundaries(t *testing.T) {
	h := newTestEmu(t)
	ep := h.alloc(8)
	long := strings.Repeat("0", 70000) + "17"
	cases := []struct {
		fn    string
		s     string
		base  uint64
		want  uint64
		end   int
		errno uint32
	}{
		{"strtol", "\v\f 5", 10, 5, 4, 0},
		{"strtoul", "-1", 10, 0xFFFFFFFF, 2, 0},
		{"strtoul", "-4294967296", 10, 0xFFFFFFFF, 11, erange},
		{"strtoull", "-1", 10, math.MaxUint64, 2, 0},
		{"strtol", "0X1f", 0, 31, 4, 0},
		{"strtol", "-0x10", 0, uint64(math.MaxUint64 - 15), 5, 0},
		{"strtol", "0x1f", 16, 31, 4, 0},
		{"strtol", "0X", 0, 0, 1, 0},
		{"strtol", "+", 10, 0, 0, 0},
		{"strtol", "z", 36, 35, 1, 0},
		{"strtoll", "9223372036854775808", 10, math.MaxInt64, 19, erange},
		{"strtoll", "-9223372036854775808", 10, 1 << 63, 20, 0},
		{"strtol", long, 10, 17, len(long), 0},
		{"strtol", strings.Repeat("9", 600), 10, math.MaxInt32, 600, erange},
	}
	for _, c := range cases {
		for _, before := range []uint64{0, 1, 300} {
			p := spanStr(h, c.s, false, before)
			h.setErrno(0)
			got := h.call(dUcrt, c.fn, p, ep, c.base)
			if c.fn == "strtol" {
				got = uint64(int64(int32(got)))
			} else if c.fn == "strtoul" {
				got = uint64(uint32(got))
			}
			if got != c.want {
				t.Errorf("%s(%.20q,%d)@%d = %#x, want %#x", c.fn, c.s, c.base, before, got, c.want)
			}
			if end := h.r64(ep) - p; end != uint64(c.end) {
				t.Errorf("%s(%.20q)@%d end = %d, want %d", c.fn, c.s, before, end, c.end)
			}
			if e := h.errno(); e != c.errno {
				t.Errorf("%s(%.20q)@%d errno = %d, want %d", c.fn, c.s, before, e, c.errno)
			}
		}
	}
	// a wide unit straddling the chunk boundary
	for _, before := range []uint64{1, 3, 0} {
		p := spanStr(h, " 123456x", true, before)
		if got := h.call(dUcrt, "wcstol", p, ep, 10); got != 123456 || h.r64(ep)-p != 14 {
			t.Errorf("wcstol@%d = %d end %d", before, got, h.r64(ep)-p)
		}
	}
}

func TestQAStrtodBoundaries(t *testing.T) {
	h := newTestEmu(t)
	ep := h.alloc(8)
	longOne := "1." + strings.Repeat("0", 70000) + "1"
	cases := []struct {
		s     string
		want  float64
		end   int
		errno uint32
	}{
		{"0x1.8p3", 12, 7, 0},
		{"0x1.8", 1.5, 5, 0},
		{"-0x", math.Copysign(0, -1), 2, 0},
		{"infinit", math.Inf(1), 3, 0},
		{"nan", math.NaN(), 3, 0},
		{"1e-400", 0, 6, erange},
		{"-1e-400", math.Copysign(0, -1), 7, erange},
		{"0e-400", 0, 6, 0},
		{"4.9e-324", 5e-324, 8, 0}, // smallest denormal: representable, no ERANGE
		// Wine ucrtbase/tests/string.c test_strtod (Windows-verified oracle)
		{"2.47e-324", 0, 9, erange},
		{"2.48e-324", 5e-324, 9, 0},
		{"0x1p-1026", 1.3906711615670009e-309, 9, 0},
		{"0x0p10000000000000000000000000", 0, 30, 0},
		{"0x0.000p-99999", 0, 14, 0},
		{"0x.1p-99999", 0, 11, erange},
		{"infini", math.Inf(1), 3, 0},
		{"1e308", 1e308, 5, 0},
		{longOne, 1, len(longOne), 0},
	}
	for _, c := range cases {
		for _, before := range []uint64{0, 2, 600} {
			p := spanStr(h, c.s, false, before)
			h.setErrno(0)
			h.call(dUcrt, "strtod", p, ep)
			got := h.E.Cur.CPU.X[0].F64(0)
			if !(math.Float64bits(got) == math.Float64bits(c.want) || math.IsNaN(c.want) && math.IsNaN(got)) {
				t.Errorf("strtod(%.20q)@%d = %v, want %v", c.s, before, got, c.want)
			}
			if end := h.r64(ep) - p; end != uint64(c.end) {
				t.Errorf("strtod(%.20q)@%d end = %d, want %d", c.s, before, end, c.end)
			}
			if e := h.errno(); e != c.errno {
				t.Errorf("strtod(%.20q)@%d errno = %d, want %d", c.s, before, e, c.errno)
			}
		}
	}
	f32 := []struct {
		s     string
		want  uint32
		errno uint32
	}{
		{"1e-50", 0, erange},
		{"1e-45", 1, 0}, // float denormal
		// halfway between two floats only after rounding to double first
		{"1.00000017881393432617187499", 0x3f800001, 0},
	}
	for _, c := range f32 {
		h.setErrno(0)
		h.call(dUcrt, "strtof", h.astr(c.s), ep)
		if got := math.Float32bits(h.E.Cur.CPU.X[0].F32(0)); got != c.want || h.errno() != c.errno {
			t.Errorf("strtof(%q) = %#x errno %d, want %#x errno %d", c.s, got, h.errno(), c.want, c.errno)
		}
	}
	h.setErrno(0)
	h.call(dUcrt, "wcstod", h.wstr("1e-400"), ep)
	if h.errno() != erange {
		t.Errorf("wcstod underflow errno = %d", h.errno())
	}
}

func TestQAStrScanAcrossChunks(t *testing.T) {
	h := newTestEmu(t)
	s := strings.Repeat("a", 5000) + "needle" + strings.Repeat("b", 2000)
	for _, before := range []uint64{0, 5003, 5000, 4999, 1} {
		p := spanStr(h, s, false, before)
		if got := h.call(dUcrt, "strlen", p); got != uint64(len(s)) {
			t.Errorf("strlen@%d = %d", before, got)
		}
		if got := h.call(dUcrt, "strstr", p, h.astr("needle")); got != p+5000 {
			t.Errorf("strstr@%d = %#x, want %#x", before, got, p+5000)
		}
		if got := h.call(dUcrt, "strchr", p, 'n'); got != p+5000 {
			t.Errorf("strchr@%d = %#x", before, got)
		}
		if got := h.call(dUcrt, "strchr", p, 0); got != p+uint64(len(s)) {
			t.Errorf("strchr NUL@%d = %#x", before, got)
		}
		if got := h.call(dUcrt, "strstr", p, h.astr("bbx")); got != 0 {
			t.Errorf("strstr miss@%d = %#x", before, got)
		}
	}
}

func TestQAMemcmpUnsigned(t *testing.T) {
	h := newTestEmu(t)
	a, b := h.alloc(1000), h.alloc(1000)
	h.write(a+700, []byte{0x80})
	h.write(b+700, []byte{0x7F})
	if got := int32(h.call(dVc, "memcmp", a, b, 1000)); got <= 0 {
		t.Errorf("memcmp 0x80 vs 0x7F = %d, want > 0", got)
	}
	if got := int32(h.call(dVc, "memcmp", a, b, 700)); got != 0 {
		t.Errorf("memcmp prefix = %d", got)
	}

}

// strtod("nan") is the x86 default quiet NaN, negated by a leading '-'.
func TestQAStrtodNaNBits(t *testing.T) {
	h := newTestEmu(t)
	for s, want := range map[string]uint64{"nan": 0x7FF8000000000000, "-nan": 0xFFF8000000000000, "+NaN(1)": 0x7FF8000000000000} {
		h.call(dUcrt, "strtod", h.astr(s), 0)
		if got := math.Float64bits(h.E.Cur.CPU.X[0].F64(0)); got != want {
			t.Errorf("strtod(%q) bits = %#x, want %#x", s, got, want)
		}
	}
	h.call(dUcrt, "strtof", h.astr("-nan"), 0)
	if got := math.Float32bits(h.E.Cur.CPU.X[0].F32(0)); got != 0xFFC00000 {
		t.Errorf("strtof(-nan) bits = %#x", got)
	}
}

// A NULL string or a base outside {0, 2..36} is an invalid parameter (UCRT
// _VALIDATE_RETURN): with no handler installed the process ends with
// STATUS_INVALID_CRT_PARAMETER; with one, the handler runs and the call
// returns 0 with errno EINVAL and the end pointer set to the string (NULL).
func TestQAStrtoInvalidParameter(t *testing.T) {
	var str uint64 // "12", set per emulator below
	fns := []struct {
		name string
		args func(ep uint64) []uint64
	}{
		{"strtol", func(ep uint64) []uint64 { return []uint64{str, ep, 1} }},
		{"strtoul", func(ep uint64) []uint64 { return []uint64{str, ep, 37} }},
		{"wcstol", func(ep uint64) []uint64 { return []uint64{str, ep, 0xFFFFFFFF} }}, // -1
		{"strtol", func(ep uint64) []uint64 { return []uint64{0, ep, 10} }},
		{"wcstoull", func(ep uint64) []uint64 { return []uint64{0, ep, 0} }},
		{"strtod", func(ep uint64) []uint64 { return []uint64{0, ep} }},
		{"wcstof", func(ep uint64) []uint64 { return []uint64{0, ep} }},
		{"atoi", func(uint64) []uint64 { return []uint64{0} }},
		{"_wtof", func(uint64) []uint64 { return []uint64{0} }},
	}
	for _, f := range fns {
		h := newTestEmu(t)
		ep := h.alloc(8)
		str = h.astr("12")
		if _, exited, code := h.tryCall(dUcrt, f.name, f.args(ep)...); !exited || code != 0xC0000417 {
			t.Errorf("%s(%v) without handler: exited=%v code=%#x, want 0xC0000417", f.name, f.args(ep), exited, code)
		}

		h = newTestEmu(t)
		ep = h.alloc(8)
		str = h.astr("12")
		handler := h.alloc(16)
		h.write(handler, []byte{0xC3}) // ret
		h.call(dUcrt, "_set_invalid_parameter_handler", handler)
		h.setErrno(0)
		h.w64(ep, 0x1234)
		if r := h.call(dUcrt, f.name, f.args(ep)...); r != 0 {
			t.Errorf("%s(NULL) = %#x, want 0", f.name, r)
		}
		if got := h.errno(); got != einval {
			t.Errorf("%s(NULL) errno = %d, want EINVAL", f.name, got)
		}
		if a := f.args(ep); len(a) > 1 && h.r64(ep) != a[0] {
			t.Errorf("%s(%#x) endptr = %#x, want the string", f.name, a[0], h.r64(ep))
		}
	}
}

// memmove/memcpy around the stack-buffer threshold, overlapping both ways.
func TestQAMemmoveThreshold(t *testing.T) {
	h := newTestEmu(t)
	buf := h.alloc(4096)
	for _, fn := range []string{"memmove", "memcpy"} {
		for _, n := range []int{1, 511, 512, 513, 1500} {
			for _, shift := range []int{-7, 0, 7} {
				ref := make([]byte, 4096)
				for i := range ref {
					ref[i] = byte(i*7 + n)
				}
				h.write(buf, ref)
				src, dst := 1024, 1024+shift
				copy(ref[dst:dst+n], ref[src:src+n])
				if r := h.call(dUcrt, fn, buf+uint64(dst), buf+uint64(src), uint64(n)); r != buf+uint64(dst) {
					t.Errorf("%s(n=%d,shift=%d) = %#x", fn, n, shift, r)
				}
				if got := h.read(buf, 4096); string(got) != string(ref) {
					t.Errorf("%s(n=%d,shift=%d): memory differs", fn, n, shift)
				}
			}
		}
	}
}
