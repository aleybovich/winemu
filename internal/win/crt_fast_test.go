package win

import (
	"math"
	"strings"
	"testing"

	"winemu/internal/mem"
)

// edgeStr maps one chunk followed by unmapped memory and places s (plus its
// NUL) so that the terminator is the last mapped byte: a scan that reads past
// the terminator faults.
func edgeStr(h *testEmu, s string, wide bool) uint64 {
	h.t.Helper()
	base := uint64(0x6f0000000)
	for !h.E.Mem.IsFree(base, 2*mem.ChunkSize) {
		base += 4 * mem.ChunkSize
	}
	if _, err := h.E.Mem.Map(base, mem.ChunkSize, mem.PageReadWrite, mem.MemPrivate, "edge"); err != nil {
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
	a := base + mem.ChunkSize - uint64(len(b))
	h.write(a, b)
	return a
}

func (h *testEmu) errno() uint32     { return h.r32(h.call(dUcrt, "_errno")) }
func (h *testEmu) setErrno(v uint32) { h.w32(h.call(dUcrt, "_errno"), v) }

func TestStrtoIntSemantics(t *testing.T) {
	h := newTestEmu(t)
	ep := h.alloc(8)
	cases := []struct {
		fn    string
		s     string
		base  uint64
		want  uint64
		end   int
		errno uint32
	}{
		{"strtol", "  -123abc", 10, uint64(math.MaxUint64 - 122), 6, 0},
		{"strtol", "0x1A", 0, 26, 4, 0},
		{"strtol", "0x", 16, 0, 1, 0},
		{"strtol", "0xg", 0, 0, 1, 0},
		{"strtol", "077", 0, 63, 3, 0},
		{"strtol", "\t\n+42 ", 0, 42, 5, 0},
		{"strtol", "2147483648", 10, math.MaxInt32, 10, erange},
		{"strtol", "-2147483649", 10, 0xFFFFFFFF80000000, 11, erange},
		{"strtol", "", 10, 0, 0, 0},
		{"strtol", "   ", 10, 0, 0, 0},
		{"strtol", "+-1", 10, 0, 0, 0},
		{"strtol", "- 1", 10, 0, 0, 0},
		{"strtol", "zz", 36, 1295, 2, 0},
		{"strtoul", "-1", 10, 0xFFFFFFFF, 2, 0},
		{"strtoul", "4294967296", 10, 0xFFFFFFFF, 10, erange},
		{"strtoull", "18446744073709551616", 10, math.MaxUint64, 20, erange},
		{"strtoll", "-9223372036854775808", 10, 1 << 63, 20, 0},
		{"strtoll", "9223372036854775808", 10, math.MaxInt64, 19, erange},
		{"_strtoi64", "0X7f", 16, 127, 4, 0},
	}
	for _, c := range cases {
		for _, edge := range []bool{false, true} {
			p := h.astr(c.s)
			if edge {
				p = edgeStr(h, c.s, false)
			}
			h.setErrno(0)
			h.w64(ep, 0)
			if got := h.call(dUcrt, c.fn, p, ep, c.base); got != c.want {
				t.Errorf("%s(%q,%d) = %#x, want %#x", c.fn, c.s, c.base, got, c.want)
			}
			if got := h.r64(ep) - p; got != uint64(c.end) {
				t.Errorf("%s(%q,%d) end = %d, want %d", c.fn, c.s, c.base, got, c.end)
			}
			if got := h.errno(); got != c.errno {
				t.Errorf("%s(%q,%d) errno = %d, want %d", c.fn, c.s, c.base, got, c.errno)
			}
		}
	}
	// NULL endptr is allowed.
	if got := h.call(dUcrt, "strtoul", h.astr("99"), 0, 10); got != 99 {
		t.Errorf("strtoul NULL endptr = %d", got)
	}
}

func TestWcstoIntSemantics(t *testing.T) {
	h := newTestEmu(t)
	ep := h.alloc(8)
	for _, edge := range []bool{false, true} {
		s := " -0x10z"
		p := h.wstr(s)
		if edge {
			p = edgeStr(h, s, true)
		}
		if got := h.call(dUcrt, "wcstol", p, ep, 0); got != uint64(math.MaxUint64-15) {
			t.Errorf("wcstol = %#x", got)
		}
		if got := h.r64(ep) - p; got != 2*6 {
			t.Errorf("wcstol end = %d units*2, want 12", got)
		}
	}
	// a non-ASCII code unit ends the number
	p := h.wstr("12é3")
	if got := h.call(dUcrt, "wcstoul", p, ep, 10); got != 12 || h.r64(ep)-p != 4 {
		t.Errorf("wcstoul non-ASCII = %d end %d", got, h.r64(ep)-p)
	}
	if got := h.call(dUcrt, "_wtoi", h.wstr("  -77x")); uint32(got) != uint32(0xFFFFFFB3) {
		t.Errorf("_wtoi = %#x", got)
	}
	if got := h.call(dUcrt, "_wtoi64", h.wstr("123456789012")); got != 123456789012 {
		t.Errorf("_wtoi64 = %d", got)
	}
}

func TestAtoiFamily(t *testing.T) {
	h := newTestEmu(t)
	if got := h.call(dUcrt, "atoi", h.astr(" 42xyz")); uint32(got) != 42 {
		t.Errorf("atoi = %d", got)
	}
	if got := h.call(dUcrt, "atoi", edgeStr(h, "-7", false)); uint32(got) != uint32(0xFFFFFFF9) {
		t.Errorf("atoi edge = %#x", got)
	}
	if got := h.call(dUcrt, "atoll", h.astr("-9000000000")); int64(got) != -9000000000 {
		t.Errorf("atoll = %d", int64(got))
	}
	h.setErrno(0)
	if got := h.call(dUcrt, "atoi", h.astr("99999999999")); uint32(got) != math.MaxInt32 || h.errno() != erange {
		t.Errorf("atoi overflow = %d errno %d, want INT_MAX ERANGE", got, h.errno())
	}
	if got := h.call(dUcrt, "atoi", h.astr("abc")); got != 0 {
		t.Errorf("atoi(abc) = %d", got)
	}
}

func TestStrtodSemantics(t *testing.T) {
	h := newTestEmu(t)
	ep := h.alloc(8)
	inf := math.Inf(1)
	cases := []struct {
		s     string
		want  float64
		end   int
		errno uint32
	}{
		{"  1.5e3x", 1500, 7, 0},
		{"-2.5", -2.5, 4, 0},
		{"inf", inf, 3, 0},
		{"-Infinity!", math.Inf(-1), 9, 0},
		{"1e999", inf, 5, erange},
		{"nan(abc)", math.NaN(), 8, 0},
		{"nan(a b)", math.NaN(), 3, 0},
		{"0x1p4", 16, 5, 0},
		{"1e+", 1, 1, 0},
		{".e1", 0, 0, 0},
		{"0x", 0, 1, 0},
		{"", 0, 0, 0},
	}
	for _, c := range cases {
		for _, edge := range []bool{false, true} {
			p := h.astr(c.s)
			if edge {
				p = edgeStr(h, c.s, false)
			}
			h.setErrno(0)
			h.call(dUcrt, "strtod", p, ep)
			got := h.E.Cur.CPU.X[0].F64(0)
			if !(got == c.want || math.IsNaN(c.want) && math.IsNaN(got)) {
				t.Errorf("strtod(%q) = %v, want %v", c.s, got, c.want)
			}
			if end := h.r64(ep) - p; end != uint64(c.end) {
				t.Errorf("strtod(%q) end = %d, want %d", c.s, end, c.end)
			}
			if e := h.errno(); e != c.errno {
				t.Errorf("strtod(%q) errno = %d, want %d", c.s, e, c.errno)
			}
		}
	}
	h.setErrno(0)
	h.call(dUcrt, "strtof", h.astr("1e39"), ep)
	if got := h.E.Cur.CPU.X[0].F32(0); !math.IsInf(float64(got), 1) || h.errno() != erange {
		t.Errorf("strtof(1e39) = %v errno %d, want +Inf ERANGE", got, h.errno())
	}
	h.setErrno(0)
	h.call(dUcrt, "wcstod", h.wstr(" 2.25z"), ep)
	if got := h.E.Cur.CPU.X[0].F64(0); got != 2.25 || h.errno() != 0 {
		t.Errorf("wcstod = %v errno %d", got, h.errno())
	}
	h.call(dUcrt, "atof", edgeStr(h, "3.5", false))
	if got := h.E.Cur.CPU.X[0].F64(0); got != 3.5 {
		t.Errorf("atof edge = %v", got)
	}
}

func TestStrScanBuiltins(t *testing.T) {
	h := newTestEmu(t)
	long := strings.Repeat("ab", 5000) + "needle" + strings.Repeat("c", 3000)
	p := h.astr(long)
	if got := h.call(dUcrt, "strlen", p); got != uint64(len(long)) {
		t.Errorf("strlen = %d", got)
	}
	if got := h.call(dUcrt, "strstr", p, h.astr("needle")); got != p+10000 {
		t.Errorf("strstr = %#x, want %#x", got, p+10000)
	}
	if got := h.call(dUcrt, "strstr", p, h.astr("needlf")); got != 0 {
		t.Errorf("strstr no match = %#x", got)
	}
	if got := h.call(dUcrt, "strstr", p, h.astr("")); got != p {
		t.Errorf("strstr empty needle = %#x", got)
	}
	// a match must not extend past the terminator
	q := h.astr("abc")
	h.write(q+4, []byte("def\x00"))
	if got := h.call(dUcrt, "strstr", q, h.astr("c")); got != q+2 {
		t.Errorf("strstr short = %#x", got)
	}
	if got := h.call(dUcrt, "strstr", q, h.astr("cd")); got != 0 {
		t.Errorf("strstr across NUL = %#x", got)
	}
	if got := h.call(dUcrt, "strchr", q, 'd'); got != 0 {
		t.Errorf("strchr past NUL = %#x", got)
	}
	if got := h.call(dUcrt, "strchr", q, 0); got != q+3 {
		t.Errorf("strchr NUL = %#x", got)
	}
	if got := h.call(dUcrt, "strchr", p, 'n'); got != p+10000 {
		t.Errorf("strchr long = %#x", got)
	}
	e := edgeStr(h, "xyz", false)
	if h.call(dUcrt, "strlen", e) != 3 || h.call(dUcrt, "strstr", e, h.astr("z")) != e+2 ||
		h.call(dUcrt, "strstr", e, h.astr("zz")) != 0 || h.call(dUcrt, "strchr", e, 'q') != 0 {
		t.Errorf("edge string scans wrong")
	}
	if got := h.call(dUcrt, "strstr", e, e); got != e {
		t.Errorf("strstr self = %#x", got)
	}
}

func TestMemBuiltins(t *testing.T) {
	h := newTestEmu(t)
	a, b := h.alloc(5000), h.alloc(5000)
	buf := make([]byte, 5000)
	for i := range buf {
		buf[i] = byte(i)
	}
	h.write(a, buf)
	if got := h.call(dVc, "memcpy", b, a, 5000); got != b || string(h.read(b, 5000)) != string(buf) {
		t.Errorf("memcpy")
	}
	if got := h.call(dVc, "memcmp", a, b, 5000); got != 0 {
		t.Errorf("memcmp equal = %d", got)
	}
	h.write(b+4999, []byte{0})
	if got := int32(h.call(dVc, "memcmp", a, b, 5000)); got != 1 {
		t.Errorf("memcmp last byte = %d", got)
	}
	if got := int32(h.call(dVc, "memcmp", b, a, 5000)); got != -1 {
		t.Errorf("memcmp reversed = %d", got)
	}
	if got := h.call(dVc, "memcmp", a, b, 0); got != 0 {
		t.Errorf("memcmp n=0 = %d", got)
	}
	// overlapping memmove, both directions
	h.write(a, []byte("0123456789"))
	h.call(dVc, "memmove", a+2, a, 6)
	if got := string(h.read(a, 10)); got != "0101234589" {
		t.Errorf("memmove fwd = %q", got)
	}
	h.write(a, []byte("0123456789"))
	h.call(dVc, "memmove", a, a+2, 6)
	if got := string(h.read(a, 10)); got != "2345676789" {
		t.Errorf("memmove back = %q", got)
	}
	if got := h.call(dVc, "memset", a, 0x1AB, 3); got != a || string(h.read(a, 4)) != "\xab\xab\xab5" {
		t.Errorf("memset = %q", h.read(a, 4))
	}
}

func BenchmarkStrtoulLongBuffer(b *testing.B) {
	h := newTestEmu(b)
	p := h.astr(strings.Repeat("1234 ", 200000))
	for b.Loop() {
		h.call(dUcrt, "strtoul", p+uint64(5*100000), 0, 10)
	}
}
