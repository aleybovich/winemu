package win

import "testing"

const (
	fmAllocate       = 0x100
	fmIgnore         = 0x200
	fmString         = 0x400
	fmHModule        = 0x800
	fmSystem         = 0x1000
	fmArray          = 0x2000
	fmMaxWidth       = 0xFF
	fileNotFoundText = "The system cannot find the file specified."
)

func TestFormatMessageSystem(t *testing.T) {
	h := newTestEmu(t)
	buf := h.alloc(512)
	if r := h.call(dK32, "FormatMessageW", fmSystem|fmIgnore, 0, 2, 0, buf, 256, 0); r != uint64(len(fileNotFoundText)+2) || h.readWStr(buf) != fileNotFoundText+"\r\n" {
		t.Fatalf("FormatMessageW = %d %q", r, h.readWStr(buf))
	}
	if r := h.call(dK32, "FormatMessageA", fmSystem|fmIgnore, 0, 2, 0x409, buf, 512, 0); r != uint64(len(fileNotFoundText)+2) || h.readAStr(buf) != fileNotFoundText+"\r\n" {
		t.Fatalf("FormatMessageA = %d %q", r, h.readAStr(buf))
	}
	// buffer must hold the text plus NUL
	secExpectFail(t, h, "FormatMessageA exact", h.call(dK32, "FormatMessageA", fmSystem|fmIgnore, 0, 2, 0, buf, uint64(len(fileNotFoundText)+2), 0), errInsufficientBuf)
	secExpectFail(t, h, "FormatMessageW unknown id", h.call(dK32, "FormatMessageW", fmSystem|fmIgnore, 0, 0xDEAD, 0, buf, 256, 0), errMrMidNotFound)
	secExpectFail(t, h, "FormatMessageW no source", h.call(dK32, "FormatMessageW", fmIgnore, 0, 2, 0, buf, 256, 0), errInvalidParameter)
	secExpectFail(t, h, "FormatMessageW module only", h.call(dK32, "FormatMessageW", fmHModule|fmIgnore, 0, 2, 0, buf, 256, 0), errMrMidNotFound)
	if r := h.call(dK32, "FormatMessageW", fmHModule|fmSystem|fmIgnore, 0, 2, 0, buf, 256, 0); r == 0 {
		t.Fatalf("FormatMessageW module+system failed: %d", h.lastError())
	}
	// MAX_WIDTH_MASK: regular line breaks become a space
	if r := h.call(dK32, "FormatMessageA", fmSystem|fmIgnore|fmMaxWidth, 0, 2, 0, buf, 512, 0); h.readAStr(buf) != fileNotFoundText+" " || r != uint64(len(fileNotFoundText)+1) {
		t.Fatalf("MAX_WIDTH = %d %q", r, h.readAStr(buf))
	}
	// inserts in a system message are passed through with IGNORE_INSERTS
	if h.call(dK32, "FormatMessageA", fmSystem|fmIgnore, 0, 193, 0, buf, 512, 0); h.readAStr(buf) != "%1 is not a valid Win32 application.\r\n" {
		t.Fatalf("193 = %q", h.readAStr(buf))
	}
	args := h.alloc(16)
	h.w64(args, h.astr("x.exe"))
	if h.call(dK32, "FormatMessageA", fmSystem|fmArray, 0, 193, 0, buf, 512, args); h.readAStr(buf) != "x.exe is not a valid Win32 application.\r\n" {
		t.Fatalf("193 with insert = %q", h.readAStr(buf))
	}
	secExpectFail(t, h, "inserts without arguments", h.call(dK32, "FormatMessageA", fmSystem, 0, 193, 0, buf, 512, 0), errInvalidParameter)
}

func TestFormatMessageAllocate(t *testing.T) {
	h := newTestEmu(t)
	out := h.alloc(8)
	for _, fn := range []string{"FormatMessageA", "FormatMessageW"} {
		h.w64(out, 0)
		r := h.call(dK32, fn, fmAllocate|fmSystem|fmIgnore, 0, 2, 0, out, 0, 0)
		p := h.r64(out)
		got := h.readAStr(p)
		if fn == "FormatMessageW" {
			got = h.readWStr(p)
		}
		if r != uint64(len(fileNotFoundText)+2) || got != fileNotFoundText+"\r\n" {
			t.Fatalf("%s ALLOCATE = %d %q", fn, r, got)
		}
		if h.call(dK32, "LocalFree", p) != 0 {
			t.Fatalf("%s: LocalFree of the buffer failed", fn)
		}
		h.w64(out, 0x99)
		secExpectFail(t, h, fn+" ALLOCATE unknown", h.call(dK32, fn, fmAllocate|fmSystem|fmIgnore, 0, 0xDEAD, 0, out, 0, 0), errMrMidNotFound)
		if h.r64(out) != 0 {
			t.Fatalf("%s: failed ALLOCATE left %#x", fn, h.r64(out))
		}
	}
	secExpectFail(t, h, "ALLOCATE NULL buffer", h.call(dK32, "FormatMessageA", fmAllocate|fmSystem|fmIgnore, 0, 2, 0, 0, 0, 0), errInvalidParameter)
}

func TestFormatMessageFromString(t *testing.T) {
	h := newTestEmu(t)
	buf := h.alloc(512)
	args := h.alloc(32)
	h.w64(args, h.astr("abc"))
	h.w64(args+8, 42)
	h.w64(args+16, 0xff)
	r := h.call(dK32, "FormatMessageA", fmString|fmArray, h.astr("%1 and %2!d! %3!04x!%%%n%t%.%0tail"), 0, 0, buf, 512, args)
	if want := "abc and 42 00ff%\r\n\t."; h.readAStr(buf) != want || r != uint64(len(want)) {
		t.Fatalf("FROM_STRING = %d %q, want %q", r, h.readAStr(buf), want)
	}
	// va_list form: Arguments is a va_list* (pointer to the argument slots)
	wargs := h.alloc(16)
	h.w64(wargs, h.wstr("wide"))
	va := h.alloc(8)
	h.w64(va, wargs)
	if h.call(dK32, "FormatMessageW", fmString, h.wstr("[%1]"), 0, 0, buf, 256, va); h.readWStr(buf) != "[wide]" {
		t.Fatalf("FormatMessageW va_list = %q", h.readWStr(buf))
	}
	if h.call(dK32, "FormatMessageA", fmString|fmIgnore, h.astr("%1 x %% y"), 0, 0, buf, 512, 0); h.readAStr(buf) != "%1 x %% y" {
		t.Fatalf("IGNORE_INSERTS = %q", h.readAStr(buf))
	}
	// a regular line break in the source is kept without MAX_WIDTH
	if h.call(dK32, "FormatMessageA", fmString|fmIgnore, h.astr("a\r\nb"), 0, 0, buf, 512, 0); h.readAStr(buf) != "a\r\nb" {
		t.Fatalf("line break = %q", h.readAStr(buf))
	}
	secExpectFail(t, h, "FROM_STRING NULL", h.call(dK32, "FormatMessageA", fmString, 0, 0, 0, buf, 512, 0), errInvalidParameter)
}

// Every Winsock error code (winerror.h, 10004-11031), every code winemu's
// APIs report, and the SCM/SSPI-related codes have a system message.
func TestFormatMessageCoverage(t *testing.T) {
	var codes []uint32
	add := func(lo, hi uint32) {
		for c := lo; c <= hi; c++ {
			codes = append(codes, c)
		}
	}
	codes = append(codes, 10004, 10009, 10013, 10014, 10022, 10024)
	add(10035, 10071)
	add(10091, 10093)
	add(10101, 10112)
	add(11001, 11031)
	codes = append(codes, 0, 2, 3, 4, 5, 6, 8, 13, 18, 24, 32, 38, 50, 53, 80, 87, 109, 111, 120, 122, 123, 124, 126, 127, 131,
		145, 183, 193, 203, 234, 258, 259, 267, 288, 298, 317, 487, 524, 998, 1004, 1008, 1060, 1063, 1065, 1083, 1113, 1114,
		1168, 1184, 1280, 1281, 1300, 1305, 1307, 1308, 1309, 1312, 1313, 1314, 1332, 1336, 1337, 1338, 1344, 1346, 1349,
		1460, 1722, 1812, 1813, 1814, 2221, 15106)
	for _, c := range codes {
		if _, ok := winMessages[c]; !ok {
			t.Errorf("no system message for %d", c)
		}
	}
}

// Line breaks and escapes as Windows produces them (cases from Wine's
// kernel32 format_msg tests, which are checked against Windows).
func TestFormatMessageLineBreaksAndIgnoredEscapes(t *testing.T) {
	h := newTestEmu(t)
	buf := h.alloc(512)
	for _, c := range []struct {
		flags    uint64
		in, want string
	}{
		{fmString, "hi\n", "hi\r\n"},
		{fmString, "\r", "\r\n"},
		{fmString, "\r\r\n", "\r\n\r\n"},
		{fmString, "a\r\nb", "a\r\nb"},
		{fmString | fmMaxWidth, "hi\n", "hi "},
		{fmString | fmMaxWidth, "\r\r\n", "  "},
		{fmString | fmMaxWidth, "a%nb", "a\r\nb"},
		{fmString | fmIgnore, "%%% %.%!", "%%% %.%!"},
		{fmString | fmIgnore, "%n%r%t", "\r\n\r\t"},
		{fmString | fmIgnore, "test%1%2!*.*s!%99", "test%1%2!*.*s!%99"},
		{fmString | fmIgnore, "test%0tail", "test"},
		{fmString, "100%% %.%!", "100% .!"},
	} {
		for _, w := range []bool{false, true} {
			fn, in := "FormatMessageA", h.astr(c.in)
			if w {
				fn, in = "FormatMessageW", h.wstr(c.in)
			}
			r := h.call(dK32, fn, c.flags, in, 0, 0, buf, 256, 0)
			got := h.readAStr(buf)
			if w {
				got = h.readWStr(buf)
			}
			if got != c.want || r != uint64(len(c.want)) {
				t.Errorf("%s(%#x, %q) = %d %q, want %d %q", fn, c.flags, c.in, r, got, len(c.want), c.want)
			}
		}
	}
}

// With ALLOCATE_BUFFER, nSize is the minimum number of TCHARs to allocate.
func TestFormatMessageAllocateMinimum(t *testing.T) {
	h := newTestEmu(t)
	out := h.alloc(8)
	for _, c := range []struct {
		fn   string
		unit uint64
	}{{"FormatMessageA", 1}, {"FormatMessageW", 2}} {
		if r := h.call(dK32, c.fn, fmAllocate|fmSystem|fmIgnore, 0, 2, 0, out, 1000, 0); r == 0 {
			t.Fatalf("%s failed: %d", c.fn, h.lastError())
		}
		if n := h.E.heapSize(h.r64(out)); n < 1000*c.unit {
			t.Fatalf("%s allocated %d bytes, want >= %d", c.fn, n, 1000*c.unit)
		}
	}
}
