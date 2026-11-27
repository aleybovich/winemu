package win

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// argSrc yields successive 8-byte variadic argument slots.
type argSrc interface{ next() uint64 }

type vaList struct {
	e *Emu
	p uint64
}

func (v *vaList) next() uint64 {
	x := v.e.Mem.R64(v.p)
	v.p += 8
	return x
}

// regArgs reads variadic arguments directly from the call frame starting
// at argument index i (msvcrt-style printf(fmt, ...)).
type regArgs struct {
	e *Emu
	i int
}

func (r *regArgs) next() uint64 {
	v := r.e.Arg(r.i)
	r.i++
	return v
}

type fmtOpts struct {
	wide          bool // output is UTF-16 (wprintf family)
	legacyWide    bool // %s in wide functions means wchar_t* (MSVC default)
	threeDigitExp bool // msvcrt legacy exponent formatting
	legacyInfNan  bool // msvcrt 1.#INF style
}

// fmtOut accumulates either bytes (narrow) or UTF-16 units (wide).
type fmtOut struct {
	wide bool
	b    []byte
	u    []uint16
}

func (o *fmtOut) str(s string) {
	if o.wide {
		for _, r := range s {
			if r >= 0x10000 {
				r1, r2 := utf16.EncodeRune(r)
				o.u = append(o.u, uint16(r1), uint16(r2))
			} else {
				o.u = append(o.u, uint16(r))
			}
		}
	} else {
		o.b = append(o.b, s...)
	}
}

func (o *fmtOut) units(u []uint16) {
	if o.wide {
		o.u = append(o.u, u...)
	} else {
		o.b = append(o.b, string(utf16.Decode(u))...)
	}
}

func (o *fmtOut) bytes(b []byte) {
	if o.wide {
		o.str(string(b))
	} else {
		o.b = append(o.b, b...)
	}
}

func (o *fmtOut) n() int {
	if o.wide {
		return len(o.u)
	}
	return len(o.b)
}

func (o *fmtOut) pad(c byte, n int) {
	for i := 0; i < n; i++ {
		if o.wide {
			o.u = append(o.u, uint16(c))
		} else {
			o.b = append(o.b, c)
		}
	}
}

// strLen returns the display length used for width padding.
func strLenUnits(s string, wide bool) int {
	if wide {
		return len(utf16.Encode([]rune(s)))
	}
	return len(s)
}

// sprintf formats a printf-style format string. fmtUnits is the format as
// runes (decoded from narrow or wide source).
func (e *Emu) sprintf(format []rune, args argSrc, o fmtOpts) *fmtOut {
	out := &fmtOut{wide: o.wide}
	f := format
	for i := 0; i < len(f); i++ {
		ch := f[i]
		if ch != '%' {
			if o.wide {
				out.str(string(ch))
			} else if ch < 0x80 {
				out.b = append(out.b, byte(ch))
			} else if ch >= 0xDC80 && ch <= 0xDCFF {
				out.b = append(out.b, byte(ch-0xDC00)) // raw byte passthrough
			} else {
				out.b = utf8.AppendRune(out.b, ch)
			}
			continue
		}
		i++
		if i >= len(f) {
			break
		}
		// flags
		var minus, plus, space, hash, zero bool
	flags:
		for ; i < len(f); i++ {
			switch f[i] {
			case '-':
				minus = true
			case '+':
				plus = true
			case ' ':
				space = true
			case '#':
				hash = true
			case '0':
				zero = true
			default:
				break flags
			}
		}
		width := -1
		if i < len(f) && f[i] == '*' {
			width = int(int32(args.next()))
			if width < 0 {
				minus = true
				width = -width
			}
			i++
		} else {
			for i < len(f) && f[i] >= '0' && f[i] <= '9' {
				if width < 0 {
					width = 0
				}
				width = width*10 + int(f[i]-'0')
				i++
			}
		}
		prec := -1
		if i < len(f) && f[i] == '.' {
			i++
			prec = 0
			if i < len(f) && f[i] == '*' {
				prec = int(int32(args.next()))
				if prec < 0 {
					prec = -1
				}
				i++
			} else {
				for i < len(f) && f[i] >= '0' && f[i] <= '9' {
					prec = prec*10 + int(f[i]-'0')
					i++
				}
			}
		}
		// length modifiers
		size := 0     // 0 default(int), 1 hh, 2 h, 4 l(32 on windows), 8 ll/I64/z/j/t
		longChar := 0 // 0 default, 1 narrow (h), 2 wide (l/w)
	length:
		for i < len(f) {
			switch f[i] {
			case 'h':
				if i+1 < len(f) && f[i+1] == 'h' {
					size = 1
					i += 2
				} else {
					size = 2
					longChar = 1
					i++
				}
			case 'l':
				if i+1 < len(f) && f[i+1] == 'l' {
					size = 8
					i += 2
				} else {
					size = 4
					longChar = 2
					i++
				}
			case 'w':
				longChar = 2
				i++
			case 'L':
				size = 8
				i++
			case 'q':
				size = 8
				i++
			case 'j', 'z', 't':
				size = 8
				i++
			case 'I':
				if i+2 < len(f) && f[i+1] == '6' && f[i+2] == '4' {
					size = 8
					i += 3
				} else if i+2 < len(f) && f[i+1] == '3' && f[i+2] == '2' {
					size = 4
					i += 3
				} else {
					size = 8
					i++
				}
			default:
				break length
			}
		}
		if i >= len(f) {
			break
		}
		conv := f[i]
		emit := func(body string, prefix string, numeric bool) {
			total := strLenUnits(prefix, o.wide) + strLenUnits(body, o.wide)
			padN := 0
			if width > total {
				padN = width - total
			}
			if minus {
				out.str(prefix)
				out.str(body)
				out.pad(' ', padN)
				return
			}
			if zero && numeric {
				out.str(prefix)
				out.pad('0', padN)
				out.str(body)
				return
			}
			out.pad(' ', padN)
			out.str(prefix)
			out.str(body)
		}
		switch conv {
		case '%':
			out.str("%")
		case 'd', 'i', 'u', 'x', 'X', 'o', 'b', 'B':
			raw := args.next()
			var v uint64
			neg := false
			signed := conv == 'd' || conv == 'i'
			switch size {
			case 1:
				if signed {
					s := int64(int8(raw))
					neg, v = s < 0, uint64(abs64(s))
				} else {
					v = uint64(uint8(raw))
				}
			case 2:
				if signed {
					s := int64(int16(raw))
					neg, v = s < 0, uint64(abs64(s))
				} else {
					v = uint64(uint16(raw))
				}
			case 8:
				if signed {
					s := int64(raw)
					neg = s < 0
					v = raw
					if neg {
						v = -raw
					}
				} else {
					v = raw
				}
			default:
				if signed {
					s := int64(int32(raw))
					neg, v = s < 0, uint64(abs64(s))
				} else {
					v = uint64(uint32(raw))
				}
			}
			base := 10
			switch conv {
			case 'x', 'X':
				base = 16
			case 'o':
				base = 8
			case 'b', 'B':
				base = 2
			}
			digits := strconv.FormatUint(v, base)
			if conv == 'X' {
				digits = strings.ToUpper(digits)
			}
			if prec >= 0 {
				zero = false
				if prec == 0 && v == 0 {
					digits = ""
				}
				for len(digits) < prec {
					digits = "0" + digits
				}
			}
			prefix := ""
			if signed {
				switch {
				case neg:
					prefix = "-"
				case plus:
					prefix = "+"
				case space:
					prefix = " "
				}
			}
			if hash && v != 0 {
				switch conv {
				case 'x':
					prefix = "0x"
				case 'X':
					prefix = "0X"
				case 'o':
					if !strings.HasPrefix(digits, "0") {
						digits = "0" + digits
					}
				}
			}
			emit(digits, prefix, true)
		case 'p':
			v := args.next()
			s := strings.ToUpper(strconv.FormatUint(v, 16))
			for len(s) < 16 {
				s = "0" + s
			}
			emit(s, "", false)
		case 'c', 'C':
			v := args.next()
			wideChar := o.wide
			if conv == 'C' {
				wideChar = !o.wide
			}
			if longChar == 1 {
				wideChar = false
			} else if longChar == 2 {
				wideChar = true
			}
			var s string
			if wideChar {
				s = string(rune(uint16(v)))
			} else if o.wide {
				s = string(rune(uint8(v)))
			} else {
				s = string([]byte{uint8(v)})
			}
			if !o.wide && !wideChar {
				// raw byte
				pad := 0
				if width > 1 {
					pad = width - 1
				}
				if !minus {
					out.pad(' ', pad)
				}
				out.b = append(out.b, uint8(v))
				if minus {
					out.pad(' ', pad)
				}
				continue
			}
			emit(s, "", false)
		case 's', 'S', 'Z':
			p := args.next()
			wideStr := !o.wide
			if o.wide {
				wideStr = o.legacyWide
			} else {
				wideStr = false
			}
			if conv == 'S' {
				wideStr = !wideStr
			}
			if longChar == 1 {
				wideStr = false
			} else if longChar == 2 {
				wideStr = true
			}
			if conv == 'Z' && p != 0 {
				// ANSI_STRING / UNICODE_STRING
				n := int(e.Mem.R16(p))
				buf := e.Mem.R64(p + 8)
				if longChar == 2 {
					emit(e.Mem.WStrN(buf, n/2), "", false)
				} else {
					emit(string(e.Mem.ReadBytes(buf, n)), "", false)
				}
				continue
			}
			if p == 0 {
				s := "(null)"
				if prec >= 0 && prec < len(s) {
					s = s[:prec]
				}
				emit(s, "", false)
				continue
			}
			if wideStr {
				var units []uint16
				for k := 0; prec < 0 || k < prec; k++ {
					u := e.Mem.R16(p + uint64(2*k))
					if u == 0 {
						break
					}
					units = append(units, u)
				}
				emit(string(utf16.Decode(units)), "", false)
			} else {
				var b []byte
				if prec >= 0 {
					b = e.Mem.CStrN(p, prec)
				} else {
					b = e.Mem.CStrBytes(p)
				}
				if o.wide {
					emit(string(b), "", false)
				} else {
					// keep raw bytes; pad by byte length
					padN := 0
					if width > len(b) {
						padN = width - len(b)
					}
					if !minus {
						out.pad(' ', padN)
					}
					out.b = append(out.b, b...)
					if minus {
						out.pad(' ', padN)
					}
				}
			}
		case 'n':
			p := args.next()
			if p != 0 {
				switch size {
				case 1:
					e.Mem.W8(p, uint8(out.n()))
				case 2:
					e.Mem.W16(p, uint16(out.n()))
				case 8:
					e.Mem.W64(p, uint64(out.n()))
				default:
					e.Mem.W32(p, uint32(out.n()))
				}
			}
		case 'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A':
			v := math.Float64frombits(args.next())
			body, prefix := formatFloat(v, conv, prec, hash, plus, space, o)
			numeric := !math.IsInf(v, 0) && !math.IsNaN(v)
			emit(body, prefix, numeric)
		default:
			// unknown conversion: print literally
			out.str("%" + string(conv))
		}
	}
	return out
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// formatFloat returns (digits, sign prefix) for a floating conversion.
func formatFloat(v float64, conv rune, prec int, hash, plus, space bool, o fmtOpts) (string, string) {
	prefix := ""
	if math.Signbit(v) {
		prefix = "-"
		v = -v
	} else if plus {
		prefix = "+"
	} else if space {
		prefix = " "
	}
	upper := conv == 'F' || conv == 'E' || conv == 'G' || conv == 'A'
	if math.IsInf(v, 0) || math.IsNaN(v) {
		var s string
		if o.legacyInfNan {
			if math.IsInf(v, 0) {
				s = "1.#INF"
			} else if prefix == "-" {
				s = "1.#IND"
			} else {
				s = "1.#QNAN"
			}
			p := prec
			if p < 0 {
				p = 6
			}
			if conv == 'f' || conv == 'F' || conv == 'e' || conv == 'E' {
				for len(s)-2 < p {
					s += "0"
				}
			}
			return s, prefix
		}
		if math.IsInf(v, 0) {
			s = "inf"
		} else if prefix == "-" {
			s = "nan(ind)"
		} else {
			s = "nan"
		}
		if upper {
			s = strings.ToUpper(s)
		}
		return s, prefix
	}
	if prec < 0 {
		prec = 6
		if conv == 'a' || conv == 'A' {
			prec = 13
		}
	}
	var s string
	switch conv {
	case 'f', 'F':
		s = strconv.FormatFloat(v, 'f', prec, 64)
		if hash && prec == 0 {
			s += "."
		}
	case 'e', 'E':
		s = fixExp(strconv.FormatFloat(v, 'e', prec, 64), o.threeDigitExp)
		if hash && prec == 0 {
			s = strings.Replace(s, "e", ".e", 1)
		}
	case 'g', 'G':
		p := prec
		if p == 0 {
			p = 1
		}
		x := 0
		if v != 0 {
			es := strconv.FormatFloat(v, 'e', p-1, 64)
			x, _ = strconv.Atoi(es[strings.IndexByte(es, 'e')+1:])
		}
		if p > x && x >= -4 {
			s = strconv.FormatFloat(v, 'f', p-1-x, 64)
		} else {
			s = fixExp(strconv.FormatFloat(v, 'e', p-1, 64), o.threeDigitExp)
		}
		if !hash {
			// strip trailing zeros in the fraction
			mant, exp := s, ""
			if k := strings.IndexByte(s, 'e'); k >= 0 {
				mant, exp = s[:k], s[k:]
			}
			if strings.Contains(mant, ".") {
				mant = strings.TrimRight(mant, "0")
				mant = strings.TrimSuffix(mant, ".")
			}
			s = mant + exp
		} else if !strings.Contains(s, ".") {
			if k := strings.IndexByte(s, 'e'); k >= 0 {
				s = s[:k] + "." + s[k:]
			} else {
				s += "."
			}
		}
	case 'a', 'A':
		s = strconv.FormatFloat(v, 'x', prec, 64)
		// Go: 0x1.8p+01 -> C: 0x1.8p+1
		if k := strings.IndexByte(s, 'p'); k >= 0 {
			sign := s[k+1]
			digits := strings.TrimLeft(s[k+2:], "0")
			if digits == "" {
				digits = "0"
			}
			s = s[:k+1] + string(sign) + digits
		}
		if v == 0 {
			s = "0x0." + strings.Repeat("0", prec) + "p+0"
			if prec == 0 {
				s = "0x0p+0"
			}
		}
	}
	if upper {
		s = strings.ToUpper(s)
	}
	return s, prefix
}

// fixExp converts Go exponent form to C (at least 2 digits, or 3 for legacy).
func fixExp(s string, three bool) string {
	k := strings.IndexAny(s, "eE")
	if k < 0 {
		return s
	}
	sign := s[k+1]
	d := s[k+2:]
	min := 2
	if three {
		min = 3
	}
	for len(d) < min {
		d = "0" + d
	}
	return s[:k+1] + string(sign) + d
}

// formatArgs helpers used by the API wrappers -------------------------------

// fmtNarrow decodes a narrow format string to runes, mapping invalid UTF-8
// bytes into a private range so they pass through unchanged.
func fmtNarrow(b []byte) []rune {
	rs := make([]rune, 0, len(b))
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n == 1 {
			rs = append(rs, 0xDC00+rune(b[0]))
		} else {
			rs = append(rs, r)
		}
		b = b[n:]
	}
	return rs
}

func fmtWide(u []uint16) []rune { return utf16.Decode(u) }
