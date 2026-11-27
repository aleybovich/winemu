package win

import (
	"bytes"
	"math"
	"math/bits"
	"math/rand"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"winemu/internal/cpu"
)

// ---------------------------------------------------------------------------
// helpers

func (e *Emu) wlen(a uint64) uint64 {
	n := uint64(0)
	for e.Mem.R16(a+2*n) != 0 {
		n++
	}
	return n
}

func (e *Emu) wunits(a uint64, n uint64) []uint16 {
	u := make([]uint16, n)
	for i := range u {
		u[i] = e.Mem.R16(a + 2*uint64(i))
	}
	return u
}

func lowerB(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
func upperB(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 32
	}
	return b
}

func lowerW(u uint16) uint16 { return uint16(unicode.ToLower(rune(u))) }
func upperW(u uint16) uint16 { return uint16(unicode.ToUpper(rune(u))) }

func sign(v int) uint64 {
	switch {
	case v < 0:
		return ^uint64(0)
	case v > 0:
		return 1
	}
	return 0
}

// strtoint parses like strtol/strtoul; returns value, chars consumed, overflow.
func strtoint(s []byte, base int, unsigned bool, bits64 bool) (uint64, int, bool) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] >= 9 && s[i] <= 13) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	if (base == 0 || base == 16) && i+1 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') && i+2 < len(s) && isDigitBase(rune(s[i+2]), 16) {
		i += 2
		base = 16
	} else if base == 0 && i < len(s) && s[i] == '0' {
		base = 8
	} else if base == 0 {
		base = 10
	}
	start := i
	var v uint64
	ovf := false
	for i < len(s) && isDigitBase(rune(s[i]), base) {
		d := uint64(digitVal(s[i]))
		hi, lo := bits.Mul64(v, uint64(base))
		lo2, carry := bits.Add64(lo, d, 0)
		if hi != 0 || carry != 0 {
			ovf = true
		}
		v = lo2
		i++
	}
	if i == start {
		return 0, 0, false
	}
	var limit uint64
	switch {
	case unsigned && bits64:
		limit = math.MaxUint64
	case unsigned:
		limit = math.MaxUint32
	case bits64:
		limit = math.MaxInt64
		if neg {
			limit++
		}
	default:
		limit = math.MaxInt32
		if neg {
			limit++
		}
	}
	if ovf || v > limit {
		if unsigned {
			if bits64 {
				return math.MaxUint64, i, true
			}
			return math.MaxUint32, i, true
		}
		if bits64 {
			if neg {
				return 1 << 63, i, true
			}
			return math.MaxInt64, i, true
		}
		if neg {
			return uint64(0xFFFFFFFF80000000), i, true
		}
		return math.MaxInt32, i, true
	}
	if neg {
		v = -v
	}
	if !bits64 {
		if unsigned {
			v = uint64(uint32(v))
		} else {
			v = uint64(int64(int32(v)))
		}
	}
	return v, i, false
}

func digitVal(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'z':
		return int(b-'a') + 10
	}
	return int(b-'A') + 10
}

// strtod parses a floating number prefix; returns value and consumed length.
func strtod(s []byte) (float64, int, bool) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] >= 9 && s[i] <= 13) {
		i++
	}
	start := i
	j := i
	if j < len(s) && (s[j] == '+' || s[j] == '-') {
		j++
	}
	low := strings.ToLower(string(s[j:min(len(s), j+8)]))
	switch {
	case strings.HasPrefix(low, "infinity"):
		j += 8
	case strings.HasPrefix(low, "inf"):
		j += 3
	case strings.HasPrefix(low, "nan"):
		j += 3
		if j < len(s) && s[j] == '(' { // nan(n-char-sequence): [0-9A-Za-z_]*
			k := j + 1
			for k < len(s) && (s[k] == '_' || isDigitBase(rune(s[k]), 36)) {
				k++
			}
			if k < len(s) && s[k] == ')' {
				j = k + 1
			}
		}
	default:
		hex := false
		if j+1 < len(s) && s[j] == '0' && (s[j+1] == 'x' || s[j+1] == 'X') {
			hex = true
			j += 2
		}
		digits := 0
		isd := func(b byte) bool { return b >= '0' && b <= '9' || hex && isDigitBase(rune(b), 16) }
		for j < len(s) && isd(s[j]) {
			j++
			digits++
		}
		if j < len(s) && s[j] == '.' {
			j++
			for j < len(s) && isd(s[j]) {
				j++
				digits++
			}
		}
		if digits == 0 {
			if hex {
				// "0x" with no digits: parse just "0"
				v, _ := parseCFloat(string(s[start : start+1+boolInt(s[start] == '+' || s[start] == '-')]))
				return v, start + 1 + boolInt(s[start] == '+' || s[start] == '-'), true
			}
			return 0, 0, false
		}
		e := byte('e')
		if hex {
			e = 'p'
		}
		if j < len(s) && (s[j]|0x20) == e {
			k := j + 1
			if k < len(s) && (s[k] == '+' || s[k] == '-') {
				k++
			}
			if k < len(s) && s[k] >= '0' && s[k] <= '9' {
				for k < len(s) && s[k] >= '0' && s[k] <= '9' {
					k++
				}
				j = k
			}
		}
	}
	v, ok := parseCFloat(string(s[start:j]))
	if !ok {
		return 0, 0, false
	}
	return v, j, true
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (e *Emu) strtoX(base int, unsigned, b64 bool) uint64 {
	return e.strtoXAt(e.Arg(0), e.Arg(1), base, unsigned, b64, false)
}

func (e *Emu) wcstoX(base int, unsigned, b64 bool) uint64 {
	return e.strtoXAt(e.Arg(0), e.Arg(1), base, unsigned, b64, true)
}

func (e *Emu) ntoa(v uint64, neg bool, radix int, wide bool, buf uint64) uint64 {
	s := strconv.FormatUint(v, radix)
	if neg {
		s = "-" + s
	}
	e.writeStrBuf(wide, buf, s)
	return buf
}

// ---------------------------------------------------------------------------
// multibyte (UTF-8 as the active code page)

func utf8ToUnits(b []byte) []uint16 { return utf16.Encode([]rune(string(b))) }
func unitsToUTF8(u []uint16) []byte { return []byte(string(utf16.Decode(u))) }

func init() {
	u := dUcrt + "," + dMsvc
	uv := u + "," + dVc + "," + dNt
	m := func(e *Emu) *Emu { return e }
	_ = m

	// ---- memory ----
	reg(uv, "memcpy", func(e *Emu) uint64 { memMove(e.Mem, e.Arg(0), e.Arg(1), e.Arg(2)); return e.Arg(0) })
	reg(uv, "memmove", func(e *Emu) uint64 { memMove(e.Mem, e.Arg(0), e.Arg(1), e.Arg(2)); return e.Arg(0) })
	reg(uv, "memset", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), byte(e.Arg(1)), e.Arg(2)); return e.Arg(0) })
	reg(dNt, "RtlMoveMemory", func(e *Emu) uint64 { e.Mem.Move(e.Arg(0), e.Arg(1), e.Arg(2)); return 0 })
	reg(dNt+","+dK32, "RtlCopyMemory", func(e *Emu) uint64 { e.Mem.Move(e.Arg(0), e.Arg(1), e.Arg(2)); return 0 })
	reg(dNt+","+dK32, "RtlFillMemory", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), byte(e.Arg(2)), e.Arg(1)); return 0 })
	reg(dNt+","+dK32, "RtlZeroMemory", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, e.Arg(1)); return 0 })
	reg(dNt, "RtlCompareMemory", func(e *Emu) uint64 {
		a, b, n := e.Arg(0), e.Arg(1), e.Arg(2)
		for i := uint64(0); i < n; i++ {
			if e.Mem.R8(a+i) != e.Mem.R8(b+i) {
				return i
			}
		}
		return n
	})
	reg(uv, "memcmp", func(e *Emu) uint64 { return memCmp(e.Mem, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "_memicmp", func(e *Emu) uint64 {
		n := int(e.Arg(2))
		a, b := bytes.ToLower(e.Mem.ReadBytes(e.Arg(0), n)), bytes.ToLower(e.Mem.ReadBytes(e.Arg(1), n))
		return sign(bytes.Compare(a, b))
	})
	reg(uv, "memchr", func(e *Emu) uint64 {
		p, ch, n := e.Arg(0), byte(e.Arg(1)), e.Arg(2)
		for off := uint64(0); off < n; {
			k := min(n-off, 4096)
			b := e.Mem.ReadBytes(p+off, int(k))
			if i := bytes.IndexByte(b, ch); i >= 0 {
				return p + off + uint64(i)
			}
			off += k
		}
		return 0
	})
	reg(u, "_memccpy", func(e *Emu) uint64 {
		d, s, ch, n := e.Arg(0), e.Arg(1), byte(e.Arg(2)), e.Arg(3)
		for i := uint64(0); i < n; i++ {
			b := e.Mem.R8(s + i)
			e.Mem.W8(d+i, b)
			if b == ch {
				return d + i + 1
			}
		}
		return 0
	})
	reg(u, "memcpy_s", func(e *Emu) uint64 {
		if e.Arg(3) > e.Arg(1) {
			e.Mem.Fill(e.Arg(0), 0, e.Arg(1))
			return erange
		}
		e.Mem.Move(e.Arg(0), e.Arg(2), e.Arg(3))
		return 0
	})
	reg(u, "memmove_s", func(e *Emu) uint64 {
		if e.Arg(3) > e.Arg(1) {
			return erange
		}
		e.Mem.Move(e.Arg(0), e.Arg(2), e.Arg(3))
		return 0
	})
	reg(u, "wmemcpy", func(e *Emu) uint64 { e.Mem.Move(e.Arg(0), e.Arg(1), 2*e.Arg(2)); return e.Arg(0) })
	reg(u, "wmemmove", func(e *Emu) uint64 { e.Mem.Move(e.Arg(0), e.Arg(1), 2*e.Arg(2)); return e.Arg(0) })
	reg(u, "wmemset", func(e *Emu) uint64 {
		for i := uint64(0); i < e.Arg(2); i++ {
			e.Mem.W16(e.Arg(0)+2*i, uint16(e.Arg(1)))
		}
		return e.Arg(0)
	})
	reg(u, "wmemcmp", func(e *Emu) uint64 {
		for i := uint64(0); i < e.Arg(2); i++ {
			a, b := e.Mem.R16(e.Arg(0)+2*i), e.Mem.R16(e.Arg(1)+2*i)
			if a != b {
				return sign(int(a) - int(b))
			}
		}
		return 0
	})
	reg(u, "wmemchr", func(e *Emu) uint64 {
		for i := uint64(0); i < e.Arg(2); i++ {
			if e.Mem.R16(e.Arg(0)+2*i) == uint16(e.Arg(1)) {
				return e.Arg(0) + 2*i
			}
		}
		return 0
	})

	// ---- narrow strings ----
	reg(uv, "strlen", func(e *Emu) uint64 { return cstrLen(e.Mem, e.Arg(0)) })
	reg(u, "strnlen", func(e *Emu) uint64 { return uint64(len(e.Mem.CStrN(e.Arg(0), int(min(e.Arg(1), 1<<31))))) })
	reg(u, "strnlen_s", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return uint64(len(e.Mem.CStrN(e.Arg(0), int(min(e.Arg(1), 1<<31)))))
	})
	reg(uv, "strcpy", func(e *Emu) uint64 {
		b := e.Mem.CStrBytes(e.Arg(1))
		e.Mem.Write(e.Arg(0), append(b, 0))
		return e.Arg(0)
	})
	reg(uv, "strncpy", func(e *Emu) uint64 {
		n := int(e.Arg(2))
		b := e.Mem.CStrN(e.Arg(1), n)
		out := make([]byte, n)
		copy(out, b)
		e.Mem.Write(e.Arg(0), out)
		return e.Arg(0)
	})
	reg(uv, "strcat", func(e *Emu) uint64 {
		d := e.Arg(0)
		l := uint64(len(e.Mem.CStrBytes(d)))
		e.Mem.Write(d+l, append(e.Mem.CStrBytes(e.Arg(1)), 0))
		return d
	})
	reg(uv, "strncat", func(e *Emu) uint64 {
		d := e.Arg(0)
		l := uint64(len(e.Mem.CStrBytes(d)))
		e.Mem.Write(d+l, append(e.Mem.CStrN(e.Arg(1), int(e.Arg(2))), 0))
		return d
	})
	reg(u, "strcpy_s", func(e *Emu) uint64 {
		b := e.Mem.CStrBytes(e.Arg(2))
		if uint64(len(b)) >= e.Arg(1) {
			if e.Arg(1) > 0 {
				e.Mem.W8(e.Arg(0), 0)
			}
			return erange
		}
		e.Mem.Write(e.Arg(0), append(b, 0))
		return 0
	})
	reg(u, "strncpy_s", func(e *Emu) uint64 {
		d, ds, s, n := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3)
		lim := n
		if n == ^uint64(0) {
			lim = ds - 1
		}
		b := e.Mem.CStrN(s, int(min(lim, 1<<31)))
		if uint64(len(b)) >= ds {
			if n == ^uint64(0) {
				e.Mem.Write(d, append(b[:ds-1], 0))
				return 80 // STRUNCATE
			}
			if ds > 0 {
				e.Mem.W8(d, 0)
			}
			return erange
		}
		e.Mem.Write(d, append(b, 0))
		return 0
	})
	reg(u, "strcat_s", func(e *Emu) uint64 {
		d, ds := e.Arg(0), e.Arg(1)
		cur := e.Mem.CStrBytes(d)
		add := e.Mem.CStrBytes(e.Arg(2))
		if uint64(len(cur)+len(add)) >= ds {
			if ds > 0 {
				e.Mem.W8(d, 0)
			}
			return erange
		}
		e.Mem.Write(d+uint64(len(cur)), append(add, 0))
		return 0
	})
	reg(u, "strncat_s", func(e *Emu) uint64 {
		d, ds, s, n := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3)
		cur := e.Mem.CStrBytes(d)
		add := e.Mem.CStrN(s, int(min(n, 1<<31)))
		if uint64(len(cur)+len(add)) >= ds {
			if n == ^uint64(0) {
				room := int(ds) - 1 - len(cur)
				if room > 0 {
					e.Mem.Write(d+uint64(len(cur)), append(add[:room], 0))
				}
				return 80
			}
			if ds > 0 {
				e.Mem.W8(d, 0)
			}
			return erange
		}
		e.Mem.Write(d+uint64(len(cur)), append(add, 0))
		return 0
	})
	reg(uv, "strcmp", func(e *Emu) uint64 {
		return sign(bytes.Compare(e.Mem.CStrBytes(e.Arg(0)), e.Mem.CStrBytes(e.Arg(1))))
	})
	reg(u, "strcoll", func(e *Emu) uint64 {
		return sign(bytes.Compare(e.Mem.CStrBytes(e.Arg(0)), e.Mem.CStrBytes(e.Arg(1))))
	})
	reg(u, "_strcoll_l", func(e *Emu) uint64 {
		return sign(bytes.Compare(e.Mem.CStrBytes(e.Arg(0)), e.Mem.CStrBytes(e.Arg(1))))
	})
	reg(uv, "strncmp", func(e *Emu) uint64 {
		n := int(min(e.Arg(2), 1<<31))
		return sign(bytes.Compare(e.Mem.CStrN(e.Arg(0), n), e.Mem.CStrN(e.Arg(1), n)))
	})
	icmp := func(e *Emu) uint64 {
		return sign(bytes.Compare(bytes.ToLower(e.Mem.CStrBytes(e.Arg(0))), bytes.ToLower(e.Mem.CStrBytes(e.Arg(1)))))
	}
	for _, n := range []string{"_stricmp", "_strcmpi", "stricmp", "strcmpi", "_stricoll", "_stricmp_l", "_stricoll_l"} {
		reg(u, n, icmp)
	}
	nicmp := func(e *Emu) uint64 {
		n := int(min(e.Arg(2), 1<<31))
		return sign(bytes.Compare(bytes.ToLower(e.Mem.CStrN(e.Arg(0), n)), bytes.ToLower(e.Mem.CStrN(e.Arg(1), n))))
	}
	for _, n := range []string{"_strnicmp", "strnicmp", "_strnicoll", "_strnicmp_l"} {
		reg(u, n, nicmp)
	}
	reg(u, "_strncoll", func(e *Emu) uint64 {
		n := int(min(e.Arg(2), 1<<31))
		return sign(bytes.Compare(e.Mem.CStrN(e.Arg(0), n), e.Mem.CStrN(e.Arg(1), n)))
	})
	reg(uv, "strchr", func(e *Emu) uint64 { return cstrChr(e.Mem, e.Arg(0), byte(e.Arg(1))) })
	reg(uv, "strrchr", func(e *Emu) uint64 {
		p := e.Arg(0)
		b := e.Mem.CStrBytes(p)
		ch := byte(e.Arg(1))
		if ch == 0 {
			return p + uint64(len(b))
		}
		if i := bytes.LastIndexByte(b, ch); i >= 0 {
			return p + uint64(i)
		}
		return 0
	})
	reg(uv, "strstr", func(e *Emu) uint64 { return cstrStr(e.Mem, e.Arg(0), e.Mem.CStrBytes(e.Arg(1))) })
	reg(u, "strspn", func(e *Emu) uint64 {
		s, set := e.Mem.CStrBytes(e.Arg(0)), e.Mem.CStrBytes(e.Arg(1))
		i := 0
		for i < len(s) && bytes.IndexByte(set, s[i]) >= 0 {
			i++
		}
		return uint64(i)
	})
	reg(u, "strcspn", func(e *Emu) uint64 {
		s, set := e.Mem.CStrBytes(e.Arg(0)), e.Mem.CStrBytes(e.Arg(1))
		i := 0
		for i < len(s) && bytes.IndexByte(set, s[i]) < 0 {
			i++
		}
		return uint64(i)
	})
	reg(u, "strpbrk", func(e *Emu) uint64 {
		s, set := e.Mem.CStrBytes(e.Arg(0)), e.Mem.CStrBytes(e.Arg(1))
		if i := bytes.IndexAny(s, string(set)); i >= 0 && len(set) > 0 {
			for j := 0; j < len(s); j++ {
				if bytes.IndexByte(set, s[j]) >= 0 {
					return e.Arg(0) + uint64(j)
				}
			}
		}
		return 0
	})
	strtok := func(e *Emu, s, delim, state uint64) uint64 {
		m := e.Mem
		if s == 0 {
			s = m.R64(state)
			if s == 0 {
				return 0
			}
		}
		d := m.CStrBytes(delim)
		for m.R8(s) != 0 && bytes.IndexByte(d, m.R8(s)) >= 0 {
			s++
		}
		if m.R8(s) == 0 {
			m.W64(state, 0)
			return 0
		}
		tok := s
		for m.R8(s) != 0 && bytes.IndexByte(d, m.R8(s)) < 0 {
			s++
		}
		if m.R8(s) != 0 {
			m.W8(s, 0)
			s++
		}
		m.W64(state, s)
		return tok
	}
	reg(u, "strtok", func(e *Emu) uint64 {
		st := e.crt.strtok[e.Cur.ID]
		if st == 0 {
			st = e.heapAllocRaw(8)
			e.crt.strtok[e.Cur.ID] = st
		}
		return strtok(e, e.Arg(0), e.Arg(1), st)
	})
	reg(u, "strtok_s", func(e *Emu) uint64 { return strtok(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "_strdup", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return e.allocCStr(string(e.Mem.CStrBytes(e.Arg(0))))
	})
	reg(u, "strdup", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return e.allocCStr(string(e.Mem.CStrBytes(e.Arg(0))))
	})
	caseConv := func(up bool) Fn {
		return func(e *Emu) uint64 {
			p := e.Arg(0)
			b := e.Mem.CStrBytes(p)
			for i := range b {
				if up {
					b[i] = upperB(b[i])
				} else {
					b[i] = lowerB(b[i])
				}
			}
			e.Mem.Write(p, b)
			return p
		}
	}
	reg(u, "_strlwr", caseConv(false))
	reg(u, "_strupr", caseConv(true))
	reg(u, "_strlwr_s", func(e *Emu) uint64 { caseConv(false)(e); return 0 })
	reg(u, "_strupr_s", func(e *Emu) uint64 { caseConv(true)(e); return 0 })
	reg(u, "_strrev", func(e *Emu) uint64 {
		b := e.Mem.CStrBytes(e.Arg(0))
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		e.Mem.Write(e.Arg(0), b)
		return e.Arg(0)
	})
	reg(u, "_strset", func(e *Emu) uint64 {
		n := uint64(len(e.Mem.CStrBytes(e.Arg(0))))
		e.Mem.Fill(e.Arg(0), byte(e.Arg(1)), n)
		return e.Arg(0)
	})
	reg(u, "_strnset", func(e *Emu) uint64 {
		n := min(uint64(len(e.Mem.CStrBytes(e.Arg(0)))), e.Arg(2))
		e.Mem.Fill(e.Arg(0), byte(e.Arg(1)), n)
		return e.Arg(0)
	})
	reg(u, "strxfrm", func(e *Emu) uint64 {
		b := e.Mem.CStrBytes(e.Arg(1))
		if uint64(len(b)) < e.Arg(2) {
			e.Mem.Write(e.Arg(0), append(b, 0))
		}
		return uint64(len(b))
	})

	// ---- wide strings ----
	reg(uv, "wcslen", func(e *Emu) uint64 { return e.wlen(e.Arg(0)) })
	reg(u, "wcsnlen", func(e *Emu) uint64 {
		n := uint64(0)
		for n < e.Arg(1) && e.Mem.R16(e.Arg(0)+2*n) != 0 {
			n++
		}
		return n
	})
	reg(u, "wcscpy", func(e *Emu) uint64 {
		e.Mem.WriteUnits(e.Arg(0), append(e.Mem.WStrUnits(e.Arg(1)), 0))
		return e.Arg(0)
	})
	reg(u, "wcscpy_s", func(e *Emu) uint64 {
		s := e.Mem.WStrUnits(e.Arg(2))
		if uint64(len(s)) >= e.Arg(1) {
			if e.Arg(1) > 0 {
				e.Mem.W16(e.Arg(0), 0)
			}
			return erange
		}
		e.Mem.WriteUnits(e.Arg(0), append(s, 0))
		return 0
	})
	reg(u, "wcsncpy", func(e *Emu) uint64 {
		n := e.Arg(2)
		s := e.Mem.WStrUnits(e.Arg(1))
		out := make([]uint16, n)
		copy(out, s)
		e.Mem.WriteUnits(e.Arg(0), out)
		return e.Arg(0)
	})
	reg(u, "wcsncpy_s", func(e *Emu) uint64 {
		d, ds, s, n := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3)
		src := e.Mem.WStrUnits(s)
		if uint64(len(src)) > n {
			src = src[:n]
		}
		if uint64(len(src)) >= ds {
			if n == ^uint64(0) {
				e.Mem.WriteUnits(d, append(src[:ds-1], 0))
				return 80
			}
			return erange
		}
		e.Mem.WriteUnits(d, append(src, 0))
		return 0
	})
	reg(u, "wcscat", func(e *Emu) uint64 {
		d := e.Arg(0)
		e.Mem.WriteUnits(d+2*e.wlen(d), append(e.Mem.WStrUnits(e.Arg(1)), 0))
		return d
	})
	reg(u, "wcscat_s", func(e *Emu) uint64 {
		d, ds := e.Arg(0), e.Arg(1)
		l := e.wlen(d)
		s := e.Mem.WStrUnits(e.Arg(2))
		if l+uint64(len(s)) >= ds {
			return erange
		}
		e.Mem.WriteUnits(d+2*l, append(s, 0))
		return 0
	})
	reg(u, "wcsncat", func(e *Emu) uint64 {
		d := e.Arg(0)
		s := e.Mem.WStrUnits(e.Arg(1))
		if uint64(len(s)) > e.Arg(2) {
			s = s[:e.Arg(2)]
		}
		e.Mem.WriteUnits(d+2*e.wlen(d), append(s, 0))
		return d
	})
	reg(u, "wcsncat_s", func(e *Emu) uint64 {
		d, ds := e.Arg(0), e.Arg(1)
		l := e.wlen(d)
		s := e.Mem.WStrUnits(e.Arg(2))
		if uint64(len(s)) > e.Arg(3) {
			s = s[:e.Arg(3)]
		}
		if l+uint64(len(s)) >= ds {
			return erange
		}
		e.Mem.WriteUnits(d+2*l, append(s, 0))
		return 0
	})
	wcmp := func(a, b []uint16, fold bool) uint64 {
		for i := 0; ; i++ {
			var x, y uint16
			if i < len(a) {
				x = a[i]
			}
			if i < len(b) {
				y = b[i]
			}
			if fold {
				x, y = lowerW(x), lowerW(y)
			}
			if x != y || x == 0 {
				return sign(int(x) - int(y))
			}
		}
	}
	reg(u, "wcscmp", func(e *Emu) uint64 { return wcmp(e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1)), false) })
	reg(u, "wcscoll", func(e *Emu) uint64 { return wcmp(e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1)), false) })
	reg(u, "_wcscoll_l", func(e *Emu) uint64 { return wcmp(e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1)), false) })
	for _, n := range []string{"_wcsicmp", "_wcsicoll", "_wcsicmp_l", "wcsicmp", "_wcsicoll_l"} {
		reg(u, n, func(e *Emu) uint64 { return wcmp(e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1)), true) })
	}
	wncmp := func(fold bool) Fn {
		return func(e *Emu) uint64 {
			a, b := e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1))
			n := int(min(e.Arg(2), 1<<31))
			if len(a) > n {
				a = a[:n]
			}
			if len(b) > n {
				b = b[:n]
			}
			return wcmp(a, b, fold)
		}
	}
	reg(u, "wcsncmp", wncmp(false))
	reg(u, "_wcsncoll", wncmp(false))
	reg(u, "_wcsnicmp", wncmp(true))
	reg(u, "_wcsnicoll", wncmp(true))
	reg(u, "_wcsnicmp_l", wncmp(true))
	reg(uv, "wcschr", func(e *Emu) uint64 {
		p := e.Arg(0)
		ch := uint16(e.Arg(1))
		for {
			v := e.Mem.R16(p)
			if v == ch {
				return p
			}
			if v == 0 {
				return 0
			}
			p += 2
		}
	})
	reg(uv, "wcsrchr", func(e *Emu) uint64 {
		p := e.Arg(0)
		ch := uint16(e.Arg(1))
		var last uint64
		for {
			v := e.Mem.R16(p)
			if v == ch {
				last = p
			}
			if v == 0 {
				return last
			}
			p += 2
		}
	})
	reg(uv, "wcsstr", func(e *Emu) uint64 {
		h, n := e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1))
		if len(n) == 0 {
			return e.Arg(0)
		}
		for i := 0; i+len(n) <= len(h); i++ {
			ok := true
			for j := range n {
				if h[i+j] != n[j] {
					ok = false
					break
				}
			}
			if ok {
				return e.Arg(0) + 2*uint64(i)
			}
		}
		return 0
	})
	inSet := func(set []uint16, x uint16) bool {
		for _, s := range set {
			if s == x {
				return true
			}
		}
		return false
	}
	reg(u, "wcsspn", func(e *Emu) uint64 {
		s, set := e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1))
		i := 0
		for i < len(s) && inSet(set, s[i]) {
			i++
		}
		return uint64(i)
	})
	reg(u, "wcscspn", func(e *Emu) uint64 {
		s, set := e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1))
		i := 0
		for i < len(s) && !inSet(set, s[i]) {
			i++
		}
		return uint64(i)
	})
	reg(u, "wcspbrk", func(e *Emu) uint64 {
		s, set := e.Mem.WStrUnits(e.Arg(0)), e.Mem.WStrUnits(e.Arg(1))
		for i := range s {
			if inSet(set, s[i]) {
				return e.Arg(0) + 2*uint64(i)
			}
		}
		return 0
	})
	wcstok := func(e *Emu, s, delim, state uint64) uint64 {
		m := e.Mem
		if s == 0 {
			s = m.R64(state)
			if s == 0 {
				return 0
			}
		}
		d := m.WStrUnits(delim)
		for m.R16(s) != 0 && inSet(d, m.R16(s)) {
			s += 2
		}
		if m.R16(s) == 0 {
			m.W64(state, 0)
			return 0
		}
		tok := s
		for m.R16(s) != 0 && !inSet(d, m.R16(s)) {
			s += 2
		}
		if m.R16(s) != 0 {
			m.W16(s, 0)
			s += 2
		}
		m.W64(state, s)
		return tok
	}
	reg(u, "wcstok", func(e *Emu) uint64 {
		st := e.Arg(2)
		if st == 0 {
			st = e.crt.wcstok[e.Cur.ID]
			if st == 0 {
				st = e.heapAllocRaw(8)
				e.crt.wcstok[e.Cur.ID] = st
			}
		}
		return wcstok(e, e.Arg(0), e.Arg(1), st)
	})
	reg(u, "wcstok_s", func(e *Emu) uint64 { return wcstok(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "_wcsdup", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		s := e.Mem.WStrUnits(e.Arg(0))
		a := e.heapAlloc(uint64(2*len(s)+2), false)
		e.Mem.WriteUnits(a, append(s, 0))
		return a
	})
	wcase := func(up bool) Fn {
		return func(e *Emu) uint64 {
			s := e.Mem.WStrUnits(e.Arg(0))
			for i := range s {
				if up {
					s[i] = upperW(s[i])
				} else {
					s[i] = lowerW(s[i])
				}
			}
			e.Mem.WriteUnits(e.Arg(0), s)
			return e.Arg(0)
		}
	}
	reg(u, "_wcslwr", wcase(false))
	reg(u, "_wcsupr", wcase(true))
	reg(u, "_wcslwr_s", func(e *Emu) uint64 { wcase(false)(e); return 0 })
	reg(u, "_wcsupr_s", func(e *Emu) uint64 { wcase(true)(e); return 0 })
	reg(u, "_wcsrev", func(e *Emu) uint64 {
		s := e.Mem.WStrUnits(e.Arg(0))
		for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
			s[i], s[j] = s[j], s[i]
		}
		e.Mem.WriteUnits(e.Arg(0), s)
		return e.Arg(0)
	})
	reg(u, "wcsxfrm", func(e *Emu) uint64 {
		s := e.Mem.WStrUnits(e.Arg(1))
		if uint64(len(s)) < e.Arg(2) {
			e.Mem.WriteUnits(e.Arg(0), append(s, 0))
		}
		return uint64(len(s))
	})

	// ---- numeric conversion ----
	reg(u, "atoi", func(e *Emu) uint64 { return e.atoX(false, false) })
	reg(u, "atol", func(e *Emu) uint64 { return e.atoX(false, false) })
	reg(u, "atoll", func(e *Emu) uint64 { return e.atoX(true, false) })
	reg(u, "_atoi64", func(e *Emu) uint64 { return e.atoX(true, false) })
	reg(u, "_atoi_l", func(e *Emu) uint64 { return e.atoX(false, false) })
	reg(u, "_wtoi", func(e *Emu) uint64 { return e.atoX(false, true) })
	reg(u, "_wtol", func(e *Emu) uint64 { return e.atoX(false, true) })
	reg(u, "_wtoi64", func(e *Emu) uint64 { return e.atoX(true, true) })
	reg(u, "_wtoll", func(e *Emu) uint64 { return e.atoX(true, true) })
	reg(u, "atof", func(e *Emu) uint64 { return e.strtodAt(e.Arg(0), 0, false, false) })
	reg(u, "_atof_l", func(e *Emu) uint64 { return e.strtodAt(e.Arg(0), 0, false, false) })
	reg(u, "_wtof", func(e *Emu) uint64 { return e.strtodAt(e.Arg(0), 0, false, true) })
	for _, n := range []string{"strtol", "_strtol_l"} {
		reg(u, n, func(e *Emu) uint64 { return e.strtoX(int(e.Arg32(2)), false, false) })
	}
	for _, n := range []string{"strtoul", "_strtoul_l"} {
		reg(u, n, func(e *Emu) uint64 { return e.strtoX(int(e.Arg32(2)), true, false) })
	}
	for _, n := range []string{"strtoll", "_strtoi64", "_strtoll_l", "_strtoi64_l", "strtoimax", "_strtoimax_l"} {
		reg(u, n, func(e *Emu) uint64 { return e.strtoX(int(e.Arg32(2)), false, true) })
	}
	for _, n := range []string{"strtoull", "_strtoui64", "_strtoull_l", "_strtoui64_l", "strtoumax", "_strtoumax_l"} {
		reg(u, n, func(e *Emu) uint64 { return e.strtoX(int(e.Arg32(2)), true, true) })
	}
	for _, n := range []string{"wcstol", "_wcstol_l"} {
		reg(u, n, func(e *Emu) uint64 { return e.wcstoX(int(e.Arg32(2)), false, false) })
	}
	for _, n := range []string{"wcstoul", "_wcstoul_l"} {
		reg(u, n, func(e *Emu) uint64 { return e.wcstoX(int(e.Arg32(2)), true, false) })
	}
	for _, n := range []string{"wcstoll", "_wcstoi64", "_wcstoll_l", "_wcstoi64_l", "wcstoimax"} {
		reg(u, n, func(e *Emu) uint64 { return e.wcstoX(int(e.Arg32(2)), false, true) })
	}
	for _, n := range []string{"wcstoull", "_wcstoui64", "_wcstoull_l", "_wcstoui64_l", "wcstoumax"} {
		reg(u, n, func(e *Emu) uint64 { return e.wcstoX(int(e.Arg32(2)), true, true) })
	}
	strtodF := func(f32 bool) Fn {
		return func(e *Emu) uint64 { return e.strtodAt(e.Arg(0), e.Arg(1), f32, false) }
	}
	for _, n := range []string{"strtod", "strtold", "_strtod_l", "_strtold_l"} {
		reg(u, n, strtodF(false))
	}
	reg(u, "strtof", strtodF(true))
	reg(u, "_strtof_l", strtodF(true))
	wcstodF := func(f32 bool) Fn {
		return func(e *Emu) uint64 { return e.strtodAt(e.Arg(0), e.Arg(1), f32, true) }
	}
	for _, n := range []string{"wcstod", "wcstold", "_wcstod_l"} {
		reg(u, n, wcstodF(false))
	}
	reg(u, "wcstof", wcstodF(true))
	// itoa family: (value, buf, radix) / _s: (value, buf, size, radix)
	type itoaSpec struct {
		name   string
		bits   int
		signed bool
		wide   bool
	}
	for _, sp := range []itoaSpec{
		{"_itoa", 32, true, false}, {"_ltoa", 32, true, false}, {"_ultoa", 32, false, false},
		{"_i64toa", 64, true, false}, {"_ui64toa", 64, false, false},
		{"_itow", 32, true, true}, {"_ltow", 32, true, true}, {"_ultow", 32, false, true},
		{"_i64tow", 64, true, true}, {"_ui64tow", 64, false, true},
	} {
		s := sp
		conv := func(e *Emu, v uint64, buf uint64, radix int) uint64 {
			neg := false
			if s.signed && radix == 10 {
				var iv int64
				if s.bits == 32 {
					iv = int64(int32(v))
				} else {
					iv = int64(v)
				}
				if iv < 0 {
					neg = true
					v = uint64(-iv)
				} else {
					v = uint64(iv)
				}
			} else if s.bits == 32 {
				v = uint64(uint32(v))
			}
			return e.ntoa(v, neg, radix, s.wide, buf)
		}
		reg(u, s.name, func(e *Emu) uint64 { return conv(e, e.Arg(0), e.Arg(1), int(e.Arg32(2))) })
		reg(u, s.name+"_s", func(e *Emu) uint64 { conv(e, e.Arg(0), e.Arg(1), int(e.Arg32(3))); return 0 })
	}
	reg(u, "_ecvt", func(e *Emu) uint64 { return ecvt(e, e.ArgF(0), int(e.ArgI(1)), e.Arg(2), e.Arg(3), false) })
	reg(u, "_fcvt", func(e *Emu) uint64 { return ecvt(e, e.ArgF(0), int(e.ArgI(1)), e.Arg(2), e.Arg(3), true) })
	reg(u, "_gcvt", func(e *Emu) uint64 {
		s := strconv.FormatFloat(e.ArgF(0), 'g', int(e.ArgI(1)), 64)
		e.Mem.WriteCStr(e.Arg(2), s)
		return e.Arg(2)
	})

	// ---- ctype ----
	ct := func(mask uint16) Fn {
		return func(e *Emu) uint64 {
			c := int(e.ArgI(0))
			if c < 0 || c > 255 {
				return 0
			}
			return uint64(ctypeOf(c) & mask)
		}
	}
	for name, mask := range map[string]uint16{
		"isalpha": ctAlpha | ctUpper | ctLower, "isupper": ctUpper, "islower": ctLower, "isdigit": ctDigit,
		"isxdigit": ctHex, "isspace": ctSpace, "ispunct": ctPunct, "isalnum": ctAlpha | ctUpper | ctLower | ctDigit,
		"isprint": ctAlpha | ctUpper | ctLower | ctDigit | ctPunct | ctBlank, "isgraph": ctAlpha | ctUpper | ctLower | ctDigit | ctPunct,
		"iscntrl": ctCntrl, "isblank": ctBlank,
	} {
		f := ct(mask)
		if name == "isprint" {
			f = func(e *Emu) uint64 {
				c := e.ArgI(0)
				return b2u(c >= 0x20 && c < 0x7F)
			}
		}
		if name == "isblank" {
			f = func(e *Emu) uint64 { c := e.ArgI(0); return b2u(c == ' ' || c == '\t') }
		}
		reg(u, name, f)
		reg(u, "_"+name+"_l", f)
	}
	reg(u, "__isascii", func(e *Emu) uint64 { return b2u(e.Arg32(0) < 0x80) })
	reg(u, "isascii", func(e *Emu) uint64 { return b2u(e.Arg32(0) < 0x80) })
	reg(u, "__iscsym", func(e *Emu) uint64 {
		c := int(e.ArgI(0))
		return b2u(c == '_' || c >= 0 && c < 256 && ctypeOf(c)&(ctAlpha|ctDigit) != 0)
	})
	reg(u, "__iscsymf", func(e *Emu) uint64 {
		c := int(e.ArgI(0))
		return b2u(c == '_' || c >= 0 && c < 256 && ctypeOf(c)&ctAlpha != 0)
	})
	reg(u, "__toascii", func(e *Emu) uint64 { return e.Arg(0) & 0x7F })
	reg(u, "_isctype", func(e *Emu) uint64 {
		c := int(e.ArgI(0))
		if c < 0 || c > 255 {
			return 0
		}
		return uint64(ctypeOf(c) & uint16(e.Arg32(1)))
	})
	reg(u, "_isctype_l", func(e *Emu) uint64 {
		c := int(e.ArgI(0))
		if c < 0 || c > 255 {
			return 0
		}
		return uint64(ctypeOf(c) & uint16(e.Arg32(1)))
	})
	for _, n := range []string{"toupper", "_toupper_l", "_toupper"} {
		reg(u, n, func(e *Emu) uint64 {
			c := e.ArgI(0)
			if c >= 'a' && c <= 'z' {
				return uint64(c - 32)
			}
			return uint64(c)
		})
	}
	for _, n := range []string{"tolower", "_tolower_l", "_tolower"} {
		reg(u, n, func(e *Emu) uint64 {
			c := e.ArgI(0)
			if c >= 'A' && c <= 'Z' {
				return uint64(c + 32)
			}
			return uint64(c)
		})
	}
	wct := func(f func(r rune) bool) Fn {
		return func(e *Emu) uint64 { return b2u(f(rune(e.Arg32(0) & 0xFFFF))) }
	}
	for name, f := range map[string]func(rune) bool{
		"iswalpha": unicode.IsLetter, "iswupper": unicode.IsUpper, "iswlower": unicode.IsLower,
		"iswdigit":  func(r rune) bool { return r >= '0' && r <= '9' },
		"iswxdigit": func(r rune) bool { return r < 128 && ctypeOf(int(r))&ctHex != 0 },
		"iswspace":  unicode.IsSpace, "iswpunct": unicode.IsPunct,
		"iswalnum": func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) },
		"iswprint": func(r rune) bool { return unicode.IsPrint(r) },
		"iswgraph": func(r rune) bool { return unicode.IsGraphic(r) && !unicode.IsSpace(r) },
		"iswcntrl": unicode.IsControl, "iswblank": func(r rune) bool { return r == ' ' || r == '\t' },
		"iswascii": func(r rune) bool { return r < 128 },
	} {
		reg(u, name, wct(f))
		reg(u, "_"+name+"_l", wct(f))
	}
	reg(u, "iswctype", func(e *Emu) uint64 { return uint64(wctypeOf(rune(e.Arg32(0)&0xFFFF)) & uint16(e.Arg32(1))) })
	reg(u, "_iswctype_l", func(e *Emu) uint64 { return uint64(wctypeOf(rune(e.Arg32(0)&0xFFFF)) & uint16(e.Arg32(1))) })
	reg(u, "is_wctype", func(e *Emu) uint64 { return uint64(wctypeOf(rune(e.Arg32(0)&0xFFFF)) & uint16(e.Arg32(1))) })
	reg(u, "wctype", func(e *Emu) uint64 {
		switch e.CStr(e.Arg(0)) {
		case "alpha":
			return ctAlpha | ctUpper | ctLower
		case "upper":
			return ctUpper
		case "lower":
			return ctLower
		case "digit":
			return ctDigit
		case "xdigit":
			return ctHex
		case "space":
			return ctSpace
		case "punct":
			return ctPunct
		case "alnum":
			return ctAlpha | ctUpper | ctLower | ctDigit
		case "print":
			return ctAlpha | ctUpper | ctLower | ctDigit | ctPunct | ctBlank
		case "graph":
			return ctAlpha | ctUpper | ctLower | ctDigit | ctPunct
		case "cntrl":
			return ctCntrl
		case "blank":
			return ctBlank
		}
		return 0
	})
	reg(u, "towupper", func(e *Emu) uint64 { return uint64(upperW(uint16(e.Arg32(0)))) })
	reg(u, "towlower", func(e *Emu) uint64 { return uint64(lowerW(uint16(e.Arg32(0)))) })
	reg(u, "_towupper_l", func(e *Emu) uint64 { return uint64(upperW(uint16(e.Arg32(0)))) })
	reg(u, "_towlower_l", func(e *Emu) uint64 { return uint64(lowerW(uint16(e.Arg32(0)))) })

	// ---- multibyte <-> wide ----
	reg(u, "mblen", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		b := e.Mem.CStrN(e.Arg(0), int(min(e.Arg(1), 4)))
		if len(b) == 0 {
			return 0
		}
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n <= 1 {
			return ^uint64(0)
		}
		return uint64(n)
	})
	mbtowc := func(e *Emu, dst, src, n uint64) uint64 {
		if src == 0 {
			return 0
		}
		b := e.Mem.CStrN(src, int(min(n, 4)))
		if len(b) == 0 {
			if dst != 0 {
				e.Mem.W16(dst, 0)
			}
			return 0
		}
		r, sz := utf8.DecodeRune(b)
		if r == utf8.RuneError && sz <= 1 {
			if !utf8.FullRune(b) && uint64(len(b)) == n {
				return ^uint64(1) // -2: incomplete
			}
			e.crt.setErrno(eilseq)
			return ^uint64(0)
		}
		if dst != 0 {
			if r > 0xFFFF {
				r = 0xFFFD
			}
			e.Mem.W16(dst, uint16(r))
		}
		return uint64(sz)
	}
	reg(u, "mbtowc", func(e *Emu) uint64 { return uint64(int64(int32(mbtowc(e, e.Arg(0), e.Arg(1), e.Arg(2))))) })
	reg(u, "_mbtowc_l", func(e *Emu) uint64 { return mbtowc(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "mbrtowc", func(e *Emu) uint64 { return mbtowc(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "mbrlen", func(e *Emu) uint64 { return mbtowc(e, 0, e.Arg(0), e.Arg(1)) })
	reg(u, "btowc", func(e *Emu) uint64 {
		c := e.ArgI(0)
		if c < 0 || c >= 0x80 {
			return 0xFFFF
		}
		return uint64(c)
	})
	reg(u, "wctob", func(e *Emu) uint64 {
		c := e.Arg32(0) & 0xFFFF
		if c >= 0x80 {
			return ^uint64(0)
		}
		return uint64(c)
	})
	reg(u, "mbsinit", ret(1))
	wctomb := func(e *Emu, dst uint64, wc uint16) uint64 {
		b := []byte(string(rune(wc)))
		if dst != 0 {
			e.Mem.Write(dst, b)
		}
		return uint64(len(b))
	}
	reg(u, "wctomb", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return wctomb(e, e.Arg(0), uint16(e.Arg32(1)))
	})
	reg(u, "wcrtomb", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 1
		}
		return wctomb(e, e.Arg(0), uint16(e.Arg32(1)))
	})
	reg(u, "wctomb_s", func(e *Emu) uint64 {
		n := wctomb(e, e.Arg(1), uint16(e.Arg32(3)))
		if e.Arg(0) != 0 {
			e.Mem.W32(e.Arg(0), uint32(n))
		}
		return 0
	})
	reg(u, "wcrtomb_s", func(e *Emu) uint64 {
		n := wctomb(e, e.Arg(1), uint16(e.Arg32(3)))
		if e.Arg(0) != 0 {
			e.Mem.W64(e.Arg(0), n)
		}
		return 0
	})
	reg(u, "c16rtomb", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 1
		}
		return wctomb(e, e.Arg(0), uint16(e.Arg32(1)))
	})
	reg(u, "c32rtomb", func(e *Emu) uint64 {
		b := []byte(string(rune(e.Arg32(1))))
		if e.Arg(0) != 0 {
			e.Mem.Write(e.Arg(0), b)
		}
		return uint64(len(b))
	})
	reg(u, "mbrtoc16", func(e *Emu) uint64 { return mbtowc(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "mbrtoc32", func(e *Emu) uint64 {
		b := e.Mem.CStrN(e.Arg(1), int(min(e.Arg(2), 4)))
		if len(b) == 0 {
			if e.Arg(0) != 0 {
				e.Mem.W32(e.Arg(0), 0)
			}
			return 0
		}
		r, n := utf8.DecodeRune(b)
		if e.Arg(0) != 0 {
			e.Mem.W32(e.Arg(0), uint32(r))
		}
		return uint64(n)
	})
	mbstowcs := func(e *Emu, dst, src, n uint64) uint64 {
		units := utf8ToUnits(e.Mem.CStrBytes(src))
		if dst == 0 {
			return uint64(len(units))
		}
		if uint64(len(units)) < n {
			e.Mem.WriteUnits(dst, append(units, 0))
			return uint64(len(units))
		}
		e.Mem.WriteUnits(dst, units[:n])
		return n
	}
	reg(u, "mbstowcs", func(e *Emu) uint64 { return mbstowcs(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "_mbstowcs_l", func(e *Emu) uint64 { return mbstowcs(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "mbsrtowcs", func(e *Emu) uint64 {
		src := e.Mem.R64(e.Arg(1))
		r := mbstowcs(e, e.Arg(0), src, e.Arg(2))
		if e.Arg(0) != 0 {
			e.Mem.W64(e.Arg(1), 0)
		}
		return r
	})
	reg(u, "mbstowcs_s", func(e *Emu) uint64 {
		// (pReturnValue, wcstr, sizeInWords, mbstr, count)
		units := utf8ToUnits(e.Mem.CStrBytes(e.Arg(3)))
		if c := e.Arg(4); c != ^uint64(0) && uint64(len(units)) > c {
			units = units[:c]
		}
		if e.Arg(1) != 0 {
			if uint64(len(units)) >= e.Arg(2) {
				units = units[:e.Arg(2)-1]
			}
			e.Mem.WriteUnits(e.Arg(1), append(units, 0))
		}
		if e.Arg(0) != 0 {
			e.Mem.W64(e.Arg(0), uint64(len(units)+1))
		}
		return 0
	})
	wcstombs := func(e *Emu, dst, src, n uint64) uint64 {
		b := unitsToUTF8(e.Mem.WStrUnits(src))
		if dst == 0 {
			return uint64(len(b))
		}
		if uint64(len(b)) < n {
			e.Mem.Write(dst, append(b, 0))
			return uint64(len(b))
		}
		k := int(n)
		for k > 0 && !utf8.RuneStart(b[k]) {
			k--
		}
		e.Mem.Write(dst, b[:k])
		return uint64(k)
	}
	reg(u, "wcstombs", func(e *Emu) uint64 { return wcstombs(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "_wcstombs_l", func(e *Emu) uint64 { return wcstombs(e, e.Arg(0), e.Arg(1), e.Arg(2)) })
	reg(u, "wcsrtombs", func(e *Emu) uint64 {
		src := e.Mem.R64(e.Arg(1))
		r := wcstombs(e, e.Arg(0), src, e.Arg(2))
		if e.Arg(0) != 0 {
			e.Mem.W64(e.Arg(1), 0)
		}
		return r
	})
	reg(u, "wcstombs_s", func(e *Emu) uint64 {
		b := unitsToUTF8(e.Mem.WStrUnits(e.Arg(3)))
		if c := e.Arg(4); c != ^uint64(0) && uint64(len(b)) > c {
			b = b[:c]
		}
		if e.Arg(1) != 0 {
			if uint64(len(b)) >= e.Arg(2) {
				b = b[:e.Arg(2)-1]
			}
			e.Mem.Write(e.Arg(1), append(b, 0))
		}
		if e.Arg(0) != 0 {
			e.Mem.W64(e.Arg(0), uint64(len(b)+1))
		}
		return 0
	})
	reg(u, "_mbstrlen", func(e *Emu) uint64 { return uint64(utf8.RuneCount(e.Mem.CStrBytes(e.Arg(0)))) })

	// ---- algorithms ----
	reg(u, "qsort", func(e *Emu) uint64 { e.qsort(e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), 0, false); return 0 })
	reg(u, "qsort_s", func(e *Emu) uint64 { e.qsort(e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4), true); return 0 })
	bsearch := func(e *Emu, key, base, n, size, cmp, ctx uint64, withCtx bool) uint64 {
		lo, hi := uint64(0), n
		for lo < hi {
			mid := (lo + hi) / 2
			p := base + mid*size
			var r int32
			if withCtx {
				r = int32(e.CallGuest(cmp, ctx, key, p))
			} else {
				r = int32(e.CallGuest(cmp, key, p))
			}
			switch {
			case r == 0:
				return p
			case r < 0:
				hi = mid
			default:
				lo = mid + 1
			}
		}
		return 0
	}
	reg(u, "bsearch", func(e *Emu) uint64 { return bsearch(e, e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4), 0, false) })
	reg(u, "bsearch_s", func(e *Emu) uint64 {
		return bsearch(e, e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4), e.Arg(5), true)
	})
	reg(u, "_lfind", func(e *Emu) uint64 {
		key, base, np, size, cmp := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4)
		n := uint64(e.Mem.R32(np))
		for i := uint64(0); i < n; i++ {
			if int32(e.CallGuest(cmp, key, base+i*size)) == 0 {
				return base + i*size
			}
		}
		return 0
	})

	// ---- random / arithmetic ----
	reg(u, "rand", func(e *Emu) uint64 {
		id := e.Cur.ID
		s, ok := e.crt.randState[id]
		if !ok {
			s = 1
		}
		s = s*214013 + 2531011
		e.crt.randState[id] = s
		return (s >> 16) & 0x7FFF
	})
	reg(u, "srand", func(e *Emu) uint64 { e.crt.randState[e.Cur.ID] = uint64(e.Arg32(0)); return 0 })
	reg(u, "rand_s", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), rand.Uint32()); return 0 })
	reg(u, "abs", func(e *Emu) uint64 { return uint64(uint32(abs64(int64(int32(e.Arg(0)))))) })
	reg(u, "labs", func(e *Emu) uint64 { return uint64(uint32(abs64(int64(int32(e.Arg(0)))))) })
	reg(u, "llabs", func(e *Emu) uint64 { return uint64(abs64(int64(e.Arg(0)))) })
	reg(u, "_abs64", func(e *Emu) uint64 { return uint64(abs64(int64(e.Arg(0)))) })
	reg(u, "imaxabs", func(e *Emu) uint64 { return uint64(abs64(int64(e.Arg(0)))) })
	reg(u, "div", func(e *Emu) uint64 {
		a, b := int32(e.Arg(0)), int32(e.Arg(1))
		if b == 0 {
			return 0
		}
		return uint64(uint32(a/b)) | uint64(uint32(a%b))<<32
	})
	reg(u, "ldiv", func(e *Emu) uint64 {
		a, b := int32(e.Arg(0)), int32(e.Arg(1))
		if b == 0 {
			return 0
		}
		return uint64(uint32(a/b)) | uint64(uint32(a%b))<<32
	})
	reg(u, "lldiv", func(e *Emu) uint64 {
		// struct returned via hidden pointer (16 bytes)
		r, a, b := e.Arg(0), int64(e.Arg(1)), int64(e.Arg(2))
		if b != 0 {
			e.Mem.W64(r, uint64(a/b))
			e.Mem.W64(r+8, uint64(a%b))
		}
		return r
	})
	reg(u, "imaxdiv", func(e *Emu) uint64 {
		r, a, b := e.Arg(0), int64(e.Arg(1)), int64(e.Arg(2))
		if b != 0 {
			e.Mem.W64(r, uint64(a/b))
			e.Mem.W64(r+8, uint64(a%b))
		}
		return r
	})
	reg(u, "_rotl", func(e *Emu) uint64 { return uint64(bits.RotateLeft32(e.Arg32(0), int(e.ArgI(1)))) })
	reg(u, "_rotr", func(e *Emu) uint64 { return uint64(bits.RotateLeft32(e.Arg32(0), -int(e.ArgI(1)))) })
	reg(u, "_lrotl", func(e *Emu) uint64 { return uint64(bits.RotateLeft32(e.Arg32(0), int(e.ArgI(1)))) })
	reg(u, "_lrotr", func(e *Emu) uint64 { return uint64(bits.RotateLeft32(e.Arg32(0), -int(e.ArgI(1)))) })
	reg(u, "_rotl64", func(e *Emu) uint64 { return bits.RotateLeft64(e.Arg(0), int(e.ArgI(1))) })
	reg(u, "_rotr64", func(e *Emu) uint64 { return bits.RotateLeft64(e.Arg(0), -int(e.ArgI(1))) })
	reg(u, "_byteswap_ushort", func(e *Emu) uint64 { return uint64(bits.ReverseBytes16(uint16(e.Arg(0)))) })
	reg(u, "_byteswap_ulong", func(e *Emu) uint64 { return uint64(bits.ReverseBytes32(e.Arg32(0))) })
	reg(u, "_byteswap_uint64", func(e *Emu) uint64 { return bits.ReverseBytes64(e.Arg(0)) })
	reg(u, "_swab", func(e *Emu) uint64 {
		n := e.ArgI(2) &^ 1
		b := e.Mem.ReadBytes(e.Arg(0), int(n))
		for i := 0; i+1 < len(b); i += 2 {
			b[i], b[i+1] = b[i+1], b[i]
		}
		e.Mem.Write(e.Arg(1), b)
		return 0
	})
}

func wctypeOf(r rune) uint16 {
	if r < 256 {
		return ctypeOf(int(r))
	}
	var v uint16
	if unicode.IsUpper(r) {
		v |= ctUpper | ctAlpha
	}
	if unicode.IsLower(r) {
		v |= ctLower | ctAlpha
	}
	if unicode.IsLetter(r) {
		v |= ctAlpha
	}
	if unicode.IsDigit(r) {
		v |= ctDigit
	}
	if unicode.IsSpace(r) {
		v |= ctSpace
	}
	if unicode.IsPunct(r) || unicode.IsSymbol(r) {
		v |= ctPunct
	}
	if unicode.IsControl(r) {
		v |= ctCntrl
	}
	return v
}

func ecvt(e *Emu, v float64, n int, decpt, signp uint64, fixed bool) uint64 {
	neg := v < 0
	if neg {
		v = -v
	}
	var digits string
	var dp int
	if fixed {
		s := strconv.FormatFloat(v, 'f', n, 64)
		i := strings.IndexByte(s, '.')
		if i < 0 {
			i = len(s)
		}
		digits = strings.Replace(s, ".", "", 1)
		dp = i
		trimmed := strings.TrimLeft(digits, "0")
		dp -= len(digits) - len(trimmed)
		digits = trimmed
	} else {
		if n < 1 {
			n = 1
		}
		s := strconv.FormatFloat(v, 'e', n-1, 64)
		k := strings.IndexByte(s, 'e')
		exp, _ := strconv.Atoi(s[k+1:])
		digits = strings.Replace(s[:k], ".", "", 1)
		dp = exp + 1
		if v == 0 {
			dp = 0
		}
	}
	e.Mem.W32(decpt, uint32(int32(dp)))
	e.Mem.W32(signp, uint32(b2u(neg)))
	buf := e.crt.strerrorBuf(digits)
	return buf
}

// qsort is a merge sort calling the guest comparator.
func (e *Emu) qsort(base, n, size, cmp, ctx uint64, withCtx bool) {
	if n < 2 || size == 0 {
		return
	}
	data := e.Mem.ReadBytes(base, int(n*size))
	// sort indices using guest comparator on scratch copies
	tmpA := e.heapAlloc(size, false)
	tmpB := e.heapAlloc(size, false)
	defer e.heap.freeBlock(tmpA)
	defer e.heap.freeBlock(tmpB)
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	less := func(i, j int) bool {
		e.Mem.Write(tmpA, data[uint64(i)*size:uint64(i+1)*size])
		e.Mem.Write(tmpB, data[uint64(j)*size:uint64(j+1)*size])
		var r int32
		if withCtx {
			r = int32(e.CallGuest(cmp, ctx, tmpA, tmpB))
		} else {
			r = int32(e.CallGuest(cmp, tmpA, tmpB))
		}
		return r < 0
	}
	// merge sort for O(n log n) comparisons and stability
	buf := make([]int, n)
	var msort func(a []int, b []int)
	msort = func(a []int, b []int) {
		if len(a) <= 1 {
			return
		}
		mid := len(a) / 2
		msort(a[:mid], b[:mid])
		msort(a[mid:], b[mid:])
		copy(b, a)
		i, j, k := 0, mid, 0
		for i < mid && j < len(a) {
			if less(b[j], b[i]) {
				a[k] = b[j]
				j++
			} else {
				a[k] = b[i]
				i++
			}
			k++
		}
		for i < mid {
			a[k] = b[i]
			i++
			k++
		}
		for j < len(a) {
			a[k] = b[j]
			j++
			k++
		}
	}
	msort(idx, buf)
	out := make([]byte, 0, len(data))
	for _, i := range idx {
		out = append(out, data[uint64(i)*size:uint64(i+1)*size]...)
	}
	e.Mem.Write(base, out)
}

var _ = cpu.RAX
