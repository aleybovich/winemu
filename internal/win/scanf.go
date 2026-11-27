package win

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// scanIn is a character source with one-character pushback.
type scanIn interface {
	get() (rune, bool)
	unget(r rune)
}

// strIn scans from a narrow (bytes) or wide (units) buffer.
type strIn struct {
	b    []byte
	u    []uint16
	wide bool
	pos  int
}

func (s *strIn) get() (rune, bool) {
	if s.wide {
		if s.pos >= len(s.u) {
			s.pos++
			return 0, false
		}
		r := rune(s.u[s.pos])
		s.pos++
		return r, true
	}
	if s.pos >= len(s.b) {
		s.pos++
		return 0, false
	}
	r := rune(s.b[s.pos])
	s.pos++
	return r, true
}

func (s *strIn) unget(rune) { s.pos-- }

// fileIn scans from a CRT stream.
type fileIn struct {
	e    *Emu
	f    *cfile
	wide bool
}

func (fi *fileIn) get() (rune, bool) {
	if fi.wide {
		r, ok := fi.e.crt.getwc(fi.f)
		return r, ok
	}
	c := fi.e.crt.getc(fi.f)
	if c < 0 {
		return 0, false
	}
	return rune(c), true
}

func (fi *fileIn) unget(r rune) {
	if fi.wide {
		fi.e.crt.ungetwc(fi.f, r)
		return
	}
	fi.e.crt.ungetc(fi.f, int(r))
}

func isSpaceRune(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
}

type scanOpts struct {
	wide       bool // wide function (wscanf)
	secure     bool // _s variants: buffer sizes follow string pointers
	legacyWide bool
}

// sscanf runs a scanf format against in. Returns the C return value.
func (e *Emu) scanf(format []rune, in scanIn, args argSrc, o scanOpts) int {
	assigned := 0
	consumed := 0
	eofHit := false
	get := func() (rune, bool) {
		r, ok := in.get()
		if ok {
			consumed++
		} else {
			eofHit = true
		}
		return r, ok
	}
	unget := func(r rune) {
		in.unget(r)
		consumed--
	}
	skipWS := func() {
		for {
			r, ok := get()
			if !ok {
				return
			}
			if !isSpaceRune(r) {
				unget(r)
				return
			}
		}
	}
	m := e.Mem
	f := format
	convs := 0
	for i := 0; i < len(f); i++ {
		c := f[i]
		if isSpaceRune(c) {
			skipWS()
			continue
		}
		if c != '%' || (i+1 < len(f) && f[i+1] == '%') {
			if c == '%' {
				i++
			}
			skipWSIfPercent := c == '%'
			if skipWSIfPercent {
				skipWS()
			}
			r, ok := get()
			if !ok {
				break
			}
			if r != c {
				unget(r)
				break
			}
			continue
		}
		i++
		suppress := false
		if i < len(f) && f[i] == '*' {
			suppress = true
			i++
		}
		width := 0
		for i < len(f) && f[i] >= '0' && f[i] <= '9' {
			width = width*10 + int(f[i]-'0')
			i++
		}
		size := 0
		charW := 0
	length:
		for i < len(f) {
			switch f[i] {
			case 'h':
				if i+1 < len(f) && f[i+1] == 'h' {
					size = 1
					i += 2
				} else {
					size = 2
					charW = 1
					i++
				}
			case 'l':
				if i+1 < len(f) && f[i+1] == 'l' {
					size = 8
					i += 2
				} else {
					size = 4
					charW = 2
					i++
				}
			case 'L', 'q', 'j', 'z', 't':
				size = 8
				i++
			case 'w':
				charW = 2
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
		if conv != 'c' && conv != 'C' && conv != '[' && conv != 'n' {
			skipWS()
		}
		limit := width
		if limit == 0 {
			limit = math.MaxInt32
		}
		failed := false
		switch conv {
		case 'n':
			if !suppress {
				p := args.next()
				switch size {
				case 1:
					m.W8(p, uint8(consumed))
				case 2:
					m.W16(p, uint16(consumed))
				case 8:
					m.W64(p, uint64(consumed))
				default:
					m.W32(p, uint32(consumed))
				}
			}
			continue
		case 'd', 'i', 'u', 'o', 'x', 'X', 'p', 'b':
			base := 10
			switch conv {
			case 'i':
				base = 0
			case 'o':
				base = 8
			case 'x', 'X', 'p':
				base = 16
			case 'b':
				base = 2
			}
			var sb strings.Builder
			n := 0
			r, ok := get()
			if ok && (r == '+' || r == '-') && n < limit {
				sb.WriteRune(r)
				n++
				r, ok = get()
			}
			if ok && r == '0' && n < limit && (base == 0 || base == 16) {
				sb.WriteRune(r)
				n++
				r2, ok2 := get()
				if ok2 && (r2 == 'x' || r2 == 'X') && n < limit {
					sb.WriteRune(r2)
					n++
					base = 16
					r, ok = get()
				} else {
					if base == 0 {
						base = 8
					}
					r, ok = r2, ok2
				}
			}
			if base == 0 {
				base = 10
			}
			digits := 0
			for ok && n < limit && isDigitBase(r, base) {
				sb.WriteRune(r)
				n++
				digits++
				r, ok = get()
			}
			if ok {
				unget(r)
			}
			s := sb.String()
			if digits == 0 && !strings.HasSuffix(strings.ToLower(s), "0") {
				failed = true
				break
			}
			if suppress {
				continue
			}
			v := parseIntWrap(s, base)
			p := args.next()
			sz := size
			if conv == 'p' {
				sz = 8
			}
			switch sz {
			case 1:
				m.W8(p, uint8(v))
			case 2:
				m.W16(p, uint16(v))
			case 8:
				m.W64(p, v)
			default:
				m.W32(p, uint32(v))
			}
			assigned++
		case 'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A':
			var sb strings.Builder
			n := 0
			r, ok := get()
			accept := func(pred func(rune) bool) bool {
				if ok && n < limit && pred(r) {
					sb.WriteRune(r)
					n++
					r, ok = get()
					return true
				}
				return false
			}
			accept(func(r rune) bool { return r == '+' || r == '-' })
			// inf / nan
			if ok && (r == 'i' || r == 'I' || r == 'n' || r == 'N') {
				for accept(func(r rune) bool { return strings.ContainsRune("infatyINFATY()", r) || r >= 'a' && r <= 'z' }) {
				}
			} else {
				hex := false
				if accept(func(r rune) bool { return r == '0' }) {
					if accept(func(r rune) bool { return r == 'x' || r == 'X' }) {
						hex = true
					}
				}
				isD := func(r rune) bool { return r >= '0' && r <= '9' || hex && isDigitBase(r, 16) }
				for accept(isD) {
				}
				if accept(func(r rune) bool { return r == '.' }) {
					for accept(isD) {
					}
				}
				expCh := func(r rune) bool { return !hex && (r == 'e' || r == 'E') || hex && (r == 'p' || r == 'P') }
				if accept(expCh) {
					accept(func(r rune) bool { return r == '+' || r == '-' })
					for accept(func(r rune) bool { return r >= '0' && r <= '9' }) {
					}
				}
			}
			if ok {
				unget(r)
			}
			s := sb.String()
			v, good := parseCFloat(s)
			if !good {
				failed = true
				break
			}
			if suppress {
				continue
			}
			p := args.next()
			if size == 4 || size == 8 {
				m.W64(p, math.Float64bits(v))
			} else {
				m.W32(p, math.Float32bits(float32(v)))
			}
			assigned++
		case 's', 'S', 'c', 'C', '[':
			// determine target width (narrow/wide)
			wideDst := o.wide && o.legacyWide || o.wide && conv != 'S' && conv != 'C' && !o.legacyWide && false
			if o.wide {
				wideDst = true
			}
			if conv == 'S' || conv == 'C' {
				wideDst = !wideDst
			}
			if charW == 1 {
				wideDst = false
			} else if charW == 2 {
				wideDst = true
			}
			var set func(rune) bool
			if conv == '[' {
				i++
				neg := false
				if i < len(f) && f[i] == '^' {
					neg = true
					i++
				}
				var items []rune
				start := i
				for i < len(f) && (f[i] != ']' || i == start) {
					items = append(items, f[i])
					i++
				}
				set = func(r rune) bool {
					in := false
					for k := 0; k < len(items); k++ {
						if k+2 < len(items) && items[k+1] == '-' {
							if r >= items[k] && r <= items[k+2] {
								in = true
							}
							k += 2
							continue
						}
						if items[k] == r {
							in = true
						}
					}
					return in != neg
				}
			}
			isChar := conv == 'c' || conv == 'C'
			if isChar && width == 0 {
				limit = 1
			}
			var p, bufSize uint64
			if !suppress {
				p = args.next()
				if o.secure {
					bufSize = uint64(uint32(args.next()))
				} else {
					bufSize = math.MaxUint32
				}
			}
			var got []rune
			r, ok := get()
			for ok && len(got) < limit {
				if isChar {
				} else if set != nil {
					if !set(r) {
						break
					}
				} else if isSpaceRune(r) {
					break
				}
				got = append(got, r)
				if len(got) < limit {
					r, ok = get()
				} else {
					ok = false
					r = -1
				}
			}
			if ok && r >= 0 {
				unget(r)
			}
			if len(got) == 0 || isChar && len(got) < limit && width > 0 && false {
				failed = true
				break
			}
			if suppress {
				continue
			}
			need := uint64(len(got))
			if !isChar {
				need++
			}
			if need > bufSize {
				if bufSize > 0 {
					m.W8(p, 0)
				}
				failed = true
				break
			}
			if wideDst {
				units := make([]uint16, 0, len(got)+1)
				for _, r := range got {
					if o.wide {
						units = append(units, uint16(r))
					} else {
						units = append(units, uint16(r)) // byte -> wide (latin1)
					}
				}
				if !isChar {
					units = append(units, 0)
				}
				m.WriteUnits(p, units)
			} else {
				bs := make([]byte, 0, len(got)+1)
				for _, r := range got {
					if o.wide {
						bs = append(bs, string(r)...)
					} else {
						bs = append(bs, byte(r))
					}
				}
				if !isChar {
					bs = append(bs, 0)
				}
				m.Write(p, bs)
			}
			assigned++
		default:
			failed = true
		}
		convs++
		if failed {
			if assigned == 0 && eofHit {
				return -1
			}
			return assigned
		}
	}
	if assigned == 0 && eofHit && convs > 0 {
		return -1
	}
	if assigned == 0 && eofHit && consumed == 0 {
		return -1
	}
	return assigned
}

func isDigitBase(r rune, base int) bool {
	var d int
	switch {
	case r >= '0' && r <= '9':
		d = int(r - '0')
	case r >= 'a' && r <= 'z':
		d = int(r-'a') + 10
	case r >= 'A' && r <= 'Z':
		d = int(r-'A') + 10
	default:
		return false
	}
	return d < base
}

func parseIntWrap(s string, base int) uint64 {
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	if base == 16 {
		s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	}
	var v uint64
	for _, r := range s {
		var d int
		switch {
		case r >= '0' && r <= '9':
			d = int(r - '0')
		case r >= 'a' && r <= 'z':
			d = int(r-'a') + 10
		case r >= 'A' && r <= 'Z':
			d = int(r-'A') + 10
		}
		v = v*uint64(base) + uint64(d)
	}
	if neg {
		v = -v
	}
	return v
}

// parseCFloat parses a C floating literal (as accepted by strtod).
func parseCFloat(s string) (float64, bool) { return parseCFloatBits(s, 64) }

// parseCFloatBits is parseCFloat rounding directly to a bitSize (32 or 64)
// float, as strtof must (rounding through float64 first can double-round).
func parseCFloatBits(s string, bitSize int) (float64, bool) {
	if s == "" || s == "+" || s == "-" {
		return 0, false
	}
	t := strings.ToLower(s)
	sign := 1.0
	body := t
	if strings.HasPrefix(body, "-") {
		sign = -1
		body = body[1:]
	} else if strings.HasPrefix(body, "+") {
		body = body[1:]
	}
	switch {
	case strings.HasPrefix(body, "inf"):
		return sign * math.Inf(1), true
	case strings.HasPrefix(body, "nan"):
		return math.Copysign(math.Float64frombits(0x7FF8000000000000), sign), true // x86 default QNaN
	}
	if strings.HasPrefix(body, "0x") {
		h := body
		if !strings.Contains(h, "p") {
			h += "p0"
		}
		v, err := strconv.ParseFloat(h, bitSize)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
				return sign * v, true
			}
			return 0, false
		}
		return sign * v, true
	}
	v, err := strconv.ParseFloat(body, bitSize)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return sign * v, true
		}
		return 0, false
	}
	return sign * v, true
}

var _ = utf16.Decode
