package win

import (
	"bytes"
	"encoding/binary"
	"math"

	"winemu/internal/mem"
)

// Bounded scans of guest strings. The CRT string builtins used to copy the
// whole NUL-terminated string out of guest memory on every call, which is
// quadratic when a program walks a long buffer with strtol/strstr. These
// helpers read small blocks and stop as soon as the answer is known. A block
// never crosses a memory chunk boundary, so they fault (like a native scan)
// only if the string itself runs into unmapped memory.

const scanMaxBlock = 4096

// readBlock copies up to len(buf) guest bytes at a, stopping at the end of
// a's chunk, and returns the filled part.
func readBlock(m *mem.Memory, a uint64, buf []byte) []byte {
	room := mem.ChunkSize - a&(mem.ChunkSize-1)
	b := buf[:min(uint64(len(buf)), room)]
	m.Read(a, b)
	return b
}

// cstrScanner yields consecutive blocks of a NUL-terminated guest string
// (terminator excluded). Blocks start small and grow, so short strings cost
// one small read. Keep it on the caller's stack: no callbacks, no allocation.
type cstrScanner struct {
	m    *mem.Memory
	a    uint64 // string start
	off  uint64 // offset of the next block
	k    int    // next block size
	done bool
	buf  [scanMaxBlock]byte
}

func newCStrScanner(m *mem.Memory, a uint64) cstrScanner { return cstrScanner{m: m, a: a, k: 64} }

// next returns the next non-empty block and its string offset; ok is false
// once the terminator has been reached.
func (s *cstrScanner) next() (off uint64, b []byte, ok bool) {
	if s.done {
		return 0, nil, false
	}
	b = readBlock(s.m, s.a+s.off, s.buf[:s.k])
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b, s.done = b[:i], true
	}
	off = s.off
	s.off += uint64(len(b))
	s.k = min(2*s.k, scanMaxBlock)
	return off, b, len(b) > 0
}

// cstrLen is strlen on guest memory.
func cstrLen(m *mem.Memory, a uint64) uint64 {
	s := newCStrScanner(m, a)
	for {
		if _, _, ok := s.next(); !ok {
			return s.off
		}
	}
}

// cstrChr is strchr: the address of the first ch in the string at a, the
// terminator's address for ch == 0, or 0.
func cstrChr(m *mem.Memory, a uint64, ch byte) uint64 {
	if ch == 0 {
		return a + cstrLen(m, a)
	}
	s := newCStrScanner(m, a)
	for {
		off, b, ok := s.next()
		if !ok {
			return 0
		}
		if i := bytes.IndexByte(b, ch); i >= 0 {
			return a + off + uint64(i)
		}
	}
}

// cstrStr is strstr: the address of the first occurrence of needle in the
// string at a, or 0.
func cstrStr(m *mem.Memory, a uint64, needle []byte) uint64 {
	if len(needle) == 0 {
		return a
	}
	// window keeps the last len(needle)-1 bytes of the previous blocks so a
	// match straddling two blocks is found.
	var window []byte
	base := uint64(0) // string offset of window[0]
	s := newCStrScanner(m, a)
	for {
		_, b, ok := s.next()
		if !ok {
			return 0
		}
		window = append(window, b...)
		if i := bytes.Index(window, needle); i >= 0 {
			return a + base + uint64(i)
		}
		if keep := len(needle) - 1; len(window) > keep {
			drop := len(window) - keep
			base += uint64(drop)
			window = append(window[:0], window[drop:]...)
		}
	}
}

// isNumTokenByte reports whether b can occur in a number accepted by
// strtol/strtoul/strtod (digits and letters of any base, sign, radix point,
// the "nan(...)" parentheses and the '_' of its n-char-sequence).
func isNumTokenByte(b byte) bool {
	switch {
	case b >= '0' && b <= '9', b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z':
		return true
	}
	return b == '+' || b == '-' || b == '.' || b == '(' || b == ')' || b == '_'
}

func isCSpace(b byte) bool { return b == ' ' || b >= 9 && b <= 13 }

// numToken returns the part of the guest string at p that a numeric
// conversion can examine: the leading white space and the following run of
// isNumTokenByte characters. The parsers stop at the first other byte just as
// at the terminator, so parsing the token is the same as parsing the whole
// string, and the token is bounded by the number's own length. For a wide
// string every UTF-16 unit maps to one byte (non-ASCII units to 0xFF, which
// no parser accepts), keeping offsets in units. dst is the initial buffer.
func numToken(m *mem.Memory, p uint64, wide bool, dst []byte) []byte {
	out := dst[:0]
	leading := true
	accept := func(c byte) bool {
		switch {
		case leading && isCSpace(c):
		case isNumTokenByte(c):
			leading = false
		default:
			return false
		}
		out = append(out, c)
		return true
	}
	if !wide {
		s := newCStrScanner(m, p)
		for {
			_, b, ok := s.next()
			if !ok {
				return out
			}
			for _, c := range b {
				if !accept(c) {
					return out
				}
			}
		}
	}
	var buf [256]byte
	for a := p; ; {
		var b []byte
		if mem.ChunkSize-a&(mem.ChunkSize-1) < 2 { // unit straddles two chunks
			binary.LittleEndian.PutUint16(buf[:2], m.R16(a))
			b = buf[:2]
		} else {
			b = readBlock(m, a, buf[:])
			b = b[:len(b)&^1]
		}
		for i := 0; i < len(b); i += 2 {
			u := binary.LittleEndian.Uint16(b[i:])
			c := byte(0xFF)
			if u < 0x80 {
				c = byte(u)
			}
			if u == 0 || !accept(c) {
				return out
			}
		}
		a += uint64(len(b))
	}
}

// strtoXAt implements strtol/strtoul/strtoll/strtoull and their wide forms
// for the string at p, storing the end pointer through ep (if non-zero).
func (e *Emu) strtoXAt(p, ep uint64, base int, unsigned, b64, wide bool) uint64 {
	if ep != 0 {
		e.Mem.W64(ep, p)
	}
	if p == 0 || base != 0 && (base < 2 || base > 36) {
		e.invalidParameter()
		return 0
	}
	var stack [64]byte
	v, n, ovf := strtoint(numToken(e.Mem, p, wide, stack[:]), base, unsigned, b64)
	if ovf {
		e.crt.setErrno(erange)
	}
	if ep != 0 && n > 0 {
		e.Mem.W64(ep, p+uint64(n)*uint64(1+boolInt(wide)))
	}
	return v
}

// atoX implements atoi/atol/atoll/_atoi64 and their wide forms: strtol in
// base 10 without an end pointer (errno is still set on overflow).
func (e *Emu) atoX(b64, wide bool) uint64 {
	return e.strtoXAt(e.Arg(0), 0, 10, false, b64, wide)
}

// strtodAt implements strtod/strtof and their wide forms for the string at p.
// errno is ERANGE only when a finite number overflows the result type.
func (e *Emu) strtodAt(p, ep uint64, f32, wide bool) uint64 {
	if p == 0 {
		if ep != 0 {
			e.Mem.W64(ep, 0)
		}
		e.invalidParameter()
		return e.RetF(0)
	}
	var stack [64]byte
	tok := numToken(e.Mem, p, wide, stack[:])
	v, n, ok := strtod(tok)
	if !ok {
		n = 0
	}
	if ep != 0 {
		e.Mem.W64(ep, p+uint64(n)*uint64(1+boolInt(wide)))
	}
	// ERANGE (as UCRT): a finite literal that overflows to infinity, or a
	// non-zero one that underflows to zero, in the result type. Denormal
	// results are not an error.
	finite := ok && !isInfLiteral(tok)
	if f32 && finite {
		v, _ = parseCFloatBits(string(bytes.TrimLeft(tok[:n], " \t\n\v\f\r")), 32)
	}
	if finite && (math.IsInf(v, 0) || v == 0 && hasNonzeroMantissa(tok[:n])) {
		e.crt.setErrno(erange)
	}
	if f32 {
		return e.RetF32(float32(v))
	}
	return e.RetF(v)
}

// hasNonzeroMantissa reports whether the decimal or hex floating literal in
// tok (as consumed by strtod) has a non-zero digit before its exponent.
func hasNonzeroMantissa(tok []byte) bool {
	s := bytes.TrimLeft(tok, " \t\n\v\f\r+-")
	exp := byte('e')
	if len(s) > 1 && s[0] == '0' && s[1]|0x20 == 'x' {
		s, exp = s[2:], 'p'
	}
	for _, c := range s {
		switch {
		case c|0x20 == exp:
			return false
		case c != '0' && c != '.':
			return true
		}
	}
	return false
}

// isInfLiteral reports whether the number in tok is spelled "inf"/"infinity".
func isInfLiteral(tok []byte) bool {
	s := bytes.TrimLeft(tok, " \t\n\v\f\r")
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	return len(s) > 0 && s[0]|0x20 == 'i'
}

// invalidParameter is the CRT's invalid-parameter path for a builtin given a
// bad argument: errno is EINVAL and the handler installed with
// _set_invalid_parameter_handler runs, after which the caller returns its
// failure value; with no handler the process ends with
// STATUS_INVALID_CRT_PARAMETER, as in _invalid_parameter_noinfo.
func (e *Emu) invalidParameter() {
	e.crt.setErrno(einval)
	if h := e.crt.invalidParamHandler; h != 0 {
		e.CallGuest(h, 0, 0, 0, 0, 0)
		return
	}
	e.crt.invalidParameterExit()
}

// smallMove is the buffer size up to which memmove copies through the stack
// instead of mem.Move's heap buffer.
const smallMove = 512

// memMove is memmove on guest memory (overlap-safe).
func memMove(m *mem.Memory, dst, src, n uint64) {
	if n > smallMove || n == 0 || dst == src {
		m.Move(dst, src, n)
		return
	}
	var buf [smallMove]byte
	m.Read(src, buf[:n])
	m.Write(dst, buf[:n])
}

// memCmp is memcmp on guest memory: the sign of the first differing byte.
func memCmp(m *mem.Memory, a, b, n uint64) uint64 {
	var x, y [256]byte
	for off := uint64(0); off < n; {
		k := min(n-off, uint64(len(x)))
		m.Read(a+off, x[:k])
		m.Read(b+off, y[:k])
		if c := bytes.Compare(x[:k], y[:k]); c != 0 {
			return sign(c)
		}
		off += k
	}
	return 0
}
