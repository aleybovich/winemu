package win

import (
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const userLCID = 0x0409

// decodeMB converts bytes in code page cp into UTF-16.
func decodeMB(cp uint32, b []byte, strict bool) ([]uint16, bool) {
	switch cp {
	case 0, 1, 2, 3, 65001:
		if strict && !utf8.Valid(b) {
			return nil, false
		}
		out := make([]uint16, 0, len(b))
		for len(b) > 0 {
			r, n := utf8.DecodeRune(b)
			if r >= 0x10000 {
				r1, r2 := utf16.EncodeRune(r)
				out = append(out, uint16(r1), uint16(r2))
			} else {
				out = append(out, uint16(r))
			}
			b = b[n:]
		}
		return out, true
	case 20127:
		out := make([]uint16, len(b))
		for i, x := range b {
			if x >= 0x80 {
				if strict {
					return nil, false
				}
				out[i] = '?'
			} else {
				out[i] = uint16(x)
			}
		}
		return out, true
	default: // treat other single-byte pages as Windows-1252/Latin-1
		out := make([]uint16, len(b))
		for i, x := range b {
			out[i] = uint16(cp1252Rune(x))
		}
		return out, true
	}
}

// encodeMB converts UTF-16 to code page cp. usedDefault reports lossy chars.
func encodeMB(cp uint32, u []uint16, def byte) ([]byte, bool) {
	switch cp {
	case 0, 1, 2, 3, 65001:
		return []byte(string(utf16.Decode(u))), false
	}
	used := false
	out := make([]byte, 0, len(u))
	for _, r := range utf16.Decode(u) {
		switch {
		case r < 0x80:
			out = append(out, byte(r))
		case r < 0x100 && (r >= 0xA0 || cp != 1252) && cp != 20127:
			out = append(out, byte(r))
		default:
			found := false
			if cp == 1252 {
				for i, x := range cp1252hi {
					if x == r {
						out = append(out, byte(0x80+i))
						found = true
						break
					}
				}
			}
			if !found {
				out = append(out, def)
				used = true
			}
		}
	}
	return out, used
}

func lcmapString(e *Emu, flags uint32, src uint64, n int64, dst uint64, dn int64) uint64 {
	var s []uint16
	if n < 0 {
		s = append(e.Mem.WStrUnits(src), 0)
	} else {
		s = e.wunits(src, uint64(n))
	}
	if flags&0x400 != 0 { // LCMAP_SORTKEY: produce comparable bytes
		var key []byte
		for _, x := range s {
			if x == 0 {
				break
			}
			l := lowerW(x)
			if flags&1 == 0 {
				l = x
			}
			key = append(key, byte(l>>8), byte(l))
		}
		key = append(key, 1, 1, 1, 1, 0)
		if dn == 0 {
			return uint64(len(key))
		}
		if int64(len(key)) > dn {
			return e.fail(errInsufficientBuf)
		}
		e.Mem.Write(dst, key)
		return uint64(len(key))
	}
	out := make([]uint16, len(s))
	for i, x := range s {
		switch {
		case flags&0x100 != 0:
			out[i] = lowerW(x)
		case flags&0x200 != 0:
			out[i] = upperW(x)
		default:
			out[i] = x
		}
	}
	if dn == 0 {
		return uint64(len(out))
	}
	if int64(len(out)) > dn {
		return e.fail(errInsufficientBuf)
	}
	e.Mem.WriteUnits(dst, out)
	return uint64(len(out))
}

func compareUnits(a, b []uint16, flags uint32) uint64 {
	sa, sb := string(utf16.Decode(a)), string(utf16.Decode(b))
	if flags&0x1 != 0 || flags&0x10000000 != 0 { // NORM_IGNORECASE / LINGUISTIC_IGNORECASE
		sa, sb = strings.ToLower(sa), strings.ToLower(sb)
	}
	if flags&0x1000 == 0 && flags&0x10 == 0 { // word sort (default): case-insensitive primary
		la, lb := strings.ToLower(sa), strings.ToLower(sb)
		if la != lb {
			sa, sb = la, lb
		}
	}
	switch {
	case sa < sb:
		return 1
	case sa > sb:
		return 3
	}
	return 2
}

func (e *Emu) unitsArg(p uint64, n int64) []uint16 {
	if n < 0 {
		return e.Mem.WStrUnits(p)
	}
	u := e.wunits(p, uint64(n))
	for i, x := range u {
		if x == 0 {
			return u[:i]
		}
	}
	return u
}

var localeInfo = map[uint32]string{
	0x1: "0409", 0x2: "English (United States)", 0x3: "ENU", 0x4: "English", 0x5: "1", 0x6: "United States",
	0x7: "USA", 0x8: "United States", 0x9: "0409", 0xA: "1", 0xB: "437", 0xC: ",", 0xD: "1", 0xE: ".",
	0xF: ",", 0x10: "3;0", 0x11: "2", 0x12: "1", 0x13: "0123456789", 0x14: "$", 0x15: "USD", 0x16: ".",
	0x17: ",", 0x18: "3;0", 0x19: "2", 0x1A: "2", 0x1B: "0", 0x1C: "0", 0x1D: "/", 0x1E: ":",
	0x1F: "M/d/yyyy", 0x20: "dddd, MMMM d, yyyy", 0x21: "0", 0x22: "0", 0x23: "0", 0x24: "0", 0x25: "0",
	0x26: "0", 0x27: "1", 0x28: "AM", 0x29: "PM", 0x50: "", 0x51: "-", 0x52: "0", 0x53: "1", 0x54: "0",
	0x55: "0", 0x56: "0", 0x57: "0", 0x58: "1", 0x59: "en", 0x5A: "US", 0x5B: "Gregorian Calendar",
	0x5C: "en-US", 0x5D: "1", 0x6D: "en", 0x6E: "0",
	0x1001: "English", 0x1002: "United States", 0x1003: "h:mm:ss tt", 0x1004: "65001", 0x1005: "1",
	0x1007: "1", 0x1008: "0", 0x1009: "1", 0x100A: "0", 0x100B: "1", 0x100C: "6", 0x100D: "0",
	0x1010: "1", 0x1011: "2", 0x1012: "1", 0x1013: "0", 0x1014: "1", 0x1015: "1", 0x1016: "1", 0x1017: "0",
	0x1018: "0", 0x1019: "0", 0x101A: "0", 0x7B: "MMMM d", 0x79: "h:mm tt", 0x1074: "English (United States)",
	0x1075: "English", 0x1076: "United States",
}

func init() {
	for i, d := range []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"} {
		localeInfo[uint32(0x2A+i)] = d
		localeInfo[uint32(0x31+i)] = d[:3]
		localeInfo[uint32(0x60+i)] = d[:2]
	}
	for i, m := range months {
		localeInfo[uint32(0x38+i)] = m
		localeInfo[uint32(0x44+i)] = m[:3]
	}
	k := dK32
	reg(k, "GetACP", ret(65001))
	reg(k, "GetOEMCP", ret(65001))
	reg(k, "IsValidCodePage", func(e *Emu) uint64 {
		switch e.Arg32(0) {
		case 65001, 1252, 437, 850, 20127, 28591, 1200, 1201, 65000:
			return 1
		}
		return 0
	})
	cpinfo := func(e *Emu, ex bool) uint64 {
		cp := e.Arg32(0)
		a := e.Arg(2)
		e.Mem.Fill(a, 0, 20)
		max := uint32(1)
		if cp == 65001 || cp == 0 || cp == 1 || cp == 3 {
			max = 4
		}
		e.Mem.W32(a, max)
		e.Mem.W8(a+4, '?')
		if ex {
			e.Mem.W16(a+18, 0xFFFD)
			e.Mem.W32(a+20, cp)
			e.Mem.WriteWStr(a+24, "65001 (UTF-8)")
		}
		return 1
	}
	reg(k, "GetCPInfo", func(e *Emu) uint64 { return cpinfo(e, false) })
	reg(k, "GetCPInfoExW", func(e *Emu) uint64 { return cpinfo(e, true) })
	reg(k, "GetCPInfoExA", func(e *Emu) uint64 { return cpinfo(e, false) })
	reg(k, "IsDBCSLeadByte", retZero)
	reg(k, "IsDBCSLeadByteEx", retZero)
	reg(k, "MultiByteToWideChar", func(e *Emu) uint64 {
		cp, flags, src, sn, dst, dn := e.Arg32(0), e.Arg32(1), e.Arg(2), int32(e.Arg32(3)), e.Arg(4), int32(e.Arg32(5))
		var b []byte
		if sn < 0 {
			b = append(e.Mem.CStrBytes(src), 0)
		} else {
			b = e.Mem.ReadBytes(src, int(sn))
		}
		u, ok := decodeMB(cp, b, flags&8 != 0)
		if !ok {
			return e.fail(errNoUnicodeTrans)
		}
		if dn == 0 {
			return uint64(len(u))
		}
		if len(u) > int(dn) {
			e.Mem.WriteUnits(dst, u[:dn])
			return e.fail(errInsufficientBuf)
		}
		e.Mem.WriteUnits(dst, u)
		return uint64(len(u))
	})
	reg(k, "WideCharToMultiByte", func(e *Emu) uint64 {
		cp, src, sn, dst, dn := e.Arg32(0), e.Arg(2), int32(e.Arg32(3)), e.Arg(4), int32(e.Arg32(5))
		defp, usedp := e.Arg(6), e.Arg(7)
		var u []uint16
		if sn < 0 {
			u = append(e.Mem.WStrUnits(src), 0)
		} else {
			u = e.wunits(src, uint64(sn))
		}
		def := byte('?')
		if defp != 0 {
			def = e.Mem.R8(defp)
		}
		b, used := encodeMB(cp, u, def)
		if usedp != 0 {
			e.Mem.W32(usedp, uint32(b2u(used)))
		}
		if dn == 0 {
			return uint64(len(b))
		}
		if len(b) > int(dn) {
			e.Mem.Write(dst, b[:dn])
			return e.fail(errInsufficientBuf)
		}
		e.Mem.Write(dst, b)
		return uint64(len(b))
	})
	// lstr*
	reg(k, "lstrlenA", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return uint64(len(e.Mem.CStrBytes(e.Arg(0))))
	})
	reg(k, "lstrlenW", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0
		}
		return e.wlen(e.Arg(0))
	})
	reg(k, "lstrcpyA", func(e *Emu) uint64 { e.Mem.Write(e.Arg(0), append(e.Mem.CStrBytes(e.Arg(1)), 0)); return e.Arg(0) })
	reg(k, "lstrcpyW", func(e *Emu) uint64 { e.Mem.WriteUnits(e.Arg(0), append(e.Mem.WStrUnits(e.Arg(1)), 0)); return e.Arg(0) })
	reg(k, "lstrcpynA", func(e *Emu) uint64 {
		n := int(e.ArgI(2))
		if n <= 0 {
			return e.Arg(0)
		}
		b := e.Mem.CStrN(e.Arg(1), n-1)
		e.Mem.Write(e.Arg(0), append(b, 0))
		return e.Arg(0)
	})
	reg(k, "lstrcpynW", func(e *Emu) uint64 {
		n := int(e.ArgI(2))
		if n <= 0 {
			return e.Arg(0)
		}
		u := e.Mem.WStrUnits(e.Arg(1))
		if len(u) > n-1 {
			u = u[:n-1]
		}
		e.Mem.WriteUnits(e.Arg(0), append(u, 0))
		return e.Arg(0)
	})
	reg(k, "lstrcatA", func(e *Emu) uint64 {
		d := e.Arg(0)
		e.Mem.Write(d+uint64(len(e.Mem.CStrBytes(d))), append(e.Mem.CStrBytes(e.Arg(1)), 0))
		return d
	})
	reg(k, "lstrcatW", func(e *Emu) uint64 {
		d := e.Arg(0)
		e.Mem.WriteUnits(d+2*e.wlen(d), append(e.Mem.WStrUnits(e.Arg(1)), 0))
		return d
	})
	lcmp := func(fold, wide bool) Fn {
		return func(e *Emu) uint64 {
			var a, b string
			if wide {
				a, b = e.WStr(e.Arg(0)), e.WStr(e.Arg(1))
			} else {
				a, b = e.CStr(e.Arg(0)), e.CStr(e.Arg(1))
			}
			if fold {
				a, b = strings.ToLower(a), strings.ToLower(b)
			}
			return sign(strings.Compare(a, b))
		}
	}
	reg(k, "lstrcmpA", lcmp(false, false))
	reg(k, "lstrcmpW", lcmp(false, true))
	reg(k, "lstrcmpiA", lcmp(true, false))
	reg(k, "lstrcmpiW", lcmp(true, true))
	reg(k, "CompareStringW", func(e *Emu) uint64 {
		return compareUnits(e.unitsArg(e.Arg(2), int64(int32(e.Arg32(3)))), e.unitsArg(e.Arg(4), int64(int32(e.Arg32(5)))), e.Arg32(1))
	})
	reg(k, "CompareStringEx", func(e *Emu) uint64 {
		return compareUnits(e.unitsArg(e.Arg(2), int64(int32(e.Arg32(3)))), e.unitsArg(e.Arg(4), int64(int32(e.Arg32(5)))), e.Arg32(1))
	})
	reg(k, "CompareStringA", func(e *Emu) uint64 {
		get := func(p uint64, n int32) []uint16 {
			if n < 0 {
				return utf8ToUnits(e.Mem.CStrBytes(p))
			}
			return utf8ToUnits(e.Mem.ReadBytes(p, int(n)))
		}
		return compareUnits(get(e.Arg(2), int32(e.Arg32(3))), get(e.Arg(4), int32(e.Arg32(5))), e.Arg32(1))
	})
	reg(k, "CompareStringOrdinal", func(e *Emu) uint64 {
		a, b := e.unitsArg(e.Arg(0), int64(int32(e.Arg32(1)))), e.unitsArg(e.Arg(2), int64(int32(e.Arg32(3))))
		fold := e.Arg32(4) != 0
		for i := 0; ; i++ {
			if i >= len(a) || i >= len(b) {
				switch {
				case len(a) < len(b):
					return 1
				case len(a) > len(b):
					return 3
				}
				return 2
			}
			x, y := a[i], b[i]
			if fold {
				x, y = upperW(x), upperW(y)
			}
			if x != y {
				if x < y {
					return 1
				}
				return 3
			}
		}
	})
	reg(k, "LCMapStringW", func(e *Emu) uint64 {
		return lcmapString(e, e.Arg32(1), e.Arg(2), int64(int32(e.Arg32(3))), e.Arg(4), int64(int32(e.Arg32(5))))
	})
	reg(k, "LCMapStringEx", func(e *Emu) uint64 {
		return lcmapString(e, e.Arg32(1), e.Arg(2), int64(int32(e.Arg32(3))), e.Arg(4), int64(int32(e.Arg32(5))))
	})
	reg(k, "LCMapStringA", func(e *Emu) uint64 {
		src, n := e.Arg(2), int32(e.Arg32(3))
		var b []byte
		if n < 0 {
			b = append(e.Mem.CStrBytes(src), 0)
		} else {
			b = e.Mem.ReadBytes(src, int(n))
		}
		flags := e.Arg32(1)
		switch {
		case flags&0x100 != 0:
			b = []byte(strings.ToLower(string(b)))
		case flags&0x200 != 0:
			b = []byte(strings.ToUpper(string(b)))
		}
		if e.Arg32(5) == 0 {
			return uint64(len(b))
		}
		if len(b) > int(e.Arg32(5)) {
			return e.fail(errInsufficientBuf)
		}
		e.Mem.Write(e.Arg(4), b)
		return uint64(len(b))
	})
	strType := func(e *Emu, typ uint32, u []uint16, out uint64) uint64 {
		for i, x := range u {
			r := rune(x)
			var v uint16
			switch typ {
			case 1:
				v = 0x200
				if unicode.IsUpper(r) {
					v |= 1
				}
				if unicode.IsLower(r) {
					v |= 2
				}
				if unicode.IsDigit(r) {
					v |= 4
				}
				if unicode.IsSpace(r) {
					v |= 8
				}
				if unicode.IsPunct(r) || unicode.IsSymbol(r) {
					v |= 0x10
				}
				if unicode.IsControl(r) {
					v |= 0x20
				}
				if r == ' ' || r == '\t' {
					v |= 0x40
				}
				if r < 128 && ctypeOf(int(r))&ctHex != 0 {
					v |= 0x80
				}
				if unicode.IsLetter(r) {
					v |= 0x100
				}
				if r == 0 {
					v = 0x20
				}
			case 2:
				v = 0
				if r < 128 {
					v = 1
				}
			case 4:
				if unicode.IsLetter(r) {
					v = 0x8000
				}
			}
			e.Mem.W16(out+uint64(2*i), v)
		}
		return 1
	}
	reg(k, "GetStringTypeW", func(e *Emu) uint64 {
		return strType(e, e.Arg32(0), e.unitsArgFull(e.Arg(1), int64(int32(e.Arg32(2)))), e.Arg(3))
	})
	reg(k, "GetStringTypeExW", func(e *Emu) uint64 {
		return strType(e, e.Arg32(1), e.unitsArgFull(e.Arg(2), int64(int32(e.Arg32(3)))), e.Arg(4))
	})
	reg(k, "GetStringTypeA", func(e *Emu) uint64 {
		n := int32(e.Arg32(3))
		var b []byte
		if n < 0 {
			b = append(e.Mem.CStrBytes(e.Arg(2)), 0)
		} else {
			b = e.Mem.ReadBytes(e.Arg(2), int(n))
		}
		u := make([]uint16, len(b))
		for i, x := range b {
			u[i] = uint16(x)
		}
		return strType(e, e.Arg32(1), u, e.Arg(4))
	})
	reg(k, "GetStringTypeExA", func(e *Emu) uint64 {
		n := int32(e.Arg32(3))
		var b []byte
		if n < 0 {
			b = append(e.Mem.CStrBytes(e.Arg(2)), 0)
		} else {
			b = e.Mem.ReadBytes(e.Arg(2), int(n))
		}
		u := make([]uint16, len(b))
		for i, x := range b {
			u[i] = uint16(x)
		}
		return strType(e, e.Arg32(1), u, e.Arg(4))
	})
	reg(k, "FoldStringW", func(e *Emu) uint64 {
		u := e.unitsArgFull(e.Arg(1), int64(int32(e.Arg32(2))))
		if e.Arg32(4) == 0 {
			return uint64(len(u))
		}
		e.Mem.WriteUnits(e.Arg(3), u)
		return uint64(len(u))
	})
	reg(k, "NormalizeString", func(e *Emu) uint64 {
		u := e.unitsArgFull(e.Arg(1), int64(int32(e.Arg32(2))))
		if e.Arg32(4) == 0 {
			return uint64(len(u))
		}
		e.Mem.WriteUnits(e.Arg(3), u)
		return uint64(len(u))
	})
	reg(k, "IsNormalizedString", retTrue)
	// locales
	reg(k, "GetUserDefaultLCID", ret(userLCID))
	reg(k, "GetSystemDefaultLCID", ret(userLCID))
	reg(k, "GetThreadLocale", ret(userLCID))
	reg(k, "SetThreadLocale", retTrue)
	reg(k, "GetUserDefaultLangID", ret(userLCID))
	reg(k, "GetSystemDefaultLangID", ret(userLCID))
	reg(k, "GetUserDefaultUILanguage", ret(userLCID))
	reg(k, "GetSystemDefaultUILanguage", ret(userLCID))
	reg(k, "GetThreadUILanguage", ret(userLCID))
	reg(k, "SetThreadUILanguage", ret(userLCID))
	reg(k, "GetUserDefaultLocaleName", func(e *Emu) uint64 { return e.putStrW(e.Arg(0), e.Arg32(1), "en-US") + 1 })
	reg(k, "GetSystemDefaultLocaleName", func(e *Emu) uint64 { return e.putStrW(e.Arg(0), e.Arg32(1), "en-US") + 1 })
	reg(k, "LocaleNameToLCID", ret(userLCID))
	reg(k, "LCIDToLocaleName", func(e *Emu) uint64 {
		if e.Arg32(2) == 0 {
			return 6
		}
		return e.putStrW(e.Arg(1), e.Arg32(2), "en-US") + 1
	})
	reg(k, "ResolveLocaleName", func(e *Emu) uint64 { return e.putStrW(e.Arg(1), e.Arg32(2), "en-US") + 1 })
	reg(k, "IsValidLocale", retTrue)
	reg(k, "IsValidLocaleName", retTrue)
	reg(k, "ConvertDefaultLocale", func(e *Emu) uint64 { return uint64(userLCID) })
	reg(k, "EnumSystemLocalesW", func(e *Emu) uint64 {
		s := e.allocWStr("00000409")
		e.CallGuest(e.Arg(0), s)
		return 1
	})
	reg(k, "EnumSystemLocalesA", func(e *Emu) uint64 {
		s := e.allocCStr("00000409")
		e.CallGuest(e.Arg(0), s)
		return 1
	})
	reg(k, "EnumSystemLocalesEx", func(e *Emu) uint64 {
		s := e.allocWStr("en-US")
		e.CallGuest(e.Arg(0), s, 1, e.Arg(2))
		return 1
	})
	locInfo := func(e *Emu, typ uint32, wide bool, buf uint64, n uint32) uint64 {
		retNum := typ&0x20000000 != 0
		typ &^= 0x80000000 | 0x20000000 | 0x40000000 // NOUSEROVERRIDE, RETURN_NUMBER, USE_CP_ACP
		v, ok := localeInfo[typ]
		if !ok {
			return e.fail(1004)
		}
		if retNum {
			x, _ := strconv.ParseUint(v, 16, 32)
			if typ != 0x1 && typ != 0x9 {
				x, _ = strconv.ParseUint(v, 10, 32)
			}
			if n == 0 {
				return 2
			}
			e.Mem.W32(buf, uint32(x))
			return 2
		}
		if n == 0 {
			return uint64(len([]rune(v)) + 1)
		}
		r := e.putStr(wide, buf, n, v)
		if r > uint64(len([]rune(v))) {
			return e.fail(errInsufficientBuf)
		}
		return r + 1
	}
	reg(k, "GetLocaleInfoW", func(e *Emu) uint64 { return locInfo(e, e.Arg32(1), true, e.Arg(2), e.Arg32(3)) })
	reg(k, "GetLocaleInfoA", func(e *Emu) uint64 { return locInfo(e, e.Arg32(1), false, e.Arg(2), e.Arg32(3)) })
	reg(k, "GetLocaleInfoEx", func(e *Emu) uint64 { return locInfo(e, e.Arg32(1), true, e.Arg(2), e.Arg32(3)) })
	reg(k, "SetLocaleInfoW", retTrue)
	reg(k, "GetUserPreferredUILanguages", func(e *Emu) uint64 {
		return uiLangs(e, e.Arg(1), e.Arg(2), e.Arg(3))
	})
	reg(k, "GetThreadPreferredUILanguages", func(e *Emu) uint64 { return uiLangs(e, e.Arg(1), e.Arg(2), e.Arg(3)) })
	reg(k, "GetSystemPreferredUILanguages", func(e *Emu) uint64 { return uiLangs(e, e.Arg(1), e.Arg(2), e.Arg(3)) })
	reg(k, "GetProcessPreferredUILanguages", func(e *Emu) uint64 { return uiLangs(e, e.Arg(1), e.Arg(2), e.Arg(3)) })
	reg(k, "SetThreadPreferredUILanguages", retTrue)
	reg(k, "SetProcessPreferredUILanguages", retTrue)
	reg(k, "GetCalendarInfoW", func(e *Emu) uint64 { return e.fail(1004) })
	reg(k, "GetCalendarInfoEx", func(e *Emu) uint64 { return e.fail(1004) })
	reg(k, "GetNumberFormatW", func(e *Emu) uint64 { return numberFormat(e, e.WStr(e.Arg(2)), e.Arg(4), e.Arg32(5)) })
	reg(k, "GetNumberFormatEx", func(e *Emu) uint64 { return numberFormat(e, e.WStr(e.Arg(2)), e.Arg(4), e.Arg32(5)) })
	reg(k, "GetCurrencyFormatW", func(e *Emu) uint64 { return numberFormat(e, "$"+e.WStr(e.Arg(2)), e.Arg(4), e.Arg32(5)) })
	reg(k, "GetCurrencyFormatEx", func(e *Emu) uint64 { return numberFormat(e, "$"+e.WStr(e.Arg(2)), e.Arg(4), e.Arg32(5)) })
	dateFmt := func(e *Emu, st uint64, fmtp uint64, buf uint64, n uint32, date bool, wide bool) uint64 {
		t := nowTime()
		if st != 0 {
			t = e.readSystemTime(st, t.Location())
		}
		var f string
		if fmtp != 0 {
			if wide {
				f = e.WStr(fmtp)
			} else {
				f = e.CStr(fmtp)
			}
		} else if date {
			f = "M/d/yyyy"
		} else {
			f = "h:mm:ss tt"
		}
		s := winDateFormat(f, t)
		if n == 0 {
			return uint64(len([]rune(s)) + 1)
		}
		r := e.putStr(wide, buf, n, s)
		if r > uint64(len([]rune(s))) {
			return e.fail(errInsufficientBuf)
		}
		return r + 1
	}
	reg(k, "GetDateFormatW", func(e *Emu) uint64 { return dateFmt(e, e.Arg(2), e.Arg(3), e.Arg(4), e.Arg32(5), true, true) })
	reg(k, "GetDateFormatA", func(e *Emu) uint64 { return dateFmt(e, e.Arg(2), e.Arg(3), e.Arg(4), e.Arg32(5), true, false) })
	reg(k, "GetDateFormatEx", func(e *Emu) uint64 { return dateFmt(e, e.Arg(2), e.Arg(3), e.Arg(4), e.Arg32(5), true, true) })
	reg(k, "GetTimeFormatW", func(e *Emu) uint64 { return dateFmt(e, e.Arg(2), e.Arg(3), e.Arg(4), e.Arg32(5), false, true) })
	reg(k, "GetTimeFormatA", func(e *Emu) uint64 { return dateFmt(e, e.Arg(2), e.Arg(3), e.Arg(4), e.Arg32(5), false, false) })
	reg(k, "GetTimeFormatEx", func(e *Emu) uint64 { return dateFmt(e, e.Arg(2), e.Arg(3), e.Arg(4), e.Arg32(5), false, true) })
	// user32 character helpers
	reg(dUser, "CharUpperW", func(e *Emu) uint64 {
		if e.Arg(0)>>16 == 0 {
			return uint64(upperW(uint16(e.Arg(0))))
		}
		u := e.Mem.WStrUnits(e.Arg(0))
		for i := range u {
			u[i] = upperW(u[i])
		}
		e.Mem.WriteUnits(e.Arg(0), u)
		return e.Arg(0)
	})
	reg(dUser, "CharLowerW", func(e *Emu) uint64 {
		if e.Arg(0)>>16 == 0 {
			return uint64(lowerW(uint16(e.Arg(0))))
		}
		u := e.Mem.WStrUnits(e.Arg(0))
		for i := range u {
			u[i] = lowerW(u[i])
		}
		e.Mem.WriteUnits(e.Arg(0), u)
		return e.Arg(0)
	})
	reg(dUser, "CharUpperA", func(e *Emu) uint64 {
		if e.Arg(0)>>16 == 0 {
			return uint64(upperB(byte(e.Arg(0))))
		}
		b := e.Mem.CStrBytes(e.Arg(0))
		for i := range b {
			b[i] = upperB(b[i])
		}
		e.Mem.Write(e.Arg(0), b)
		return e.Arg(0)
	})
	reg(dUser, "CharLowerA", func(e *Emu) uint64 {
		if e.Arg(0)>>16 == 0 {
			return uint64(lowerB(byte(e.Arg(0))))
		}
		b := e.Mem.CStrBytes(e.Arg(0))
		for i := range b {
			b[i] = lowerB(b[i])
		}
		e.Mem.Write(e.Arg(0), b)
		return e.Arg(0)
	})
	reg(dUser, "CharUpperBuffW", func(e *Emu) uint64 {
		for i := uint64(0); i < e.Arg(1); i++ {
			p := e.Arg(0) + 2*i
			e.Mem.W16(p, upperW(e.Mem.R16(p)))
		}
		return e.Arg(1)
	})
	reg(dUser, "CharLowerBuffW", func(e *Emu) uint64 {
		for i := uint64(0); i < e.Arg(1); i++ {
			p := e.Arg(0) + 2*i
			e.Mem.W16(p, lowerW(e.Mem.R16(p)))
		}
		return e.Arg(1)
	})
	reg(dUser, "CharNextW", func(e *Emu) uint64 {
		if e.Mem.R16(e.Arg(0)) == 0 {
			return e.Arg(0)
		}
		return e.Arg(0) + 2
	})
	reg(dUser, "CharNextA", func(e *Emu) uint64 {
		p := e.Arg(0)
		b := e.Mem.CStrN(p, 4)
		if len(b) == 0 {
			return p
		}
		_, n := utf8.DecodeRune(b)
		return p + uint64(n)
	})
	reg(dUser, "CharPrevW", func(e *Emu) uint64 {
		if e.Arg(1) > e.Arg(0) {
			return e.Arg(1) - 2
		}
		return e.Arg(0)
	})
	reg(dUser, "IsCharAlphaW", func(e *Emu) uint64 { return b2u(unicode.IsLetter(rune(e.Arg32(0) & 0xFFFF))) })
	reg(dUser, "IsCharAlphaNumericW", func(e *Emu) uint64 {
		r := rune(e.Arg32(0) & 0xFFFF)
		return b2u(unicode.IsLetter(r) || unicode.IsDigit(r))
	})
	reg(dUser, "IsCharUpperW", func(e *Emu) uint64 { return b2u(unicode.IsUpper(rune(e.Arg32(0) & 0xFFFF))) })
	reg(dUser, "IsCharLowerW", func(e *Emu) uint64 { return b2u(unicode.IsLower(rune(e.Arg32(0) & 0xFFFF))) })
	reg(dUser, "CharToOemA", func(e *Emu) uint64 { e.Mem.Write(e.Arg(1), append(e.Mem.CStrBytes(e.Arg(0)), 0)); return 1 })
	reg(dUser, "OemToCharA", func(e *Emu) uint64 { e.Mem.Write(e.Arg(1), append(e.Mem.CStrBytes(e.Arg(0)), 0)); return 1 })
	reg(dUser, "CharToOemBuffA", func(e *Emu) uint64 { e.Mem.Move(e.Arg(1), e.Arg(0), uint64(e.Arg32(2))); return 1 })
	reg(dUser, "OemToCharBuffA", func(e *Emu) uint64 { e.Mem.Move(e.Arg(1), e.Arg(0), uint64(e.Arg32(2))); return 1 })
	reg(dUser, "wsprintfW", func(e *Emu) uint64 {
		o := msvcrtOpts
		o.wide = true
		return e.sprintfTo(e.Arg(0), 0, e.sprintf(e.fmtFormat(e.Arg(1), true), &regArgs{e, 2}, o), 0)
	})
	reg(dUser, "wsprintfA", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), 0, e.sprintf(e.fmtFormat(e.Arg(1), false), &regArgs{e, 2}, msvcrtOpts), 0)
	})
	reg(dUser, "wvsprintfW", func(e *Emu) uint64 {
		o := msvcrtOpts
		o.wide = true
		return e.sprintfTo(e.Arg(0), 0, e.sprintf(e.fmtFormat(e.Arg(1), true), &vaList{e, e.Arg(2)}, o), 0)
	})
	reg(dUser, "wvsprintfA", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), 0, e.sprintf(e.fmtFormat(e.Arg(1), false), &vaList{e, e.Arg(2)}, msvcrtOpts), 0)
	})
}

func (e *Emu) unitsArgFull(p uint64, n int64) []uint16 {
	if n < 0 {
		return append(e.Mem.WStrUnits(p), 0)
	}
	return e.wunits(p, uint64(n))
}

func uiLangs(e *Emu, nump, buf, sizep uint64) uint64 {
	// "en-US\0\0"
	need := uint32(7)
	if nump != 0 {
		e.Mem.W32(nump, 1)
	}
	if buf == 0 || e.Mem.R32(sizep) < need {
		e.Mem.W32(sizep, need)
		if buf != 0 {
			return e.fail(errInsufficientBuf)
		}
		return 1
	}
	e.Mem.WriteWStr(buf, "en-US")
	e.Mem.W16(buf+12, 0)
	e.Mem.W32(sizep, need)
	return 1
}

func numberFormat(e *Emu, v string, buf uint64, n uint32) uint64 {
	// insert thousands separators, two decimals
	neg := strings.HasPrefix(v, "-")
	v = strings.TrimPrefix(v, "-")
	prefix := ""
	if strings.HasPrefix(v, "$") {
		prefix = "$"
		v = v[1:]
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return e.fail(errInvalidParameter)
	}
	s := strconv.FormatFloat(f, 'f', 2, 64)
	ip, fp := s[:len(s)-3], s[len(s)-3:]
	var parts []string
	for len(ip) > 3 {
		parts = append([]string{ip[len(ip)-3:]}, parts...)
		ip = ip[:len(ip)-3]
	}
	parts = append([]string{ip}, parts...)
	out := prefix + strings.Join(parts, ",") + fp
	if neg {
		out = "-" + out
	}
	if n == 0 {
		return uint64(len(out) + 1)
	}
	if uint32(len(out)) >= n {
		return e.fail(errInsufficientBuf)
	}
	e.Mem.WriteWStr(buf, out)
	return uint64(len(out) + 1)
}

// winDateFormat formats using Windows date/time picture strings.
func winDateFormat(f string, t time.Time) string {
	var b strings.Builder
	rs := []rune(f)
	for i := 0; i < len(rs); {
		c := rs[i]
		if c == '\'' {
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				b.WriteRune(rs[j])
				j++
			}
			i = j + 1
			continue
		}
		n := 1
		for i+n < len(rs) && rs[i+n] == c {
			n++
		}
		h12 := t.Hour() % 12
		if h12 == 0 {
			h12 = 12
		}
		switch c {
		case 'd':
			switch n {
			case 1:
				b.WriteString(strconv.Itoa(t.Day()))
			case 2:
				b.WriteString(fmt2(t.Day()))
			case 3:
				b.WriteString(t.Weekday().String()[:3])
			default:
				b.WriteString(t.Weekday().String())
			}
		case 'M':
			switch n {
			case 1:
				b.WriteString(strconv.Itoa(int(t.Month())))
			case 2:
				b.WriteString(fmt2(int(t.Month())))
			case 3:
				b.WriteString(t.Month().String()[:3])
			default:
				b.WriteString(t.Month().String())
			}
		case 'y':
			switch {
			case n <= 2:
				b.WriteString(fmt2(t.Year() % 100))
			default:
				b.WriteString(strconv.Itoa(t.Year()))
			}
		case 'h':
			if n == 1 {
				b.WriteString(strconv.Itoa(h12))
			} else {
				b.WriteString(fmt2(h12))
			}
		case 'H':
			if n == 1 {
				b.WriteString(strconv.Itoa(t.Hour()))
			} else {
				b.WriteString(fmt2(t.Hour()))
			}
		case 'm':
			if n == 1 {
				b.WriteString(strconv.Itoa(t.Minute()))
			} else {
				b.WriteString(fmt2(t.Minute()))
			}
		case 's':
			if n == 1 {
				b.WriteString(strconv.Itoa(t.Second()))
			} else {
				b.WriteString(fmt2(t.Second()))
			}
		case 't':
			ap := "AM"
			if t.Hour() >= 12 {
				ap = "PM"
			}
			if n == 1 {
				ap = ap[:1]
			}
			b.WriteString(ap)
		default:
			b.WriteString(strings.Repeat(string(c), n))
		}
		i += n
	}
	return b.String()
}

func fmt2(v int) string {
	if v < 10 {
		return "0" + strconv.Itoa(v)
	}
	return strconv.Itoa(v)
}

var _ = sort.Strings
