package win

import (
	"fmt"
	"math"
	"strings"
	"time"

	"winemu/internal/cpu"
)

func init() {
	u := dUcrt + "," + dMsvc
	f1 := func(f func(float64) float64) Fn {
		return func(e *Emu) uint64 { return e.RetF(f(e.ArgF(0))) }
	}
	f1f := func(f func(float64) float64) Fn {
		return func(e *Emu) uint64 { return e.RetF32(float32(f(float64(e.ArgF32(0))))) }
	}
	f2 := func(f func(a, b float64) float64) Fn {
		return func(e *Emu) uint64 { return e.RetF(f(e.ArgF(0), e.ArgF(1))) }
	}
	f2f := func(f func(a, b float64) float64) Fn {
		return func(e *Emu) uint64 { return e.RetF32(float32(f(float64(e.ArgF32(0)), float64(e.ArgF32(1))))) }
	}
	ones := map[string]func(float64) float64{
		"sin": math.Sin, "cos": math.Cos, "tan": math.Tan, "asin": math.Asin, "acos": math.Acos,
		"atan": math.Atan, "sinh": math.Sinh, "cosh": math.Cosh, "tanh": math.Tanh, "asinh": math.Asinh,
		"acosh": math.Acosh, "atanh": math.Atanh, "exp": math.Exp, "exp2": math.Exp2, "expm1": math.Expm1,
		"log": math.Log, "log10": math.Log10, "log2": math.Log2, "log1p": math.Log1p, "logb": math.Logb,
		"sqrt": math.Sqrt, "cbrt": math.Cbrt, "fabs": math.Abs, "floor": math.Floor, "ceil": math.Ceil,
		"trunc": math.Trunc, "round": math.Round, "rint": math.RoundToEven, "nearbyint": math.RoundToEven,
		"erf": math.Erf, "erfc": math.Erfc, "tgamma": math.Gamma,
		"lgamma": func(x float64) float64 { v, _ := math.Lgamma(x); return v },
		"_logb":  math.Logb, "_j0": math.J0, "_j1": math.J1, "_y0": math.Y0, "_y1": math.Y1,
	}
	for name, f := range ones {
		reg(u, name, f1(f))
		if !strings.HasPrefix(name, "_") {
			reg(u, name+"f", f1f(f))
			reg(u, name+"l", f1(f))
		}
	}
	twos := map[string]func(a, b float64) float64{
		"atan2": math.Atan2, "pow": math.Pow, "fmod": math.Mod, "hypot": math.Hypot, "_hypot": math.Hypot,
		"copysign": math.Copysign, "_copysign": math.Copysign,
		"fdim": math.Dim, "remainder": math.Remainder, "nextafter": math.Nextafter, "_nextafter": math.Nextafter,
		"nexttoward": math.Nextafter,
	}
	for name, f := range twos {
		reg(u, name, f2(f))
		if !strings.HasPrefix(name, "_") {
			reg(u, name+"f", f2f(f))
			reg(u, name+"l", f2(f))
		}
	}
	// libm functions with special C semantics
	reg(u, "fmin", f2(cfmin))
	reg(u, "fmax", f2(cfmax))
	reg(u, "fminf", f2f(cfmin))
	reg(u, "fmaxf", f2f(cfmax))
	reg(u, "fminl", f2(cfmin))
	reg(u, "fmaxl", f2(cfmax))
	reg(u, "_hypotf", f2f(math.Hypot))
	reg(u, "_copysignf", f2f(math.Copysign))
	reg(u, "_chgsign", func(e *Emu) uint64 { return e.RetF(-e.ArgF(0)) })
	reg(u, "_chgsignf", func(e *Emu) uint64 { return e.RetF32(-e.ArgF32(0)) })
	reg(u, "fma", func(e *Emu) uint64 { return e.RetF(math.FMA(e.ArgF(0), e.ArgF(1), e.ArgF(2))) })
	reg(u, "fmaf", func(e *Emu) uint64 {
		return e.RetF32(float32(math.FMA(float64(e.ArgF32(0)), float64(e.ArgF32(1)), float64(e.ArgF32(2)))))
	})
	reg(u, "ldexp", func(e *Emu) uint64 { return e.RetF(math.Ldexp(e.ArgF(0), int(e.ArgI(1)))) })
	reg(u, "ldexpf", func(e *Emu) uint64 { return e.RetF32(float32(math.Ldexp(float64(e.ArgF32(0)), int(e.ArgI(1))))) })
	reg(u, "scalbn", func(e *Emu) uint64 { return e.RetF(math.Ldexp(e.ArgF(0), int(e.ArgI(1)))) })
	reg(u, "scalbnf", func(e *Emu) uint64 { return e.RetF32(float32(math.Ldexp(float64(e.ArgF32(0)), int(e.ArgI(1))))) })
	reg(u, "scalbln", func(e *Emu) uint64 { return e.RetF(math.Ldexp(e.ArgF(0), int(e.ArgI(1)))) })
	reg(u, "_scalb", func(e *Emu) uint64 { return e.RetF(math.Ldexp(e.ArgF(0), int(e.ArgI(1)))) })
	reg(u, "frexp", func(e *Emu) uint64 {
		fr, ex := math.Frexp(e.ArgF(0))
		e.Mem.W32(e.Arg(1), uint32(int32(ex)))
		return e.RetF(fr)
	})
	reg(u, "frexpf", func(e *Emu) uint64 {
		fr, ex := math.Frexp(float64(e.ArgF32(0)))
		e.Mem.W32(e.Arg(1), uint32(int32(ex)))
		return e.RetF32(float32(fr))
	})
	reg(u, "modf", func(e *Emu) uint64 {
		ip, fr := math.Modf(e.ArgF(0))
		e.Mem.W64(e.Arg(1), math.Float64bits(ip))
		return e.RetF(fr)
	})
	reg(u, "modff", func(e *Emu) uint64 {
		ip, fr := math.Modf(float64(e.ArgF32(0)))
		e.Mem.W32(e.Arg(1), math.Float32bits(float32(ip)))
		return e.RetF32(float32(fr))
	})
	reg(u, "remquo", func(e *Emu) uint64 {
		x, y := e.ArgF(0), e.ArgF(1)
		r := math.Remainder(x, y)
		q := math.RoundToEven((x - r) / y)
		e.Mem.W32(e.Arg(2), uint32(int32(int64(q)&7)*int32(math.Copysign(1, x/y))))
		return e.RetF(r)
	})
	reg(u, "ilogb", func(e *Emu) uint64 { return uint64(uint32(int32(math.Ilogb(e.ArgF(0))))) })
	reg(u, "ilogbf", func(e *Emu) uint64 { return uint64(uint32(int32(math.Ilogb(float64(e.ArgF32(0)))))) })
	reg(u, "lround", func(e *Emu) uint64 { return uint64(uint32(int32(math.Round(e.ArgF(0))))) })
	reg(u, "lroundf", func(e *Emu) uint64 { return uint64(uint32(int32(math.Round(float64(e.ArgF32(0)))))) })
	reg(u, "llround", func(e *Emu) uint64 { return uint64(int64(math.Round(e.ArgF(0)))) })
	reg(u, "llroundf", func(e *Emu) uint64 { return uint64(int64(math.Round(float64(e.ArgF32(0))))) })
	reg(u, "lrint", func(e *Emu) uint64 { return uint64(uint32(int32(math.RoundToEven(e.ArgF(0))))) })
	reg(u, "lrintf", func(e *Emu) uint64 { return uint64(uint32(int32(math.RoundToEven(float64(e.ArgF32(0)))))) })
	reg(u, "llrint", func(e *Emu) uint64 { return uint64(int64(math.RoundToEven(e.ArgF(0)))) })
	reg(u, "llrintf", func(e *Emu) uint64 { return uint64(int64(math.RoundToEven(float64(e.ArgF32(0))))) })
	reg(u, "nan", func(e *Emu) uint64 { return e.RetF(math.NaN()) })
	reg(u, "nanf", func(e *Emu) uint64 { return e.RetF32(float32(math.NaN())) })
	reg(u, "_isnan", func(e *Emu) uint64 { return b2u(math.IsNaN(e.ArgF(0))) })
	reg(u, "_isnanf", func(e *Emu) uint64 { return b2u(math.IsNaN(float64(e.ArgF32(0)))) })
	reg(u, "_finite", func(e *Emu) uint64 { v := e.ArgF(0); return b2u(!math.IsNaN(v) && !math.IsInf(v, 0)) })
	reg(u, "_finitef", func(e *Emu) uint64 { v := float64(e.ArgF32(0)); return b2u(!math.IsNaN(v) && !math.IsInf(v, 0)) })
	classify := func(v float64, f32 bool) uint64 {
		switch {
		case math.IsNaN(v):
			return 2
		case math.IsInf(v, 0):
			return 1
		case v == 0:
			return 0
		case f32 && math.Abs(v) < 1.1754943508222875e-38, !f32 && math.Abs(v) < 2.2250738585072014e-308:
			return uint64(0xFFFFFFFE) // FP_SUBNORMAL (-2)
		}
		return uint64(0xFFFFFFFF) // FP_NORMAL (-1)
	}
	reg(u, "_dclass", func(e *Emu) uint64 { return classify(e.ArgF(0), false) })
	reg(u, "_dtest", func(e *Emu) uint64 { return classify(e.Mem.R64Float(e.Arg(0)), false) })
	reg(u, "_fdclass", func(e *Emu) uint64 { return classify(float64(e.ArgF32(0)), true) })
	reg(u, "_fdtest", func(e *Emu) uint64 {
		return classify(float64(math.Float32frombits(e.Mem.R32(e.Arg(0)))), true)
	})
	reg(u, "_ldclass", func(e *Emu) uint64 { return classify(e.ArgF(0), false) })
	reg(u, "_ldtest", func(e *Emu) uint64 { return classify(e.Mem.R64Float(e.Arg(0)), false) })
	reg(u, "_dsign", func(e *Emu) uint64 { return b2u(math.Signbit(e.ArgF(0))) * 0x8000 })
	reg(u, "_fdsign", func(e *Emu) uint64 { return b2u(math.Signbit(float64(e.ArgF32(0)))) * 0x8000 })
	reg(u, "_ldsign", func(e *Emu) uint64 { return b2u(math.Signbit(e.ArgF(0))) * 0x8000 })
	pcomp := func(a, b float64) uint64 {
		switch {
		case math.IsNaN(a) || math.IsNaN(b):
			return 0
		case a < b:
			return 1
		case a == b:
			return 2
		}
		return 4
	}
	reg(u, "_dpcomp", func(e *Emu) uint64 { return pcomp(e.ArgF(0), e.ArgF(1)) })
	reg(u, "_fdpcomp", func(e *Emu) uint64 { return pcomp(float64(e.ArgF32(0)), float64(e.ArgF32(1))) })
	reg(u, "_ldpcomp", func(e *Emu) uint64 { return pcomp(e.ArgF(0), e.ArgF(1)) })
	reg(u, "_fpclass", func(e *Emu) uint64 {
		v := e.ArgF(0)
		neg := math.Signbit(v)
		switch {
		case math.IsNaN(v):
			return 2 // _FPCLASS_QNAN
		case math.IsInf(v, 0):
			if neg {
				return 4
			}
			return 0x200
		case v == 0:
			if neg {
				return 0x20
			}
			return 0x40
		case math.Abs(v) < 2.2250738585072014e-308:
			if neg {
				return 0x10
			}
			return 0x80
		}
		if neg {
			return 8
		}
		return 0x100
	})
	reg(u, "_matherr", retZero)
	reg(u, "__libm_sse2_sqrt_precise", f1(math.Sqrt))

	// floating point environment
	reg(u, "_controlfp", func(e *Emu) uint64 { return 0x0009001F })
	reg(u, "_control87", func(e *Emu) uint64 { return 0x0009001F })
	reg(u, "_controlfp_s", func(e *Emu) uint64 {
		if e.Arg(0) != 0 {
			e.Mem.W32(e.Arg(0), 0x0009001F)
		}
		return 0
	})
	reg(u, "__control87_2", func(e *Emu) uint64 {
		if e.Arg(2) != 0 {
			e.Mem.W32(e.Arg(2), 0x0009001F)
		}
		if e.Arg(3) != 0 {
			e.Mem.W32(e.Arg(3), 0x0009001F)
		}
		return 1
	})
	reg(u, "_clearfp", retZero)
	reg(u, "_statusfp", retZero)
	reg(u, "_statusfp2", func(e *Emu) uint64 {
		for i := 0; i < 2; i++ {
			if e.Arg(i) != 0 {
				e.Mem.W32(e.Arg(i), 0)
			}
		}
		return 0
	})
	reg(u, "_fpreset", retZero)
	reg(u, "_set_controlfp", retZero)
	reg(u, "fegetround", func(e *Emu) uint64 {
		return [4]uint64{0, 0x100, 0x200, 0x300}[(e.Cur.CPU.MXCSR>>13)&3]
	})
	reg(u, "fesetround", func(e *Emu) uint64 {
		var rc uint32
		switch e.Arg32(0) {
		case 0:
			rc = 0
		case 0x100:
			rc = 1
		case 0x200:
			rc = 2
		case 0x300:
			rc = 3
		default:
			return 1
		}
		c := e.Cur.CPU
		c.MXCSR = c.MXCSR&^(3<<13) | rc<<13
		return 0
	})
	reg(u, "fegetenv", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), uint64(e.Cur.CPU.MXCSR)); return 0 })
	reg(u, "fesetenv", func(e *Emu) uint64 { return 0 })
	reg(u, "feholdexcept", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), uint64(e.Cur.CPU.MXCSR)); return 0 })
	reg(u, "feupdateenv", retZero)
	reg(u, "feclearexcept", retZero)
	reg(u, "fetestexcept", retZero)
	reg(u, "feraiseexcept", retZero)
	reg(u, "fegetexceptflag", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), 0); return 0 })
	reg(u, "fesetexceptflag", retZero)
}

func cfmin(a, b float64) float64 {
	if math.IsNaN(a) {
		return b
	}
	if math.IsNaN(b) {
		return a
	}
	return math.Min(a, b)
}

func cfmax(a, b float64) float64 {
	if math.IsNaN(a) {
		return b
	}
	if math.IsNaN(b) {
		return a
	}
	return math.Max(a, b)
}

// ---------------------------------------------------------------------------
// time

func nowZone() (string, int) { return time.Now().Zone() }
func nowTime() time.Time     { return time.Now() }
func unixTime(s int64) time.Time {
	return time.Unix(s, 0)
}

var (
	wdays  = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	months = []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
)

func (e *Emu) writeTm(a uint64, t time.Time) {
	m := e.Mem
	vals := []int{t.Second(), t.Minute(), t.Hour(), t.Day(), int(t.Month()) - 1, t.Year() - 1900,
		int(t.Weekday()), t.YearDay() - 1, 0}
	if t.Location() != time.UTC && t.IsDST() {
		vals[8] = 1
	}
	for i, v := range vals {
		m.W32(a+uint64(4*i), uint32(int32(v)))
	}
}

func (e *Emu) readTm(a uint64) (sec, min, hour, mday, mon, year, wday, yday, isdst int) {
	m := e.Mem
	r := func(i int) int { return int(int32(m.R32(a + uint64(4*i)))) }
	return r(0), r(1), r(2), r(3), r(4), r(5), r(6), r(7), r(8)
}

func (e *Emu) tmTime(a uint64, loc *time.Location) time.Time {
	sec, mn, hr, md, mo, yr, _, _, _ := e.readTm(a)
	return time.Date(yr+1900, time.Month(mo+1), md, hr, mn, sec, 0, loc)
}

func (e *Emu) tmBuf() uint64 {
	id := e.Cur.ID
	a := e.crt.tmBuf[id]
	if a == 0 {
		a = e.heapAllocRaw(64)
		e.crt.tmBuf[id] = a
	}
	return a
}

func asctime(t time.Time) string {
	return fmt.Sprintf("%s %s %2d %02d:%02d:%02d %d\n", wdays[t.Weekday()][:3], months[t.Month()-1][:3],
		t.Day(), t.Hour(), t.Minute(), t.Second(), t.Year())
}

// strftime implements the MSVC strftime formatting.
func strftime(format string, t time.Time, isdst bool) string {
	var b strings.Builder
	rs := []rune(format)
	for i := 0; i < len(rs); i++ {
		if rs[i] != '%' || i+1 >= len(rs) {
			b.WriteRune(rs[i])
			continue
		}
		i++
		alt := false
		if rs[i] == '#' || rs[i] == 'E' || rs[i] == 'O' {
			alt = rs[i] == '#'
			i++
			if i >= len(rs) {
				break
			}
		}
		num := func(v, w int) string {
			if alt {
				return fmt.Sprintf("%d", v)
			}
			return fmt.Sprintf("%0*d", w, v)
		}
		h12 := t.Hour() % 12
		if h12 == 0 {
			h12 = 12
		}
		switch rs[i] {
		case 'a':
			b.WriteString(wdays[t.Weekday()][:3])
		case 'A':
			b.WriteString(wdays[t.Weekday()])
		case 'b', 'h':
			b.WriteString(months[t.Month()-1][:3])
		case 'B':
			b.WriteString(months[t.Month()-1])
		case 'c':
			if alt {
				b.WriteString(fmt.Sprintf("%s, %s %d, %d %02d:%02d:%02d", wdays[t.Weekday()], months[t.Month()-1], t.Day(), t.Year(), t.Hour(), t.Minute(), t.Second()))
			} else {
				b.WriteString(fmt.Sprintf("%02d/%02d/%02d %02d:%02d:%02d", int(t.Month()), t.Day(), t.Year()%100, t.Hour(), t.Minute(), t.Second()))
			}
		case 'C':
			b.WriteString(num(t.Year()/100, 2))
		case 'd':
			b.WriteString(num(t.Day(), 2))
		case 'D':
			b.WriteString(fmt.Sprintf("%02d/%02d/%02d", int(t.Month()), t.Day(), t.Year()%100))
		case 'e':
			b.WriteString(fmt.Sprintf("%2d", t.Day()))
		case 'F':
			b.WriteString(fmt.Sprintf("%04d-%02d-%02d", t.Year(), int(t.Month()), t.Day()))
		case 'g':
			y, _ := t.ISOWeek()
			b.WriteString(num(y%100, 2))
		case 'G':
			y, _ := t.ISOWeek()
			b.WriteString(fmt.Sprintf("%04d", y))
		case 'H':
			b.WriteString(num(t.Hour(), 2))
		case 'I':
			b.WriteString(num(h12, 2))
		case 'j':
			b.WriteString(num(t.YearDay(), 3))
		case 'm':
			b.WriteString(num(int(t.Month()), 2))
		case 'M':
			b.WriteString(num(t.Minute(), 2))
		case 'n':
			b.WriteByte('\n')
		case 'p':
			if t.Hour() < 12 {
				b.WriteString("AM")
			} else {
				b.WriteString("PM")
			}
		case 'r':
			ampm := "AM"
			if t.Hour() >= 12 {
				ampm = "PM"
			}
			b.WriteString(fmt.Sprintf("%02d:%02d:%02d %s", h12, t.Minute(), t.Second(), ampm))
		case 'R':
			b.WriteString(fmt.Sprintf("%02d:%02d", t.Hour(), t.Minute()))
		case 'S':
			b.WriteString(num(t.Second(), 2))
		case 't':
			b.WriteByte('\t')
		case 'T', 'X':
			b.WriteString(fmt.Sprintf("%02d:%02d:%02d", t.Hour(), t.Minute(), t.Second()))
		case 'u':
			wd := int(t.Weekday())
			if wd == 0 {
				wd = 7
			}
			b.WriteString(fmt.Sprintf("%d", wd))
		case 'U':
			b.WriteString(num((t.YearDay()+6-int(t.Weekday()))/7, 2))
		case 'V':
			_, w := t.ISOWeek()
			b.WriteString(num(w, 2))
		case 'w':
			b.WriteString(fmt.Sprintf("%d", int(t.Weekday())))
		case 'W':
			wd := (int(t.Weekday()) + 6) % 7
			b.WriteString(num((t.YearDay()+6-wd)/7, 2))
		case 'x':
			if alt {
				b.WriteString(fmt.Sprintf("%s, %s %d, %d", wdays[t.Weekday()], months[t.Month()-1], t.Day(), t.Year()))
			} else {
				b.WriteString(fmt.Sprintf("%02d/%02d/%02d", int(t.Month()), t.Day(), t.Year()%100))
			}
		case 'y':
			b.WriteString(num(t.Year()%100, 2))
		case 'Y':
			b.WriteString(fmt.Sprintf("%d", t.Year()))
		case 'z':
			_, off := t.Zone()
			s := "+"
			if off < 0 {
				s = "-"
				off = -off
			}
			b.WriteString(fmt.Sprintf("%s%02d%02d", s, off/3600, off%3600/60))
		case 'Z':
			n, _ := t.Zone()
			b.WriteString(n)
		case '%':
			b.WriteByte('%')
		default:
			b.WriteRune('%')
			b.WriteRune(rs[i])
		}
	}
	return b.String()
}

func init() {
	u := dUcrt + "," + dMsvc
	timeFn := func(e *Emu) uint64 {
		t := uint64(time.Now().Unix())
		if e.Arg(0) != 0 {
			e.Mem.W64(e.Arg(0), t)
		}
		return t
	}
	reg(u, "_time64", timeFn)
	reg(dMsvc, "time", timeFn)
	reg(u, "_time32", func(e *Emu) uint64 {
		t := uint64(uint32(time.Now().Unix()))
		if e.Arg(0) != 0 {
			e.Mem.W32(e.Arg(0), uint32(t))
		}
		return t
	})
	reg(u, "clock", func(e *Emu) uint64 { return uint64(uint32(time.Since(e.started).Milliseconds())) })
	reg(u, "_difftime64", func(e *Emu) uint64 { return e.RetF(float64(int64(e.Arg(0)) - int64(e.Arg(1)))) })
	reg(u, "_difftime32", func(e *Emu) uint64 { return e.RetF(float64(int32(e.Arg(0)) - int32(e.Arg(1)))) })
	reg(dMsvc, "difftime", func(e *Emu) uint64 { return e.RetF(float64(int64(e.Arg(0)) - int64(e.Arg(1)))) })
	conv := func(local, t64, secure bool) Fn {
		return func(e *Emu) uint64 {
			var tp, out uint64
			if secure {
				out, tp = e.Arg(0), e.Arg(1)
			} else {
				tp = e.Arg(0)
				out = e.tmBuf()
			}
			if tp == 0 {
				if secure {
					return einval
				}
				return 0
			}
			var s int64
			if t64 {
				s = int64(e.Mem.R64(tp))
			} else {
				s = int64(int32(e.Mem.R32(tp)))
			}
			if s < 0 {
				if secure {
					return einval
				}
				return 0
			}
			t := time.Unix(s, 0)
			if local {
				t = t.Local()
			} else {
				t = t.UTC()
			}
			e.writeTm(out, t)
			if secure {
				return 0
			}
			return out
		}
	}
	reg(u, "_localtime64", conv(true, true, false))
	reg(u, "_localtime32", conv(true, false, false))
	reg(u, "_gmtime64", conv(false, true, false))
	reg(u, "_gmtime32", conv(false, false, false))
	reg(u, "_localtime64_s", conv(true, true, true))
	reg(u, "_localtime32_s", conv(true, false, true))
	reg(u, "_gmtime64_s", conv(false, true, true))
	reg(u, "_gmtime32_s", conv(false, false, true))
	reg(dMsvc, "localtime", conv(true, true, false))
	reg(dMsvc, "gmtime", conv(false, true, false))
	mktime := func(utc, t64 bool) Fn {
		return func(e *Emu) uint64 {
			loc := time.Local
			if utc {
				loc = time.UTC
			}
			t := e.tmTime(e.Arg(0), loc)
			e.writeTm(e.Arg(0), t)
			if t64 {
				return uint64(t.Unix())
			}
			return uint64(uint32(t.Unix()))
		}
	}
	reg(u, "_mktime64", mktime(false, true))
	reg(u, "_mktime32", mktime(false, false))
	reg(dMsvc, "mktime", mktime(false, true))
	reg(u, "_mkgmtime64", mktime(true, true))
	reg(u, "_mkgmtime32", mktime(true, false))
	reg(u, "_mkgmtime", mktime(true, true))
	sf := func(e *Emu, wide bool) uint64 {
		buf, max, tm := e.Arg(0), e.Arg(1), e.Arg(3)
		var f string
		if wide {
			f = e.WStr(e.Arg(2))
		} else {
			f = e.CStr(e.Arg(2))
		}
		t := e.tmTime(tm, time.Local)
		_, _, _, _, _, _, _, _, dst := e.readTm(tm)
		s := strftime(f, t, dst > 0)
		n := uint64(len(s))
		if wide {
			n = uint64(len([]rune(s)))
		}
		if n >= max {
			if max > 0 {
				e.Mem.W8(buf, 0)
			}
			return 0
		}
		e.writeStrBuf(wide, buf, s)
		return n
	}
	reg(u, "strftime", func(e *Emu) uint64 { return sf(e, false) })
	reg(u, "_strftime_l", func(e *Emu) uint64 { return sf(e, false) })
	reg(u, "wcsftime", func(e *Emu) uint64 { return sf(e, true) })
	reg(u, "_wcsftime_l", func(e *Emu) uint64 { return sf(e, true) })
	reg(u, "_Strftime", func(e *Emu) uint64 { return sf(e, false) })
	reg(u, "_Wcsftime", func(e *Emu) uint64 { return sf(e, true) })
	asc := func(e *Emu, s string) uint64 {
		id := e.Cur.ID
		a := e.crt.ascBuf[id]
		if a == 0 {
			a = e.heapAllocRaw(64)
			e.crt.ascBuf[id] = a
		}
		e.Mem.WriteCStr(a, s)
		return a
	}
	reg(u, "asctime", func(e *Emu) uint64 { return asc(e, asctime(e.tmTime(e.Arg(0), time.Local))) })
	reg(u, "asctime_s", func(e *Emu) uint64 {
		e.Mem.WriteCStr(e.Arg(0), asctime(e.tmTime(e.Arg(2), time.Local)))
		return 0
	})
	reg(u, "_wasctime", func(e *Emu) uint64 { return e.allocWStr(asctime(e.tmTime(e.Arg(0), time.Local))) })
	reg(u, "_ctime64", func(e *Emu) uint64 { return asc(e, asctime(time.Unix(int64(e.Mem.R64(e.Arg(0))), 0))) })
	reg(u, "_ctime32", func(e *Emu) uint64 { return asc(e, asctime(time.Unix(int64(int32(e.Mem.R32(e.Arg(0)))), 0))) })
	reg(dMsvc, "ctime", func(e *Emu) uint64 { return asc(e, asctime(time.Unix(int64(e.Mem.R64(e.Arg(0))), 0))) })
	reg(u, "_ctime64_s", func(e *Emu) uint64 {
		e.Mem.WriteCStr(e.Arg(0), asctime(time.Unix(int64(e.Mem.R64(e.Arg(2))), 0)))
		return 0
	})
	reg(u, "_wctime64", func(e *Emu) uint64 { return e.allocWStr(asctime(time.Unix(int64(e.Mem.R64(e.Arg(0))), 0))) })
	reg(u, "_tzset", retZero)
	reg(u, "__daylight", func(e *Emu) uint64 { return e.crt.daylight })
	reg(u, "__timezone", func(e *Emu) uint64 { return e.crt.timezone })
	reg(u, "__dstbias", func(e *Emu) uint64 { return e.crt.dstbias })
	reg(u, "__tzname", func(e *Emu) uint64 { return e.crt.tzname })
	reg(u, "_get_timezone", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), e.Mem.R32(e.crt.timezone)); return 0 })
	reg(u, "_get_daylight", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), 0); return 0 })
	reg(u, "_get_dstbias", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), 0xFFFFF1F0); return 0 })
	reg(u, "_get_tzname", func(e *Emu) uint64 {
		name, _ := nowZone()
		if e.Arg(0) != 0 {
			e.Mem.W64(e.Arg(0), uint64(len(name)+1))
		}
		if e.Arg(1) != 0 && e.Arg(2) > uint64(len(name)) {
			e.Mem.WriteCStr(e.Arg(1), name)
		}
		return 0
	})
	ftime := func(e *Emu) uint64 {
		now := time.Now()
		a := e.Arg(0)
		_, off := now.Zone()
		e.Mem.W64(a, uint64(now.Unix()))
		e.Mem.W16(a+8, uint16(now.Nanosecond()/1e6))
		e.Mem.W16(a+10, uint16(int16(-off/60)))
		e.Mem.W16(a+12, 0)
		return 0
	}
	reg(u, "_ftime64", ftime)
	reg(u, "_ftime64_s", ftime)
	reg(u, "_ftime", ftime)
	reg(u, "_ftime32", func(e *Emu) uint64 {
		now := time.Now()
		a := e.Arg(0)
		e.Mem.W32(a, uint32(now.Unix()))
		e.Mem.W16(a+4, uint16(now.Nanosecond()/1e6))
		return 0
	})
	tsGet := func(e *Emu) uint64 {
		if e.Arg32(1) != 1 {
			return 0
		}
		now := time.Now()
		e.Mem.W64(e.Arg(0), uint64(now.Unix()))
		e.Mem.W32(e.Arg(0)+8, uint32(now.Nanosecond()))
		return 1
	}
	reg(u, "_timespec64_get", tsGet)
	reg(u, "timespec_get", tsGet)
	reg(u, "_timespec32_get", func(e *Emu) uint64 {
		now := time.Now()
		e.Mem.W32(e.Arg(0), uint32(now.Unix()))
		e.Mem.W32(e.Arg(0)+4, uint32(now.Nanosecond()))
		return 1
	})
	reg(u, "_strdate", func(e *Emu) uint64 { e.Mem.WriteCStr(e.Arg(0), time.Now().Format("01/02/06")); return e.Arg(0) })
	reg(u, "_strtime", func(e *Emu) uint64 { e.Mem.WriteCStr(e.Arg(0), time.Now().Format("15:04:05")); return e.Arg(0) })
	reg(u, "_strdate_s", func(e *Emu) uint64 { e.Mem.WriteCStr(e.Arg(0), time.Now().Format("01/02/06")); return 0 })
	reg(u, "_strtime_s", func(e *Emu) uint64 { e.Mem.WriteCStr(e.Arg(0), time.Now().Format("15:04:05")); return 0 })
	reg(u, "_wstrdate", func(e *Emu) uint64 { e.Mem.WriteWStr(e.Arg(0), time.Now().Format("01/02/06")); return e.Arg(0) })
	reg(u, "_wstrtime", func(e *Emu) uint64 { e.Mem.WriteWStr(e.Arg(0), time.Now().Format("15:04:05")); return e.Arg(0) })
	reg(u, "_getsystime", func(e *Emu) uint64 { e.writeTm(e.Arg(0), time.Now()); return 0 })
	reg(u, "_sleep", func(e *Emu) uint64 { return e.sleep(e.Arg32(0)) })
}

var _ = cpu.RAX
