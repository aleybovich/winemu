package win

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// virtual cursor tracking so that cursor-positioning programs work on an
// ANSI terminal without querying it.
func (c *Console) track(s string) {
	w, _ := c.size()
	esc := 0 // 0 none, 1 after ESC, 2 CSI, 3 OSC
	for _, r := range s {
		switch esc {
		case 1:
			switch r {
			case '[':
				esc = 2
			case ']':
				esc = 3
			default:
				esc = 0
			}
			continue
		case 2:
			if r >= 0x40 && r <= 0x7E {
				esc = 0
			}
			continue
		case 3:
			if r == 7 || r == '\\' {
				esc = 0
			}
			continue
		}
		if r == 27 {
			esc = 1
			continue
		}
		switch r {
		case '\n':
			c.vy++
			c.vx = 0
		case '\r':
			c.vx = 0
		case '\b':
			if c.vx > 0 {
				c.vx--
			}
		case '\t':
			c.vx = (c.vx + 8) &^ 7
		default:
			if r >= 0x20 {
				c.vx++
				if c.vx >= w {
					c.vx = 0
					c.vy++
				}
			}
		}
	}
}

func (c *Console) emit(fo *fileObj, s string) {
	c.write(fo, []byte(s))
}

func (c *Console) moveTo(fo *fileObj, x, y int) {
	if fo == nil || fo.kind != fileChar {
		return
	}
	var b strings.Builder
	dy := y - c.vy
	if dy < 0 {
		fmt.Fprintf(&b, "\x1b[%dA", -dy)
	} else if dy > 0 {
		fmt.Fprintf(&b, "\x1b[%dB", dy)
	}
	fmt.Fprintf(&b, "\x1b[%dG", x+1)
	fo.f.Write([]byte(b.String()))
	c.vx, c.vy = x, y
}

func coord(v uint32) (int, int) { return int(int16(v)), int(int16(v >> 16)) }

func (e *Emu) conOut(h uint64) *fileObj {
	fo := e.fileObj(h)
	if fo == nil || fo.console != 2 {
		return nil
	}
	return fo
}

func vkFor(r rune) (uint16, rune) {
	switch {
	case r == '\r' || r == '\n':
		return 0x0D, '\r'
	case r == 27:
		return 0x1B, r
	case r == 8 || r == 127:
		return 0x08, 8
	case r == '\t':
		return 0x09, r
	case r == ' ':
		return 0x20, r
	case r >= 'a' && r <= 'z':
		return uint16(r - 32), r
	case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return uint16(r), r
	}
	return 0, r
}

func init() {
	k := dK32
	writeConsole := func(e *Emu, wide bool) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		buf, n := e.Arg(1), e.Arg32(2)
		var s string
		if wide {
			s = e.Mem.WStrN(buf, int(n))
		} else {
			s = decodeCP(e.con.outCP, e.Mem.ReadBytes(buf, int(n)))
		}
		e.crt.flushStd()
		if fo.console == 2 {
			e.con.emit(fo, s)
		} else {
			e.fileWrite(fo, []byte(s))
		}
		if p := e.Arg(3); p != 0 {
			e.Mem.W32(p, n)
		}
		return 1
	}
	reg(k, "WriteConsoleA", func(e *Emu) uint64 { return writeConsole(e, false) })
	reg(k, "WriteConsoleW", func(e *Emu) uint64 { return writeConsole(e, true) })
	readConsole := func(e *Emu, wide bool) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.console != 1 {
			return e.fail(errInvalidHandle)
		}
		buf, n := e.Arg(1), e.Arg32(2)
		e.crt.flushStd()
		c := e.con
		if len(c.pendingIn) == 0 {
			line, err := c.readLine()
			if err != nil && line == "" {
				if p := e.Arg(3); p != 0 {
					e.Mem.W32(p, 0)
				}
				return 1
			}
			if strings.HasSuffix(line, "\n") && !strings.HasSuffix(line, "\r\n") {
				line = line[:len(line)-1] + "\r\n"
			}
			c.vx, c.vy = 0, c.vy+1
			c.pendingIn = utf16.Encode([]rune(line))
		}
		var got uint32
		if wide {
			k := min(int(n), len(c.pendingIn))
			e.Mem.WriteUnits(buf, c.pendingIn[:k])
			c.pendingIn = c.pendingIn[k:]
			got = uint32(k)
		} else {
			s := []byte(string(utf16.Decode(c.pendingIn)))
			k := min(int(n), len(s))
			for k > 0 && k < len(s) && !utf8.RuneStart(s[k]) {
				k--
			}
			e.Mem.Write(buf, s[:k])
			c.pendingIn = utf16.Encode([]rune(string(s[k:])))
			got = uint32(k)
		}
		if p := e.Arg(3); p != 0 {
			e.Mem.W32(p, got)
		}
		return 1
	}
	reg(k, "ReadConsoleA", func(e *Emu) uint64 { return readConsole(e, false) })
	reg(k, "ReadConsoleW", func(e *Emu) uint64 { return readConsole(e, true) })
	readInput := func(e *Emu, peek bool) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.console != 1 {
			return e.fail(errInvalidHandle)
		}
		buf, n := e.Arg(1), e.Arg32(2)
		if n == 0 {
			e.Mem.W32(e.Arg(3), 0)
			return 1
		}
		c := e.con
		if peek && !c.kbhit() && c.keyUp == 0 {
			e.Mem.W32(e.Arg(3), 0)
			return 1
		}
		e.crt.flushStd()
		m := e.Mem
		m.Fill(buf, 0, 20)
		m.W16(buf, 1) // KEY_EVENT
		if c.keyUp != 0 {
			vk, ch := vkFor(c.keyUp)
			m.W32(buf+4, 0)
			m.W16(buf+8, 1)
			m.W16(buf+10, vk)
			m.W16(buf+14, uint16(ch))
			if !peek {
				c.keyUp = 0
			}
			e.Mem.W32(e.Arg(3), 1)
			return 1
		}
		r, ok := c.getch()
		if !ok {
			e.Mem.W32(e.Arg(3), 0)
			return 1
		}
		vk, ch := vkFor(r)
		if r == 27 && c.kbhit() {
			// escape sequence for arrow keys
			r2, _ := c.getch()
			if r2 == '[' || r2 == 'O' {
				r3, _ := c.getch()
				switch r3 {
				case 'A':
					vk, ch = 0x26, 0
				case 'B':
					vk, ch = 0x28, 0
				case 'C':
					vk, ch = 0x27, 0
				case 'D':
					vk, ch = 0x25, 0
				case 'H':
					vk, ch = 0x24, 0
				case 'F':
					vk, ch = 0x23, 0
				}
			} else {
				c.pushback = append(c.pushback, r2)
			}
		}
		m.W32(buf+4, 1)
		m.W16(buf+8, 1)
		m.W16(buf+10, vk)
		m.W16(buf+14, uint16(ch))
		if peek {
			c.pushback = append([]rune{r}, c.pushback...)
		} else {
			c.keyUp = r
		}
		e.Mem.W32(e.Arg(3), 1)
		return 1
	}
	reg(k, "ReadConsoleInputW", func(e *Emu) uint64 { return readInput(e, false) })
	reg(k, "ReadConsoleInputA", func(e *Emu) uint64 { return readInput(e, false) })
	reg(k, "ReadConsoleInputExW", func(e *Emu) uint64 { return readInput(e, false) })
	reg(k, "PeekConsoleInputW", func(e *Emu) uint64 { return readInput(e, true) })
	reg(k, "PeekConsoleInputA", func(e *Emu) uint64 { return readInput(e, true) })
	reg(k, "GetNumberOfConsoleInputEvents", func(e *Emu) uint64 {
		n := uint32(0)
		if e.con.kbhit() || e.con.keyUp != 0 {
			n = 1
		}
		e.Mem.W32(e.Arg(1), n)
		return 1
	})
	reg(k, "FlushConsoleInputBuffer", func(e *Emu) uint64 { e.con.pendingIn = nil; return 1 })
	reg(k, "GetConsoleMode", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || !e.con.isConsole(fo) {
			return e.fail(errInvalidHandle)
		}
		if fo.console == 1 {
			e.Mem.W32(e.Arg(1), e.con.inMode)
		} else {
			e.Mem.W32(e.Arg(1), e.con.outMode)
		}
		return 1
	})
	reg(k, "SetConsoleMode", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || !e.con.isConsole(fo) {
			return e.fail(errInvalidHandle)
		}
		if fo.console == 1 {
			e.con.inMode = e.Arg32(1)
			// line input off -> deliver keystrokes immediately
			if e.con.inMode&0x2 == 0 && isTerminal(e.Opt.Stdin) {
				e.con.rawWanted = true
				e.con.enterRaw()
			} else if e.con.rawWanted {
				e.con.rawWanted = false
				e.con.leaveRaw()
			}
		} else {
			e.con.outMode = e.Arg32(1)
		}
		return 1
	})
	reg(k, "GetConsoleCP", func(e *Emu) uint64 { return uint64(e.con.cp) })
	reg(k, "GetConsoleOutputCP", func(e *Emu) uint64 { return uint64(e.con.outCP) })
	reg(k, "SetConsoleCP", func(e *Emu) uint64 { e.con.cp = e.Arg32(0); return 1 })
	reg(k, "SetConsoleOutputCP", func(e *Emu) uint64 { e.con.outCP = e.Arg32(0); return 1 })
	csbi := func(e *Emu, ex bool) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || !e.con.isConsole(fo) || fo.console != 2 {
			return e.fail(errInvalidHandle)
		}
		c := e.con
		w, h := c.size()
		a := e.Arg(1)
		m := e.Mem
		off := uint64(0)
		if ex {
			off = 4
		}
		top := c.vy - (h - 1)
		if top < 0 {
			top = 0
		}
		bufH := 9001
		if c.vy >= bufH {
			bufH = c.vy + 1
		}
		m.W16(a+off, uint16(w))
		m.W16(a+off+2, uint16(bufH))
		m.W16(a+off+4, uint16(c.vx))
		m.W16(a+off+6, uint16(c.vy))
		m.W16(a+off+8, c.attr)
		m.W16(a+off+10, 0)
		m.W16(a+off+12, uint16(top))
		m.W16(a+off+14, uint16(w-1))
		m.W16(a+off+16, uint16(top+h-1))
		m.W16(a+off+18, uint16(w))
		m.W16(a+off+20, uint16(h))
		if ex {
			m.W16(a+26, 0xF5)
			m.W32(a+28, 0)
			cols := []uint32{0x0C0C0C, 0xDA3700, 0x0EA113, 0xDD963A, 0x1F0FC5, 0x981788, 0x009CC1, 0xCCCCCC,
				0x767676, 0xFF783B, 0x0CC616, 0xD6D661, 0x5648E7, 0x9E00B4, 0xA5F1F9, 0xF2F2F2}
			for i, v := range cols {
				m.W32(a+32+uint64(4*i), v)
			}
		}
		return 1
	}
	reg(k, "GetConsoleScreenBufferInfo", func(e *Emu) uint64 { return csbi(e, false) })
	reg(k, "GetConsoleScreenBufferInfoEx", func(e *Emu) uint64 { return csbi(e, true) })
	reg(k, "SetConsoleScreenBufferInfoEx", retTrue)
	reg(k, "SetConsoleTextAttribute", func(e *Emu) uint64 {
		fo := e.conOut(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		e.crt.flushStd()
		e.con.setAttr(fo, uint16(e.Arg32(1)))
		return 1
	})
	reg(k, "SetConsoleCursorPosition", func(e *Emu) uint64 {
		fo := e.conOut(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		e.crt.flushStd()
		x, y := coord(e.Arg32(1))
		e.con.moveTo(fo, x, y)
		return 1
	})
	reg(k, "GetConsoleCursorInfo", func(e *Emu) uint64 {
		e.Mem.W32(e.Arg(1), 25)
		e.Mem.W32(e.Arg(1)+4, uint32(b2u(!e.con.cursorHidden)))
		return 1
	})
	reg(k, "SetConsoleCursorInfo", func(e *Emu) uint64 {
		fo := e.conOut(e.Arg(0))
		vis := e.Mem.R32(e.Arg(1)+4) != 0
		e.con.cursorHidden = !vis
		if fo != nil && fo.kind == fileChar {
			if vis {
				e.con.write(fo, []byte("\x1b[?25h"))
			} else {
				e.con.write(fo, []byte("\x1b[?25l"))
			}
		}
		return 1
	})
	fillChar := func(e *Emu, wide bool) uint64 {
		fo := e.conOut(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		ch := rune(e.Arg32(1) & 0xFFFF)
		if !wide {
			ch = rune(e.Arg32(1) & 0xFF)
		}
		n := int(e.Arg32(2))
		x, y := coord(e.Arg32(3))
		c := e.con
		w, h := c.size()
		e.crt.flushStd()
		if fo.kind == fileChar {
			if x == 0 && n >= w*h && ch == ' ' {
				c.write(fo, []byte("\x1b[2J\x1b[3J\x1b[H"))
				c.vx, c.vy = 0, 0
			} else {
				sx, sy := c.vx, c.vy
				c.moveTo(fo, x, y)
				s := strings.Repeat(string(ch), n)
				c.write(fo, []byte(s))
				c.moveTo(fo, sx, sy)
			}
		}
		if p := e.Arg(4); p != 0 {
			e.Mem.W32(p, uint32(n))
		}
		return 1
	}
	reg(k, "FillConsoleOutputCharacterA", func(e *Emu) uint64 { return fillChar(e, false) })
	reg(k, "FillConsoleOutputCharacterW", func(e *Emu) uint64 { return fillChar(e, true) })
	reg(k, "FillConsoleOutputAttribute", func(e *Emu) uint64 {
		if p := e.Arg(4); p != 0 {
			e.Mem.W32(p, e.Arg32(2))
		}
		return 1
	})
	writeOut := func(e *Emu, wide bool) uint64 {
		fo := e.conOut(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		buf, n := e.Arg(1), e.Arg32(2)
		x, y := coord(e.Arg32(3))
		var s string
		if wide {
			s = e.Mem.WStrN(buf, int(n))
		} else {
			s = string(e.Mem.ReadBytes(buf, int(n)))
		}
		c := e.con
		sx, sy := c.vx, c.vy
		c.moveTo(fo, x, y)
		c.emit(fo, s)
		c.moveTo(fo, sx, sy)
		if p := e.Arg(4); p != 0 {
			e.Mem.W32(p, n)
		}
		return 1
	}
	reg(k, "WriteConsoleOutputCharacterA", func(e *Emu) uint64 { return writeOut(e, false) })
	reg(k, "WriteConsoleOutputCharacterW", func(e *Emu) uint64 { return writeOut(e, true) })
	reg(k, "WriteConsoleOutputAttribute", func(e *Emu) uint64 {
		if p := e.Arg(4); p != 0 {
			e.Mem.W32(p, e.Arg32(2))
		}
		return 1
	})
	reg(k, "WriteConsoleOutputW", func(e *Emu) uint64 {
		// CHAR_INFO grid: render row by row
		fo := e.conOut(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		buf := e.Arg(1)
		bw, _ := coord(e.Arg32(2))
		bx, by := coord(e.Arg32(3))
		rect := e.Arg(4)
		l, t := int(int16(e.Mem.R16(rect))), int(int16(e.Mem.R16(rect+2)))
		r, b := int(int16(e.Mem.R16(rect+4))), int(int16(e.Mem.R16(rect+6)))
		c := e.con
		sx, sy := c.vx, c.vy
		attr := c.attr
		for row := t; row <= b; row++ {
			c.moveTo(fo, l, row)
			var sb strings.Builder
			for col := l; col <= r; col++ {
				ci := buf + uint64(4*((by+row-t)*bw+(bx+col-l)))
				ch := rune(e.Mem.R16(ci))
				at := e.Mem.R16(ci + 2)
				if at != attr {
					sb.WriteString(ansiFor(at))
					attr = at
				}
				if ch == 0 {
					ch = ' '
				}
				sb.WriteRune(ch)
			}
			c.emit(fo, sb.String())
		}
		c.write(fo, []byte(ansiFor(c.attr)))
		c.moveTo(fo, sx, sy)
		return 1
	})
	reg(k, "ScrollConsoleScreenBufferW", retTrue)
	reg(k, "ScrollConsoleScreenBufferA", retTrue)
	regAW(k, "SetConsoleTitle", func(e *Emu, w bool) uint64 {
		e.con.title = e.strArg(0, w)
		if fo := e.conOut(stdOutputHandle); fo != nil && fo.kind == fileChar && os.Getenv("WINEMU_NO_TITLE") == "" {
			e.con.write(fo, []byte("\x1b]0;"+e.con.title+"\x07"))
		}
		return 1
	})
	regAW(k, "GetConsoleTitle", func(e *Emu, w bool) uint64 {
		r := e.putStr(w, e.Arg(0), e.Arg32(1), e.con.title)
		if r > uint64(len([]rune(e.con.title))) {
			return 0
		}
		return r
	})
	regAW(k, "GetConsoleOriginalTitle", func(e *Emu, w bool) uint64 {
		return e.putStr(w, e.Arg(0), e.Arg32(1), e.con.title)
	})
	reg(k, "GetConsoleWindow", func(e *Emu) uint64 { return 0x10010 })
	reg(k, "AllocConsole", func(e *Emu) uint64 { return e.fail(5) })
	reg(k, "FreeConsole", retTrue)
	reg(k, "AttachConsole", func(e *Emu) uint64 { return e.fail(5) })
	reg(k, "GetConsoleProcessList", func(e *Emu) uint64 {
		if e.Arg32(1) >= 1 {
			e.Mem.W32(e.Arg(0), e.proc.pid)
		}
		return 1
	})
	reg(k, "SetConsoleCtrlHandler", func(e *Emu) uint64 {
		fn, add := e.Arg(0), e.Arg32(1) != 0
		switch {
		case fn == 0:
			// NULL: sets / clears the ignore-CTRL+C attribute; no console
			// control events are delivered, so there is nothing to record
		case add:
			e.con.ctrlHandlers = append(e.con.ctrlHandlers, fn)
		default:
			// remove the most recent registration of fn
			hs := e.con.ctrlHandlers
			for i := len(hs) - 1; i >= 0; i-- {
				if hs[i] == fn {
					e.con.ctrlHandlers = slices.Delete(hs, i, i+1)
					return 1
				}
			}
			return e.fail(errInvalidParameter)
		}
		return 1
	})
	reg(k, "GetLargestConsoleWindowSize", func(e *Emu) uint64 {
		w, h := e.con.size()
		return uint64(uint32(w) | uint32(h)<<16)
	})
	reg(k, "SetConsoleScreenBufferSize", retTrue)
	reg(k, "SetConsoleWindowInfo", retTrue)
	reg(k, "SetConsoleActiveScreenBuffer", retTrue)
	reg(k, "CreateConsoleScreenBuffer", func(e *Emu) uint64 {
		fo := *e.fileObj(stdOutputHandle)
		fo.refs = 0
		return e.handles.add(&fo)
	})
	reg(k, "GetCurrentConsoleFont", func(e *Emu) uint64 { e.Mem.W32(e.Arg(2), 0); e.Mem.W32(e.Arg(2)+4, 0x100008); return 1 })
	reg(k, "GetCurrentConsoleFontEx", func(e *Emu) uint64 { return 1 })
	reg(k, "SetCurrentConsoleFontEx", retTrue)
	reg(k, "GetConsoleFontSize", ret(0x100008))
	reg(k, "GetConsoleDisplayMode", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), 0); return 1 })
	reg(k, "SetConsoleDisplayMode", retTrue)
	reg(k, "GetConsoleSelectionInfo", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, 16); return 1 })
	reg(k, "GetNumberOfConsoleMouseButtons", func(e *Emu) uint64 { e.Mem.W32(e.Arg(0), 3); return 1 })
	reg(k, "GetConsoleAliasW", retZero)
	reg(k, "SetConsoleHistoryInfo", retTrue)
	reg(k, "GetConsoleHistoryInfo", func(e *Emu) uint64 { return 1 })
	reg(k, "ClosePseudoConsole", retZero)
	reg(k, "CreatePseudoConsole", ret(0x80004001))
}
