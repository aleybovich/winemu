package win

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Console provides the Windows console on top of the host terminal.
type Console struct {
	e            *Emu
	in           *bufio.Reader
	inMode       uint32
	outMode      uint32
	attr         uint16
	title        string
	cp           uint32
	outCP        uint32
	rawSaved     any
	pending      []byte // partial UTF-8 sequence for output
	ctrlHandlers []uint64
	inputEcho    bool
	pushback     []rune
	vx, vy       int
	pendingIn    []uint16
	keyUp        rune
	cursorHidden bool
	rawWanted    bool
}

const defaultAttr = 0x07

func newConsole(e *Emu) *Console {
	c := &Console{e: e, in: bufio.NewReaderSize(e.Opt.Stdin, 4096), inMode: 0x1F7, outMode: 0x7,
		attr: defaultAttr, cp: 65001, outCP: 65001}
	e.handles.set(stdInputHandle, &fileObj{f: e.Opt.Stdin, kind: kindOf(e.Opt.Stdin), console: 1, win: "CONIN$"})
	e.handles.set(stdOutputHandle, &fileObj{f: e.Opt.Stdout, kind: kindOf(e.Opt.Stdout), console: 2, win: "CONOUT$"})
	e.handles.set(stdErrorHandle, &fileObj{f: e.Opt.Stderr, kind: kindOf(e.Opt.Stderr), console: 2, win: "CONOUT$"})
	return c
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func kindOf(f *os.File) int {
	st, err := f.Stat()
	if err != nil {
		return fileChar
	}
	switch {
	case st.Mode()&os.ModeCharDevice != 0:
		return fileChar
	case st.Mode()&os.ModeNamedPipe != 0, st.Mode()&os.ModeSocket != 0:
		return filePipe
	}
	return fileDisk
}

// isConsoleHandle reports whether a handle refers to an interactive console.
func (c *Console) isConsole(fo *fileObj) bool {
	return fo != nil && fo.console != 0 && fo.kind == fileChar
}

// writeOut writes bytes destined for a console output handle.
func (c *Console) write(fo *fileObj, b []byte) (int, error) {
	if fo.f == nil {
		return len(b), nil
	}
	if fo.kind == fileChar {
		if !utf8.Valid(b) {
			b = c.fixLegacy(b)
		}
		c.track(string(b))
	}
	return fo.f.Write(b)
}

// writeText writes text (already UTF-8) honoring the current colours.
func (c *Console) writeText(fo *fileObj, s string) {
	c.write(fo, []byte(s))
}

// ansiFor converts a console attribute to an SGR sequence.
func ansiFor(attr uint16) string {
	fgMap := []int{30, 34, 32, 36, 31, 35, 33, 37}
	fg := fgMap[attr&7]
	if attr&8 != 0 {
		fg += 60
	}
	bg := fgMap[(attr>>4)&7] + 10
	if attr&0x80 != 0 {
		bg += 60
	}
	var sb strings.Builder
	sb.WriteString("\x1b[0")
	if attr&0x4000 != 0 { // COMMON_LVB_REVERSE_VIDEO
		sb.WriteString(";7")
	}
	if attr&0x8000 != 0 { // underscore
		sb.WriteString(";4")
	}
	sb.WriteString(";" + strconv.Itoa(fg))
	if (attr>>4)&0xF != 0 {
		sb.WriteString(";" + strconv.Itoa(bg))
	}
	sb.WriteString("m")
	return sb.String()
}

func (c *Console) setAttr(fo *fileObj, attr uint16) {
	c.attr = attr
	if fo == nil || fo.kind != fileChar || os.Getenv("NO_COLOR") != "" {
		return
	}
	if attr == defaultAttr {
		c.write(fo, []byte("\x1b[0m"))
		return
	}
	c.write(fo, []byte(ansiFor(attr)))
}

func (c *Console) restore() {
	if c == nil {
		return
	}
	if c.attr != defaultAttr {
		if fo, ok := c.e.handles.get(stdOutputHandle).(*fileObj); ok && fo.kind == fileChar {
			fo.f.Write([]byte("\x1b[0m"))
		}
	}
	if c.cursorHidden {
		if fo, ok := c.e.handles.get(stdOutputHandle).(*fileObj); ok && fo.kind == fileChar {
			fo.f.Write([]byte("\x1b[?25h"))
		}
	}
	c.rawWanted = false
	c.leaveRaw()
}

// readLine reads one line of cooked input (including the newline).
func (c *Console) readLine() (string, error) {
	if !c.rawWanted {
		c.leaveRaw()
	}
	defer c.e.releaseRun()() // host read: other processes may touch this one
	s, err := c.in.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return s, nil
}

// readRaw reads up to n bytes from stdin.
func (c *Console) readRaw(p []byte) (int, error) {
	defer c.e.releaseRun()()
	n, err := c.in.Read(p)
	if err == io.EOF && n > 0 {
		err = nil
	}
	return n, err
}

// getch reads a single key without echo (as _getch does).
func (c *Console) getch() (rune, bool) {
	if len(c.pushback) > 0 {
		r := c.pushback[0]
		c.pushback = c.pushback[1:]
		return r, true
	}
	if isTerminal(c.e.Opt.Stdin) && !c.rawWanted {
		c.enterRaw()
		defer c.leaveRaw()
	}
	relock := c.e.releaseRun()
	r, _, err := c.in.ReadRune()
	relock()
	if err != nil {
		return 0, false
	}
	if r == '\n' {
		r = '\r'
	}
	return r, true
}

// kbhit reports whether input is available.
func (c *Console) kbhit() bool {
	if len(c.pushback) > 0 || c.in.Buffered() > 0 {
		return true
	}
	return inputReady(c.e.Opt.Stdin)
}

func (c *Console) enterRaw() {
	if c.rawSaved != nil {
		return
	}
	if s, ok := setRaw(c.e.Opt.Stdin); ok {
		c.rawSaved = s
	}
}

func (c *Console) leaveRaw() {
	if c.rawSaved == nil || c.rawWanted {
		return
	}
	restoreTerm(c.e.Opt.Stdin, c.rawSaved)
	c.rawSaved = nil
}

// size returns terminal columns and rows.
func (c *Console) size() (int, int) {
	if w, h, ok := termSize(c.e.Opt.Stdout); ok {
		return w, h
	}
	w, h := 80, 25
	if v, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && v > 0 {
		w = v
	}
	if v, err := strconv.Atoi(os.Getenv("LINES")); err == nil && v > 0 {
		h = v
	}
	return w, h
}

// decodeCP converts bytes in code page cp to a Go string.
func decodeCP(cp uint32, b []byte) string {
	switch cp {
	case 65001, 0, 1, 2, 3:
		return string(b)
	case 1252, 28591, 437, 850:
		if utf8.Valid(b) {
			return string(b)
		}
		rs := make([]rune, len(b))
		for i, x := range b {
			rs[i] = cp1252Rune(x)
		}
		return string(rs)
	}
	return string(b)
}

var cp1252hi = [32]rune{0x20AC, 0x81, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8D, 0x017D, 0x8F,
	0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x9D, 0x017E, 0x0178}

func cp1252Rune(b byte) rune {
	if b >= 0x80 && b < 0xA0 {
		return cp1252hi[b-0x80]
	}
	return rune(b)
}

func (c *Console) String() string { return fmt.Sprintf("console(attr=%#x)", c.attr) }

// cp437 maps the upper half of the OEM code page used by legacy console
// programs (box drawing etc.).
var cp437 = []rune("ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0")

// fixLegacy converts non-UTF-8 console output, keeping complete UTF-8
// sequences split across writes intact.
func (c *Console) fixLegacy(b []byte) []byte {
	b = append(c.pending, b...)
	c.pending = nil
	// hold back an incomplete trailing UTF-8 sequence
	if n := len(b); n > 0 {
		for k := 1; k <= 3 && k <= n; k++ {
			if utf8.RuneStart(b[n-k]) {
				if !utf8.FullRune(b[n-k:]) && utf8.Valid(b[:n-k]) {
					c.pending = append([]byte{}, b[n-k:]...)
					return b[:n-k]
				}
				break
			}
		}
	}
	if utf8.Valid(b) {
		return b
	}
	// not UTF-8: the program is writing in a legacy code page
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		switch {
		case x < 0x80:
			out = append(out, x)
		case c.outCP == 1252:
			out = utf8.AppendRune(out, cp1252Rune(x))
		default:
			out = utf8.AppendRune(out, cp437[x-0x80])
		}
	}
	return out
}
