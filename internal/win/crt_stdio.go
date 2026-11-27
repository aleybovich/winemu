package win

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	ioFBF = 0x0000
	ioLBF = 0x0040
	ioNBF = 0x0004
	eofC  = -1
)

type cfile struct {
	addr     uint64
	fd       int
	text     bool
	readable bool
	writable bool
	appendM  bool
	std      int // 1..3 for stdin/out/err
	rbuf     []byte
	wbuf     []byte
	unget    []byte
	eof, err bool
	bufMode  int
	tmpPath  string
	closed   bool
	lastRead bool
}

// ---------------------------------------------------------------------------
// low-level fd I/O

func (c *CRT) fdObj(fd int) (*fdEntry, *fileObj) {
	ent := c.fds[fd]
	if ent == nil {
		return nil, nil
	}
	h := ent.h
	if fd <= 2 {
		h = c.e.stdHandle(fd)
	}
	return ent, c.e.fileObj(h)
}

func (c *CRT) newFd(h uint64, text, app bool, path string) int {
	for fd := 3; ; fd++ {
		if c.fds[fd] == nil {
			c.fds[fd] = &fdEntry{h: h, text: text, append: app, path: path}
			return fd
		}
	}
}

func (c *CRT) readFd(fd int, n int) ([]byte, error) {
	_, fo := c.fdObj(fd)
	if fo == nil {
		return nil, os.ErrInvalid
	}
	buf := make([]byte, n)
	got, err := c.e.fileRead(fo, buf)
	if err == io.ErrClosedPipe { // the CRT reports a closed write end as end-of-file
		err = io.EOF
	}
	return buf[:got], err
}

func (c *CRT) writeFd(fd int, b []byte) (int, error) {
	ent, fo := c.fdObj(fd)
	if fo == nil {
		return 0, os.ErrInvalid
	}
	if ent.append && fo.f != nil && fo.console == 0 {
		fo.f.Seek(0, io.SeekEnd)
	}
	return c.e.fileWrite(fo, b)
}

func (c *CRT) seekFd(fd int, off int64, whence int) (int64, error) {
	_, fo := c.fdObj(fd)
	if fo == nil {
		return -1, os.ErrInvalid
	}
	if fo.f == nil || fo.console != 0 || fo.pipe != nil {
		return 0, nil
	}
	return fo.f.Seek(off, whence)
}

func (c *CRT) closeFd(fd int) bool {
	ent := c.fds[fd]
	if ent == nil {
		return false
	}
	delete(c.fds, fd)
	if fd > 2 {
		c.e.handles.close(ent.h)
	}
	return true
}

// writeStd writes directly to stdout/stderr (bypassing FILE buffers).
func (c *CRT) writeStd(fd int, b []byte) { c.writeFd(fd, b) }

// ---------------------------------------------------------------------------
// FILE streams

func (c *CRT) file(p uint64) *cfile {
	f := c.files[p]
	if f == nil || f.closed {
		return nil
	}
	return f
}

func (c *CRT) flush(f *cfile) bool {
	if f == nil || len(f.wbuf) == 0 {
		return true
	}
	b := f.wbuf
	f.wbuf = f.wbuf[:0]
	if _, err := c.writeFd(f.fd, b); err != nil {
		f.err = true
		return false
	}
	return true
}

func (c *CRT) flushAll() {
	if c == nil {
		return
	}
	seen := map[*cfile]bool{}
	for _, f := range c.files {
		if !seen[f] && !f.closed {
			seen[f] = true
			c.flush(f)
		}
	}
}

func (c *CRT) flushStd() {
	if c == nil {
		return
	}
	c.flush(c.files[c.iob+48])
	c.flush(c.files[c.iob+96])
}

func (c *CRT) fwrite(f *cfile, b []byte) int {
	if f == nil {
		return 0
	}
	if !f.writable {
		f.err = true
		return 0
	}
	if len(f.rbuf) > 0 || len(f.unget) > 0 {
		// switch from reading: reposition the OS file pointer
		back := int64(len(f.rbuf) + len(f.unget))
		c.seekFd(f.fd, -back, io.SeekCurrent)
		f.rbuf, f.unget = nil, nil
	}
	f.wbuf = append(f.wbuf, b...)
	switch {
	case f.bufMode == ioNBF:
		c.flush(f)
	case f.bufMode == ioLBF && containsNL(b):
		c.flush(f)
	case len(f.wbuf) >= 8192:
		c.flush(f)
	}
	return len(b)
}

func containsNL(b []byte) bool {
	for _, x := range b {
		if x == '\n' {
			return true
		}
	}
	return false
}

// fill reads more data into the read buffer. Returns false at EOF/error.
func (c *CRT) fill(f *cfile) bool {
	if f.eof && f.std != 1 {
		return false
	}
	if len(f.wbuf) > 0 {
		c.flush(f)
	}
	if f.std == 1 {
		c.flushStd()
	}
	ent, _ := c.fdObj(f.fd)
	if ent == nil {
		f.err = true
		return false
	}
	b, err := c.readFd(f.fd, 4096)
	if len(b) == 0 {
		if err != nil && err != io.EOF {
			f.err = true
		} else {
			f.eof = true
		}
		return false
	}
	if f.text {
		// strip CR before LF
		if b[len(b)-1] == '\r' {
			if nb, _ := c.readFd(f.fd, 1); len(nb) > 0 {
				b = append(b, nb...)
			}
		}
		out := b[:0]
		for i := 0; i < len(b); i++ {
			if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
				continue
			}
			if b[i] == 0x1A && f.std == 0 && f.text && false {
				break
			}
			out = append(out, b[i])
		}
		b = out
	}
	f.rbuf = append(f.rbuf, b...)
	return true
}

func (c *CRT) getc(f *cfile) int {
	if f == nil || !f.readable {
		if f != nil {
			f.err = true
		}
		return eofC
	}
	if n := len(f.unget); n > 0 {
		v := f.unget[n-1]
		f.unget = f.unget[:n-1]
		return int(v)
	}
	if len(f.rbuf) == 0 && !c.fill(f) {
		return eofC
	}
	v := f.rbuf[0]
	f.rbuf = f.rbuf[1:]
	return int(v)
}

func (c *CRT) ungetc(f *cfile, ch int) int {
	if f == nil || ch == eofC {
		return eofC
	}
	f.unget = append(f.unget, byte(ch))
	f.eof = false
	return ch & 0xFF
}

// getwc reads a UTF-8 encoded character from a text stream as UTF-16 (BMP).
func (c *CRT) getwc(f *cfile) (rune, bool) {
	b0 := c.getc(f)
	if b0 < 0 {
		return 0, false
	}
	if b0 < 0x80 {
		return rune(b0), true
	}
	buf := []byte{byte(b0)}
	need := 1
	switch {
	case b0&0xE0 == 0xC0:
		need = 2
	case b0&0xF0 == 0xE0:
		need = 3
	case b0&0xF8 == 0xF0:
		need = 4
	}
	for len(buf) < need {
		b := c.getc(f)
		if b < 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	r, _ := utf8.DecodeRune(buf)
	if r > 0xFFFF {
		r = 0xFFFD
	}
	return r, true
}

func (c *CRT) ungetwc(f *cfile, r rune) {
	if f == nil {
		return
	}
	b := []byte(string(r))
	for i := len(b) - 1; i >= 0; i-- {
		f.unget = append(f.unget, b[i])
	}
	f.eof = false
}

func (c *CRT) tell(f *cfile) int64 {
	pos, err := c.seekFd(f.fd, 0, io.SeekCurrent)
	if err != nil {
		return -1
	}
	return pos - int64(len(f.rbuf)) - int64(len(f.unget)) + int64(len(f.wbuf))
}

func (c *CRT) seek(f *cfile, off int64, whence int) int {
	c.flush(f)
	if whence == io.SeekCurrent {
		off -= int64(len(f.rbuf) + len(f.unget))
	}
	f.rbuf, f.unget = nil, nil
	if _, err := c.seekFd(f.fd, off, whence); err != nil {
		c.setErrno(einval)
		return -1
	}
	f.eof = false
	return 0
}

// parseMode parses an fopen mode string.
func parseMode(mode string) (flag int, read, write, app, text, ok bool) {
	text = true
	if mode == "" {
		return
	}
	switch mode[0] {
	case 'r':
		read = true
		flag = os.O_RDONLY
	case 'w':
		write = true
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	case 'a':
		write = true
		app = true
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	default:
		return
	}
	for _, ch := range mode[1:] {
		switch ch {
		case '+':
			read, write = true, true
			flag = flag&^(os.O_WRONLY|os.O_RDONLY) | os.O_RDWR
		case 'b':
			text = false
		case 't':
			text = true
		case 'x':
			flag |= os.O_EXCL
		case ',':
			goto done
		}
	}
done:
	ok = true
	return
}

func (c *CRT) fopen(name, mode string) (uint64, int) {
	flag, read, write, app, text, ok := parseMode(strings.TrimSpace(mode))
	if !ok {
		return 0, einval
	}
	e := c.e
	var h uint64
	if dev := deviceName(name); dev != "" {
		access := uint32(genericRead)
		if write {
			access = genericWrite
		}
		h = e.createFile(name, access, 3, 0)
	} else {
		host := e.fs.toHost(name)
		if st, err := os.Stat(host); err == nil && st.IsDir() {
			return 0, eacces
		}
		f, err := os.OpenFile(host, flag, 0o644)
		if err != nil {
			return 0, errnoOf(err)
		}
		h = e.handles.add(&fileObj{f: f, host: host, win: e.fs.full(name), kind: fileDisk})
	}
	fd := c.newFd(h, text, app, name)
	return c.newStream(fd, read, write, app, text), 0
}

func (c *CRT) newStream(fd int, read, write, app, text bool) uint64 {
	a := c.e.heapAllocRaw(48)
	c.e.Mem.W32(a+28, uint32(fd))
	c.files[a] = &cfile{addr: a, fd: fd, readable: read, writable: write, appendM: app, text: text}
	return a
}

func (c *CRT) fclose(p uint64) int {
	f := c.file(p)
	if f == nil {
		return eofC
	}
	ok := c.flush(f)
	if f.std == 0 {
		c.closeFd(f.fd)
		f.closed = true
		delete(c.files, p)
		c.e.heap.freeBlock(p)
		if f.tmpPath != "" {
			os.Remove(f.tmpPath)
		}
	}
	if !ok {
		return eofC
	}
	return 0
}

// fgets reads a line of at most n-1 bytes.
func (c *CRT) fgets(f *cfile, n int) ([]byte, bool) {
	var out []byte
	for len(out) < n-1 {
		ch := c.getc(f)
		if ch < 0 {
			if len(out) == 0 {
				return nil, false
			}
			break
		}
		out = append(out, byte(ch))
		if ch == '\n' {
			break
		}
	}
	return out, true
}

// ---------------------------------------------------------------------------
// printf / scanf front ends

const (
	pfLegacyVsprintfNull = 1
	pfStandardSnprintf   = 2
	pfLegacyWide         = 4
	pfLegacyMsvcrt       = 8
	pfLegacyThreeDigit   = 16
)

func (e *Emu) ucrtFmtOpts(options uint64, wide bool) fmtOpts {
	return fmtOpts{wide: wide, legacyWide: options&pfLegacyWide != 0 || !wide,
		threeDigitExp: options&pfLegacyThreeDigit != 0, legacyInfNan: options&pfLegacyMsvcrt != 0}
}

var msvcrtOpts = fmtOpts{legacyWide: true, threeDigitExp: true, legacyInfNan: true}

func (e *Emu) fmtFormat(p uint64, wide bool) []rune {
	if wide {
		return fmtWide(e.Mem.WStrUnits(p))
	}
	return fmtNarrow(e.Mem.CStrBytes(p))
}

// writeFormatted sends formatted output to a FILE; returns chars written.
func (e *Emu) printfTo(stream uint64, out *fmtOut) uint64 {
	f := e.crt.file(stream)
	if f == nil {
		e.crt.setErrno(einval)
		return ^uint64(0)
	}
	if out.wide {
		b := []byte(string(utf16.Decode(out.u)))
		e.crt.fwrite(f, b)
		return uint64(len(out.u))
	}
	e.crt.fwrite(f, out.b)
	return uint64(len(out.b))
}

// sprintfTo writes formatted output to a buffer with snprintf semantics.
// mode: 0 = unlimited (sprintf), 1 = standard snprintf, 2 = legacy _snprintf, 3 = _s (fail on overflow)
func (e *Emu) sprintfTo(buf uint64, count uint64, out *fmtOut, mode int) uint64 {
	var n int
	if out.wide {
		n = len(out.u)
	} else {
		n = len(out.b)
	}
	unit := uint64(1)
	if out.wide {
		unit = 2
	}
	writeN := func(k int, term bool) {
		if out.wide {
			u := out.u[:k]
			if term {
				u = append(append([]uint16{}, u...), 0)
			}
			e.Mem.WriteUnits(buf, u)
		} else {
			b := out.b[:k]
			if term {
				b = append(append([]byte{}, b...), 0)
			}
			e.Mem.Write(buf, b)
		}
	}
	switch mode {
	case 0:
		writeN(n, true)
		return uint64(n)
	case 1:
		if buf == 0 || count == 0 {
			return uint64(n)
		}
		if uint64(n) < count {
			writeN(n, true)
		} else {
			writeN(int(count-1), true)
		}
		return uint64(n)
	case 2:
		if buf == 0 && count == 0 {
			return uint64(n)
		}
		if uint64(n) < count {
			writeN(n, true)
			return uint64(n)
		}
		if uint64(n) == count {
			writeN(n, false)
			return uint64(n)
		}
		writeN(int(count), false)
		return ^uint64(0)
	default:
		if uint64(n) >= count {
			if count > 0 {
				e.Mem.Fill(buf, 0, unit)
			}
			e.crt.setErrno(erange)
			return ^uint64(0)
		}
		writeN(n, true)
		return uint64(n)
	}
}

func init() {
	u := dUcrt + "," + dMsvc
	c := func(e *Emu) *CRT { return e.crt }

	// ---- UCRT common stdio entry points ----
	reg(dUcrt, "__acrt_iob_func", func(e *Emu) uint64 { return e.crt.iob + 48*uint64(e.Arg32(0)) })
	reg(dUcrt, "__stdio_common_vfprintf", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(2), false), &vaList{e, e.Arg(4)}, e.ucrtFmtOpts(e.Arg(0), false))
		return e.printfTo(e.Arg(1), out)
	})
	reg(dUcrt, "__stdio_common_vfprintf_s", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(2), false), &vaList{e, e.Arg(4)}, e.ucrtFmtOpts(e.Arg(0), false))
		return e.printfTo(e.Arg(1), out)
	})
	reg(dUcrt, "__stdio_common_vfprintf_p", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(2), false), &vaList{e, e.Arg(4)}, e.ucrtFmtOpts(e.Arg(0), false))
		return e.printfTo(e.Arg(1), out)
	})
	reg(dUcrt, "__stdio_common_vfwprintf", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(2), true), &vaList{e, e.Arg(4)}, e.ucrtFmtOpts(e.Arg(0), true))
		return e.printfTo(e.Arg(1), out)
	})
	reg(dUcrt, "__stdio_common_vfwprintf_s", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(2), true), &vaList{e, e.Arg(4)}, e.ucrtFmtOpts(e.Arg(0), true))
		return e.printfTo(e.Arg(1), out)
	})
	reg(dUcrt, "__stdio_common_vsprintf", func(e *Emu) uint64 {
		opt := e.Arg(0)
		out := e.sprintf(e.fmtFormat(e.Arg(3), false), &vaList{e, e.Arg(5)}, e.ucrtFmtOpts(opt, false))
		mode := 2
		if opt&pfStandardSnprintf != 0 {
			mode = 1
		}
		if e.Arg(2) == ^uint64(0) {
			mode = 0
		}
		return e.sprintfTo(e.Arg(1), e.Arg(2), out, mode)
	})
	reg(dUcrt, "__stdio_common_vswprintf", func(e *Emu) uint64 {
		opt := e.Arg(0)
		out := e.sprintf(e.fmtFormat(e.Arg(3), true), &vaList{e, e.Arg(5)}, e.ucrtFmtOpts(opt, true))
		mode := 2
		if opt&pfStandardSnprintf != 0 {
			mode = 1
		}
		if e.Arg(2) == ^uint64(0) {
			mode = 0
		}
		return e.sprintfTo(e.Arg(1), e.Arg(2), out, mode)
	})
	reg(dUcrt, "__stdio_common_vsprintf_s", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(3), false), &vaList{e, e.Arg(5)}, e.ucrtFmtOpts(e.Arg(0), false))
		return e.sprintfTo(e.Arg(1), e.Arg(2), out, 3)
	})
	reg(dUcrt, "__stdio_common_vswprintf_s", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(3), true), &vaList{e, e.Arg(5)}, e.ucrtFmtOpts(e.Arg(0), true))
		return e.sprintfTo(e.Arg(1), e.Arg(2), out, 3)
	})
	reg(dUcrt, "__stdio_common_vsnprintf_s", func(e *Emu) uint64 {
		// (options, buf, sizeOfBuffer, count, format, locale, va)
		out := e.sprintf(e.fmtFormat(e.Arg(4), false), &vaList{e, e.Arg(6)}, e.ucrtFmtOpts(e.Arg(0), false))
		return snprintfS(e, e.Arg(1), e.Arg(2), e.Arg(3), out)
	})
	reg(dUcrt, "__stdio_common_vsnwprintf_s", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(4), true), &vaList{e, e.Arg(6)}, e.ucrtFmtOpts(e.Arg(0), true))
		return snprintfS(e, e.Arg(1), e.Arg(2), e.Arg(3), out)
	})
	reg(dUcrt, "__stdio_common_vsprintf_p", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(3), false), &vaList{e, e.Arg(5)}, e.ucrtFmtOpts(e.Arg(0), false))
		return e.sprintfTo(e.Arg(1), e.Arg(2), out, 1)
	})
	reg(dUcrt, "__stdio_common_vfscanf", func(e *Emu) uint64 {
		f := e.crt.file(e.Arg(1))
		if f == nil {
			return ^uint64(0)
		}
		opt := e.Arg(0)
		r := e.scanf(e.fmtFormat(e.Arg(2), false), &fileIn{e: e, f: f}, &vaList{e, e.Arg(4)},
			scanOpts{secure: opt&1 != 0, legacyWide: opt&2 != 0})
		return uint64(int64(r))
	})
	reg(dUcrt, "__stdio_common_vfwscanf", func(e *Emu) uint64 {
		f := e.crt.file(e.Arg(1))
		if f == nil {
			return ^uint64(0)
		}
		opt := e.Arg(0)
		r := e.scanf(e.fmtFormat(e.Arg(2), true), &fileIn{e: e, f: f, wide: true}, &vaList{e, e.Arg(4)},
			scanOpts{wide: true, secure: opt&1 != 0, legacyWide: opt&2 != 0})
		return uint64(int64(r))
	})
	reg(dUcrt, "__stdio_common_vsscanf", func(e *Emu) uint64 {
		opt := e.Arg(0)
		buf, n := e.Arg(1), e.Arg(2)
		var b []byte
		if n == ^uint64(0) {
			b = e.Mem.CStrBytes(buf)
		} else {
			b = e.Mem.CStrN(buf, int(n))
		}
		r := e.scanf(e.fmtFormat(e.Arg(3), false), &strIn{b: b}, &vaList{e, e.Arg(5)},
			scanOpts{secure: opt&1 != 0, legacyWide: opt&2 != 0})
		return uint64(int64(r))
	})
	reg(dUcrt, "__stdio_common_vswscanf", func(e *Emu) uint64 {
		opt := e.Arg(0)
		buf, n := e.Arg(1), e.Arg(2)
		units := e.Mem.WStrUnits(buf)
		if n != ^uint64(0) && uint64(len(units)) > n {
			units = units[:n]
		}
		r := e.scanf(e.fmtFormat(e.Arg(3), true), &strIn{u: units, wide: true}, &vaList{e, e.Arg(5)},
			scanOpts{wide: true, secure: opt&1 != 0, legacyWide: opt&2 != 0})
		return uint64(int64(r))
	})

	// ---- msvcrt-style variadic functions ----
	stdout := func(e *Emu) uint64 { return e.crt.iob + 48 }
	stdin := func(e *Emu) uint64 { return e.crt.iob }
	reg(dMsvc, "printf", func(e *Emu) uint64 {
		return e.printfTo(stdout(e), e.sprintf(e.fmtFormat(e.Arg(0), false), &regArgs{e, 1}, msvcrtOpts))
	})
	reg(dMsvc, "wprintf", func(e *Emu) uint64 {
		o := msvcrtOpts
		o.wide = true
		return e.printfTo(stdout(e), e.sprintf(e.fmtFormat(e.Arg(0), true), &regArgs{e, 1}, o))
	})
	reg(dMsvc, "fprintf", func(e *Emu) uint64 {
		return e.printfTo(e.Arg(0), e.sprintf(e.fmtFormat(e.Arg(1), false), &regArgs{e, 2}, msvcrtOpts))
	})
	reg(dMsvc, "fwprintf", func(e *Emu) uint64 {
		o := msvcrtOpts
		o.wide = true
		return e.printfTo(e.Arg(0), e.sprintf(e.fmtFormat(e.Arg(1), true), &regArgs{e, 2}, o))
	})
	reg(dMsvc, "vprintf", func(e *Emu) uint64 {
		return e.printfTo(stdout(e), e.sprintf(e.fmtFormat(e.Arg(0), false), &vaList{e, e.Arg(1)}, msvcrtOpts))
	})
	reg(dMsvc, "vfprintf", func(e *Emu) uint64 {
		return e.printfTo(e.Arg(0), e.sprintf(e.fmtFormat(e.Arg(1), false), &vaList{e, e.Arg(2)}, msvcrtOpts))
	})
	reg(dMsvc, "vwprintf", func(e *Emu) uint64 {
		o := msvcrtOpts
		o.wide = true
		return e.printfTo(stdout(e), e.sprintf(e.fmtFormat(e.Arg(0), true), &vaList{e, e.Arg(1)}, o))
	})
	reg(dMsvc, "vfwprintf", func(e *Emu) uint64 {
		o := msvcrtOpts
		o.wide = true
		return e.printfTo(e.Arg(0), e.sprintf(e.fmtFormat(e.Arg(1), true), &vaList{e, e.Arg(2)}, o))
	})
	reg(dMsvc, "sprintf", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), 0, e.sprintf(e.fmtFormat(e.Arg(1), false), &regArgs{e, 2}, msvcrtOpts), 0)
	})
	reg(dMsvc, "vsprintf", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), 0, e.sprintf(e.fmtFormat(e.Arg(1), false), &vaList{e, e.Arg(2)}, msvcrtOpts), 0)
	})
	reg(dMsvc, "_snprintf", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), e.Arg(1), e.sprintf(e.fmtFormat(e.Arg(2), false), &regArgs{e, 3}, msvcrtOpts), 2)
	})
	reg(dMsvc, "_vsnprintf", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), e.Arg(1), e.sprintf(e.fmtFormat(e.Arg(2), false), &vaList{e, e.Arg(3)}, msvcrtOpts), 2)
	})
	reg(dMsvc, "snprintf", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), e.Arg(1), e.sprintf(e.fmtFormat(e.Arg(2), false), &regArgs{e, 3}, msvcrtOpts), 1)
	})
	reg(dMsvc, "vsnprintf", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), e.Arg(1), e.sprintf(e.fmtFormat(e.Arg(2), false), &vaList{e, e.Arg(3)}, msvcrtOpts), 1)
	})
	reg(dMsvc, "_scprintf", func(e *Emu) uint64 {
		return uint64(len(e.sprintf(e.fmtFormat(e.Arg(0), false), &regArgs{e, 1}, msvcrtOpts).b))
	})
	reg(dMsvc, "_vscprintf", func(e *Emu) uint64 {
		return uint64(len(e.sprintf(e.fmtFormat(e.Arg(0), false), &vaList{e, e.Arg(1)}, msvcrtOpts).b))
	})
	reg(dMsvc, "_vscwprintf", func(e *Emu) uint64 {
		o := msvcrtOpts
		o.wide = true
		return uint64(len(e.sprintf(e.fmtFormat(e.Arg(0), true), &vaList{e, e.Arg(1)}, o).u))
	})
	reg(dMsvc, "sprintf_s", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), e.Arg(1), e.sprintf(e.fmtFormat(e.Arg(2), false), &regArgs{e, 3}, msvcrtOpts), 3)
	})
	reg(dMsvc, "vsprintf_s", func(e *Emu) uint64 {
		return e.sprintfTo(e.Arg(0), e.Arg(1), e.sprintf(e.fmtFormat(e.Arg(2), false), &vaList{e, e.Arg(3)}, msvcrtOpts), 3)
	})
	reg(dMsvc, "_snprintf_s", func(e *Emu) uint64 {
		return snprintfS(e, e.Arg(0), e.Arg(1), e.Arg(2), e.sprintf(e.fmtFormat(e.Arg(3), false), &regArgs{e, 4}, msvcrtOpts))
	})
	reg(dMsvc, "_vsnprintf_s", func(e *Emu) uint64 {
		return snprintfS(e, e.Arg(0), e.Arg(1), e.Arg(2), e.sprintf(e.fmtFormat(e.Arg(3), false), &vaList{e, e.Arg(4)}, msvcrtOpts))
	})
	wsp := func(argFmt, argVa int, va bool, mode int, bufArg, countArg int) Fn {
		return func(e *Emu) uint64 {
			o := msvcrtOpts
			o.wide = true
			var src argSrc = &regArgs{e, argVa}
			if va {
				src = &vaList{e, e.Arg(argVa)}
			}
			out := e.sprintf(e.fmtFormat(e.Arg(argFmt), true), src, o)
			cnt := uint64(0)
			if countArg >= 0 {
				cnt = e.Arg(countArg)
			}
			return e.sprintfTo(e.Arg(bufArg), cnt, out, mode)
		}
	}
	reg(dMsvc, "swprintf", wsp(2, 3, false, 1, 0, 1))
	reg(dMsvc, "_swprintf", wsp(1, 2, false, 0, 0, -1))
	reg(dMsvc, "vswprintf", wsp(2, 3, true, 1, 0, 1))
	reg(dMsvc, "_vswprintf", wsp(1, 2, true, 0, 0, -1))
	reg(dMsvc, "_snwprintf", wsp(2, 3, false, 2, 0, 1))
	reg(dMsvc, "_vsnwprintf", wsp(2, 3, true, 2, 0, 1))
	reg(dMsvc, "swprintf_s", wsp(2, 3, false, 3, 0, 1))
	reg(dMsvc, "vswprintf_s", wsp(2, 3, true, 3, 0, 1))
	reg(dMsvc, "_scwprintf", func(e *Emu) uint64 {
		o := msvcrtOpts
		o.wide = true
		return uint64(len(e.sprintf(e.fmtFormat(e.Arg(0), true), &regArgs{e, 1}, o).u))
	})
	// scanf family (msvcrt)
	sscan := func(wide, va, secure bool) Fn {
		return func(e *Emu) uint64 {
			var in scanIn
			if wide {
				in = &strIn{u: e.Mem.WStrUnits(e.Arg(0)), wide: true}
			} else {
				in = &strIn{b: e.Mem.CStrBytes(e.Arg(0))}
			}
			var src argSrc = &regArgs{e, 2}
			if va {
				src = &vaList{e, e.Arg(2)}
			}
			return uint64(int64(e.scanf(e.fmtFormat(e.Arg(1), wide), in, src, scanOpts{wide: wide, secure: secure, legacyWide: true})))
		}
	}
	reg(dMsvc, "sscanf", sscan(false, false, false))
	reg(dMsvc, "sscanf_s", sscan(false, false, true))
	reg(dMsvc, "vsscanf", sscan(false, true, false))
	reg(dMsvc, "swscanf", sscan(true, false, false))
	reg(dMsvc, "swscanf_s", sscan(true, false, true))
	reg(dMsvc, "vswscanf", sscan(true, true, false))
	fscan := func(wide, va, secure bool, useStdin bool) Fn {
		return func(e *Emu) uint64 {
			fi := 0
			if useStdin {
				fi = -1
			}
			var f *cfile
			if useStdin {
				f = e.crt.file(stdin(e))
			} else {
				f = e.crt.file(e.Arg(0))
			}
			fmtArg := fi + 1
			if f == nil {
				return ^uint64(0)
			}
			var src argSrc = &regArgs{e, fmtArg + 1}
			if va {
				src = &vaList{e, e.Arg(fmtArg + 1)}
			}
			return uint64(int64(e.scanf(e.fmtFormat(e.Arg(fmtArg), wide), &fileIn{e: e, f: f, wide: wide}, src,
				scanOpts{wide: wide, secure: secure, legacyWide: true})))
		}
	}
	reg(dMsvc, "fscanf", fscan(false, false, false, false))
	reg(dMsvc, "fscanf_s", fscan(false, false, true, false))
	reg(dMsvc, "vfscanf", fscan(false, true, false, false))
	reg(dMsvc, "fwscanf", fscan(true, false, false, false))
	reg(dMsvc, "scanf", fscan(false, false, false, true))
	reg(dMsvc, "scanf_s", fscan(false, false, true, true))
	reg(dMsvc, "vscanf", fscan(false, true, false, true))
	reg(dMsvc, "wscanf", fscan(true, false, false, true))

	// ---- FILE functions ----
	reg(u, "fopen", func(e *Emu) uint64 {
		p, en := c(e).fopen(e.CStr(e.Arg(0)), e.CStr(e.Arg(1)))
		if p == 0 {
			c(e).setErrno(en)
		}
		return p
	})
	reg(u, "_wfopen", func(e *Emu) uint64 {
		p, en := c(e).fopen(e.WStr(e.Arg(0)), e.WStr(e.Arg(1)))
		if p == 0 {
			c(e).setErrno(en)
		}
		return p
	})
	reg(u, "_fsopen", func(e *Emu) uint64 {
		p, en := c(e).fopen(e.CStr(e.Arg(0)), e.CStr(e.Arg(1)))
		if p == 0 {
			c(e).setErrno(en)
		}
		return p
	})
	reg(u, "_wfsopen", func(e *Emu) uint64 {
		p, en := c(e).fopen(e.WStr(e.Arg(0)), e.WStr(e.Arg(1)))
		if p == 0 {
			c(e).setErrno(en)
		}
		return p
	})
	reg(u, "fopen_s", func(e *Emu) uint64 {
		p, en := c(e).fopen(e.CStr(e.Arg(1)), e.CStr(e.Arg(2)))
		e.Mem.W64(e.Arg(0), p)
		if p == 0 {
			c(e).setErrno(en)
			return uint64(en)
		}
		return 0
	})
	reg(u, "_wfopen_s", func(e *Emu) uint64 {
		p, en := c(e).fopen(e.WStr(e.Arg(1)), e.WStr(e.Arg(2)))
		e.Mem.W64(e.Arg(0), p)
		if p == 0 {
			c(e).setErrno(en)
			return uint64(en)
		}
		return 0
	})
	freopen := func(e *Emu, name, mode string, stream uint64) uint64 {
		cc := c(e)
		f := cc.file(stream)
		if f == nil {
			return 0
		}
		cc.flush(f)
		if name == "" {
			// mode change only
			_, read, write, app, text, _ := parseMode(mode)
			f.readable, f.writable, f.appendM, f.text = read, write, app, text
			return stream
		}
		np, en := cc.fopen(name, mode)
		if np == 0 {
			cc.setErrno(en)
			return 0
		}
		nf := cc.files[np]
		if f.std == 0 {
			cc.closeFd(f.fd)
		}
		// move new stream state into the old FILE*
		delete(cc.files, np)
		nf.addr = stream
		nf.std = f.std
		if f.std != 0 {
			// redirect standard descriptor
			cc.fds[f.fd] = cc.fds[nf.fd]
			delete(cc.fds, nf.fd)
			nf.fd = f.fd
			if f.fd <= 2 {
				cc.stdH[f.fd] = cc.fds[f.fd].h
			}
		}
		*f = *nf
		e.heap.freeBlock(np)
		return stream
	}
	reg(u, "freopen", func(e *Emu) uint64 { return freopen(e, e.CStr(e.Arg(0)), e.CStr(e.Arg(1)), e.Arg(2)) })
	reg(u, "_wfreopen", func(e *Emu) uint64 { return freopen(e, e.WStr(e.Arg(0)), e.WStr(e.Arg(1)), e.Arg(2)) })
	reg(u, "freopen_s", func(e *Emu) uint64 {
		r := freopen(e, e.CStr(e.Arg(1)), e.CStr(e.Arg(2)), e.Arg(3))
		e.Mem.W64(e.Arg(0), r)
		if r == 0 {
			return einval
		}
		return 0
	})
	reg(u, "_wfreopen_s", func(e *Emu) uint64 {
		r := freopen(e, e.WStr(e.Arg(1)), e.WStr(e.Arg(2)), e.Arg(3))
		e.Mem.W64(e.Arg(0), r)
		if r == 0 {
			return einval
		}
		return 0
	})
	reg(u, "_fdopen", func(e *Emu) uint64 {
		fd := int(e.ArgI(0))
		if c(e).fds[fd] == nil {
			return 0
		}
		_, r, w, a, t, _ := parseMode(e.CStr(e.Arg(1)))
		return c(e).newStream(fd, r, w, a, t)
	})
	reg(u, "_wfdopen", func(e *Emu) uint64 {
		fd := int(e.ArgI(0))
		if c(e).fds[fd] == nil {
			return 0
		}
		_, r, w, a, t, _ := parseMode(e.WStr(e.Arg(1)))
		return c(e).newStream(fd, r, w, a, t)
	})
	reg(u, "fclose", func(e *Emu) uint64 { return uint64(int64(c(e).fclose(e.Arg(0)))) })
	reg(u, "_fclose_nolock", func(e *Emu) uint64 { return uint64(int64(c(e).fclose(e.Arg(0)))) })
	reg(u, "_fcloseall", func(e *Emu) uint64 {
		n := 0
		for p, f := range c(e).files {
			if f.std == 0 {
				c(e).fclose(p)
				n++
			}
		}
		return uint64(n)
	})
	fflush := func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			c(e).flushAll()
			return 0
		}
		f := c(e).file(e.Arg(0))
		if f == nil || !c(e).flush(f) {
			return ^uint64(0)
		}
		return 0
	}
	reg(u, "fflush", fflush)
	reg(u, "_fflush_nolock", fflush)
	reg(u, "_flushall", func(e *Emu) uint64 { c(e).flushAll(); return uint64(len(c(e).files)) })
	fread := func(e *Emu) uint64 {
		buf, size, n := e.Arg(0), e.Arg(1), e.Arg(2)
		f := c(e).file(e.Arg(3))
		total := size * n
		if f == nil || total == 0 {
			return 0
		}
		cc := c(e)
		out := make([]byte, 0, min(total, 1<<20))
		for uint64(len(out)) < total {
			if nu := len(f.unget); nu > 0 {
				out = append(out, f.unget[nu-1])
				f.unget = f.unget[:nu-1]
				continue
			}
			if len(f.rbuf) == 0 {
				if !f.text && total-uint64(len(out)) >= 65536 && len(f.wbuf) == 0 {
					// large binary read: bypass buffer
					b, _ := cc.readFd(f.fd, int(total-uint64(len(out))))
					if len(b) == 0 {
						f.eof = true
						break
					}
					out = append(out, b...)
					continue
				}
				if !cc.fill(f) {
					break
				}
			}
			k := min(uint64(len(f.rbuf)), total-uint64(len(out)))
			out = append(out, f.rbuf[:k]...)
			f.rbuf = f.rbuf[k:]
		}
		e.Mem.Write(buf, out)
		return uint64(len(out)) / size
	}
	reg(u, "fread", fread)
	reg(u, "_fread_nolock", fread)
	reg(u, "fread_s", func(e *Emu) uint64 {
		// (buf, bufsize, elemsize, count, stream)
		c := e.Cur.CPU
		_ = c
		buf, bs, size, n, stream := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.Arg(4)
		if size*n > bs {
			n = bs / size
		}
		f := e.crt.file(stream)
		if f == nil {
			return 0
		}
		total := size * n
		var out []byte
		for uint64(len(out)) < total {
			ch := e.crt.getc(f)
			if ch < 0 {
				break
			}
			out = append(out, byte(ch))
		}
		e.Mem.Write(buf, out)
		return uint64(len(out)) / size
	})
	fwrite := func(e *Emu) uint64 {
		buf, size, n := e.Arg(0), e.Arg(1), e.Arg(2)
		f := c(e).file(e.Arg(3))
		if f == nil || size*n == 0 {
			return 0
		}
		w := c(e).fwrite(f, e.Mem.ReadBytes(buf, int(size*n)))
		return uint64(w) / size
	}
	reg(u, "fwrite", fwrite)
	reg(u, "_fwrite_nolock", fwrite)
	getc := func(e *Emu) uint64 { return uint64(int64(c(e).getc(c(e).file(e.Arg(0))))) }
	reg(u, "fgetc", getc)
	reg(u, "getc", getc)
	reg(u, "_getc_nolock", getc)
	reg(u, "_fgetc_nolock", getc)
	reg(u, "_fgetchar", func(e *Emu) uint64 { return uint64(int64(c(e).getc(c(e).file(stdin(e))))) })
	reg(u, "getchar", func(e *Emu) uint64 { return uint64(int64(c(e).getc(c(e).file(stdin(e))))) })
	reg(u, "_getchar_nolock", func(e *Emu) uint64 { return uint64(int64(c(e).getc(c(e).file(stdin(e))))) })
	reg(u, "ungetc", func(e *Emu) uint64 { return uint64(int64(c(e).ungetc(c(e).file(e.Arg(1)), int(e.ArgI(0))))) })
	reg(u, "_ungetc_nolock", func(e *Emu) uint64 { return uint64(int64(c(e).ungetc(c(e).file(e.Arg(1)), int(e.ArgI(0))))) })
	putc := func(e *Emu) uint64 {
		f := c(e).file(e.Arg(1))
		if f == nil || c(e).fwrite(f, []byte{byte(e.Arg(0))}) == 0 {
			return ^uint64(0)
		}
		return e.Arg(0) & 0xFF
	}
	reg(u, "fputc", putc)
	reg(u, "putc", putc)
	reg(u, "_putc_nolock", putc)
	reg(u, "_fputc_nolock", putc)
	reg(u, "putchar", func(e *Emu) uint64 {
		c(e).fwrite(c(e).file(stdout(e)), []byte{byte(e.Arg(0))})
		return e.Arg(0) & 0xFF
	})
	reg(u, "_fputchar", func(e *Emu) uint64 {
		c(e).fwrite(c(e).file(stdout(e)), []byte{byte(e.Arg(0))})
		return e.Arg(0) & 0xFF
	})
	reg(u, "_putchar_nolock", func(e *Emu) uint64 {
		c(e).fwrite(c(e).file(stdout(e)), []byte{byte(e.Arg(0))})
		return e.Arg(0) & 0xFF
	})
	reg(u, "fputs", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(1))
		if f == nil {
			return ^uint64(0)
		}
		c(e).fwrite(f, e.Mem.CStrBytes(e.Arg(0)))
		return 0
	})
	reg(u, "puts", func(e *Emu) uint64 {
		f := c(e).file(stdout(e))
		c(e).fwrite(f, append(e.Mem.CStrBytes(e.Arg(0)), '\n'))
		return 0
	})
	reg(u, "fgets", func(e *Emu) uint64 {
		buf, n := e.Arg(0), int(e.ArgI(1))
		f := c(e).file(e.Arg(2))
		if f == nil || n <= 0 {
			return 0
		}
		line, ok := c(e).fgets(f, n)
		if !ok {
			return 0
		}
		e.Mem.Write(buf, append(line, 0))
		return buf
	})
	reg(u, "gets_s", func(e *Emu) uint64 {
		buf, n := e.Arg(0), int(e.Arg(1))
		f := c(e).file(stdin(e))
		line, ok := c(e).fgets(f, 1<<20)
		if !ok {
			return 0
		}
		s := strings.TrimSuffix(string(line), "\n")
		if len(s) >= n {
			s = s[:n-1]
		}
		e.Mem.WriteCStr(buf, s)
		return buf
	})
	reg(dMsvc, "gets", func(e *Emu) uint64 {
		f := c(e).file(stdin(e))
		line, ok := c(e).fgets(f, 1<<20)
		if !ok {
			return 0
		}
		e.Mem.WriteCStr(e.Arg(0), strings.TrimSuffix(string(line), "\n"))
		return e.Arg(0)
	})
	// wide char streams (UTF-8 on the wire)
	reg(u, "fgetwc", func(e *Emu) uint64 {
		r, ok := c(e).getwc(c(e).file(e.Arg(0)))
		if !ok {
			return 0xFFFF
		}
		return uint64(r)
	})
	reg(u, "getwc", func(e *Emu) uint64 {
		r, ok := c(e).getwc(c(e).file(e.Arg(0)))
		if !ok {
			return 0xFFFF
		}
		return uint64(r)
	})
	reg(u, "_fgetwc_nolock", func(e *Emu) uint64 {
		r, ok := c(e).getwc(c(e).file(e.Arg(0)))
		if !ok {
			return 0xFFFF
		}
		return uint64(r)
	})
	reg(u, "getwchar", func(e *Emu) uint64 {
		r, ok := c(e).getwc(c(e).file(stdin(e)))
		if !ok {
			return 0xFFFF
		}
		return uint64(r)
	})
	reg(u, "ungetwc", func(e *Emu) uint64 {
		c(e).ungetwc(c(e).file(e.Arg(1)), rune(e.Arg32(0)&0xFFFF))
		return e.Arg(0) & 0xFFFF
	})
	putwc := func(e *Emu) uint64 {
		f := c(e).file(e.Arg(1))
		if f == nil {
			return 0xFFFF
		}
		c(e).fwrite(f, []byte(string(rune(e.Arg32(0)&0xFFFF))))
		return e.Arg(0) & 0xFFFF
	}
	reg(u, "fputwc", putwc)
	reg(u, "putwc", putwc)
	reg(u, "_fputwc_nolock", putwc)
	reg(u, "putwchar", func(e *Emu) uint64 {
		c(e).fwrite(c(e).file(stdout(e)), []byte(string(rune(e.Arg32(0)&0xFFFF))))
		return e.Arg(0) & 0xFFFF
	})
	reg(u, "fputws", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(1))
		if f == nil {
			return 0xFFFF
		}
		c(e).fwrite(f, []byte(e.WStr(e.Arg(0))))
		return 0
	})
	reg(u, "_putws", func(e *Emu) uint64 {
		c(e).fwrite(c(e).file(stdout(e)), []byte(e.WStr(e.Arg(0))+"\n"))
		return 0
	})
	reg(u, "fgetws", func(e *Emu) uint64 {
		buf, n := e.Arg(0), int(e.ArgI(1))
		f := c(e).file(e.Arg(2))
		if f == nil || n <= 0 {
			return 0
		}
		var units []uint16
		for len(units) < n-1 {
			r, ok := c(e).getwc(f)
			if !ok {
				if len(units) == 0 {
					return 0
				}
				break
			}
			units = append(units, uint16(r))
			if r == '\n' {
				break
			}
		}
		e.Mem.WriteUnits(buf, append(units, 0))
		return buf
	})
	reg(u, "_getws_s", func(e *Emu) uint64 {
		f := c(e).file(stdin(e))
		line, ok := c(e).fgets(f, 1<<20)
		if !ok {
			return 0
		}
		e.putStrW(e.Arg(0), uint32(e.Arg(1)), strings.TrimSuffix(string(line), "\n"))
		return e.Arg(0)
	})
	reg(u, "fseek", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		return uint64(int64(c(e).seek(f, e.ArgI(1), int(e.Arg32(2)))))
	})
	reg(u, "_fseeki64", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		return uint64(int64(c(e).seek(f, int64(e.Arg(1)), int(e.Arg32(2)))))
	})
	reg(u, "_fseek_nolock", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		return uint64(int64(c(e).seek(f, e.ArgI(1), int(e.Arg32(2)))))
	})
	reg(u, "_fseeki64_nolock", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		return uint64(int64(c(e).seek(f, int64(e.Arg(1)), int(e.Arg32(2)))))
	})
	ftell := func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		return uint64(c(e).tell(f))
	}
	reg(u, "ftell", func(e *Emu) uint64 { return uint64(uint32(ftell(e))) })
	reg(u, "_ftell_nolock", func(e *Emu) uint64 { return uint64(uint32(ftell(e))) })
	reg(u, "_ftelli64", ftell)
	reg(u, "_ftelli64_nolock", ftell)
	reg(u, "fgetpos", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		e.Mem.W64(e.Arg(1), uint64(c(e).tell(f)))
		return 0
	})
	reg(u, "fsetpos", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		return uint64(int64(c(e).seek(f, int64(e.Mem.R64(e.Arg(1))), 0)))
	})
	reg(u, "rewind", func(e *Emu) uint64 {
		if f := c(e).file(e.Arg(0)); f != nil {
			c(e).seek(f, 0, 0)
			f.err = false
		}
		return 0
	})
	reg(u, "feof", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return 0
		}
		if f.eof && len(f.rbuf) == 0 && len(f.unget) == 0 {
			return 0x10
		}
		return 0
	})
	reg(u, "ferror", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil || !f.err {
			return 0
		}
		return 0x20
	})
	reg(u, "clearerr", func(e *Emu) uint64 {
		if f := c(e).file(e.Arg(0)); f != nil {
			f.err, f.eof = false, false
		}
		return 0
	})
	reg(u, "clearerr_s", func(e *Emu) uint64 {
		if f := c(e).file(e.Arg(0)); f != nil {
			f.err, f.eof = false, false
		}
		return 0
	})
	reg(u, "setvbuf", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		c(e).flush(f)
		switch e.Arg32(2) {
		case ioNBF:
			f.bufMode = ioNBF
		case ioLBF:
			f.bufMode = ioLBF
		default:
			if f.std == 0 || !isTerminal(e.Opt.Stdout) {
				f.bufMode = ioFBF
			}
		}
		return 0
	})
	reg(u, "setbuf", func(e *Emu) uint64 {
		if f := c(e).file(e.Arg(0)); f != nil && e.Arg(1) == 0 {
			f.bufMode = ioNBF
		}
		return 0
	})
	reg(u, "_fileno", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(0))
		if f == nil {
			return ^uint64(0)
		}
		return uint64(f.fd)
	})
	reg(u, "_lock_file", retZero)
	reg(u, "_unlock_file", retZero)
	reg(u, "_get_stream_buffer_pointers", func(e *Emu) uint64 {
		// point at zeroed fields so callers always take the slow path
		p := e.Arg(0)
		for i, off := range []uint64{8, 0, 16} {
			if q := e.Arg(i + 1); q != 0 {
				e.Mem.W64(q, p+off)
			}
		}
		return 0
	})
	reg(u, "_filbuf", func(e *Emu) uint64 { return uint64(int64(c(e).getc(c(e).file(e.Arg(0))))) })
	reg(u, "_flsbuf", func(e *Emu) uint64 {
		f := c(e).file(e.Arg(1))
		c(e).fwrite(f, []byte{byte(e.Arg(0))})
		return e.Arg(0) & 0xFF
	})
	reg(u, "tmpfile", func(e *Emu) uint64 {
		f, err := os.CreateTemp("", "winemu-tmp")
		if err != nil {
			return 0
		}
		h := e.handles.add(&fileObj{f: f, host: f.Name(), kind: fileDisk, delClose: true})
		fd := c(e).newFd(h, false, false, f.Name())
		return c(e).newStream(fd, true, true, false, false)
	})
	reg(u, "tmpfile_s", func(e *Emu) uint64 {
		f, err := os.CreateTemp("", "winemu-tmp")
		if err != nil {
			return eacces
		}
		h := e.handles.add(&fileObj{f: f, host: f.Name(), kind: fileDisk, delClose: true})
		fd := c(e).newFd(h, false, false, f.Name())
		e.Mem.W64(e.Arg(0), c(e).newStream(fd, true, true, false, false))
		return 0
	})
	tmpnam := func(e *Emu) string {
		cc := c(e)
		cc.nextTmp++
		return e.fs.tempDir() + "s" + itoa(int64(e.proc.pid)) + "." + itoa(int64(cc.nextTmp))
	}
	reg(u, "tmpnam", func(e *Emu) uint64 {
		s := tmpnam(e)
		if e.Arg(0) != 0 {
			e.Mem.WriteCStr(e.Arg(0), s)
			return e.Arg(0)
		}
		if c(e).tmpnamBuf == 0 {
			c(e).tmpnamBuf = e.heapAllocRaw(260)
		}
		e.Mem.WriteCStr(c(e).tmpnamBuf, s)
		return c(e).tmpnamBuf
	})
	reg(u, "tmpnam_s", func(e *Emu) uint64 { e.Mem.WriteCStr(e.Arg(0), tmpnam(e)); return 0 })
	reg(u, "_wtmpnam", func(e *Emu) uint64 { return e.allocWStr(tmpnam(e)) })
	reg(u, "_tempnam", func(e *Emu) uint64 {
		dir := e.CStr(e.Arg(0))
		if dir == "" {
			dir = e.fs.tempDir()
		}
		return e.allocCStr(strings.TrimRight(dir, `\/`) + `\` + e.CStr(e.Arg(1)) + itoa(int64(e.proc.pid)) + itoa(int64(len(c(e).files))))
	})

	// ---- low level io ----
	open := func(e *Emu, name string, oflag uint32, pmode uint32) uint64 {
		cc := c(e)
		access := uint32(0)
		switch oflag & 3 {
		case 0:
			access = genericRead
		case 1:
			access = genericWrite
		case 2:
			access = genericRead | genericWrite
		}
		disp := uint32(3)
		switch {
		case oflag&0x100 != 0 && oflag&0x400 != 0: // CREAT|EXCL
			disp = 1
		case oflag&0x100 != 0 && oflag&0x200 != 0: // CREAT|TRUNC
			disp = 2
		case oflag&0x100 != 0:
			disp = 4
		case oflag&0x200 != 0:
			disp = 5
		}
		flags := uint32(0)
		if oflag&0x100 != 0 && pmode&0x80 == 0 && pmode != 0 {
			flags = attrReadonly
		}
		h := e.createFile(name, access, disp, flags)
		if h == invalidHandle {
			cc.setErrno(errnoFromWin(e.LastError()))
			return ^uint64(0)
		}
		text := oflag&0x8000 == 0 // _O_BINARY
		if oflag&0x4000 != 0 {    // _O_TEXT
			text = true
		}
		if fo := e.fileObj(h); fo != nil && oflag&0x40 != 0 { // _O_TEMPORARY
			fo.delClose = true
		}
		return uint64(cc.newFd(h, text, oflag&8 != 0, name))
	}
	reg(u, "_open", func(e *Emu) uint64 { return open(e, e.CStr(e.Arg(0)), e.Arg32(1), e.Arg32(2)) })
	reg(u, "_wopen", func(e *Emu) uint64 { return open(e, e.WStr(e.Arg(0)), e.Arg32(1), e.Arg32(2)) })
	reg(u, "_sopen", func(e *Emu) uint64 { return open(e, e.CStr(e.Arg(0)), e.Arg32(1), e.Arg32(3)) })
	reg(u, "_wsopen", func(e *Emu) uint64 { return open(e, e.WStr(e.Arg(0)), e.Arg32(1), e.Arg32(3)) })
	reg(u, "_sopen_s", func(e *Emu) uint64 {
		r := open(e, e.CStr(e.Arg(1)), e.Arg32(2), e.Arg32(4))
		e.Mem.W32(e.Arg(0), uint32(r))
		if int32(r) < 0 {
			return uint64(e.Mem.R32(c(e).errnoAddr()))
		}
		return 0
	})
	reg(u, "_wsopen_s", func(e *Emu) uint64 {
		r := open(e, e.WStr(e.Arg(1)), e.Arg32(2), e.Arg32(4))
		e.Mem.W32(e.Arg(0), uint32(r))
		if int32(r) < 0 {
			return uint64(e.Mem.R32(c(e).errnoAddr()))
		}
		return 0
	})
	reg(u, "_sopen_dispatch", func(e *Emu) uint64 {
		r := open(e, e.CStr(e.Arg(0)), e.Arg32(1), e.Arg32(3))
		e.Mem.W32(e.Arg(4), uint32(r))
		if int32(r) < 0 {
			return uint64(e.Mem.R32(c(e).errnoAddr()))
		}
		return 0
	})
	reg(u, "_wsopen_dispatch", func(e *Emu) uint64 {
		r := open(e, e.WStr(e.Arg(0)), e.Arg32(1), e.Arg32(3))
		e.Mem.W32(e.Arg(4), uint32(r))
		if int32(r) < 0 {
			return uint64(e.Mem.R32(c(e).errnoAddr()))
		}
		return 0
	})
	reg(u, "_creat", func(e *Emu) uint64 { return open(e, e.CStr(e.Arg(0)), 0x301, e.Arg32(1)) })
	reg(u, "_close", func(e *Emu) uint64 {
		if !c(e).closeFd(int(e.ArgI(0))) {
			c(e).setErrno(ebadf)
			return ^uint64(0)
		}
		return 0
	})
	reg(u, "_read", func(e *Emu) uint64 {
		fd := int(e.ArgI(0))
		cc := c(e)
		ent := cc.fds[fd]
		if ent == nil {
			cc.setErrno(ebadf)
			return ^uint64(0)
		}
		if fd == 0 {
			cc.flushStd()
		}
		if _, fo := cc.fdObj(fd); fo != nil && e.blockOnEmptyPipe(fo) {
			return 0
		}
		b, err := cc.readFd(fd, int(e.Arg32(2)))
		if err != nil && err != io.EOF && len(b) == 0 {
			cc.setErrno(ebadf)
			return ^uint64(0)
		}
		if ent.text {
			b = []byte(strings.ReplaceAll(string(b), "\r\n", "\n"))
		}
		e.Mem.Write(e.Arg(1), b)
		return uint64(len(b))
	})
	reg(u, "_write", func(e *Emu) uint64 {
		fd := int(e.ArgI(0))
		cc := c(e)
		if cc.fds[fd] == nil {
			cc.setErrno(ebadf)
			return ^uint64(0)
		}
		if fd <= 2 {
			cc.flushStd()
		}
		n, err := cc.writeFd(fd, e.Mem.ReadBytes(e.Arg(1), int(e.Arg32(2))))
		if err != nil {
			cc.setErrno(errnoOf(err))
			return ^uint64(0)
		}
		return uint64(n)
	})
	lseek := func(e *Emu) uint64 {
		p, err := c(e).seekFd(int(e.ArgI(0)), int64(e.Arg(1)), int(e.Arg32(2)))
		if err != nil {
			c(e).setErrno(ebadf)
			return ^uint64(0)
		}
		return uint64(p)
	}
	reg(u, "_lseeki64", lseek)
	reg(u, "_lseek", func(e *Emu) uint64 {
		p, err := c(e).seekFd(int(e.ArgI(0)), e.ArgI(1), int(e.Arg32(2)))
		if err != nil {
			c(e).setErrno(ebadf)
			return ^uint64(0)
		}
		return uint64(uint32(p))
	})
	reg(u, "_tell", func(e *Emu) uint64 {
		p, _ := c(e).seekFd(int(e.ArgI(0)), 0, 1)
		return uint64(uint32(p))
	})
	reg(u, "_telli64", func(e *Emu) uint64 { p, _ := c(e).seekFd(int(e.ArgI(0)), 0, 1); return uint64(p) })
	reg(u, "_eof", func(e *Emu) uint64 {
		_, fo := c(e).fdObj(int(e.ArgI(0)))
		if fo == nil || fo.f == nil {
			return ^uint64(0)
		}
		pos, _ := fo.f.Seek(0, 1)
		st, err := fo.f.Stat()
		if err != nil {
			return ^uint64(0)
		}
		return b2u(pos >= st.Size())
	})
	reg(u, "_filelength", func(e *Emu) uint64 {
		_, fo := c(e).fdObj(int(e.ArgI(0)))
		if fo == nil || fo.f == nil {
			return ^uint64(0)
		}
		st, _ := fo.f.Stat()
		return uint64(uint32(st.Size()))
	})
	reg(u, "_filelengthi64", func(e *Emu) uint64 {
		_, fo := c(e).fdObj(int(e.ArgI(0)))
		if fo == nil || fo.f == nil {
			return ^uint64(0)
		}
		st, _ := fo.f.Stat()
		return uint64(st.Size())
	})
	reg(u, "_chsize", func(e *Emu) uint64 {
		_, fo := c(e).fdObj(int(e.ArgI(0)))
		if fo == nil || fo.f == nil || fo.f.Truncate(e.ArgI(1)) != nil {
			return ^uint64(0)
		}
		return 0
	})
	reg(u, "_chsize_s", func(e *Emu) uint64 {
		_, fo := c(e).fdObj(int(e.ArgI(0)))
		if fo == nil || fo.f == nil || fo.f.Truncate(int64(e.Arg(1))) != nil {
			return ebadf
		}
		return 0
	})
	reg(u, "_commit", func(e *Emu) uint64 {
		if _, fo := c(e).fdObj(int(e.ArgI(0))); fo != nil && fo.f != nil && fo.console == 0 {
			fo.f.Sync()
		}
		return 0
	})
	reg(u, "_isatty", func(e *Emu) uint64 {
		_, fo := c(e).fdObj(int(e.ArgI(0)))
		if fo != nil && fo.kind == fileChar {
			return 0x40
		}
		return 0
	})
	reg(u, "_setmode", func(e *Emu) uint64 {
		ent := c(e).fds[int(e.ArgI(0))]
		if ent == nil {
			c(e).setErrno(ebadf)
			return ^uint64(0)
		}
		old := uint64(0x4000)
		if !ent.text {
			old = 0x8000
		}
		mode := e.Arg32(1)
		ent.text = mode&0x8000 == 0
		for _, f := range c(e).files {
			if f.fd == int(e.ArgI(0)) {
				f.text = ent.text
			}
		}
		return old
	})
	reg(u, "_get_osfhandle", func(e *Emu) uint64 {
		fd := int(e.ArgI(0))
		ent := c(e).fds[fd]
		if ent == nil {
			c(e).setErrno(ebadf)
			return invalidHandle
		}
		if fd <= 2 {
			return e.stdHandle(fd)
		}
		return ent.h
	})
	reg(u, "_open_osfhandle", func(e *Emu) uint64 {
		return uint64(c(e).newFd(e.Arg(0), e.Arg32(1)&0x8000 == 0, e.Arg32(1)&8 != 0, ""))
	})
	reg(u, "_dup", func(e *Emu) uint64 {
		ent := c(e).fds[int(e.ArgI(0))]
		if ent == nil {
			c(e).setErrno(ebadf)
			return ^uint64(0)
		}
		o := e.handles.get(ent.h)
		if int(e.ArgI(0)) <= 2 {
			o = e.handles.get(e.stdHandle(int(e.ArgI(0))))
		}
		return uint64(c(e).newFd(e.handles.add(o), ent.text, ent.append, ent.path))
	})
	reg(u, "_dup2", func(e *Emu) uint64 {
		src, dst := int(e.ArgI(0)), int(e.ArgI(1))
		cc := c(e)
		ent := cc.fds[src]
		if ent == nil {
			cc.setErrno(ebadf)
			return ^uint64(0)
		}
		h := ent.h
		if src <= 2 {
			h = e.stdHandle(src)
		}
		nh := e.handles.add(e.handles.get(h))
		if old := cc.fds[dst]; old != nil && dst > 2 {
			e.handles.close(old.h)
		}
		cc.fds[dst] = &fdEntry{h: nh, text: ent.text, append: ent.append}
		if dst <= 2 {
			cc.flushStd()
			cc.stdH[dst] = nh
		}
		return 0
	})
	reg(u, "_pipe", func(e *Emu) uint64 {
		p := &pipeBuf{}
		r := e.handles.add(&fileObj{pipe: p, kind: filePipe})
		w := e.handles.add(&fileObj{pipe: p, pipeW: true, kind: filePipe})
		text := e.Arg32(2)&0x8000 == 0
		e.Mem.W32(e.Arg(0), uint32(c(e).newFd(r, text, false, "")))
		e.Mem.W32(e.Arg(0)+4, uint32(c(e).newFd(w, text, false, "")))
		return 0
	})
	reg(u, "_locking", retZero)
	reg(u, "_umask", ret(0o22))
	reg(u, "_umask_s", func(e *Emu) uint64 { e.Mem.W32(e.Arg(1), 0o22); return 0 })

	// ---- conio ----
	reg(u, "_getch", func(e *Emu) uint64 {
		c(e).flushStd()
		r, ok := e.con.getch()
		if !ok {
			return 0xFFFF
		}
		return uint64(r)
	})
	reg(u, "_getwch", func(e *Emu) uint64 {
		c(e).flushStd()
		r, ok := e.con.getch()
		if !ok {
			return 0xFFFF
		}
		return uint64(r)
	})
	reg(u, "_getche", func(e *Emu) uint64 {
		c(e).flushStd()
		r, ok := e.con.getch()
		if !ok {
			return 0xFFFF
		}
		c(e).writeStd(1, []byte(string(r)))
		return uint64(r)
	})
	reg(u, "_getch_nolock", func(e *Emu) uint64 {
		r, ok := e.con.getch()
		if !ok {
			return 0xFFFF
		}
		return uint64(r)
	})
	reg(u, "_ungetch", func(e *Emu) uint64 { e.con.pushback = append(e.con.pushback, rune(e.Arg32(0))); return e.Arg(0) })
	reg(u, "_kbhit", func(e *Emu) uint64 { c(e).flushStd(); return b2u(e.con.kbhit()) })
	reg(u, "_putch", func(e *Emu) uint64 {
		c(e).flushStd()
		c(e).writeStd(1, []byte{byte(e.Arg(0))})
		return e.Arg(0) & 0xFF
	})
	reg(u, "_putwch", func(e *Emu) uint64 {
		c(e).flushStd()
		c(e).writeStd(1, []byte(string(rune(e.Arg32(0)&0xFFFF))))
		return e.Arg(0) & 0xFFFF
	})
	reg(u, "_cputs", func(e *Emu) uint64 {
		c(e).flushStd()
		c(e).writeStd(1, e.Mem.CStrBytes(e.Arg(0)))
		return 0
	})
	reg(u, "_cputws", func(e *Emu) uint64 {
		c(e).flushStd()
		c(e).writeStd(1, []byte(e.WStr(e.Arg(0))))
		return 0
	})
	reg(dUcrt, "__conio_common_vcprintf", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(1), false), &vaList{e, e.Arg(3)}, e.ucrtFmtOpts(e.Arg(0), false))
		c(e).flushStd()
		c(e).writeStd(1, out.b)
		return uint64(len(out.b))
	})
	reg(dUcrt, "__conio_common_vcwprintf", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(1), true), &vaList{e, e.Arg(3)}, e.ucrtFmtOpts(e.Arg(0), true))
		c(e).flushStd()
		c(e).writeStd(1, []byte(string(utf16.Decode(out.u))))
		return uint64(len(out.u))
	})
	reg(dMsvc, "_cprintf", func(e *Emu) uint64 {
		out := e.sprintf(e.fmtFormat(e.Arg(0), false), &regArgs{e, 1}, msvcrtOpts)
		c(e).flushStd()
		c(e).writeStd(1, out.b)
		return uint64(len(out.b))
	})
	reg(u, "_cgets", func(e *Emu) uint64 { return 0 })
	reg(dUcrt, "__conio_common_vcscanf", func(e *Emu) uint64 { return ^uint64(0) })

	// ---- file system (CRT layer) ----
	statCall := func(e *Emu, name string, buf uint64, kind int) uint64 {
		cc := c(e)
		host := e.fs.toHost(name)
		st, err := os.Stat(host)
		if err != nil {
			cc.setErrno(errnoOf(err))
			return ^uint64(0)
		}
		e.writeStat(buf, st, kind, filepath.Base(host))
		return 0
	}
	// kinds: 0 = _stat64 (64/64), 1 = _stat64i32, 2 = _stat32, 3 = _stat32i64
	for name, kind := range map[string]int{"_stat64": 0, "_stat64i32": 1, "_stat32": 2, "_stat32i64": 3, "_stat": 1, "_stati64": 3} {
		k := kind
		reg(u, name, func(e *Emu) uint64 { return statCall(e, e.CStr(e.Arg(0)), e.Arg(1), k) })
		reg(u, "_w"+name[1:], func(e *Emu) uint64 { return statCall(e, e.WStr(e.Arg(0)), e.Arg(1), k) })
	}
	for name, kind := range map[string]int{"_fstat64": 0, "_fstat64i32": 1, "_fstat32": 2, "_fstat32i64": 3, "_fstat": 1, "_fstati64": 3} {
		k := kind
		reg(u, name, func(e *Emu) uint64 {
			_, fo := c(e).fdObj(int(e.ArgI(0)))
			if fo == nil {
				c(e).setErrno(ebadf)
				return ^uint64(0)
			}
			st, err := e.statObj(fo)
			if err != nil {
				c(e).setErrno(ebadf)
				return ^uint64(0)
			}
			e.writeStat(e.Arg(1), st, k, filepath.Base(fo.host))
			if fo.kind == fileChar {
				e.Mem.W16(e.Arg(1)+6, 0x2000|0o666)
			} else if fo.kind == filePipe {
				e.Mem.W16(e.Arg(1)+6, 0x1000|0o666)
			}
			return 0
		})
	}
	access := func(e *Emu, name string, mode uint32) uint64 {
		host := e.fs.toHost(name)
		st, err := os.Stat(host)
		if err != nil {
			c(e).setErrno(enoent)
			return ^uint64(0)
		}
		if mode&2 != 0 && st.Mode().Perm()&0o200 == 0 {
			c(e).setErrno(eacces)
			return ^uint64(0)
		}
		return 0
	}
	reg(u, "_access", func(e *Emu) uint64 { return access(e, e.CStr(e.Arg(0)), e.Arg32(1)) })
	reg(u, "_waccess", func(e *Emu) uint64 { return access(e, e.WStr(e.Arg(0)), e.Arg32(1)) })
	reg(u, "_access_s", func(e *Emu) uint64 {
		if int64(access(e, e.CStr(e.Arg(0)), e.Arg32(1))) < 0 {
			return uint64(e.Mem.R32(c(e).errnoAddr()))
		}
		return 0
	})
	reg(u, "_waccess_s", func(e *Emu) uint64 {
		if int64(access(e, e.WStr(e.Arg(0)), e.Arg32(1))) < 0 {
			return uint64(e.Mem.R32(c(e).errnoAddr()))
		}
		return 0
	})
	chmod := func(e *Emu, name string, mode uint32) uint64 {
		host := e.fs.toHost(name)
		st, err := os.Stat(host)
		if err != nil {
			c(e).setErrno(enoent)
			return ^uint64(0)
		}
		p := st.Mode().Perm()
		if mode&0x80 != 0 {
			p |= 0o200
		} else {
			p &^= 0o222
		}
		os.Chmod(host, p)
		return 0
	}
	reg(u, "_chmod", func(e *Emu) uint64 { return chmod(e, e.CStr(e.Arg(0)), e.Arg32(1)) })
	reg(u, "_wchmod", func(e *Emu) uint64 { return chmod(e, e.WStr(e.Arg(0)), e.Arg32(1)) })
	unlink := func(e *Emu, name string) uint64 {
		host := e.fs.toHost(name)
		st, err := os.Lstat(host)
		if err == nil && st.IsDir() {
			c(e).setErrno(eacces)
			return ^uint64(0)
		}
		if err := os.Remove(host); err != nil {
			c(e).setErrno(errnoOf(err))
			return ^uint64(0)
		}
		return 0
	}
	reg(u, "remove", func(e *Emu) uint64 { return unlink(e, e.CStr(e.Arg(0))) })
	reg(u, "_unlink", func(e *Emu) uint64 { return unlink(e, e.CStr(e.Arg(0))) })
	reg(u, "_wremove", func(e *Emu) uint64 { return unlink(e, e.WStr(e.Arg(0))) })
	reg(u, "_wunlink", func(e *Emu) uint64 { return unlink(e, e.WStr(e.Arg(0))) })
	rename := func(e *Emu, a, b string) uint64 {
		ha, hb := e.fs.toHost(a), e.fs.toHost(b)
		if _, err := os.Lstat(hb); err == nil {
			c(e).setErrno(eacces)
			return ^uint64(0)
		}
		if err := os.Rename(ha, hb); err != nil {
			c(e).setErrno(errnoOf(err))
			return ^uint64(0)
		}
		return 0
	}
	reg(u, "rename", func(e *Emu) uint64 { return rename(e, e.CStr(e.Arg(0)), e.CStr(e.Arg(1))) })
	reg(u, "_wrename", func(e *Emu) uint64 { return rename(e, e.WStr(e.Arg(0)), e.WStr(e.Arg(1))) })
	mkdir := func(e *Emu, name string) uint64 {
		if err := os.Mkdir(e.fs.toHost(name), 0o755); err != nil {
			c(e).setErrno(errnoOf(err))
			return ^uint64(0)
		}
		return 0
	}
	reg(u, "_mkdir", func(e *Emu) uint64 { return mkdir(e, e.CStr(e.Arg(0))) })
	reg(u, "_wmkdir", func(e *Emu) uint64 { return mkdir(e, e.WStr(e.Arg(0))) })
	rmdir := func(e *Emu, name string) uint64 {
		host := e.fs.toHost(name)
		st, err := os.Stat(host)
		if err != nil {
			c(e).setErrno(enoent)
			return ^uint64(0)
		}
		if !st.IsDir() {
			c(e).setErrno(enotdir)
			return ^uint64(0)
		}
		if err := os.Remove(host); err != nil {
			c(e).setErrno(errnoOf(err))
			return ^uint64(0)
		}
		return 0
	}
	reg(u, "_rmdir", func(e *Emu) uint64 { return rmdir(e, e.CStr(e.Arg(0))) })
	reg(u, "_wrmdir", func(e *Emu) uint64 { return rmdir(e, e.WStr(e.Arg(0))) })
	chdir := func(e *Emu, name string) uint64 {
		full := e.fs.full(name)
		st, err := os.Stat(e.fs.toHost(full))
		if err != nil || !st.IsDir() {
			c(e).setErrno(enoent)
			return ^uint64(0)
		}
		e.fs.cwd = strings.TrimSuffix(full, `\`)
		if len(e.fs.cwd) == 2 {
			e.fs.cwd += `\`
		}
		return 0
	}
	reg(u, "_chdir", func(e *Emu) uint64 { return chdir(e, e.CStr(e.Arg(0))) })
	reg(u, "_wchdir", func(e *Emu) uint64 { return chdir(e, e.WStr(e.Arg(0))) })
	getcwd := func(e *Emu, wide bool, buf uint64, n uint64) uint64 {
		s := e.fs.cwd
		if buf == 0 {
			if wide {
				return e.allocWStr(s)
			}
			return e.allocCStr(s)
		}
		ln := uint64(len(s))
		if wide {
			ln = uint64(len(utf16.Encode([]rune(s))))
		}
		if ln >= n {
			c(e).setErrno(erange)
			return 0
		}
		e.writeStrBuf(wide, buf, s)
		return buf
	}
	reg(u, "_getcwd", func(e *Emu) uint64 { return getcwd(e, false, e.Arg(0), uint64(e.Arg32(1))) })
	reg(u, "_wgetcwd", func(e *Emu) uint64 { return getcwd(e, true, e.Arg(0), uint64(e.Arg32(1))) })
	reg(u, "_getdcwd", func(e *Emu) uint64 { return getcwd(e, false, e.Arg(1), uint64(e.Arg32(2))) })
	reg(u, "_wgetdcwd", func(e *Emu) uint64 { return getcwd(e, true, e.Arg(1), uint64(e.Arg32(2))) })
	reg(u, "_getdrive", func(e *Emu) uint64 { return uint64(e.fs.cwd[0]-'A') + 1 })
	reg(u, "_chdrive", func(e *Emu) uint64 {
		d := e.Arg32(0)
		if d == 3 || d == 26 {
			e.fs.cwd = string(rune('A'+d-1)) + `:\`
			return 0
		}
		return ^uint64(0)
	})
	fullpath := func(e *Emu, wide bool) uint64 {
		var in string
		if wide {
			in = e.WStr(e.Arg(1))
		} else {
			in = e.CStr(e.Arg(1))
		}
		full := e.fs.full(in)
		buf := e.Arg(0)
		if buf == 0 {
			if wide {
				return e.allocWStr(full)
			}
			return e.allocCStr(full)
		}
		if uint64(len(full)) >= e.Arg(2) {
			c(e).setErrno(erange)
			return 0
		}
		e.writeStrBuf(wide, buf, full)
		return buf
	}
	reg(u, "_fullpath", func(e *Emu) uint64 { return fullpath(e, false) })
	reg(u, "_wfullpath", func(e *Emu) uint64 { return fullpath(e, true) })
	splitpath := func(e *Emu, wide bool, secure bool) uint64 {
		var p string
		if wide {
			p = e.WStr(e.Arg(0))
		} else {
			p = e.CStr(e.Arg(0))
		}
		drive, dir, fname, ext := splitPath(p)
		parts := []string{drive, dir, fname, ext}
		for i := 0; i < 4; i++ {
			var a uint64
			if secure {
				a = e.Arg(1 + 2*i)
			} else {
				a = e.Arg(1 + i)
			}
			if a != 0 {
				e.writeStrBuf(wide, a, parts[i])
			}
		}
		return 0
	}
	reg(u, "_splitpath", func(e *Emu) uint64 { return splitpath(e, false, false) })
	reg(u, "_wsplitpath", func(e *Emu) uint64 { return splitpath(e, true, false) })
	reg(u, "_splitpath_s", func(e *Emu) uint64 { return splitpath(e, false, true) })
	reg(u, "_wsplitpath_s", func(e *Emu) uint64 { return splitpath(e, true, true) })
	makepath := func(e *Emu, wide bool, off int) uint64 {
		get := func(i int) string {
			if wide {
				return e.WStr(e.Arg(off + i))
			}
			return e.CStr(e.Arg(off + i))
		}
		s := ""
		if d := get(0); d != "" {
			s += d[:1] + ":"
		}
		if d := get(1); d != "" {
			s += d
			if !strings.HasSuffix(d, `\`) && !strings.HasSuffix(d, "/") {
				s += `\`
			}
		}
		s += get(2)
		if x := get(3); x != "" {
			if !strings.HasPrefix(x, ".") {
				s += "."
			}
			s += x
		}
		e.writeStrBuf(wide, e.Arg(0), s)
		return 0
	}
	reg(u, "_makepath", func(e *Emu) uint64 { return makepath(e, false, 1) })
	reg(u, "_wmakepath", func(e *Emu) uint64 { return makepath(e, true, 1) })
	reg(u, "_makepath_s", func(e *Emu) uint64 { return makepath(e, false, 2) })
	reg(u, "_wmakepath_s", func(e *Emu) uint64 { return makepath(e, true, 2) })
	// _findfirst family
	find := func(e *Emu, pat string, buf uint64, wide bool, kind int) uint64 {
		fo, code := e.findFirst(pat)
		if fo == nil {
			c(e).setErrno(errnoFromWin(code))
			return ^uint64(0)
		}
		e.writeFinddata(buf, fo.entries[0], fo.names[0], wide, kind)
		fo.idx = 1
		h := e.heapAllocRaw(8)
		c(e).findHandles[h] = fo
		return h
	}
	next := func(e *Emu, h, buf uint64, wide bool, kind int) uint64 {
		fo := c(e).findHandles[h]
		if fo == nil || fo.idx >= len(fo.entries) {
			c(e).setErrno(enoent)
			return ^uint64(0)
		}
		e.writeFinddata(buf, fo.entries[fo.idx], fo.names[fo.idx], wide, kind)
		fo.idx++
		return 0
	}
	// kind: 0 = 64-bit time + 64-bit size, 1 = 64 time/32 size, 2 = 32/32, 3 = 32 time/64 size
	for name, kind := range map[string]int{"_findfirst64": 0, "_findfirst64i32": 1, "_findfirst32": 2, "_findfirst": 2, "_findfirsti64": 3, "_findfirst32i64": 3} {
		k := kind
		reg(u, name, func(e *Emu) uint64 { return find(e, e.CStr(e.Arg(0)), e.Arg(1), false, k) })
		reg(u, "_w"+name[1:], func(e *Emu) uint64 { return find(e, e.WStr(e.Arg(0)), e.Arg(1), true, k) })
		nn := strings.Replace(name, "first", "next", 1)
		reg(u, nn, func(e *Emu) uint64 { return next(e, e.Arg(0), e.Arg(1), false, k) })
		reg(u, "_w"+nn[1:], func(e *Emu) uint64 { return next(e, e.Arg(0), e.Arg(1), true, k) })
	}
	reg(u, "_findclose", func(e *Emu) uint64 {
		delete(c(e).findHandles, e.Arg(0))
		return 0
	})
	reg(u, "_searchenv", func(e *Emu) uint64 { e.Mem.W8(e.Arg(2), 0); return 0 })
	reg(u, "_utime64", func(e *Emu) uint64 { return utime(e, e.CStr(e.Arg(0)), e.Arg(1), true) })
	reg(u, "_wutime64", func(e *Emu) uint64 { return utime(e, e.WStr(e.Arg(0)), e.Arg(1), true) })
	reg(u, "_utime32", func(e *Emu) uint64 { return utime(e, e.CStr(e.Arg(0)), e.Arg(1), false) })
	reg(u, "_futime64", func(e *Emu) uint64 {
		_, fo := c(e).fdObj(int(e.ArgI(0)))
		if fo == nil || fo.host == "" {
			return ^uint64(0)
		}
		return utime(e, e.fs.toWin(fo.host), e.Arg(1), true)
	})
}

func utime(e *Emu, name string, tb uint64, t64 bool) uint64 {
	host := e.fs.toHost(name)
	at, mt := nowTime(), nowTime()
	if tb != 0 {
		if t64 {
			at, mt = unixTime(int64(e.Mem.R64(tb))), unixTime(int64(e.Mem.R64(tb+8)))
		} else {
			at, mt = unixTime(int64(int32(e.Mem.R32(tb)))), unixTime(int64(int32(e.Mem.R32(tb+4))))
		}
	}
	if err := os.Chtimes(host, at, mt); err != nil {
		e.crt.setErrno(errnoOf(err))
		return ^uint64(0)
	}
	return 0
}

func splitPath(p string) (drive, dir, fname, ext string) {
	if len(p) >= 2 && p[1] == ':' {
		drive, p = p[:2], p[2:]
	}
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		dir, p = p[:i+1], p[i+1:]
	}
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		fname, ext = p[:i], p[i:]
	} else {
		fname = p
	}
	return
}

func snprintfS(e *Emu, buf, size, count uint64, out *fmtOut) uint64 {
	n := uint64(out.n())
	if count == ^uint64(0) { // _TRUNCATE
		if n < size {
			return e.sprintfTo(buf, size, out, 1)
		}
		e.sprintfTo(buf, size, out, 1)
		return ^uint64(0)
	}
	lim := min(count, size-1)
	if n <= lim {
		return e.sprintfTo(buf, size, out, 1)
	}
	if count < size {
		// truncate at count
		if out.wide {
			e.Mem.WriteUnits(buf, append(append([]uint16{}, out.u[:count]...), 0))
		} else {
			e.Mem.Write(buf, append(append([]byte{}, out.b[:count]...), 0))
		}
		return ^uint64(0)
	}
	if size > 0 {
		e.Mem.W8(buf, 0)
	}
	e.crt.setErrno(erange)
	return ^uint64(0)
}

// writeStat fills struct _stat variants.
func (e *Emu) writeStat(a uint64, st os.FileInfo, kind int, name string) {
	m := e.Mem
	var mode uint16
	if st.IsDir() {
		mode = 0x4000 | 0o111
	} else {
		mode = 0x8000
	}
	mode |= 0o444
	if st.Mode().Perm()&0o200 != 0 {
		mode |= 0o222
	}
	if !st.IsDir() {
		ln := strings.ToLower(name)
		for _, x := range []string{".exe", ".bat", ".cmd", ".com"} {
			if strings.HasSuffix(ln, x) {
				mode |= 0o111
			}
		}
	}
	_, ac, wt := fileTimes(st)
	ctime := filetimeToUnix(ac).Unix()
	mtime := st.ModTime().Unix()
	atime := filetimeToUnix(ac).Unix()
	_ = wt
	ino, dev, nl := fileID(st)
	_ = ino
	size := st.Size()
	if st.IsDir() {
		size = 0
	}
	// common header: dev u32, ino u16, mode u16, nlink i16, uid i16, gid i16, pad, rdev u32
	m.W32(a, uint32(dev&0x1F))
	m.W16(a+4, 0)
	m.W16(a+6, mode)
	m.W16(a+8, uint16(nl))
	m.W16(a+10, 0)
	m.W16(a+12, 0)
	m.W16(a+14, 0)
	m.W32(a+16, uint32(dev&0x1F))
	switch kind {
	case 0: // _stat64: size i64 @24, atime @32, mtime @40, ctime @48 (size 56)
		m.W64(a+24, uint64(size))
		m.W64(a+32, uint64(atime))
		m.W64(a+40, uint64(mtime))
		m.W64(a+48, uint64(ctime))
	case 1: // _stat64i32: size i32 @20, pad, times @24 @32 @40 (size 48)
		m.W32(a+20, uint32(size))
		m.W64(a+24, uint64(atime))
		m.W64(a+32, uint64(mtime))
		m.W64(a+40, uint64(ctime))
	case 2: // _stat32: size i32 @20, times i32 @24 @28 @32 (size 36)
		m.W32(a+20, uint32(size))
		m.W32(a+24, uint32(atime))
		m.W32(a+28, uint32(mtime))
		m.W32(a+32, uint32(ctime))
	case 3: // _stat32i64: size i64 @24, times i32 @32 @36 @40 (size 48)
		m.W64(a+24, uint64(size))
		m.W32(a+32, uint32(atime))
		m.W32(a+36, uint32(mtime))
		m.W32(a+40, uint32(ctime))
	}
}

// writeFinddata fills _finddata*_t variants.
func (e *Emu) writeFinddata(a uint64, st os.FileInfo, name string, wide bool, kind int) {
	m := e.Mem
	attrs := fileAttrs(st, name)
	c, ac, w := fileTimes(st)
	ct, at, wt := filetimeToUnix(c).Unix(), filetimeToUnix(ac).Unix(), filetimeToUnix(w).Unix()
	size := st.Size()
	if st.IsDir() {
		size = 0
	}
	m.W32(a, attrs)
	var off uint64
	switch kind {
	case 0: // time64 x3 @8, size i64 @32, name @40
		m.W64(a+8, uint64(ct))
		m.W64(a+16, uint64(at))
		m.W64(a+24, uint64(wt))
		m.W64(a+32, uint64(size))
		off = 40
	case 1: // time64 x3 @8, size u32 @32, name @36
		m.W64(a+8, uint64(ct))
		m.W64(a+16, uint64(at))
		m.W64(a+24, uint64(wt))
		m.W32(a+32, uint32(size))
		off = 36
	case 2: // time32 x3 @4, size u32 @16, name @20
		m.W32(a+4, uint32(ct))
		m.W32(a+8, uint32(at))
		m.W32(a+12, uint32(wt))
		m.W32(a+16, uint32(size))
		off = 20
	case 3: // time32 x3 @4, pad, size i64 @16? (align 8) -> @16, name @24
		m.W32(a+4, uint32(ct))
		m.W32(a+8, uint32(at))
		m.W32(a+12, uint32(wt))
		m.W64(a+16, uint64(size))
		off = 24
	}
	if len(name) > 259 {
		name = name[:259]
	}
	e.writeStrBuf(wide, a+off, name)
}
