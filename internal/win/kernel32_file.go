package win

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

const (
	genericRead    = 0x80000000
	genericWrite   = 0x40000000
	genericAll     = 0x10000000
	fileReadData   = 1
	fileWriteData  = 2
	fileAppendData = 4

	attrReadonly  = 0x1
	attrHidden    = 0x2
	attrDirectory = 0x10
	attrArchive   = 0x20
	attrNormal    = 0x80
	attrReparse   = 0x400
	invalidAttrs  = 0xFFFFFFFF
)

// ---------------------------------------------------------------------------
// file object helpers

func (e *Emu) fileObj(h uint64) *fileObj {
	switch h {
	case 0xFFFFFFF6: // STD_INPUT_HANDLE passed as a handle by mistake
		h = stdInputHandle
	case 0xFFFFFFF5:
		h = stdOutputHandle
	case 0xFFFFFFF4:
		h = stdErrorHandle
	}
	fo, _ := e.handles.get(h).(*fileObj)
	return fo
}

// fileRead reads from a file object, handling console and pipes.
func (e *Emu) fileRead(fo *fileObj, p []byte) (int, error) {
	switch {
	case fo.nul:
		return 0, io.EOF
	case fo.pipe != nil:
		for {
			n, eof := fo.pipe.read(p)
			switch {
			case n > 0 || len(p) == 0:
				return n, nil
			case eof:
				return 0, io.ErrClosedPipe
			case fo.pipe.k == nil:
				return 0, nil
			}
			// kernel pipe: the writer is another process (or thread); this
			// reader blocks like a host pipe read would
			e.hostWait(func() bool { n, closedW := fo.pipe.state(); return n > 0 || closedW })
		}
	case fo.console == 1:
		e.crt.flushStd()
		return e.con.readRaw(p)
	case fo.isDir:
		return 0, syscall.EISDIR
	}
	return fo.f.Read(p)
}

// blockOnEmptyPipe makes the calling thread wait while fo is a pipe with no
// data and an open write end; the API call is re-executed when the thread
// resumes, and the other threads of the process keep running meanwhile. It
// reports whether the caller must return now (its return value is unused).
func (e *Emu) blockOnEmptyPipe(fo *fileObj) bool {
	if fo.pipe != nil {
		ready := func() bool { n, closedW := fo.pipe.state(); return n > 0 || closedW }
		if !ready() {
			e.block(ready, infinite)
			return true
		}
	}
	e.endWaitIf()
	return false
}

func (e *Emu) fileWrite(fo *fileObj, p []byte) (int, error) {
	switch {
	case fo.nul:
		return len(p), nil
	case fo.pipe != nil:
		if !fo.pipe.write(p) {
			return 0, io.ErrClosedPipe
		}
		return len(p), nil
	case fo.console == 2:
		return e.con.write(fo, p)
	case fo.console == 1:
		return 0, syscall.EBADF
	}
	if fo.append {
		fo.f.Seek(0, io.SeekEnd)
	}
	return fo.f.Write(p)
}

func fileAttrs(st os.FileInfo, name string) uint32 {
	var a uint32
	if st.IsDir() {
		a |= attrDirectory
	} else {
		a |= attrArchive
	}
	if st.Mode()&0o200 == 0 {
		a |= attrReadonly
	}
	if st.Mode()&os.ModeSymlink != 0 {
		a |= attrReparse
	}
	if strings.HasPrefix(name, ".") && name != "." && name != ".." {
		a |= attrHidden
	}
	return a
}

func fileTimes(st os.FileInfo) (create, access, write uint64) {
	w := unixToFiletime(st.ModTime())
	a, c := w, w
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		at, ct := statTimes(s)
		a, c = unixToFiletime(at), unixToFiletime(ct)
	}
	return c, a, w
}

func fileID(st os.FileInfo) (uint64, uint64, uint32) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Ino), uint64(s.Dev), uint32(s.Nlink)
	}
	return 0, 0, 1
}

// ---------------------------------------------------------------------------
// CreateFile

func (e *Emu) createFile(name string, access, disp, flags uint32) uint64 {
	if key, ok := npKey(name); ok { // named pipe client (namedpipe.go)
		return e.openPipeClient(key, access, flags)
	}
	if dev := deviceName(name); dev != "" {
		switch dev {
		case "NUL":
			return e.handles.add(&fileObj{nul: true, kind: fileChar, win: "NUL"})
		case "CONIN$":
			fo := *e.fileObj(stdInputHandle)
			fo.refs = 0
			return e.handles.add(&fo)
		case "CONOUT$", "CON":
			fo := *e.fileObj(stdOutputHandle)
			fo.refs = 0
			if dev == "CON" && access&genericWrite == 0 {
				fo = *e.fileObj(stdInputHandle)
				fo.refs = 0
			}
			return e.handles.add(&fo)
		}
		return e.fail(errFileNotFound)
	}
	if name == "" {
		return e.failH(errPathNotFound)
	}
	host := e.fs.toHost(name)
	st, statErr := os.Stat(host)
	exists := statErr == nil
	if exists && st.IsDir() {
		if flags&0x02000000 == 0 && access&(genericWrite|fileWriteData|fileAppendData) != 0 {
			return e.failH(errAccessDenied)
		}
		if flags&0x02000000 == 0 && access&(genericRead|fileReadData) != 0 {
			return e.failH(errAccessDenied)
		}
		f, err := os.Open(host)
		if err != nil {
			return e.failH(winErr(err))
		}
		return e.handles.add(&fileObj{f: f, host: host, win: e.fs.full(name), kind: fileDisk, isDir: true, access: access})
	}
	write := access&(genericWrite|genericAll|fileWriteData|fileAppendData|0x40000) != 0
	read := access&(genericRead|genericAll|fileReadData) != 0
	of := 0
	switch {
	case read && write:
		of = os.O_RDWR
	case write:
		of = os.O_WRONLY
	default:
		of = os.O_RDONLY
	}
	var lastErr uint32
	switch disp {
	case 1: // CREATE_NEW
		if exists {
			return e.failH(errFileExists)
		}
		of |= os.O_CREATE | os.O_EXCL
	case 2: // CREATE_ALWAYS
		of |= os.O_CREATE | os.O_TRUNC
		if exists {
			lastErr = errAlreadyExists
		}
	case 3: // OPEN_EXISTING
		if !exists {
			if _, err := os.Stat(filepath.Dir(host)); err != nil {
				return e.failH(errPathNotFound)
			}
			return e.failH(errFileNotFound)
		}
	case 4: // OPEN_ALWAYS
		of |= os.O_CREATE
		if exists {
			lastErr = errAlreadyExists
		}
	case 5: // TRUNCATE_EXISTING
		if !exists {
			return e.failH(errFileNotFound)
		}
		of |= os.O_TRUNC
	default:
		return e.failH(errInvalidParameter)
	}
	if of&os.O_CREATE != 0 && of&(os.O_WRONLY|os.O_RDWR) == 0 {
		of |= os.O_RDWR
	}
	perm := os.FileMode(0o644)
	if flags&attrReadonly != 0 {
		perm = 0o444
	}
	f, err := os.OpenFile(host, of, perm)
	if err != nil && of&(os.O_WRONLY|os.O_RDWR) == 0 && !read {
		// metadata-only open of an unreadable file
		f, err = os.Open(host)
	}
	if err != nil {
		code := winErr(err)
		if code == errFileNotFound {
			if _, e2 := os.Stat(filepath.Dir(host)); e2 != nil {
				code = errPathNotFound
			}
		}
		return e.failH(code)
	}
	fo := &fileObj{f: f, host: host, win: e.fs.full(name), kind: fileDisk, access: access,
		append:   access&fileAppendData != 0 && access&(fileWriteData|genericWrite) == 0,
		delClose: flags&0x04000000 != 0}
	e.SetLastError(lastErr)
	return e.handles.add(fo)
}

// failH sets last error and returns INVALID_HANDLE_VALUE.
func (e *Emu) failH(code uint32) uint64 {
	e.SetLastError(code)
	return invalidHandle
}

// ---------------------------------------------------------------------------
// find files

type findObj struct {
	dir     string
	entries []os.FileInfo
	names   []string
	idx     int
}

func wildMatch(pat, name string) bool {
	if pat == "*" || pat == "*.*" {
		return true
	}
	p := []rune(strings.ToLower(pat))
	s := []rune(strings.ToLower(name))
	var match func(i, j int) bool
	match = func(i, j int) bool {
		for i < len(p) {
			switch p[i] {
			case '*', '<':
				for k := j; k <= len(s); k++ {
					if match(i+1, k) {
						return true
					}
				}
				return false
			case '?', '>':
				if j >= len(s) {
					// '?' may match end of name before a dot in DOS semantics
					i++
					continue
				}
				i++
				j++
			case '"':
				if j < len(s) && s[j] == '.' {
					j++
				}
				i++
			default:
				if j >= len(s) || s[j] != p[i] {
					return false
				}
				i++
				j++
			}
		}
		return j == len(s)
	}
	if match(0, 0) {
		return true
	}
	// "*." matches names without extension
	if strings.HasSuffix(pat, ".") && !strings.Contains(name, ".") {
		return match(0, 0) || wildMatch(strings.TrimSuffix(pat, "."), name)
	}
	return false
}

func (e *Emu) findFirst(pattern string) (*findObj, uint32) {
	full := e.fs.full(pattern)
	i := strings.LastIndexByte(full, '\\')
	dirWin, pat := full[:i], full[i+1:]
	if len(dirWin) == 2 {
		dirWin += `\`
	}
	host := e.fs.toHost(dirWin)
	if pat == "" {
		return nil, errFileNotFound
	}
	if !strings.ContainsAny(pat, "*?<>\"") {
		// exact name
		p := e.fs.toHost(full)
		st, err := os.Lstat(p)
		if err != nil {
			return nil, winErr(err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			if st2, err := os.Stat(p); err == nil {
				st = st2
			}
		}
		return &findObj{dir: host, entries: []os.FileInfo{st}, names: []string{filepath.Base(p)}}, 0
	}
	ents, err := os.ReadDir(host)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errPathNotFound
		}
		return nil, winErr(err)
	}
	fo := &findObj{dir: host}
	isRoot := len(dirWin) <= 3
	if !isRoot {
		if st, err := os.Stat(host); err == nil {
			for _, n := range []string{".", ".."} {
				if wildMatch(pat, n) {
					fo.entries = append(fo.entries, st)
					fo.names = append(fo.names, n)
				}
			}
		}
	}
	sort.Slice(ents, func(a, b int) bool { return strings.ToLower(ents[a].Name()) < strings.ToLower(ents[b].Name()) })
	for _, en := range ents {
		if !wildMatch(pat, en.Name()) {
			continue
		}
		st, err := en.Info()
		if err != nil {
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 {
			if st2, err := os.Stat(filepath.Join(host, en.Name())); err == nil {
				st = st2
			}
		}
		fo.entries = append(fo.entries, st)
		fo.names = append(fo.names, en.Name())
	}
	if len(fo.entries) == 0 {
		return nil, errFileNotFound
	}
	return fo, 0
}

func (e *Emu) writeFindData(a uint64, st os.FileInfo, name string, wide bool) {
	m := e.Mem
	size := uint64(592)
	if !wide {
		size = 320
	}
	m.Fill(a, 0, size)
	m.W32(a, fileAttrs(st, name))
	c, ac, w := fileTimes(st)
	m.W64(a+4, c)
	m.W64(a+12, ac)
	m.W64(a+20, w)
	sz := uint64(st.Size())
	if st.IsDir() {
		sz = 0
	}
	m.W32(a+28, uint32(sz>>32))
	m.W32(a+32, uint32(sz))
	if wide {
		u := utf16.Encode([]rune(name))
		if len(u) > 259 {
			u = u[:259]
		}
		m.WriteUnits(a+44, append(u, 0))
	} else {
		if len(name) > 259 {
			name = name[:259]
		}
		m.WriteCStr(a+44, name)
	}
}

func init() {
	k := dK32
	regAW(k, "CreateFile", func(e *Emu, w bool) uint64 {
		h := e.createFile(e.strArg(0, w), e.Arg32(1), e.Arg32(4), e.Arg32(5))
		if h != invalidHandle {
			e.handles.setInherit(h, e.saInherit(e.Arg(3)))
		}
		return h
	})
	reg(k, "CreateFile2", func(e *Emu) uint64 {
		var flags uint32
		var sa uint64
		if p := e.Arg(4); p != 0 {
			flags = e.Mem.R32(p+4) | e.Mem.R32(p+8)
			sa = e.Mem.R64(p + 16) // lpSecurityAttributes
		}
		h := e.createFile(e.WStr(e.Arg(0)), e.Arg32(1), e.Arg32(3), flags)
		if h != invalidHandle {
			e.handles.setInherit(h, e.saInherit(sa))
		}
		return h
	})
	reg(k, "CloseHandle", func(e *Emu) uint64 {
		h := e.Arg(0)
		if h == pseudoProcess || h == pseudoThread {
			return 1
		}
		if !e.handles.close(h) {
			return e.fail(errInvalidHandle)
		}
		return 1
	})
	reg(k, "GetStdHandle", func(e *Emu) uint64 {
		switch e.Arg32(0) {
		case 0xFFFFFFF6:
			return e.stdHandle(0)
		case 0xFFFFFFF5:
			return e.stdHandle(1)
		case 0xFFFFFFF4:
			return e.stdHandle(2)
		}
		return e.failH(errInvalidHandle)
	})
	reg(k, "SetStdHandle", func(e *Emu) uint64 {
		h := e.Arg(1)
		switch e.Arg32(0) {
		case 0xFFFFFFF6:
			e.crt.stdH[0] = h
		case 0xFFFFFFF5:
			e.crt.stdH[1] = h
		case 0xFFFFFFF4:
			e.crt.stdH[2] = h
		default:
			return e.fail(errInvalidHandle)
		}
		return 1
	})
	reg(k, "SetStdHandleEx", func(e *Emu) uint64 { return 1 })
	reg(k, "GetFileType", func(e *Emu) uint64 {
		if e.npEndOf(e.Arg(0)) != nil {
			return filePipe
		}
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			if _, ok := e.handles.get(e.Arg(0)).(*processObj); ok {
				return 0
			}
			e.SetLastError(errInvalidHandle)
			return 0
		}
		if fo.nul {
			return fileChar
		}
		if fo.pipe != nil {
			return filePipe
		}
		e.SetLastError(0)
		return uint64(fo.kind)
	})
	reg(k, "ReadFile", func(e *Emu) uint64 {
		if x := e.npEndOf(e.Arg(0)); x != nil {
			return e.npRead(x, e.Arg(1), e.Arg32(2), e.Arg(3), e.Arg(4))
		}
		fo := e.fileObj(e.Arg(0))
		buf, n, nread := e.Arg(1), e.Arg32(2), e.Arg(3)
		if nread != 0 {
			e.Mem.W32(nread, 0)
		}
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		if ov := e.Arg(4); ov != 0 && fo.f != nil && fo.console == 0 {
			off := int64(e.Mem.R32(ov+16)) | int64(e.Mem.R32(ov+20))<<32
			fo.f.Seek(off, io.SeekStart)
		}
		if e.blockOnEmptyPipe(fo) {
			return 0
		}
		tmp := make([]byte, n)
		var got int
		var err error
		if isOSPipe(fo) {
			var again bool
			got, err, again = e.pipeIO(fo, tmp, false)
			if again {
				e.block(func() bool { return true }, 1)
				return 0
			}
			if err == io.EOF {
				return e.fail(errBrokenPipe)
			}
		} else {
			got, err = e.fileRead(fo, tmp)
		}
		if got > 0 {
			e.Mem.Write(buf, tmp[:got])
		}
		if nread != 0 {
			e.Mem.W32(nread, uint32(got))
		}
		if ov := e.Arg(4); ov != 0 {
			e.Mem.W64(ov+8, uint64(got))
			e.Mem.W64(ov, 0)
		}
		if err != nil && err != io.EOF {
			if err == io.ErrClosedPipe {
				return e.fail(errBrokenPipe)
			}
			if got == 0 {
				return e.fail(winErr(err))
			}
		}
		return 1
	})
	reg(k, "WriteFile", func(e *Emu) uint64 {
		if x := e.npEndOf(e.Arg(0)); x != nil {
			return e.npWrite(x, e.Arg(1), e.Arg32(2), e.Arg(3), e.Arg(4))
		}
		fo := e.fileObj(e.Arg(0))
		buf, n, nw := e.Arg(1), e.Arg32(2), e.Arg(3)
		if nw != 0 {
			e.Mem.W32(nw, 0)
		}
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		if fo.console == 2 {
			e.crt.flushStd()
		}
		if ov := e.Arg(4); ov != 0 && fo.f != nil && fo.console == 0 {
			off := int64(e.Mem.R32(ov+16)) | int64(e.Mem.R32(ov+20))<<32
			if uint32(off) != 0xFFFFFFFF {
				fo.f.Seek(off, io.SeekStart)
			}
		}
		data := e.Mem.ReadBytes(buf, int(n))
		var got int
		var err error
		if isOSPipe(fo) {
			if e.inWait() {
				e.endWait()
			}
			var again bool
			got, err, again = e.pipeIO(fo, data, true)
			if again {
				e.block(func() bool { return true }, 1)
				return 0
			}
		} else {
			got, err = e.fileWrite(fo, data)
		}
		if nw != 0 {
			e.Mem.W32(nw, uint32(got))
		}
		if ov := e.Arg(4); ov != 0 {
			e.Mem.W64(ov+8, uint64(got))
			e.Mem.W64(ov, 0)
		}
		if err != nil {
			if err == io.ErrClosedPipe {
				return e.fail(errBrokenPipe)
			}
			return e.fail(winErr(err))
		}
		return 1
	})
	reg(k, "FlushFileBuffers", func(e *Emu) uint64 {
		if x := e.npEndOf(e.Arg(0)); x != nil {
			return e.npFlush(x)
		}
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		if fo.f != nil && fo.console == 0 {
			fo.f.Sync()
		}
		return 1
	})
	reg(k, "GetFileSize", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.f == nil {
			e.SetLastError(errInvalidHandle)
			return 0xFFFFFFFF
		}
		st, err := fo.f.Stat()
		if err != nil {
			return 0xFFFFFFFF
		}
		if e.Arg(1) != 0 {
			e.Mem.W32(e.Arg(1), uint32(uint64(st.Size())>>32))
		}
		e.SetLastError(0)
		return uint64(uint32(st.Size()))
	})
	reg(k, "GetFileSizeEx", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.f == nil {
			return e.fail(errInvalidHandle)
		}
		st, err := fo.f.Stat()
		if err != nil {
			return e.fail(winErr(err))
		}
		e.Mem.W64(e.Arg(1), uint64(st.Size()))
		return 1
	})
	reg(k, "SetFilePointer", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.f == nil {
			e.SetLastError(errInvalidHandle)
			return 0xFFFFFFFF
		}
		off := int64(int32(e.Arg32(1)))
		if hp := e.Arg(2); hp != 0 {
			off = int64(uint64(e.Arg32(1)) | uint64(e.Mem.R32(hp))<<32)
		}
		if fo.console != 0 {
			return 0
		}
		pos, err := fo.f.Seek(off, int(e.Arg32(3)))
		if err != nil {
			e.SetLastError(131)
			return 0xFFFFFFFF
		}
		if hp := e.Arg(2); hp != 0 {
			e.Mem.W32(hp, uint32(uint64(pos)>>32))
		}
		e.SetLastError(0)
		return uint64(uint32(pos))
	})
	reg(k, "SetFilePointerEx", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.f == nil {
			return e.fail(errInvalidHandle)
		}
		if fo.console != 0 {
			if e.Arg(2) != 0 {
				e.Mem.W64(e.Arg(2), 0)
			}
			return 1
		}
		pos, err := fo.f.Seek(int64(e.Arg(1)), int(e.Arg32(3)))
		if err != nil {
			return e.fail(131)
		}
		if e.Arg(2) != 0 {
			e.Mem.W64(e.Arg(2), uint64(pos))
		}
		return 1
	})
	reg(k, "SetEndOfFile", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.f == nil {
			return e.fail(errInvalidHandle)
		}
		pos, _ := fo.f.Seek(0, io.SeekCurrent)
		if err := fo.f.Truncate(pos); err != nil {
			return e.fail(winErr(err))
		}
		return 1
	})
	reg(k, "SetFileValidData", retTrue)
	reg(k, "LockFile", retTrue)
	reg(k, "LockFileEx", retTrue)
	reg(k, "UnlockFile", retTrue)
	reg(k, "UnlockFileEx", retTrue)
	reg(k, "GetFileTime", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.f == nil {
			return e.fail(errInvalidHandle)
		}
		st, err := fo.f.Stat()
		if err != nil {
			return e.fail(winErr(err))
		}
		c, a, w := fileTimes(st)
		for i, v := range []uint64{c, a, w} {
			if p := e.Arg(i + 1); p != 0 {
				e.Mem.W64(p, v)
			}
		}
		return 1
	})
	reg(k, "SetFileTime", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.host == "" {
			return e.fail(errInvalidHandle)
		}
		st, err := os.Stat(fo.host)
		if err != nil {
			return e.fail(winErr(err))
		}
		at, mt := st.ModTime(), st.ModTime()
		if p := e.Arg(2); p != 0 && e.Mem.R64(p) != 0 && e.Mem.R64(p) != ^uint64(0) {
			at = filetimeToUnix(e.Mem.R64(p))
		}
		if p := e.Arg(3); p != 0 && e.Mem.R64(p) != 0 && e.Mem.R64(p) != ^uint64(0) {
			mt = filetimeToUnix(e.Mem.R64(p))
		}
		os.Chtimes(fo.host, at, mt)
		return 1
	})
	reg(k, "GetFileInformationByHandle", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		st, err := e.statObj(fo)
		if err != nil {
			return e.fail(winErr(err))
		}
		a := e.Arg(1)
		m := e.Mem
		m.Fill(a, 0, 52)
		m.W32(a, fileAttrs(st, filepath.Base(fo.host)))
		c, ac, w := fileTimes(st)
		m.W64(a+4, c)
		m.W64(a+12, ac)
		m.W64(a+20, w)
		ino, dev, nl := fileID(st)
		m.W32(a+28, uint32(dev))
		m.W32(a+32, uint32(uint64(st.Size())>>32))
		m.W32(a+36, uint32(st.Size()))
		m.W32(a+40, nl)
		m.W32(a+44, uint32(ino>>32))
		m.W32(a+48, uint32(ino))
		return 1
	})
	reg(k, "GetFileInformationByHandleEx", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		class, a, n := e.Arg32(1), e.Arg(2), e.Arg32(3)
		st, err := e.statObj(fo)
		if err != nil {
			return e.fail(winErr(err))
		}
		m := e.Mem
		switch class {
		case 0: // FileBasicInfo
			c, ac, w := fileTimes(st)
			m.W64(a, c)
			m.W64(a+8, ac)
			m.W64(a+16, w)
			m.W64(a+24, w)
			m.W32(a+32, fileAttrs(st, filepath.Base(fo.host)))
			m.W32(a+36, 0)
		case 1: // FileStandardInfo
			sz := uint64(st.Size())
			if st.IsDir() {
				sz = 0
			}
			_, _, nl := fileID(st)
			m.W64(a, (sz+4095)&^4095)
			m.W64(a+8, sz)
			m.W32(a+16, nl)
			m.W8(a+20, 0)
			m.W8(a+21, uint8(b2u(st.IsDir())))
			m.W16(a+22, 0)
		case 2: // FileNameInfo
			name := fo.win
			if len(name) >= 2 && name[1] == ':' {
				name = name[2:]
			}
			u := utf16.Encode([]rune(name))
			m.W32(a, uint32(2*len(u)))
			if uint32(4+2*len(u)) > n {
				return e.fail(errMoreData)
			}
			m.WriteUnits(a+4, u)
		case 9: // FileAttributeTagInfo
			m.W32(a, fileAttrs(st, filepath.Base(fo.host)))
			m.W32(a+4, 0)
		case 18: // FileIdInfo
			ino, dev, _ := fileID(st)
			m.W64(a, dev)
			m.W64(a+8, ino)
			m.W64(a+16, 0)
		case 10, 11, 14, 15: // FileId/Full DirectoryInfo (+Restart)
			if !fo.isDir {
				return e.fail(errInvalidParameter)
			}
			if class == 11 || class == 15 {
				fo.dirPos = 0
			}
			if _, ok := e.fillDirInfo(fo, a, n, class <= 11, false); !ok {
				if fo.dirPos >= len(e.dirListing(fo)) {
					return e.fail(errNoMoreFiles)
				}
				return e.fail(errMoreData)
			}
		case 16: // FileStorageInfo
			m.Fill(a, 0, uint64(n))
			for i := uint64(0); i < 4; i++ {
				m.W32(a+4*i, 4096)
			}
		default:
			return e.fail(errInvalidParameter)
		}
		return 1
	})
	reg(k, "SetFileInformationByHandle", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		class, a := e.Arg32(1), e.Arg(2)
		m := e.Mem
		switch class {
		case 0: // basic info: times + attributes
			if w := m.R64(a + 16); w != 0 && w != ^uint64(0) && fo.host != "" {
				t := filetimeToUnix(w)
				os.Chtimes(fo.host, t, t)
			}
			if at := m.R32(a + 32); at != 0 && fo.host != "" {
				e.setAttrs(fo.host, at)
			}
		case 4, 21: // FileDispositionInfo(Ex)
			if m.R8(a)&1 != 0 {
				fo.delClose = true
			} else {
				fo.delClose = false
			}
		case 6, 5: // FileEndOfFileInfo / FileAllocationInfo
			if class == 6 && fo.f != nil {
				if err := fo.f.Truncate(int64(m.R64(a))); err != nil {
					return e.fail(winErr(err))
				}
			}
		case 3, 22: // FileRenameInfo(Ex)
			replace := m.R8(a) != 0
			if class == 22 {
				replace = m.R32(a)&1 != 0
			}
			nlen := m.R32(a + 16)
			name := m.WStrN(a+20, int(nlen/2))
			dst := e.fs.toHost(name)
			if !replace {
				if _, err := os.Stat(dst); err == nil {
					return e.fail(errAlreadyExists)
				}
			}
			if err := os.Rename(fo.host, dst); err != nil {
				return e.fail(winErr(err))
			}
			fo.host = dst
			fo.win = e.fs.full(name)
		default:
			return e.fail(errInvalidParameter)
		}
		return 1
	})
	regAW(k, "GetFinalPathNameByHandle", func(e *Emu, w bool) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil || fo.host == "" {
			return e.fail(errInvalidHandle)
		}
		p := e.fs.toWin(fo.host)
		if e.Arg32(3)&0xF == 0 {
			p = `\\?\` + p
		}
		return e.putStr(w, e.Arg(1), e.Arg32(2), p)
	})
	regAW(k, "GetFileAttributes", func(e *Emu, w bool) uint64 {
		name := e.strArg(0, w)
		if deviceName(name) != "" {
			return attrArchive
		}
		h := e.fs.toHost(name)
		st, err := os.Stat(h)
		if err != nil {
			e.SetLastError(winErrPath(err, h))
			return invalidAttrs
		}
		return uint64(fileAttrs(st, filepath.Base(h)))
	})
	regAW(k, "GetFileAttributesEx", func(e *Emu, w bool) uint64 {
		h := e.fs.toHost(e.strArg(0, w))
		st, err := os.Stat(h)
		if err != nil {
			return e.fail(winErrPath(err, h))
		}
		a := e.Arg(2)
		m := e.Mem
		m.W32(a, fileAttrs(st, filepath.Base(h)))
		c, ac, wt := fileTimes(st)
		m.W64(a+4, c)
		m.W64(a+12, ac)
		m.W64(a+20, wt)
		sz := uint64(st.Size())
		if st.IsDir() {
			sz = 0
		}
		m.W32(a+28, uint32(sz>>32))
		m.W32(a+32, uint32(sz))
		return 1
	})
	regAW(k, "SetFileAttributes", func(e *Emu, w bool) uint64 {
		h := e.fs.toHost(e.strArg(0, w))
		if _, err := os.Stat(h); err != nil {
			return e.fail(winErrPath(err, h))
		}
		e.setAttrs(h, e.Arg32(1))
		return 1
	})
	regAW(k, "DeleteFile", func(e *Emu, w bool) uint64 {
		h := e.fs.toHost(e.strArg(0, w))
		st, err := os.Lstat(h)
		if err != nil {
			return e.fail(winErrPath(err, h))
		}
		if st.IsDir() {
			return e.fail(errAccessDenied)
		}
		if err := os.Remove(h); err != nil {
			return e.fail(winErr(err))
		}
		return 1
	})
	regAW(k, "CreateDirectory", func(e *Emu, w bool) uint64 {
		h := e.fs.toHost(e.strArg(0, w))
		if err := os.Mkdir(h, 0o755); err != nil {
			if os.IsExist(err) {
				return e.fail(errAlreadyExists)
			}
			return e.fail(winErrPath(err, h))
		}
		return 1
	})
	regAW(k, "CreateDirectoryEx", func(e *Emu, w bool) uint64 {
		h := e.fs.toHost(e.strArg(1, w))
		if err := os.Mkdir(h, 0o755); err != nil {
			if os.IsExist(err) {
				return e.fail(errAlreadyExists)
			}
			return e.fail(winErrPath(err, h))
		}
		return 1
	})
	regAW(k, "RemoveDirectory", func(e *Emu, w bool) uint64 {
		h := e.fs.toHost(e.strArg(0, w))
		st, err := os.Lstat(h)
		if err != nil {
			return e.fail(winErrPath(err, h))
		}
		if !st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			return e.fail(267) // ERROR_DIRECTORY
		}
		if err := syscall.Rmdir(h); err != nil {
			if st.Mode()&os.ModeSymlink != 0 {
				os.Remove(h)
				return 1
			}
			return e.fail(winErr(err))
		}
		return 1
	})
	moveFile := func(e *Emu, src, dst string, flags uint32) uint64 {
		hs, hd := e.fs.toHost(src), e.fs.toHost(dst)
		if _, err := os.Lstat(hs); err != nil {
			return e.fail(winErrPath(err, hs))
		}
		if dst == "" {
			if flags&4 != 0 { // DELAY_UNTIL_REBOOT with NULL dst
				return 1
			}
			return e.fail(errInvalidParameter)
		}
		if _, err := os.Lstat(hd); err == nil && flags&1 == 0 && !strings.EqualFold(hs, hd) {
			return e.fail(errAlreadyExists)
		}
		if err := os.Rename(hs, hd); err != nil {
			if flags&2 != 0 { // COPY_ALLOWED
				if err2 := copyFile(hs, hd); err2 == nil {
					os.Remove(hs)
					return 1
				}
			}
			return e.fail(winErr(err))
		}
		return 1
	}
	regAW(k, "MoveFile", func(e *Emu, w bool) uint64 { return moveFile(e, e.strArg(0, w), e.strArg(1, w), 2) })
	regAW(k, "MoveFileEx", func(e *Emu, w bool) uint64 { return moveFile(e, e.strArg(0, w), e.strArg(1, w), e.Arg32(2)) })
	regAW(k, "MoveFileWithProgress", func(e *Emu, w bool) uint64 { return moveFile(e, e.strArg(0, w), e.strArg(1, w), e.Arg32(4)) })
	regAW(k, "ReplaceFile", func(e *Emu, w bool) uint64 { return moveFile(e, e.strArg(1, w), e.strArg(0, w), 1) })
	regAW(k, "CopyFile", func(e *Emu, w bool) uint64 {
		hs, hd := e.fs.toHost(e.strArg(0, w)), e.fs.toHost(e.strArg(1, w))
		if _, err := os.Stat(hd); err == nil && e.Arg32(2) != 0 {
			return e.fail(errFileExists)
		}
		if err := copyFile(hs, hd); err != nil {
			return e.fail(winErrPath(err, hs))
		}
		return 1
	})
	regAW(k, "CopyFileEx", func(e *Emu, w bool) uint64 {
		hs, hd := e.fs.toHost(e.strArg(0, w)), e.fs.toHost(e.strArg(1, w))
		if _, err := os.Stat(hd); err == nil && e.Arg32(5)&1 != 0 {
			return e.fail(errFileExists)
		}
		if err := copyFile(hs, hd); err != nil {
			return e.fail(winErrPath(err, hs))
		}
		return 1
	})
	reg(k, "CopyFile2", func(e *Emu) uint64 {
		hs, hd := e.fs.toHost(e.WStr(e.Arg(0))), e.fs.toHost(e.WStr(e.Arg(1)))
		if err := copyFile(hs, hd); err != nil {
			return 0x80070000 | uint64(winErrPath(err, hs))
		}
		return 0
	})
	regAW(k, "CreateHardLink", func(e *Emu, w bool) uint64 {
		if err := os.Link(e.fs.toHost(e.strArg(1, w)), e.fs.toHost(e.strArg(0, w))); err != nil {
			return e.fail(winErr(err))
		}
		return 1
	})
	regAW(k, "CreateSymbolicLink", func(e *Emu, w bool) uint64 {
		target := e.strArg(1, w)
		t := strings.ReplaceAll(target, `\`, "/")
		if len(target) > 1 && target[1] == ':' || strings.HasPrefix(target, `\`) {
			t = e.fs.toHost(target)
		}
		if err := os.Symlink(t, e.fs.toHost(e.strArg(0, w))); err != nil {
			return e.fail(winErr(err))
		}
		return 1
	})
	regAW(k, "FindFirstFile", func(e *Emu, w bool) uint64 {
		fo, code := e.findFirst(e.strArg(0, w))
		if fo == nil {
			return e.failH(code)
		}
		e.writeFindData(e.Arg(1), fo.entries[0], fo.names[0], w)
		fo.idx = 1
		return e.handles.add(fo)
	})
	regAW(k, "FindFirstFileEx", func(e *Emu, w bool) uint64 {
		fo, code := e.findFirst(e.strArg(0, w))
		if fo == nil {
			return e.failH(code)
		}
		if e.Arg32(3) == 1 { // FindExSearchLimitToDirectories: advisory only
		}
		e.writeFindData(e.Arg(2), fo.entries[0], fo.names[0], w)
		fo.idx = 1
		return e.handles.add(fo)
	})
	regAW(k, "FindNextFile", func(e *Emu, w bool) uint64 {
		fo, ok := e.handles.get(e.Arg(0)).(*findObj)
		if !ok {
			return e.fail(errInvalidHandle)
		}
		if fo.idx >= len(fo.entries) {
			return e.fail(errNoMoreFiles)
		}
		e.writeFindData(e.Arg(1), fo.entries[fo.idx], fo.names[fo.idx], w)
		fo.idx++
		return 1
	})
	reg(k, "FindClose", func(e *Emu) uint64 { e.handles.close(e.Arg(0)); return 1 })
	regAW(k, "GetCurrentDirectory", func(e *Emu, w bool) uint64 {
		return e.putStr(w, e.Arg(1), e.Arg32(0), e.fs.cwd)
	})
	regAW(k, "SetCurrentDirectory", func(e *Emu, w bool) uint64 {
		full := e.fs.full(e.strArg(0, w))
		h := e.fs.toHost(full)
		st, err := os.Stat(h)
		if err != nil {
			return e.fail(winErrPath(err, h))
		}
		if !st.IsDir() {
			return e.fail(267)
		}
		e.fs.cwd = strings.TrimSuffix(full, `\`)
		if len(e.fs.cwd) == 2 {
			e.fs.cwd += `\`
		}
		return 1
	})
	regAW(k, "GetFullPathName", func(e *Emu, w bool) uint64 {
		in := e.strArg(0, w)
		full := e.fs.full(in)
		if (strings.HasSuffix(in, `\`) || strings.HasSuffix(in, "/")) && !strings.HasSuffix(full, `\`) {
			full += `\`
		}
		r := e.putStr(w, e.Arg(2), e.Arg32(1), full)
		if fp := e.Arg(3); fp != 0 && r < uint64(e.Arg32(1)) {
			i := strings.LastIndexByte(full, '\\')
			off := uint64(len(utf16.Encode([]rune(full[:i+1]))))
			if !w {
				off = uint64(i + 1)
			}
			if i == len(full)-1 {
				e.Mem.W64(fp, 0)
			} else if w {
				e.Mem.W64(fp, e.Arg(2)+2*off)
			} else {
				e.Mem.W64(fp, e.Arg(2)+off)
			}
		}
		return r
	})
	regAW(k, "GetLongPathName", func(e *Emu, w bool) uint64 {
		s := e.strArg(0, w)
		h := e.fs.toHost(s)
		if _, err := os.Stat(h); err != nil {
			return e.fail(winErrPath(err, h))
		}
		return e.putStr(w, e.Arg(1), e.Arg32(2), s)
	})
	regAW(k, "GetShortPathName", func(e *Emu, w bool) uint64 {
		return e.putStr(w, e.Arg(1), e.Arg32(2), e.strArg(0, w))
	})
	regAW(k, "GetTempPath", func(e *Emu, w bool) uint64 {
		return e.putStr(w, e.Arg(1), e.Arg32(0), e.fs.tempDir())
	})
	regAW(k, "GetTempPath2", func(e *Emu, w bool) uint64 {
		return e.putStr(w, e.Arg(1), e.Arg32(0), e.fs.tempDir())
	})
	regAW(k, "GetTempFileName", func(e *Emu, w bool) uint64 {
		dir, prefix, unique := e.strArg(0, w), e.strArg(1, w), e.Arg32(2)
		if len(prefix) > 3 {
			prefix = prefix[:3]
		}
		dir = strings.TrimRight(dir, `\/`)
		for i := uint32(0); i < 0xFFFF; i++ {
			u := unique
			if u == 0 {
				u = (uint32(time.Now().UnixNano()) + i) & 0xFFFF
				if u == 0 {
					u = 1
				}
			}
			name := dir + `\` + prefix + strings.ToUpper(hex16(u)) + ".tmp"
			h := e.fs.toHost(name)
			if unique != 0 {
				e.writeStrBuf(w, e.Arg(3), name)
				return uint64(u)
			}
			f, err := os.OpenFile(h, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
			if err == nil {
				f.Close()
				e.writeStrBuf(w, e.Arg(3), name)
				return uint64(u)
			}
			if !os.IsExist(err) {
				return e.fail(winErrPath(err, h))
			}
		}
		return e.fail(errFileExists)
	})
	regAW(k, "SearchPath", func(e *Emu, w bool) uint64 {
		name := e.strArg(1, w)
		ext := e.strArg(2, w)
		dirs := []string{}
		if e.Arg(0) != 0 {
			dirs = strings.Split(e.strArg(0, w), ";")
		} else {
			dirs = []string{e.fs.toWin(filepath.Dir(e.exeHost)), e.fs.cwd, `C:\windows\system32`, `C:\windows`}
		}
		cands := []string{name}
		if ext != "" && winExt(name) == "" {
			cands = append([]string{name + ext}, cands...)
		}
		// a fully qualified name or one relative to the current directory
		// (".\", "..\") is not searched for
		if strings.ContainsRune(name, ':') || strings.HasPrefix(name, `\`) || strings.HasPrefix(name, "/") ||
			strings.HasPrefix(name, `.\`) || strings.HasPrefix(name, `..\`) || strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../") {
			dirs = []string{""}
		}
		for _, d := range dirs {
			for _, c := range cands {
				p := e.fs.full(c)
				if d != "" {
					p = e.fs.full(d + `\` + c)
				}
				if _, err := os.Stat(e.fs.toHost(p)); err == nil {
					return e.putStr(w, e.Arg(4), e.Arg32(3), p)
				}
			}
		}
		return e.fail(errFileNotFound)
	})
	regAW(k, "GetDriveType", func(e *Emu, w bool) uint64 {
		root := strings.ToUpper(e.strArg(0, w))
		if root == "" || strings.HasPrefix(root, "C:") || strings.HasPrefix(root, "Z:") {
			return 3 // DRIVE_FIXED
		}
		return 1 // DRIVE_NO_ROOT_DIR
	})
	reg(k, "GetLogicalDrives", ret(1<<2|1<<25))
	regAW(k, "GetLogicalDriveStrings", func(e *Emu, w bool) uint64 {
		parts := []string{`C:\`, `Z:\`}
		need := 0
		for _, p := range parts {
			need += len(p) + 1
		}
		need++
		if e.Arg32(0) < uint32(need) {
			return uint64(need)
		}
		a := e.Arg(1)
		for _, p := range parts {
			if w {
				n := e.Mem.WriteWStr(a, p)
				a += uint64(2*n + 2)
			} else {
				e.Mem.WriteCStr(a, p)
				a += uint64(len(p) + 1)
			}
		}
		if w {
			e.Mem.W16(a, 0)
		} else {
			e.Mem.W8(a, 0)
		}
		return uint64(need - 1)
	})
	regAW(k, "GetDiskFreeSpaceEx", func(e *Emu, w bool) uint64 {
		free, total := diskFree(e.fs.hostCwd())
		for i, v := range []uint64{free, total, free} {
			if p := e.Arg(i + 1); p != 0 {
				e.Mem.W64(p, v)
			}
		}
		return 1
	})
	regAW(k, "GetDiskFreeSpace", func(e *Emu, w bool) uint64 {
		free, total := diskFree(e.fs.hostCwd())
		vals := []uint32{8, 512, uint32(free / 4096), uint32(total / 4096)}
		for i, v := range vals {
			if p := e.Arg(i + 1); p != 0 {
				e.Mem.W32(p, v)
			}
		}
		return 1
	})
	regAW(k, "GetVolumeInformation", func(e *Emu, w bool) uint64 {
		if e.Arg(1) != 0 {
			e.putStr(w, e.Arg(1), e.Arg32(2), "WINEMU")
		}
		if e.Arg(3) != 0 {
			e.Mem.W32(e.Arg(3), 0x12345678)
		}
		if e.Arg(4) != 0 {
			e.Mem.W32(e.Arg(4), 255)
		}
		if e.Arg(5) != 0 {
			e.Mem.W32(e.Arg(5), 0x3|0x2|0x40000)
		}
		if e.Arg(6) != 0 {
			e.putStr(w, e.Arg(6), e.Arg32(7), "NTFS")
		}
		return 1
	})
	reg(k, "GetVolumeInformationByHandleW", func(e *Emu) uint64 {
		if e.Arg(1) != 0 {
			e.putStrW(e.Arg(1), e.Arg32(2), "WINEMU")
		}
		if e.Arg(3) != 0 {
			e.Mem.W32(e.Arg(3), 0x12345678)
		}
		if e.Arg(4) != 0 {
			e.Mem.W32(e.Arg(4), 255)
		}
		if e.Arg(5) != 0 {
			e.Mem.W32(e.Arg(5), 0x3|0x2|0x40000)
		}
		if e.Arg(6) != 0 {
			e.putStrW(e.Arg(6), e.Arg32(7), "NTFS")
		}
		return 1
	})
	regAW(k, "GetVolumePathName", func(e *Emu, w bool) uint64 {
		full := e.fs.full(e.strArg(0, w))
		e.putStr(w, e.Arg(1), e.Arg32(2), full[:3])
		return 1
	})
	reg(k, "AreFileApisANSI", retTrue)
	reg(k, "SetFileApisToANSI", retZero)
	reg(k, "SetFileApisToOEM", retZero)
	reg(k, "DeviceIoControl", func(e *Emu) uint64 { return e.fail(errNotSupported) })
	reg(k, "GetBinaryTypeW", func(e *Emu) uint64 { e.Mem.W32(e.Arg(1), 6); return 1 })
	reg(k, "Wow64DisableWow64FsRedirection", retTrue)
	reg(k, "Wow64RevertWow64FsRedirection", retTrue)
	reg(k, "ReadDirectoryChangesW", func(e *Emu) uint64 { return e.fail(errNotSupported) })
	reg(k, "FindFirstChangeNotificationW", func(e *Emu) uint64 { return e.failH(errNotSupported) })

	// ---- handles ----
	reg(k, "GetHandleInformation", func(e *Emu) uint64 {
		if e.handles.get(e.Arg(0)) == nil {
			return e.fail(errInvalidHandle)
		}
		e.Mem.W32(e.Arg(1), uint32(b2u(e.handles.inheritable(e.Arg(0))))) // HANDLE_FLAG_INHERIT
		return 1
	})
	reg(k, "SetHandleInformation", func(e *Emu) uint64 {
		h, mask, flags := e.Arg(0), e.Arg32(1), e.Arg32(2)
		if e.handles.get(h) == nil {
			return e.fail(errInvalidHandle)
		}
		if mask&1 != 0 {
			e.handles.setInherit(h, flags&1 != 0)
		}
		return 1
	})
	reg(k, "CompareObjectHandles", func(e *Emu) uint64 {
		return b2u(e.handles.get(e.Arg(0)) == e.handles.get(e.Arg(1)))
	})
	reg(k, "PeekNamedPipe", func(e *Emu) uint64 {
		if x := e.npEndOf(e.Arg(0)); x != nil {
			return e.npPeek(x, e.Arg(1), e.Arg32(2), e.Arg(3), e.Arg(4), e.Arg(5))
		}
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			return e.fail(errInvalidHandle)
		}
		avail := uint32(0)
		if isOSPipe(fo) {
			if inputReady(fo.f) {
				avail = 1
			}
		} else if fo.pipe != nil {
			n, _ := fo.pipe.state()
			avail = uint32(n)
		} else if fo.console == 1 && e.con.kbhit() {
			avail = 1
		}
		if e.Arg(4) != 0 {
			e.Mem.W32(e.Arg(4), avail)
		}
		if e.Arg(3) != 0 {
			e.Mem.W32(e.Arg(3), 0)
		}
		return 1
	})

	// ---- file mapping ----
	// file mappings: xproc_section.go
}

func (e *Emu) writeStrBuf(w bool, a uint64, s string) {
	if w {
		e.Mem.WriteWStr(a, s)
	} else {
		e.Mem.WriteCStr(a, s)
	}
}

func hex16(v uint32) string {
	const d = "0123456789abcdef"
	return string([]byte{d[v>>12&15], d[v>>8&15], d[v>>4&15], d[v&15]})
}

func (e *Emu) stdHandle(i int) uint64 {
	if e.crt.stdH[i] != 0 {
		return e.crt.stdH[i]
	}
	return []uint64{stdInputHandle, stdOutputHandle, stdErrorHandle}[i]
}

func (e *Emu) statObj(fo *fileObj) (os.FileInfo, error) {
	if fo.f != nil {
		if fo.console != 0 {
			return fo.f.Stat()
		}
		return fo.f.Stat()
	}
	if fo.nul || fo.pipe != nil {
		return nulInfo{}, nil
	}
	return nil, syscall.EBADF
}

type nulInfo struct{}

func (nulInfo) Name() string       { return "NUL" }
func (nulInfo) Size() int64        { return 0 }
func (nulInfo) Mode() fs.FileMode  { return fs.ModeCharDevice }
func (nulInfo) ModTime() time.Time { return time.Now() }
func (nulInfo) IsDir() bool        { return false }
func (nulInfo) Sys() any           { return nil }

func (e *Emu) setAttrs(host string, a uint32) {
	st, err := os.Stat(host)
	if err != nil {
		return
	}
	mode := st.Mode().Perm()
	if a&attrReadonly != 0 {
		mode &^= 0o222
	} else {
		mode |= 0o200
	}
	os.Chmod(host, mode)
}

// winErrPath distinguishes file-not-found and path-not-found.
func winErrPath(err error, host string) uint32 {
	c := winErr(err)
	if c == errFileNotFound {
		if _, e2 := os.Stat(filepath.Dir(host)); e2 != nil {
			return errPathNotFound
		}
	}
	return c
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	os.Chtimes(dst, st.ModTime(), st.ModTime())
	return out.Close()
}
