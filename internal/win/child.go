package win

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// pipes with non-blocking guest semantics

// pipeIO performs a read or write on an OS pipe without blocking the whole
// emulator: it uses short deadlines and asks the scheduler to retry.
func (e *Emu) pipeIO(fo *fileObj, p []byte, write bool) (n int, err error, again bool) {
	dl := time.Now().Add(2 * time.Millisecond)
	if write {
		fo.f.SetWriteDeadline(dl)
		n, err = fo.f.Write(p)
	} else {
		fo.f.SetReadDeadline(dl)
		n, err = fo.f.Read(p)
	}
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		if n > 0 {
			return n, nil, false
		}
		return 0, nil, true
	}
	return n, err, false
}

func isOSPipe(fo *fileObj) bool {
	return fo != nil && fo.kind == filePipe && fo.f != nil && fo.console == 0
}

// ---------------------------------------------------------------------------
// locating executables

// createProcessExts: CreateProcess appends only .exe to a module name
// without extension.
var createProcessExts = []string{".exe"}

func (e *Emu) searchExe(name string) string {
	if strings.ContainsAny(name, `\/:`) {
		return e.findExe(name, nil, createProcessExts)
	}
	dirs := []string{e.fs.toWin(filepath.Dir(e.exeHost)), e.fs.cwd, `C:\windows\system32`, `C:\windows`}
	if p, ok := e.getEnv("PATH"); ok {
		dirs = append(dirs, strings.Split(p, ";")...)
	}
	return e.findExe(name, dirs, createProcessExts)
}

// winExt returns the extension of the last component of the Windows path p
// ("" if it has none); dots in directory names do not count.
func winExt(p string) string {
	_, _, _, ext := splitPath(p)
	return ext
}

// findExe returns the host path of name (each of exts tried in order when
// it has no extension, then name itself), as given if it has a path, else
// in the first of dirs that has it. The builtin cmd.exe resolves to its
// (virtual) image path.
func (e *Emu) findExe(name string, dirs, exts []string) string {
	try := func(p string) string {
		if strings.EqualFold(e.fs.full(p), builtinCmdPath) {
			return e.fs.toHost(builtinCmdPath)
		}
		h := e.fs.toHost(p)
		if st, err := os.Stat(h); err == nil && !st.IsDir() {
			return h
		}
		return ""
	}
	cands := []string{name}
	if winExt(name) == "" {
		cands = nil
		for _, x := range exts {
			cands = append(cands, name+x)
		}
		cands = append(cands, name)
	}
	if strings.ContainsAny(name, `\/:`) {
		for _, c := range cands {
			if h := try(c); h != "" {
				return h
			}
		}
		return ""
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		for _, c := range cands {
			if h := try(strings.TrimRight(d, `\`) + `\` + c); h != "" {
				return h
			}
		}
	}
	return ""
}

func firstToken(cmdline string) string {
	s := strings.TrimLeft(cmdline, " \t")
	if strings.HasPrefix(s, `"`) {
		if i := strings.IndexByte(s[1:], '"'); i >= 0 {
			return s[1 : i+1]
		}
		return s[1:]
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

func (e *Emu) readEnvBlock(p uint64, wide bool) []string {
	var env []string
	for {
		var s string
		if wide {
			s = e.Mem.WStr(p)
			p += uint64(2*len([]rune(s)) + 2) // approximate for BMP
			if strings.ContainsRune(s, 0xFFFD) {
				break
			}
		} else {
			b := e.Mem.CStrBytes(p)
			s = string(b)
			p += uint64(len(b) + 1)
		}
		if s == "" {
			break
		}
		env = append(env, s)
	}
	return env
}

// ---------------------------------------------------------------------------
// system()

// runSystem runs cmd through %COMSPEC% /c, blocking only the calling
// thread (the call is re-executed when the shell has exited).
func (e *Emu) runSystem(cmd string) uint64 {
	if code, ok := e.resumedChild(); ok {
		return uint64(code)
	}
	p, err := e.spawnShell(cmd, [3]any{})
	if err != nil {
		e.crt.setErrno(enoent)
		return ^uint64(0)
	}
	e.waitChild(p)
	return 0
}

func init() {
	u := dUcrt + "," + dMsvc
	reg(u, "system", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 1
		}
		return e.runSystem(e.CStr(e.Arg(0)))
	})
	reg(u, "_wsystem", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 1
		}
		return e.runSystem(e.WStr(e.Arg(0)))
	})
	popen := func(e *Emu, cmd, mode string) uint64 {
		pb := newKernelPipe(e.k)
		r, w := &fileObj{pipe: pb, kind: filePipe}, &fileObj{pipe: pb, pipeW: true, kind: filePipe}
		read := strings.HasPrefix(mode, "r")
		var std [3]any
		mine := w
		if read {
			std[1], mine = w, r
		} else {
			std[0] = r
		}
		cp, err := e.spawnShell(cmd, std)
		if err != nil {
			e.crt.setErrno(enoent)
			return 0
		}
		h := e.handles.add(mine)
		fd := e.crt.newFd(h, !strings.Contains(mode, "b"), false, "")
		p := e.crt.newStream(fd, read, !read, false, !strings.Contains(mode, "b"))
		e.crt.popen[p] = cp
		return p
	}
	reg(u, "_popen", func(e *Emu) uint64 { return popen(e, e.CStr(e.Arg(0)), e.CStr(e.Arg(1))) })
	reg(u, "_wpopen", func(e *Emu) uint64 { return popen(e, e.WStr(e.Arg(0)), e.WStr(e.Arg(1))) })
	reg(u, "_pclose", func(e *Emu) uint64 {
		if code, ok := e.resumedChild(); ok {
			return uint64(code)
		}
		p := e.Arg(0)
		cp := e.crt.popen[p]
		e.crt.fclose(p)
		if cp == nil {
			return ^uint64(0)
		}
		delete(e.crt.popen, p)
		e.waitChild(cp)
		return 0
	})
}

var _ = io.EOF
