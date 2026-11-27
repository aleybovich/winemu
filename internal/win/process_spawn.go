package win

// In-process child processes: every Windows .exe started by a guest runs as
// another Emu of the same kernel on its own goroutine (docs/multiprocess.md).

import (
	"os"
	"slices"
)

const (
	stillActive    = 259
	statusDLLNotFd = 0xC0000135
)

// childSpec describes a process to create.
type childSpec struct {
	host    string // host path of the image
	cmdline string
	cwd     string // Windows path
	env     []string
	inherit bool     // bInheritHandles: copy inheritable handles with identical values
	handles []uint64 // with inherit: only these (PROC_THREAD_ATTRIBUTE_HANDLE_LIST); nil: all
	std     [3]any   // objects for the child's std handles (nil: the parent's)
}

var stdSlots = [3]uint64{stdInputHandle, stdOutputHandle, stdErrorHandle}

// newChildProcess prepares a child process without starting it (the start is
// startProcess - the support point for CREATE_SUSPENDED). It fails only for
// images that are not runnable PE executables; a child whose image or DLLs
// fail to load is created already exited with STATUS_DLL_NOT_FOUND.
func (e *Emu) newChildProcess(sp childSpec) (*Emu, error) {
	builtinCmd := e.isBuiltinCmd(sp.host) // cmd.go
	if _, _, err := parseExe(sp.host); err != nil && !builtinCmd {
		return nil, err
	}
	opt := e.Opt
	opt.CmdLine, opt.Cwd, opt.Env = sp.cmdline, sp.cwd, sp.env
	c := newEmu(opt, e.k, 0, e.proc.pid)
	if sp.inherit {
		// before anything else is allocated, so the values stay free
		for v, o := range e.handles.snapshotInheritable() {
			if sp.handles != nil && !slices.Contains(sp.handles, v) {
				continue
			}
			c.handles.set(v, o)
			c.handles.setInherit(v, true)
		}
	}
	var loadErr error
	if builtinCmd {
		loadErr = c.loadBuiltinCmd(sp.host)
	} else {
		loadErr = c.load(sp.host, nil)
	}
	for i, o := range sp.std {
		if o == nil {
			o = e.handles.get(e.stdHandle(i))
		}
		if o != nil {
			c.handles.set(stdSlots[i], o)
		}
	}
	if loadErr != nil {
		c.logf("%v", loadErr)
		c.proc.markStarted()
		c.endProcess(statusDLLNotFd)
	}
	return c, nil
}

// startProcess runs a prepared process on a new goroutine.
func (e *Emu) startProcess() {
	if !e.proc.markStarted() {
		return // already started, or ended before it was started
	}
	go func() {
		if _, err := e.runProcess(); err != nil {
			e.logf("%v", err)
		}
	}()
}

// processOf resolves a process handle (or the pseudo handle) to its process.
// Hook for cross-process APIs (WS-E1).
func (e *Emu) processOf(h uint64) *Process {
	if h == pseudoProcess {
		return e.proc
	}
	if o, ok := e.handles.get(h).(*processObj); ok {
		if o.p != nil {
			return o.p
		}
		return e.proc
	}
	return nil
}

func (e *Emu) createProcess(app, cmdline string, flags uint32, envp uint64, cwd string, si, pi uint64, wide, inherit bool, procSA, threadSA uint64, tok *tokenObj) uint64 {
	exe := app
	if exe == "" {
		exe = firstToken(cmdline)
	}
	if cmdline == "" {
		cmdline = quoteArg(app)
	}
	host := e.searchExe(exe)
	if host == "" {
		return e.fail(errFileNotFound)
	}
	if data, err := os.ReadFile(host); !e.isBuiltinCmd(host) && (err != nil || len(data) < 2 || data[0] != 'M' || data[1] != 'Z') {
		e.warnOnce("cp"+host, "CreateProcess: %s is not a Windows executable", host)
		return e.fail(193) // ERROR_BAD_EXE_FORMAT
	}
	env := e.env
	if envp != 0 {
		env = e.readEnvBlock(envp, wide || flags&0x400 != 0)
	}
	if cwd == "" {
		cwd = e.fs.cwd
	} else {
		cwd = e.fs.full(cwd)
	}
	sp := childSpec{host: host, cmdline: cmdline, cwd: cwd, env: env, inherit: inherit}
	if si != 0 && flags&0x80000 != 0 && e.Mem.R32(si) >= 112 { // EXTENDED_STARTUPINFO_PRESENT
		if hs, ok := e.attrHandles(e.Mem.R64(si + 104)); ok && inherit {
			if !e.checkHandleList(hs) {
				return e.fail(errInvalidParameter)
			}
			sp.handles = hs
		}
	}
	job, jerr := e.childJob(flags)
	if jerr != 0 {
		return e.fail(jerr)
	}
	if si != 0 && e.Mem.R32(si+60)&0x100 != 0 { // STARTF_USESTDHANDLES
		for i := range sp.std {
			o := e.handles.get(e.Mem.R64(si + 80 + 8*uint64(i)))
			if o == nil {
				o = &fileObj{nul: true, kind: fileChar, win: "NUL"}
			}
			sp.std[i] = o
		}
	}
	e.crt.flushAll()
	c, err := e.newChildProcess(sp)
	if err != nil {
		return e.fail(193)
	}
	if tok != nil {
		c.proc.tokenOnce.Do(func() { c.proc.token = tok })
	}
	e.joinJob(job, c.proc)
	suspended := flags&4 != 0 && len(c.threads) > 0 // CREATE_SUSPENDED
	if suspended {
		c.threads[0].suspend = 1
	}
	if pi != 0 {
		hp := e.handles.add(&processObj{p: c.proc})
		e.handles.setInherit(hp, e.saInherit(procSA))
		tid, ht := uint32(0), uint64(0)
		if len(c.threads) > 0 {
			tid = c.threads[0].ID
			ht = e.handles.add(&threadObj{t: c.threads[0]})
			e.handles.setInherit(ht, e.saInherit(threadSA))
		}
		e.Mem.W64(pi, hp)
		e.Mem.W64(pi+8, ht)
		e.Mem.W32(pi+16, c.proc.pid)
		e.Mem.W32(pi+20, tid)
	}
	if !suspended {
		c.startProcess() // else by ResumeThread (xproc.go)
	}
	return 1
}

// runChild starts host with the given std objects and waits for it on this
// goroutine (system/_popen semantics). It returns the child's process.
func (e *Emu) runChild(host, cmdline string, std [3]any) (*Process, error) {
	e.crt.flushAll()
	c, err := e.newChildProcess(childSpec{host: host, cmdline: cmdline, cwd: e.fs.cwd, env: e.env, std: std})
	if err != nil {
		return nil, err
	}
	e.inheritJob(c.proc)
	c.startProcess()
	return c.proc, nil
}

func init() {
	k := dK32
	regAW(k, "CreateProcess", func(e *Emu, w bool) uint64 {
		return e.createProcess(e.strArg(0, w), e.strArg(1, w), e.Arg32(5), e.Arg(6), e.strArg(7, w), e.Arg(8), e.Arg(9), w,
			e.Arg32(4) != 0, e.Arg(2), e.Arg(3), nil)
	})
	reg(k, "GetExitCodeProcess", func(e *Emu) uint64 {
		p := e.processOf(e.Arg(0))
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		code, done := p.exitStatus()
		if !done {
			code = stillActive
		}
		e.Mem.W32(e.Arg(1), code)
		return 1
	})
	reg(k, "TerminateProcess", func(e *Emu) uint64 {
		p := e.processOf(e.Arg(0))
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		if p == e.proc {
			e.crt.flushAll()
			e.exitProcess(e.Arg32(1))
		}
		if _, done := p.exitStatus(); done {
			return e.fail(errAccessDenied)
		}
		p.terminate(e.Arg32(1))
		return 1
	})
	reg(k, "GetProcessId", func(e *Emu) uint64 {
		p := e.processOf(e.Arg(0))
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		return uint64(p.pid)
	})
	reg(k, "OpenProcess", func(e *Emu) uint64 {
		pid := e.Arg32(2)
		p := e.proc
		if pid != p.pid {
			p = e.k.process(pid)
		}
		if p == nil || pid == 0 {
			return e.fail(errInvalidParameter)
		}
		h := e.handles.add(&processObj{p: p})
		e.handles.setInherit(h, e.Arg32(1) != 0)
		return h
	})
	reg(k, "CreatePipe", func(e *Emu) uint64 {
		p := newKernelPipe(e.k)
		inherit := e.saInherit(e.Arg(2))
		r := e.handles.add(&fileObj{pipe: p, kind: filePipe})
		w := e.handles.add(&fileObj{pipe: p, pipeW: true, kind: filePipe})
		e.handles.setInherit(r, inherit)
		e.handles.setInherit(w, inherit)
		e.Mem.W64(e.Arg(0), r)
		e.Mem.W64(e.Arg(1), w)
		return 1
	})
}
