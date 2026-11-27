package win

// Cross-process access (WS-E1): the handshake that lets one process touch
// another's private state (memory, thread suspend counts), cross-process
// thread suspension, DuplicateHandle between processes, and the
// STARTUPINFOEX attribute list. See docs/multiprocess.md.
//
// Handshake: a process's goroutine holds xp.runMu whenever it runs (from
// runProcess, or the outermost schedule for harness processes) and releases
// it while it idles (idleSleep) and at every slice boundary when another
// goroutine has asked for it (pausePoint). Another process takes runMu
// (withProcess) to read or change the target's private state: the target
// is then stopped at a scheduler boundary, or not started, or gone. The
// requester releases its own runMu while it waits, so two processes
// operating on each other cannot deadlock.

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type xprocState struct {
	runMu    sync.Mutex   // held by the process's goroutine while it runs
	pauseReq atomic.Int32 // goroutines of other processes waiting for runMu
	held     bool         // the owner holds runMu (touched only by the owner)
	job      *jobObj      // job membership, guarded by Kernel.mu (job.go)
}

func (e *Emu) lockRun() {
	x := &e.proc.xp
	x.runMu.Lock()
	x.held = true
}

func (e *Emu) unlockRun() {
	x := &e.proc.xp
	x.held = false
	x.runMu.Unlock()
}

// pausePoint lets waiting processes in between two slices.
func (e *Emu) pausePoint() {
	x := &e.proc.xp
	if !x.held || x.pauseReq.Load() == 0 {
		return
	}
	x.runMu.Unlock()
	for x.pauseReq.Load() != 0 {
		time.Sleep(50 * time.Microsecond)
	}
	x.runMu.Lock()
}

// releaseRun releases the caller's runMu, if it holds it, around a blocking
// wait (idle sleep, host read, another process's lock); the returned func
// re-acquires it. held is cleared meanwhile, so nested users see the truth.
func (e *Emu) releaseRun() (relock func()) {
	if !e.proc.xp.held {
		return func() {}
	}
	e.unlockRun()
	return e.lockRun
}

// idleSleep is the scheduler's idle sleep; other processes may touch this
// one meanwhile.
func (e *Emu) idleSleep(g0 uint64, d time.Duration) {
	defer e.releaseRun()()
	e.k.sleep(g0, d, e.idleTimer)
}

// withProcess runs fn with p's process stopped (fn gets p's Emu). fn must
// touch only p's state, not the caller's.
func (e *Emu) withProcess(p *Process, fn func(c *Emu)) {
	if p == e.proc {
		fn(e)
		return
	}
	defer e.releaseRun()()
	p.lockFromOutside()
	defer p.unlockFromOutside()
	fn(p.emu)
}

func (p *Process) lockFromOutside() {
	p.xp.pauseReq.Add(1)
	p.xp.runMu.Lock()
}

func (p *Process) unlockFromOutside() {
	p.xp.runMu.Unlock()
	p.xp.pauseReq.Add(-1)
}

func (p *Process) isStarted() bool {
	p.k.mu.Lock()
	defer p.k.mu.Unlock()
	return p.started
}

// terminate ends p with code: a running process is asked to exit, one that
// was never started (CREATE_SUSPENDED) is ended right here.
func (p *Process) terminate(code uint32) {
	if !p.isStarted() {
		p.lockFromOutside()
		ended := false
		if !p.isStarted() {
			if _, done := p.exitStatus(); !done {
				p.emu.endProcess(code)
			}
			ended = true
		}
		p.unlockFromOutside()
		if ended {
			return
		}
	}
	p.requestKill(code)
}

const errSignalRefcountExceeded = 156

// resumeThread decrements t's suspend count and starts its process if it
// was created suspended. It returns the previous count.
func (e *Emu) resumeThread(t *Thread) int {
	prev := 0
	e.withProcess(t.emu.proc, func(c *Emu) {
		prev = t.suspend
		if t.suspend > 0 {
			t.suspend--
		}
		if prev == 1 {
			// under the target's run lock: ordered against terminate, which
			// ends an unstarted process under the same lock
			c.startProcess()
		}
	})
	e.k.notify()
	return prev
}

func (e *Emu) suspendThread(t *Thread) (int, bool) {
	prev, ok := 0, true
	e.withProcess(t.emu.proc, func(*Emu) {
		prev = t.suspend
		if prev >= 127 { // MAXIMUM_SUSPEND_COUNT
			ok = false
			return
		}
		t.suspend++
	})
	if ok && t == e.Cur {
		e.yield()
	}
	return prev, ok
}

// dupSource resolves hSource in process sp (pseudo handles relative to sp).
func (e *Emu) dupSource(sp *Process, h uint64) any {
	switch h {
	case pseudoProcess:
		return &processObj{p: sp}
	case pseudoThread:
		if sp == e.proc {
			return &threadObj{t: e.Cur}
		}
		return nil
	}
	o := sp.emu.handles.get(h)
	if po, ok := o.(*processObj); ok && po.p == nil {
		o = &processObj{p: sp} // "self" handle: the source process
	}
	return o
}

// Attribute list (opaque to the caller): u32 capacity, u32 count, then
// {attribute, value pointer, size} entries of 3 qwords.
const (
	attrParentProcess = 0x20000
	attrHandleList    = 0x20002
	errGenFailure     = 31
	errPartialCopy    = 299
)

func attrListSize(n uint64) uint64 { return 8 + 24*n }

// attrHandles returns the PROC_THREAD_ATTRIBUTE_HANDLE_LIST of an attribute
// list (nil, false if absent).
func (e *Emu) attrHandles(list uint64) ([]uint64, bool) {
	if list == 0 {
		return nil, false
	}
	n := uint64(e.Mem.R32(list + 4))
	for i := range n {
		ent := list + 8 + 24*i
		if e.Mem.R64(ent) != attrHandleList {
			continue
		}
		v, size := e.Mem.R64(ent+8), e.Mem.R64(ent+16)
		hs := make([]uint64, 0, size/8)
		for j := uint64(0); j < size/8; j++ {
			hs = append(hs, e.Mem.R64(v+8*j))
		}
		return hs, true
	}
	return nil, false
}

// checkHandleList validates a handle list for inheritance: every entry must
// be an inheritable handle of this process.
func (e *Emu) checkHandleList(hs []uint64) bool {
	return !slices.ContainsFunc(hs, func(h uint64) bool { return !e.handles.inheritable(h) })
}

func init() {
	k := dK32
	reg(k, "ResumeThread", func(e *Emu) uint64 {
		t := e.anyThreadOf(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle) | 0xFFFFFFFF
		}
		return uint64(e.resumeThread(t))
	})
	reg(k, "SuspendThread", func(e *Emu) uint64 {
		t := e.anyThreadOf(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle) | 0xFFFFFFFF
		}
		prev, ok := e.suspendThread(t)
		if !ok {
			return e.fail(errSignalRefcountExceeded) | 0xFFFFFFFF
		}
		return uint64(prev)
	})
	reg(k, "DuplicateHandle", func(e *Emu) uint64 {
		src, out, inherit, opts := e.Arg(1), e.Arg(3), e.Arg32(5) != 0, e.Arg32(6)
		sp := e.processOf(e.Arg(0))
		if sp == nil {
			return e.fail(errInvalidHandle)
		}
		o := e.dupSource(sp, src)
		closeSrc := func() {
			if opts&1 != 0 && src != pseudoProcess && src != pseudoThread { // DUPLICATE_CLOSE_SOURCE
				sp.emu.handles.close(src)
			}
		}
		if o == nil {
			closeSrc() // closed even if the duplication fails
			return e.fail(errInvalidHandle)
		}
		tp := e.processOf(e.Arg(2))
		if tp == nil && (out != 0 || opts&1 == 0) {
			closeSrc()
			return e.fail(errInvalidHandle)
		}
		if out != 0 {
			// insert before closing the source, so the object stays alive
			h := tp.emu.handles.add(o)
			tp.emu.handles.setInherit(h, inherit)
			e.Mem.W64(out, h)
		}
		closeSrc()
		return 1
	})

	reg(k, "InitializeProcThreadAttributeList", func(e *Emu) uint64 {
		list, n, flags, psize := e.Arg(0), e.Arg(1)&0xFFFFFFFF, e.Arg32(2), e.Arg(3)
		if flags != 0 || psize == 0 {
			return e.fail(errInvalidParameter)
		}
		need := attrListSize(n)
		if list == 0 || e.Mem.R64(psize) < need {
			e.Mem.W64(psize, need)
			return e.fail(errInsufficientBuf)
		}
		e.Mem.Fill(list, 0, need)
		e.Mem.W32(list, uint32(n))
		e.Mem.W64(psize, need)
		return 1
	})
	reg(k, "UpdateProcThreadAttribute", func(e *Emu) uint64 {
		list, flags, attr, val, size := e.Arg(0), e.Arg32(1), e.Arg(2), e.Arg(3), e.Arg(4)
		if list == 0 || flags&^1 != 0 { // PROC_THREAD_ATTRIBUTE_REPLACE_VALUE
			return e.fail(errInvalidParameter)
		}
		switch attr {
		case attrHandleList:
			if size == 0 || size%8 != 0 {
				return e.fail(errBadLength)
			}
		case attrParentProcess:
			if size != 8 {
				return e.fail(errBadLength)
			}
		}
		capa, n := uint64(e.Mem.R32(list)), uint64(e.Mem.R32(list+4))
		i := uint64(0)
		for ; i < n && e.Mem.R64(list+8+24*i) != attr; i++ {
		}
		if i == n {
			if n >= capa {
				return e.fail(errGenFailure)
			}
			e.Mem.W32(list+4, uint32(n+1))
		}
		ent := list + 8 + 24*i
		e.Mem.W64(ent, attr)
		e.Mem.W64(ent+8, val)
		e.Mem.W64(ent+16, size)
		return 1
	})
	reg(k, "DeleteProcThreadAttributeList", retZero)

	regAW(dAdv+","+k, "CreateProcessAsUser", func(e *Emu, w bool) uint64 {
		var tok *tokenObj
		if h := e.Arg(0); h != 0 {
			t, ok := e.handles.get(h).(*tokenObj)
			if !ok {
				return e.fail(errInvalidHandle)
			}
			if t.typ != tokenPrimary {
				return e.fail(errBadTokenType)
			}
			tok = t
		}
		return e.createProcess(e.strArg(1, w), e.strArg(2, w), e.Arg32(6), e.Arg(7), e.strArg(8, w), e.Arg(9), e.Arg(10), w,
			e.Arg32(5) != 0, e.Arg(3), e.Arg(4), tok)
	})
}
