package win

// Pool threads and registered waits (RegisterWaitForSingleObject).
//
// A pool thread is an ordinary guest thread of the process whose code is a
// builtin: it runs a poolWork, which may block like any API call (e.block,
// re-executed when ready), call a guest function, or end the thread. Pool
// threads are used for registered waits and for completing overlapped I/O
// (namedpipe.go). Their state is process-local: only the owning Emu's
// goroutine touches it.

import "winemu/internal/cpu"

const (
	wtExecuteOnlyOnce = 0x8
	errIOPending      = 997
	errIOIncomplete   = 996
)

type poolAction int

const (
	poolBlocked poolAction = iota // run called e.block; it is re-run when ready
	poolCall                      // call fn(a0, a1), then run again
	poolExit                      // end the pool thread
)

type poolWork interface {
	// run is called on the pool thread. For poolCall it returns the guest
	// function and its two arguments.
	run(e *Emu) (act poolAction, fn, a0, a1 uint64)
	// returned is called on the pool thread after a guest call returns.
	returned(e *Emu)
}

// startPoolThread runs w on a new thread of this process.
func (e *Emu) startPoolThread(w poolWork) (*Thread, error) {
	t, err := e.newThread(e.poolEntry(), 0, 0)
	if err != nil {
		return nil, err
	}
	t.xop = w
	t.name = "pool"
	e.handles.close(t.Handle)
	t.Handle = 0
	return t, nil
}

// poolEntry returns the builtin that drives a pool thread; poolReturn is
// the return address of the guest calls it makes.
func (e *Emu) poolEntry() uint64 {
	ret := e.stub("winemu", "__pool_return", func(e *Emu) uint64 {
		e.Cur.xop.(poolWork).returned(e)
		e.Cur.CPU.RIP = e.poolEntry()
		e.skipRet = true
		return 0
	})
	return e.stub("winemu", "__pool_thread", func(e *Emu) uint64 {
		t := e.Cur
		w, ok := t.xop.(poolWork)
		if !ok {
			e.exitThread(0)
		}
		act, fn, a0, a1 := w.run(e)
		switch act {
		case poolExit:
			t.xop = nil
			e.exitThread(0)
		case poolCall:
			c := t.CPU
			sp := (t.StackBase-0x100)&^15 - 8 // as after a call: RSP = 8 mod 16
			e.Mem.W64(sp, ret)
			c.R[cpu.RSP] = sp
			c.R[cpu.RCX], c.R[cpu.RDX] = a0, a1
			c.RIP = fn
			e.skipRet = true
		}
		return 0
	})
}

// waitReg is one RegisterWaitForSingleObject registration; its handle is an
// entry of the process handle table.
type waitReg struct {
	obj      waitable
	cb, ctx  uint64
	timeout  uint32
	once     bool
	thread   *Thread
	unreg    bool // UnregisterWait(Ex) called
	running  bool // the callback is executing
	fired    bool // WT_EXECUTEONLYONCE callback done
	finished bool // the wait thread has ended
	done     *eventObj
}

func (r *waitReg) run(e *Emu) (poolAction, uint64, uint64, uint64) {
	if r.unreg || (r.once && r.fired) {
		e.endWaitIf()
		r.finish(e)
		return poolExit, 0, 0, 0
	}
	t := e.Cur
	k := e.k
	k.mu.Lock()
	sig := r.obj.signaled(t)
	if sig {
		r.obj.acquire(t)
	}
	k.mu.Unlock()
	timedOut := !sig && e.inWait() && t.waitTimedOut
	if sig || timedOut || (!sig && r.timeout == 0) {
		e.endWaitIf()
		r.running = true
		return poolCall, r.cb, r.ctx, b2u(!sig)
	}
	e.block(func() bool {
		if r.unreg {
			return true
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		return r.obj.signaled(t)
	}, r.timeout)
	return poolBlocked, 0, 0, 0
}

func (r *waitReg) returned(e *Emu) {
	r.running = false
	if r.once {
		r.fired = true
	}
	if r.unreg {
		r.finish(e)
	}
	e.k.notify()
}

// finish ends the registration's callbacks: the completion event of
// UnregisterWaitEx is signalled once no callback runs any more.
func (r *waitReg) finish(e *Emu) {
	r.finished = true
	if r.done != nil {
		e.k.mu.Lock()
		r.done.set = true
		e.k.mu.Unlock()
		r.done = nil
		e.k.notify()
	}
}

// unregisterWait implements UnregisterWait(Ex); ce is the CompletionEvent
// (0: none, invalidHandle: wait for running callbacks).
func (e *Emu) unregisterWait(h, ce uint64) uint64 {
	r, ok := e.handles.get(h).(*waitReg)
	if !ok || h == 0 {
		e.endWaitIf()
		return e.fail(errInvalidHandle)
	}
	var ev *eventObj
	if ce != 0 && ce != invalidHandle {
		if ev, ok = e.handles.get(ce).(*eventObj); !ok {
			return e.fail(errInvalidHandle)
		}
	}
	r.unreg = true
	e.k.notify()
	busy := r.running && r.thread != e.Cur
	if ce == invalidHandle && busy {
		// the wait handle stays open until the callback has returned; the
		// call is re-executed then
		e.block(func() bool { return !r.running }, infinite)
		return 0
	}
	e.endWaitIf()
	e.handles.close(h)
	switch {
	case ce == invalidHandle:
		return 1
	case ev != nil:
		r.done = ev
		if !busy {
			r.finish(e)
		}
		return 1
	case busy:
		return e.fail(errIOPending)
	}
	return 1
}

func init() {
	k := dK32
	register := func(e *Emu, obj, cb, ctx uint64, ms, flags uint32) (uint64, uint32) {
		w := e.waitableOf(obj)
		if w == nil {
			return 0, errInvalidHandle
		}
		if cb == 0 {
			return 0, errInvalidParameter
		}
		r := &waitReg{obj: w, cb: cb, ctx: ctx, timeout: ms, once: flags&wtExecuteOnlyOnce != 0}
		t, err := e.startPoolThread(r)
		if err != nil {
			return 0, errNotEnoughMemory
		}
		r.thread = t
		return e.handles.add(r), 0
	}
	reg(k, "RegisterWaitForSingleObject", func(e *Emu) uint64 {
		out := e.Arg(0)
		if out == 0 {
			return e.fail(errInvalidParameter)
		}
		h, code := register(e, e.Arg(1), e.Arg(2), e.Arg(3), e.Arg32(4), e.Arg32(5))
		if h == 0 {
			return e.fail(code)
		}
		e.Mem.W64(out, h)
		return 1
	})
	reg(k, "RegisterWaitForSingleObjectEx", func(e *Emu) uint64 {
		h, code := register(e, e.Arg(0), e.Arg(1), e.Arg(2), e.Arg32(3), e.Arg32(4))
		if h == 0 {
			return e.fail(code)
		}
		return h
	})
	reg(k, "UnregisterWait", func(e *Emu) uint64 { return e.unregisterWait(e.Arg(0), 0) })
	reg(k, "UnregisterWaitEx", func(e *Emu) uint64 { return e.unregisterWait(e.Arg(0), e.Arg(1)) })
}
