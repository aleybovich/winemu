package win

import (
	"time"

	"winemu/internal/cpu"
)

const (
	waitObject0   = 0
	waitAbandoned = 0x80
	waitTimeout   = 0x102
	waitFailed    = 0xFFFFFFFF
	infinite      = 0xFFFFFFFF
)

type cvWaiter struct {
	cv       uint64
	woken    bool
	phase    int // 1 = waiting for wake, 2 = reacquiring lock
	timedOut bool
}

type flsState struct {
	used      []bool
	callbacks []uint64
	values    map[uint32][]uint64
}

// namedObj is a kernel object that can carry a name (embeds kname).
type namedObj interface{ kn() *kname }

func (n *kname) kn() *kname { return n }

// createNamed returns the object registered under key (existed = true) or
// registers o under it (key "" = unnamed). The result carries a temporary
// reference; hand it to handleFor.
func (e *Emu) createNamed(key string, o namedObj) (_ namedObj, existed bool) {
	k := e.k
	k.mu.Lock()
	defer k.mu.Unlock()
	if key != "" {
		if ex, ok := k.names[key].(namedObj); ok {
			ex.kn().refs++
			return ex, true
		}
	}
	n := o.kn()
	n.k, n.key = k, key
	if key != "" {
		k.names[key] = o
	}
	n.refs++
	return o, false
}

// openNamed returns the object registered under key (with a temporary
// reference) or nil.
func (e *Emu) openNamed(key string) namedObj {
	k := e.k
	k.mu.Lock()
	defer k.mu.Unlock()
	ex, ok := k.names[key].(namedObj)
	if !ok {
		return nil
	}
	ex.kn().refs++
	return ex
}

// handleFor adds a handle for o and drops the temporary reference.
func (e *Emu) handleFor(o namedObj, inherit bool) uint64 {
	h := e.handles.add(o)
	o.kn().unref()
	if inherit {
		e.handles.setInherit(h, true)
	}
	return h
}

// saInherit reads bInheritHandle from a SECURITY_ATTRIBUTES pointer.
func (e *Emu) saInherit(sa uint64) bool { return sa != 0 && e.Mem.R32(sa+16) != 0 }

// threadOf resolves a thread handle to a thread of this process.
func (e *Emu) threadOf(h uint64) *Thread {
	if t := e.anyThreadOf(h); t != nil && t.emu == e {
		return t
	}
	return nil
}

// anyThreadOf resolves a thread handle to a thread of any process. Only the
// cross-process-safe fields (ID, gone, exitCode once gone) may be used for a
// thread of another process.
func (e *Emu) anyThreadOf(h uint64) *Thread {
	if h == pseudoThread {
		return e.Cur
	}
	if o, ok := e.handles.get(h).(*threadObj); ok {
		return o.t
	}
	return nil
}

func (e *Emu) waitableOf(h uint64) waitable {
	if h == pseudoThread {
		return &threadObj{t: e.Cur}
	}
	if h == pseudoProcess {
		return &processObj{self: true}
	}
	w, _ := e.handles.get(h).(waitable)
	return w
}

// waitMany implements WaitFor{Single,Multiple}Objects.
func (e *Emu) waitMany(hs []uint64, all bool, timeout uint32) uint64 {
	ws := make([]waitable, len(hs))
	for i, h := range hs {
		ws[i] = e.waitableOf(h)
		if ws[i] == nil {
			e.endWaitIf()
			e.SetLastError(errInvalidHandle)
			return waitFailed
		}
	}
	t := e.Cur
	k := e.k
	var hint time.Time
	for _, w := range ws {
		if tm, ok := w.(*timerObj); ok {
			k.mu.Lock()
			due := tm.due
			k.mu.Unlock()
			if d := time.Unix(0, due); due != 0 && (hint.IsZero() || d.Before(hint)) {
				hint = d
			}
		}
	}
	check := func() int {
		if all {
			for _, w := range ws {
				if !w.signaled(t) {
					return -1
				}
			}
			return 0
		}
		for i, w := range ws {
			if w.signaled(t) {
				return i
			}
		}
		return -1
	}
	k.mu.Lock()
	i := check()
	abandoned := false
	if i >= 0 {
		if all {
			for _, w := range ws {
				abandoned = abandoned || isAbandoned(w, t)
				w.acquire(t)
			}
		} else {
			abandoned = isAbandoned(ws[i], t)
			ws[i].acquire(t)
		}
	}
	k.mu.Unlock()
	if i >= 0 {
		e.endWaitIf()
		if abandoned {
			// WAIT_ABANDONED_0 (+ index for wait-any; wait-all reports
			// WAIT_ABANDONED_0 when any of the mutexes was abandoned)
			return waitAbandoned + uint64(i)
		}
		return uint64(i)
	}
	if e.inWait() {
		if t.waitTimedOut {
			e.endWait()
			return waitTimeout
		}
	}
	if timeout == 0 {
		return waitTimeout
	}
	e.block(func() bool {
		k.mu.Lock()
		defer k.mu.Unlock()
		return check() >= 0
	}, timeout)
	t.waitHint = hint
	return 0
}

// isAbandoned reports whether acquiring w would take over a mutex whose
// owner thread ended without releasing it. Call with the kernel lock held.
func isAbandoned(w waitable, t *Thread) bool {
	m, ok := w.(*mutexObj)
	return ok && m.owner != nil && m.owner != t && m.owner.gone.Load()
}

func (e *Emu) endWaitIf() {
	if e.inWait() {
		e.endWait()
	}
}

// sleep implements Sleep/SleepEx.
func (e *Emu) sleep(ms uint32) uint64 {
	if e.inWait() {
		e.endWait()
		return 0
	}
	if ms == 0 {
		e.yield()
		return 0
	}
	e.block(func() bool { return false }, ms)
	return 0
}

// critical sections ----------------------------------------------------------

func (e *Emu) csEnter(cs uint64, try bool) bool {
	m := e.Mem
	tid := uint64(e.Cur.ID)
	owner := m.R64(cs + 16)
	if owner != 0 && e.threadByID(uint32(owner)) != nil && e.threadByID(uint32(owner)).exited {
		owner = 0
	}
	if owner == 0 {
		e.endWaitIf()
		m.W64(cs+16, tid)
		m.W32(cs+12, 1)
		m.W32(cs+8, 0xFFFFFFFE)
		return true
	}
	if owner == tid {
		e.endWaitIf()
		m.W32(cs+12, m.R32(cs+12)+1)
		return true
	}
	if try {
		return false
	}
	e.block(func() bool { return m.R64(cs+16) == 0 }, infinite)
	return false
}

func (e *Emu) csLeave(cs uint64) {
	m := e.Mem
	if m.R64(cs+16) != uint64(e.Cur.ID) {
		return
	}
	n := m.R32(cs+12) - 1
	m.W32(cs+12, n)
	if n == 0 {
		m.W64(cs+16, 0)
		m.W32(cs+8, 0xFFFFFFFF)
	}
}

// SRW locks: 0 = free, 1 = exclusive, 2*n = n shared owners
func (e *Emu) srwAcquire(l uint64, excl, try bool) bool {
	m := e.Mem
	v := m.R64(l)
	if excl && v == 0 {
		e.endWaitIf()
		m.W64(l, 1)
		return true
	}
	if !excl && v&1 == 0 {
		e.endWaitIf()
		m.W64(l, v+2)
		return true
	}
	if try {
		return false
	}
	if excl {
		e.block(func() bool { return m.R64(l) == 0 }, infinite)
	} else {
		e.block(func() bool { return m.R64(l)&1 == 0 }, infinite)
	}
	return false
}

func (e *Emu) srwRelease(l uint64, excl bool) {
	m := e.Mem
	v := m.R64(l)
	if excl {
		m.W64(l, 0)
	} else if v >= 2 {
		m.W64(l, v-2)
	}
}

// condition variables ------------------------------------------------------------

// sleepCV: kind 0 = critical section, 1 = SRW exclusive, 2 = SRW shared.
func (e *Emu) sleepCV(cv, lock uint64, kind int, timeout uint32) uint64 {
	t := e.Cur
	st := e.cvByThread[t]
	if st == nil {
		switch kind {
		case 0:
			// fully release (recursion count saved implicitly as 1)
			e.Mem.W32(lock+12, 1)
			e.csLeave(lock)
		default:
			e.srwRelease(lock, kind == 1)
		}
		st = &cvWaiter{cv: cv, phase: 1}
		e.cvByThread[t] = st
		e.cvWaiters[cv] = append(e.cvWaiters[cv], st)
		e.block(func() bool { return st.woken }, timeout)
		return 0
	}
	if st.phase == 1 {
		timedOut := t.waitTimedOut
		e.endWait()
		if !st.woken {
			st.timedOut = timedOut
			// remove from waiter list
			l := e.cvWaiters[cv]
			for i, w := range l {
				if w == st {
					e.cvWaiters[cv] = append(l[:i], l[i+1:]...)
					break
				}
			}
		}
		st.phase = 2
	}
	// reacquire
	var ok bool
	switch kind {
	case 0:
		ok = e.csEnter(lock, true)
	default:
		ok = e.srwAcquire(lock, kind == 1, true)
	}
	if !ok {
		m := e.Mem
		switch kind {
		case 0:
			e.block(func() bool { return m.R64(lock+16) == 0 }, infinite)
		case 1:
			e.block(func() bool { return m.R64(lock) == 0 }, infinite)
		default:
			e.block(func() bool { return m.R64(lock)&1 == 0 }, infinite)
		}
		return 0
	}
	e.endWaitIf()
	delete(e.cvByThread, t)
	if st.timedOut {
		e.SetLastError(errTimeout)
		return 0
	}
	return 1
}

func (e *Emu) wakeCV(cv uint64, all bool) {
	l := e.cvWaiters[cv]
	if len(l) == 0 {
		return
	}
	if all {
		for _, w := range l {
			w.woken = true
		}
		delete(e.cvWaiters, cv)
		return
	}
	l[0].woken = true
	e.cvWaiters[cv] = l[1:]
}

// TLS / FLS -------------------------------------------------------------------

func (e *Emu) tlsSlotAddr(t *Thread, i uint32) uint64 {
	if i < 64 {
		return t.TEB + 0x1480 + 8*uint64(i)
	}
	exp := e.Mem.R64(t.TEB + 0x1780)
	if exp == 0 {
		exp = e.heapAlloc(8*1024, true)
		e.Mem.W64(t.TEB+0x1780, exp)
	}
	return exp + 8*uint64(i-64)
}

func (e *Emu) flsThreadExit(t *Thread) {
	vals := e.fls.values[t.ID]
	for i, v := range vals {
		if v != 0 && i < len(e.fls.callbacks) && e.fls.callbacks[i] != 0 && e.fls.used[i] {
			e.CallGuest(e.fls.callbacks[i], v)
		}
	}
	delete(e.fls.values, t.ID)
}

func init() {
	k := dK32
	reg(k, "CreateThread", func(e *Emu) uint64 {
		t, err := e.newThread(e.Arg(2), e.Arg(3), e.Arg(1))
		if err != nil {
			return e.fail(errNotEnoughMemory)
		}
		if e.Arg32(4)&4 != 0 {
			t.suspend = 1
		}
		if p := e.Arg(5); p != 0 {
			e.Mem.W32(p, t.ID)
		}
		return t.Handle
	})
	reg(k, "CreateRemoteThread", func(e *Emu) uint64 {
		if e.Arg(0) != pseudoProcess {
			return e.fail(errAccessDenied)
		}
		t, err := e.newThread(e.Arg(3), e.Arg(4), e.Arg(2))
		if err != nil {
			return 0
		}
		if e.Arg32(5)&4 != 0 {
			t.suspend = 1
		}
		if p := e.Arg(6); p != 0 {
			e.Mem.W32(p, t.ID)
		}
		return t.Handle
	})
	reg(k, "CreateRemoteThreadEx", func(e *Emu) uint64 {
		t, err := e.newThread(e.Arg(3), e.Arg(4), e.Arg(2))
		if err != nil {
			return 0
		}
		if e.Arg32(5)&4 != 0 {
			t.suspend = 1
		}
		if p := e.Arg(7); p != 0 {
			e.Mem.W32(p, t.ID)
		}
		return t.Handle
	})
	reg(k, "ExitThread", func(e *Emu) uint64 {
		if e.Cur == e.threads[0] && e.liveThreads() == 1 {
			e.exitProcess(e.Arg32(0))
		}
		e.exitThread(e.Arg32(0))
		return 0
	})
	reg(k, "TerminateThread", func(e *Emu) uint64 {
		t := e.threadOf(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		if t == e.Cur {
			e.exitThread(e.Arg32(1))
		}
		e.finishThread(t, e.Arg32(1))
		return 1
	})
	reg(k, "GetExitCodeThread", func(e *Emu) uint64 {
		t := e.anyThreadOf(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		c := uint32(259)
		if t.gone.Load() {
			c = t.exitCode
		}
		e.Mem.W32(e.Arg(1), c)
		return 1
	})
	reg(k, "OpenThread", func(e *Emu) uint64 {
		t := e.threadByID(e.Arg32(2))
		if t == nil {
			return e.fail(errInvalidParameter)
		}
		return e.handles.add(&threadObj{t: t})
	})
	reg(k, "SwitchToThread", func(e *Emu) uint64 { e.yield(); return 1 })
	reg(k, "Sleep", func(e *Emu) uint64 { return e.sleep(e.Arg32(0)) })
	reg(k, "SleepEx", func(e *Emu) uint64 { return e.alertWait(e.Arg32(1) != 0, func() uint64 { return e.sleep(e.Arg32(0)) }) })
	reg(dNt, "NtDelayExecution", func(e *Emu) uint64 {
		iv := int64(e.Mem.R64(e.Arg(1)))
		ms := uint32(0)
		if iv < 0 {
			ms = uint32(-iv / 10000)
		}
		e.sleep(ms)
		return 0
	})
	reg(dNt, "NtYieldExecution", func(e *Emu) uint64 { e.yield(); return 0 })
	reg(k, "SetThreadPriority", retTrue)
	reg(k, "GetThreadPriority", retZero)
	reg(k, "SetThreadPriorityBoost", retTrue)
	reg(k, "GetThreadPriorityBoost", func(e *Emu) uint64 { e.Mem.W32(e.Arg(1), 0); return 1 })
	reg(k, "SetThreadIdealProcessor", retZero)
	reg(k, "SetThreadIdealProcessorEx", retTrue)
	reg(k, "SetThreadGroupAffinity", retTrue)
	reg(k, "GetThreadGroupAffinity", func(e *Emu) uint64 { e.Mem.W64(e.Arg(1), 0xF); e.Mem.W16(e.Arg(1)+8, 0); return 1 })
	reg(k, "SetThreadStackGuarantee", func(e *Emu) uint64 {
		if e.Arg(0) != 0 {
			e.Mem.W32(e.Arg(0), 0)
		}
		return 1
	})
	reg(k, "SetThreadDescription", func(e *Emu) uint64 {
		if t := e.threadOf(e.Arg(0)); t != nil {
			t.name = e.WStr(e.Arg(1))
		}
		return 0
	})
	reg(k, "GetThreadDescription", func(e *Emu) uint64 {
		name := ""
		if t := e.threadOf(e.Arg(0)); t != nil {
			name = t.name
		}
		e.Mem.W64(e.Arg(1), e.allocWStr(name))
		return 0
	})
	reg(k, "GetThreadContext", func(e *Emu) uint64 {
		t := e.threadOf(e.Arg(0))
		if t == nil {
			return e.fail(errInvalidHandle)
		}
		x := ctxFromCPU(t.CPU)
		if t == e.Cur {
			x = e.callerContext()
		}
		e.writeContext(e.Arg(1), &x)
		return 1
	})
	reg(k, "SetThreadContext", func(e *Emu) uint64 {
		t := e.threadOf(e.Arg(0))
		if t == nil || t == e.Cur {
			return e.fail(errInvalidHandle)
		}
		x := e.readContext(e.Arg(1))
		x.toCPU(t.CPU)
		return 1
	})
	reg(k, "QueueUserAPC", func(e *Emu) uint64 {
		t := e.threadOf(e.Arg(1))
		if t == nil {
			return 0
		}
		// run the APC in a fresh thread (approximation)
		e.newThread(e.Arg(0), e.Arg(2), 0)
		return 1
	})
	reg(k, "GetThreadIOPendingFlag", func(e *Emu) uint64 { e.Mem.W32(e.Arg(1), 0); return 1 })

	// waits
	reg(k, "WaitForSingleObject", func(e *Emu) uint64 { return e.waitMany([]uint64{e.Arg(0)}, false, e.Arg32(1)) })
	reg(k, "WaitForSingleObjectEx", func(e *Emu) uint64 {
		return e.alertWait(e.Arg32(2) != 0, func() uint64 { return e.waitMany([]uint64{e.Arg(0)}, false, e.Arg32(1)) })
	})
	msgWaitMult := func(e *Emu) uint64 { // nCount 0 is valid: no objects, messages only
		n := e.Arg32(0)
		hs := make([]uint64, n)
		for i := range hs {
			hs[i] = e.Mem.R64(e.Arg(1) + 8*uint64(i))
		}
		return e.waitMany(hs, e.Arg32(2) != 0, e.Arg32(3))
	}
	waitMult := func(e *Emu) uint64 {
		if n := e.Arg32(0); n == 0 || n > 64 { // MAXIMUM_WAIT_OBJECTS
			e.endWaitIf()
			e.SetLastError(errInvalidParameter)
			return waitFailed
		}
		return msgWaitMult(e)
	}
	reg(k, "WaitForMultipleObjects", waitMult)
	reg(k, "WaitForMultipleObjectsEx", func(e *Emu) uint64 { return e.alertWait(e.Arg32(4) != 0, func() uint64 { return waitMult(e) }) })
	reg("user32.dll", "MsgWaitForMultipleObjects", msgWaitMult)
	reg(k, "SignalObjectAndWait", func(e *Emu) uint64 {
		if !e.inWait() {
			e.signal(e.Arg(0))
		}
		return e.alertWait(e.Arg32(3) != 0, func() uint64 { return e.waitMany([]uint64{e.Arg(1)}, false, e.Arg32(2)) })
	})
	reg(dNt, "NtWaitForSingleObject", func(e *Emu) uint64 {
		to := uint32(infinite)
		if p := e.Arg(2); p != 0 {
			iv := int64(e.Mem.R64(p))
			if iv < 0 {
				to = uint32(-iv / 10000)
			} else {
				to = 0
			}
		}
		return e.waitMany([]uint64{e.Arg(0)}, false, to)
	})

	// events
	createEvent := func(e *Emu, sa uint64, name string, manual, initial bool) uint64 {
		key := ""
		if name != "" {
			key = "event:" + name
		}
		o, existed := e.createNamed(key, &eventObj{manual: manual, set: initial, name: name})
		if existed {
			e.SetLastError(errAlreadyExists)
		} else {
			e.SetLastError(0)
		}
		return e.handleFor(o, e.saInherit(sa))
	}
	regAW(k, "CreateEvent", func(e *Emu, w bool) uint64 {
		return createEvent(e, e.Arg(0), e.strArg(3, w), e.Arg32(1) != 0, e.Arg32(2) != 0)
	})
	regAW(k, "CreateEventEx", func(e *Emu, w bool) uint64 {
		fl := e.Arg32(2)
		return createEvent(e, e.Arg(0), e.strArg(1, w), fl&1 != 0, fl&2 != 0)
	})
	openNamed := func(e *Emu, prefix string, w bool) uint64 {
		o := e.openNamed(prefix + e.strArg(2, w))
		if o == nil {
			return e.fail(errFileNotFound)
		}
		return e.handleFor(o, e.Arg32(1) != 0)
	}
	regAW(k, "OpenEvent", func(e *Emu, w bool) uint64 { return openNamed(e, "event:", w) })
	reg(k, "SetEvent", func(e *Emu) uint64 { return b2u(e.signal(e.Arg(0))) })
	resetEvent := func(e *Emu) uint64 {
		o, ok := e.handles.get(e.Arg(0)).(*eventObj)
		if !ok {
			return e.fail(errInvalidHandle)
		}
		e.k.mu.Lock()
		o.set = false
		e.k.mu.Unlock()
		return 1
	}
	reg(k, "ResetEvent", resetEvent)
	reg(k, "PulseEvent", resetEvent)
	// mutexes
	createMutex := func(e *Emu, sa uint64, name string, own bool) uint64 {
		key := ""
		if name != "" {
			key = "mutex:" + name
		}
		o, existed := e.createNamed(key, &mutexObj{name: name})
		if existed {
			e.SetLastError(errAlreadyExists)
		} else {
			if own {
				e.k.mu.Lock()
				o.(*mutexObj).acquire(e.Cur)
				e.k.mu.Unlock()
			}
			e.SetLastError(0)
		}
		return e.handleFor(o, e.saInherit(sa))
	}
	regAW(k, "CreateMutex", func(e *Emu, w bool) uint64 { return createMutex(e, e.Arg(0), e.strArg(2, w), e.Arg32(1) != 0) })
	regAW(k, "CreateMutexEx", func(e *Emu, w bool) uint64 { return createMutex(e, e.Arg(0), e.strArg(1, w), e.Arg32(2)&1 != 0) })
	regAW(k, "OpenMutex", func(e *Emu, w bool) uint64 { return openNamed(e, "mutex:", w) })
	reg(k, "ReleaseMutex", func(e *Emu) uint64 {
		o, ok := e.handles.get(e.Arg(0)).(*mutexObj)
		if !ok {
			return e.fail(errInvalidHandle)
		}
		e.k.mu.Lock()
		owned := o.owner == e.Cur
		if owned {
			o.count--
			if o.count <= 0 {
				o.owner = nil
				o.count = 0
			}
		}
		e.k.mu.Unlock()
		if !owned {
			return e.fail(288) // ERROR_NOT_OWNER
		}
		e.k.notify()
		return 1
	})
	// semaphores
	createSem := func(e *Emu, sa uint64, name string, init, max int64) uint64 {
		if max <= 0 || init < 0 || init > max {
			return e.fail(errInvalidParameter)
		}
		key := ""
		if name != "" {
			key = "sem:" + name
		}
		o, existed := e.createNamed(key, &semObj{count: init, max: max, name: name})
		if existed {
			e.SetLastError(errAlreadyExists)
		} else {
			e.SetLastError(0)
		}
		return e.handleFor(o, e.saInherit(sa))
	}
	regAW(k, "CreateSemaphore", func(e *Emu, w bool) uint64 {
		return createSem(e, e.Arg(0), e.strArg(3, w), e.ArgI(1), e.ArgI(2))
	})
	regAW(k, "CreateSemaphoreEx", func(e *Emu, w bool) uint64 {
		return createSem(e, e.Arg(0), e.strArg(3, w), e.ArgI(1), e.ArgI(2))
	})
	regAW(k, "OpenSemaphore", func(e *Emu, w bool) uint64 { return openNamed(e, "sem:", w) })
	reg(k, "ReleaseSemaphore", func(e *Emu) uint64 {
		o, ok := e.handles.get(e.Arg(0)).(*semObj)
		if !ok {
			return e.fail(errInvalidHandle)
		}
		n := e.ArgI(1)
		if n <= 0 {
			return e.fail(errInvalidParameter)
		}
		e.k.mu.Lock()
		prev := o.count
		ok = prev+n <= o.max
		if ok {
			o.count += n
		}
		e.k.mu.Unlock()
		if !ok {
			return e.fail(298) // ERROR_TOO_MANY_POSTS
		}
		if p := e.Arg(2); p != 0 {
			e.Mem.W32(p, uint32(prev))
		}
		e.k.notify()
		return 1
	})
	// waitable timers
	createTimer := func(e *Emu, sa uint64, manual bool) uint64 {
		o, _ := e.createNamed("", &timerObj{manual: manual})
		e.SetLastError(0)
		return e.handleFor(o, e.saInherit(sa))
	}
	regAW(k, "CreateWaitableTimer", func(e *Emu, w bool) uint64 { return createTimer(e, e.Arg(0), e.Arg32(1) != 0) })
	regAW(k, "CreateWaitableTimerEx", func(e *Emu, w bool) uint64 { return createTimer(e, e.Arg(0), e.Arg32(2)&1 != 0) })
	setTimer := func(e *Emu) uint64 {
		o, ok := e.handles.get(e.Arg(0)).(*timerObj)
		if !ok {
			return e.fail(errInvalidHandle)
		}
		due := int64(e.Mem.R64(e.Arg(1)))
		e.k.mu.Lock()
		if due < 0 {
			o.due = nowNano() + (-due)*100
		} else {
			o.due = filetimeToUnix(uint64(due)).UnixNano()
		}
		o.period = int64(e.Arg32(2)) * 1e6
		o.set = false
		e.k.mu.Unlock()
		e.k.notify()
		return 1
	}
	reg(k, "SetWaitableTimer", setTimer)
	reg(k, "SetWaitableTimerEx", setTimer)
	reg(k, "CancelWaitableTimer", func(e *Emu) uint64 {
		o, ok := e.handles.get(e.Arg(0)).(*timerObj)
		if !ok {
			return e.fail(errInvalidHandle)
		}
		e.k.mu.Lock()
		o.due = 0
		e.k.mu.Unlock()
		return 1
	})

	// critical sections
	initCS := func(e *Emu) uint64 {
		cs := e.Arg(0)
		e.Mem.Fill(cs, 0, 40)
		e.Mem.W32(cs+8, 0xFFFFFFFF)
		return 1
	}
	reg(k+","+dNt, "InitializeCriticalSection", initCS)
	reg(k, "InitializeCriticalSectionAndSpinCount", initCS)
	reg(k, "InitializeCriticalSectionEx", initCS)
	reg(dNt, "RtlInitializeCriticalSection", initCS)
	reg(dNt, "RtlInitializeCriticalSectionEx", initCS)
	reg(k, "SetCriticalSectionSpinCount", retZero)
	reg(k+","+dNt, "DeleteCriticalSection", retZero)
	reg(dNt, "RtlDeleteCriticalSection", retZero)
	reg(k+","+dNt, "EnterCriticalSection", func(e *Emu) uint64 { e.csEnter(e.Arg(0), false); return 0 })
	reg(dNt, "RtlEnterCriticalSection", func(e *Emu) uint64 { e.csEnter(e.Arg(0), false); return 0 })
	reg(k, "TryEnterCriticalSection", func(e *Emu) uint64 { return b2u(e.csEnter(e.Arg(0), true)) })
	reg(dNt, "RtlTryEnterCriticalSection", func(e *Emu) uint64 { return b2u(e.csEnter(e.Arg(0), true)) })
	reg(k+","+dNt, "LeaveCriticalSection", func(e *Emu) uint64 { e.csLeave(e.Arg(0)); return 0 })
	reg(dNt, "RtlLeaveCriticalSection", func(e *Emu) uint64 { e.csLeave(e.Arg(0)); return 0 })

	// SRW locks
	reg(k+","+dNt, "InitializeSRWLock", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 0); return 0 })
	reg(dNt, "RtlInitializeSRWLock", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 0); return 0 })
	for _, p := range []string{"", "Rtl"} {
		reg(k+","+dNt, p+"AcquireSRWLockExclusive", func(e *Emu) uint64 { e.srwAcquire(e.Arg(0), true, false); return 0 })
		reg(k+","+dNt, p+"AcquireSRWLockShared", func(e *Emu) uint64 { e.srwAcquire(e.Arg(0), false, false); return 0 })
		reg(k+","+dNt, p+"TryAcquireSRWLockExclusive", func(e *Emu) uint64 { return b2u(e.srwAcquire(e.Arg(0), true, true)) })
		reg(k+","+dNt, p+"TryAcquireSRWLockShared", func(e *Emu) uint64 { return b2u(e.srwAcquire(e.Arg(0), false, true)) })
		reg(k+","+dNt, p+"ReleaseSRWLockExclusive", func(e *Emu) uint64 { e.srwRelease(e.Arg(0), true); return 0 })
		reg(k+","+dNt, p+"ReleaseSRWLockShared", func(e *Emu) uint64 { e.srwRelease(e.Arg(0), false); return 0 })
	}

	// condition variables
	reg(k+","+dNt, "InitializeConditionVariable", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 0); return 0 })
	reg(dNt, "RtlInitializeConditionVariable", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 0); return 0 })
	reg(k, "SleepConditionVariableCS", func(e *Emu) uint64 { return e.sleepCV(e.Arg(0), e.Arg(1), 0, e.Arg32(2)) })
	reg(k, "SleepConditionVariableSRW", func(e *Emu) uint64 {
		kind := 1
		if e.Arg32(3)&1 != 0 {
			kind = 2
		}
		return e.sleepCV(e.Arg(0), e.Arg(1), kind, e.Arg32(2))
	})
	reg(k+","+dNt, "WakeConditionVariable", func(e *Emu) uint64 { e.wakeCV(e.Arg(0), false); return 0 })
	reg(k+","+dNt, "WakeAllConditionVariable", func(e *Emu) uint64 { e.wakeCV(e.Arg(0), true); return 0 })
	reg(dNt, "RtlWakeConditionVariable", func(e *Emu) uint64 { e.wakeCV(e.Arg(0), false); return 0 })
	reg(dNt, "RtlWakeAllConditionVariable", func(e *Emu) uint64 { e.wakeCV(e.Arg(0), true); return 0 })

	// WaitOnAddress (api-ms-win-core-synch-l1-2-0 / kernelbase)
	reg(k+",synchronization.dll", "WaitOnAddress", func(e *Emu) uint64 {
		addr, cmp, size, to := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg32(3)
		m := e.Mem
		differs := func() bool {
			switch size {
			case 1:
				return m.R8(addr) != m.R8(cmp)
			case 2:
				return m.R16(addr) != m.R16(cmp)
			case 4:
				return m.R32(addr) != m.R32(cmp)
			}
			return m.R64(addr) != m.R64(cmp)
		}
		if e.inWait() {
			woken := e.Cur.waitTimedOut
			e.endWait()
			if woken {
				e.SetLastError(errTimeout)
				return 0
			}
			return 1
		}
		if differs() {
			return 1
		}
		if to == 0 {
			e.SetLastError(errTimeout)
			return 0
		}
		e.addrWaiters()[e.Cur] = addr
		t := e.Cur
		e.block(func() bool {
			_, still := e.addrWaiters()[t]
			return !still || differs()
		}, to)
		return 0
	})
	reg(k+",synchronization.dll", "WakeByAddressSingle", func(e *Emu) uint64 {
		for t, a := range e.addrWaiters() {
			if a == e.Arg(0) {
				delete(e.addrWaiters(), t)
				break
			}
		}
		return 0
	})
	reg(k+",synchronization.dll", "WakeByAddressAll", func(e *Emu) uint64 {
		for t, a := range e.addrWaiters() {
			if a == e.Arg(0) {
				delete(e.addrWaiters(), t)
			}
		}
		return 0
	})
	reg(dNt, "RtlWaitOnAddress", func(e *Emu) uint64 { return 0 })

	// init once
	reg(k, "InitOnceInitialize", func(e *Emu) uint64 { e.Mem.W64(e.Arg(0), 0); return 0 })
	reg(k, "InitOnceExecuteOnce", func(e *Emu) uint64 {
		io, fn, param, ctxp := e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3)
		m := e.Mem
		v := m.R64(io)
		switch v & 3 {
		case 2:
			e.endWaitIf()
			if ctxp != 0 {
				m.W64(ctxp, v&^3)
			}
			return 1
		case 1:
			e.block(func() bool { return m.R64(io)&3 != 1 }, infinite)
			return 0
		}
		m.W64(io, 1)
		tmp := e.heapAlloc(8, true)
		r := e.CallGuest(fn, io, param, tmp)
		if uint32(r) == 0 {
			m.W64(io, 0)
			e.heap.freeBlock(tmp)
			return 0
		}
		c := m.R64(tmp)
		e.heap.freeBlock(tmp)
		m.W64(io, c&^3|2)
		if ctxp != 0 {
			m.W64(ctxp, c)
		}
		return 1
	})
	reg(k, "InitOnceBeginInitialize", func(e *Emu) uint64 {
		io, flags, pending, ctxp := e.Arg(0), e.Arg32(1), e.Arg(2), e.Arg(3)
		m := e.Mem
		v := m.R64(io)
		if v&3 == 2 {
			m.W32(pending, 0)
			if ctxp != 0 {
				m.W64(ctxp, v&^3)
			}
			return 1
		}
		if flags&1 != 0 { // CHECK_ONLY
			return e.fail(524)
		}
		if v&3 == 1 && flags&2 == 0 {
			e.block(func() bool { return m.R64(io)&3 != 1 }, infinite)
			return 0
		}
		e.endWaitIf()
		m.W64(io, 1)
		m.W32(pending, 1)
		return 1
	})
	reg(k, "InitOnceComplete", func(e *Emu) uint64 {
		io, flags, c := e.Arg(0), e.Arg32(1), e.Arg(2)
		if flags&4 != 0 { // FAILED
			e.Mem.W64(io, 0)
		} else {
			e.Mem.W64(io, c&^3|2)
		}
		return 1
	})

	// TLS
	reg(k, "TlsAlloc", func(e *Emu) uint64 {
		for i := range e.tlsSlots {
			if !e.tlsSlots[i] {
				e.tlsSlots[i] = true
				for _, t := range e.threads {
					e.Mem.W64(e.tlsSlotAddr(t, uint32(i)), 0)
				}
				return uint64(i)
			}
		}
		return 0xFFFFFFFF
	})
	reg(k, "TlsFree", func(e *Emu) uint64 {
		i := e.Arg32(0)
		if i >= uint32(len(e.tlsSlots)) {
			return 0
		}
		e.tlsSlots[i] = false
		return 1
	})
	reg(k, "TlsGetValue", func(e *Emu) uint64 {
		i := e.Arg32(0)
		if i >= uint32(len(e.tlsSlots)) {
			return e.fail(errInvalidParameter)
		}
		e.SetLastError(0)
		return e.Mem.R64(e.tlsSlotAddr(e.Cur, i))
	})
	reg(k, "TlsGetValue2", func(e *Emu) uint64 { return e.Mem.R64(e.tlsSlotAddr(e.Cur, e.Arg32(0))) })
	reg(k, "TlsSetValue", func(e *Emu) uint64 {
		i := e.Arg32(0)
		if i >= uint32(len(e.tlsSlots)) {
			return e.fail(errInvalidParameter)
		}
		e.Mem.W64(e.tlsSlotAddr(e.Cur, i), e.Arg(1))
		return 1
	})
	// FLS
	reg(k, "FlsAlloc", func(e *Emu) uint64 {
		f := &e.fls
		if f.values == nil {
			f.values = map[uint32][]uint64{}
		}
		for i := range f.used {
			if !f.used[i] {
				f.used[i] = true
				f.callbacks[i] = e.Arg(0)
				return uint64(i)
			}
		}
		f.used = append(f.used, true)
		f.callbacks = append(f.callbacks, e.Arg(0))
		return uint64(len(f.used) - 1)
	})
	reg(k, "FlsFree", func(e *Emu) uint64 {
		f := &e.fls
		i := int(e.Arg32(0))
		if i >= len(f.used) || !f.used[i] {
			return e.fail(errInvalidParameter)
		}
		if cb := f.callbacks[i]; cb != 0 {
			for _, vals := range f.values {
				if i < len(vals) && vals[i] != 0 {
					v := vals[i]
					vals[i] = 0
					e.CallGuest(cb, v)
				}
			}
		}
		f.used[i] = false
		return 1
	})
	reg(k, "FlsGetValue", func(e *Emu) uint64 {
		vals := e.fls.values[e.Cur.ID]
		i := int(e.Arg32(0))
		e.SetLastError(0)
		if i < len(vals) {
			return vals[i]
		}
		return 0
	})
	reg(k, "FlsGetValue2", func(e *Emu) uint64 {
		vals := e.fls.values[e.Cur.ID]
		i := int(e.Arg32(0))
		if i < len(vals) {
			return vals[i]
		}
		return 0
	})
	reg(k, "FlsSetValue", func(e *Emu) uint64 {
		f := &e.fls
		if f.values == nil {
			f.values = map[uint32][]uint64{}
		}
		i := int(e.Arg32(0))
		if i >= len(f.used) {
			return e.fail(errInvalidParameter)
		}
		vals := f.values[e.Cur.ID]
		for len(vals) <= i {
			vals = append(vals, 0)
		}
		vals[i] = e.Arg(1)
		f.values[e.Cur.ID] = vals
		return 1
	})

	// SList
	reg(k+","+dNt, "InitializeSListHead", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, 16); return 0 })
	reg(dNt, "RtlInitializeSListHead", func(e *Emu) uint64 { e.Mem.Fill(e.Arg(0), 0, 16); return 0 })
	push := func(e *Emu) uint64 {
		h, ent := e.Arg(0), e.Arg(1)
		old := e.Mem.R64(h + 8)
		e.Mem.W64(ent, old)
		e.Mem.W64(h+8, ent)
		e.Mem.W16(h, e.Mem.R16(h)+1)
		return old
	}
	pop := func(e *Emu) uint64 {
		h := e.Arg(0)
		ent := e.Mem.R64(h + 8)
		if ent == 0 {
			return 0
		}
		e.Mem.W64(h+8, e.Mem.R64(ent))
		e.Mem.W16(h, e.Mem.R16(h)-1)
		return ent
	}
	reg(k+","+dNt, "InterlockedPushEntrySList", push)
	reg(dNt, "RtlInterlockedPushEntrySList", push)
	reg(k+","+dNt, "InterlockedPopEntrySList", pop)
	reg(dNt, "RtlInterlockedPopEntrySList", pop)
	reg(k+","+dNt, "InterlockedFlushSList", func(e *Emu) uint64 {
		h := e.Arg(0)
		ent := e.Mem.R64(h + 8)
		e.Mem.W64(h+8, 0)
		e.Mem.W16(h, 0)
		return ent
	})
	reg(dNt, "RtlInterlockedFlushSList", func(e *Emu) uint64 {
		h := e.Arg(0)
		ent := e.Mem.R64(h + 8)
		e.Mem.W64(h+8, 0)
		e.Mem.W16(h, 0)
		return ent
	})
	reg(k+","+dNt, "QueryDepthSList", func(e *Emu) uint64 { return uint64(e.Mem.R16(e.Arg(0))) })
	reg(dNt, "RtlQueryDepthSList", func(e *Emu) uint64 { return uint64(e.Mem.R16(e.Arg(0))) })
	reg(dNt, "RtlFirstEntrySList", func(e *Emu) uint64 { return e.Mem.R64(e.Arg(0) + 8) })

	// thread pool (approximated with dedicated threads)
	reg(k, "QueueUserWorkItem", func(e *Emu) uint64 {
		_, err := e.newThread(e.Arg(0), e.Arg(1), 0)
		return b2u(err == nil)
	})
	reg(k, "CreateThreadpoolWork", func(e *Emu) uint64 {
		w := e.heapAlloc(32, true)
		e.Mem.W64(w, e.Arg(0))
		e.Mem.W64(w+8, e.Arg(1))
		return w
	})
	reg(k, "SubmitThreadpoolWork", func(e *Emu) uint64 {
		w := e.Arg(0)
		fn, ctx := e.Mem.R64(w), e.Mem.R64(w+8)
		tramp := e.stub("winemu", "__tp_work", func(e *Emu) uint64 {
			p := e.Cur.CPU.R[cpu.RCX]
			f, c, wk := e.Mem.R64(p), e.Mem.R64(p+8), e.Mem.R64(p+16)
			e.heap.freeBlock(p)
			e.CallGuest(f, 0, c, wk)
			if wk != 0 {
				e.Mem.W32(wk+16, e.Mem.R32(wk+16)-1)
			}
			return 0
		})
		blk := e.heapAlloc(24, false)
		e.Mem.W64(blk, fn)
		e.Mem.W64(blk+8, ctx)
		e.Mem.W64(blk+16, w)
		e.Mem.W32(w+16, e.Mem.R32(w+16)+1)
		e.newThread(tramp, blk, 0)
		return 0
	})
	reg(k, "TrySubmitThreadpoolCallback", func(e *Emu) uint64 {
		fn, ctx := e.Arg(0), e.Arg(1)
		tramp := e.stub("winemu", "__tp_simple", func(e *Emu) uint64 {
			p := e.Cur.CPU.R[cpu.RCX]
			f, c := e.Mem.R64(p), e.Mem.R64(p+8)
			e.heap.freeBlock(p)
			e.CallGuest(f, 0, c)
			return 0
		})
		blk := e.heapAlloc(16, false)
		e.Mem.W64(blk, fn)
		e.Mem.W64(blk+8, ctx)
		_, err := e.newThread(tramp, blk, 0)
		return b2u(err == nil)
	})
	reg(k, "WaitForThreadpoolWorkCallbacks", func(e *Emu) uint64 {
		w := e.Arg(0)
		if e.Mem.R32(w+16) != 0 {
			e.block(func() bool { return e.Mem.R32(w+16) == 0 }, infinite)
			return 0
		}
		e.endWaitIf()
		return 0
	})
	reg(k, "CloseThreadpoolWork", retZero)
	reg(k, "CreateThreadpool", func(e *Emu) uint64 { return e.heapAlloc(16, true) })
	reg(k, "CloseThreadpool", retZero)
	reg(k, "SetThreadpoolThreadMaximum", retZero)
	reg(k, "SetThreadpoolThreadMinimum", retTrue)
	reg(k, "CreateThreadpoolCleanupGroup", func(e *Emu) uint64 { return e.heapAlloc(16, true) })
	reg(k, "CloseThreadpoolCleanupGroupMembers", retZero)
	reg(k, "CloseThreadpoolCleanupGroup", retZero)
}

func (e *Emu) addrWaiters() map[*Thread]uint64 { return e.addrWait }

func (e *Emu) liveThreads() int {
	n := 0
	for _, t := range e.threads {
		if !t.exited {
			n++
		}
	}
	return n
}

// signal sets an event / releases a mutex or semaphore.
func (e *Emu) signal(h uint64) bool {
	o := e.handles.get(h)
	switch o.(type) {
	case *eventObj, *semObj, *mutexObj:
	default:
		e.SetLastError(errInvalidHandle)
		return false
	}
	e.k.mu.Lock()
	switch o := o.(type) {
	case *eventObj:
		o.set = true
	case *semObj:
		if o.count < o.max {
			o.count++
		}
	case *mutexObj:
		if o.owner == e.Cur {
			o.count--
			if o.count <= 0 {
				o.owner = nil
				o.count = 0
			}
		}
	}
	e.k.mu.Unlock()
	e.k.notify()
	return true
}
