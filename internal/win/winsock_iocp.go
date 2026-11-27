//go:build darwin || linux

package win

// I/O completion ports, overlapped results, CancelIo(Ex) and user APCs for
// completion routines.
//
// A completion port is a kernel object: its packet queue is guarded by the
// kernel lock and posting notifies every process, so ports work across
// processes. Waits for packets use block (a thread of a process with pending
// overlapped I/O is a host wait anyway, see netEventsActive).

const (
	sizeofOverlappedEntry = 32 // lpCompletionKey, lpOverlapped, Internal, dwNumberOfBytesTransferred
	errAbandonedWait0     = 735
	fileSkipPortOnSuccess = 1
)

// cancelSockIo cancels pending operations on socket h (cancelOps); ok is
// false if h is not a socket.
func (e *Emu) cancelSockIo(h uint64, t *Thread, ov uint64) (n int, ok bool) {
	s, ok := e.handles.get(h).(*sockObj)
	if !ok {
		return 0, false
	}
	s.mu.Lock()
	n = e.cancelOps(s, t, ov)
	s.mu.Unlock()
	return n, true
}

func (e *Emu) iocpArg(i int) *iocpObj {
	o, _ := e.handles.get(e.Arg(i)).(*iocpObj)
	return o
}

// user APCs (completion routines), per thread of this process
type apcCall struct {
	fn   uint64
	args []uint64
}

func (e *Emu) queueAPC(t *Thread, fn uint64, args ...uint64) {
	n := e.netSt()
	if n.ovl.apcs == nil {
		n.ovl.apcs = map[*Thread][]apcCall{}
	}
	n.ovl.apcs[t] = append(n.ovl.apcs[t], apcCall{fn, args})
}

func (e *Emu) hasAPC(t *Thread) bool { return e.net != nil && len(e.net.ovl.apcs[t]) > 0 }

// runAlertAPCs runs the current thread's queued APCs if the wait is
// alertable; it reports whether any ran (the wait then returns
// WAIT_IO_COMPLETION).
func (e *Emu) runAlertAPCs(alertable bool) bool {
	t := e.Cur
	if !alertable || !e.hasAPC(t) {
		return false
	}
	e.endWaitIf()
	for e.hasAPC(t) {
		q := e.net.ovl.apcs[t]
		c := q[0]
		e.net.ovl.apcs[t] = q[1:]
		e.unlockedCall(func() { e.CallGuest(c.fn, c.args...) })
	}
	delete(e.net.ovl.apcs, t)
	return true
}

// wakeOnAPC makes a queued APC end the alertable wait the current call just
// parked in (the call is re-executed and runs it).
func (e *Emu) wakeOnAPC(alertable bool) {
	t := e.Cur
	if !alertable || !e.skipRet || !t.waiting {
		return
	}
	inner := t.wait
	t.wait = func() bool { return e.hasAPC(t) || inner != nil && inner() }
}

// alertWait wraps a WaitFor*/SleepEx implementation with alertable-wait
// semantics: queued APCs run and the wait returns WAIT_IO_COMPLETION.
func (e *Emu) alertWait(alertable bool, wait func() uint64) uint64 {
	if e.runAlertAPCs(alertable) {
		return waitIOCompletion
	}
	r := wait()
	e.wakeOnAPC(alertable)
	return r
}

func init() {
	k := dK32
	reg(k, "CreateIoCompletionPort", func(e *Emu) uint64 {
		fh, ph, key := e.Arg(0), e.Arg(1), e.Arg(2)
		if fh == invalidHandle {
			if ph != 0 {
				return e.fail(errInvalidParameter)
			}
			return e.handles.add(&iocpObj{k: e.k})
		}
		obj := e.handles.get(fh)
		if obj == nil {
			return e.fail(errInvalidHandle)
		}
		var port *iocpObj
		if ph != 0 {
			if port = e.iocpArg(1); port == nil {
				return e.fail(errInvalidParameter)
			}
		}
		bound := false
		switch o := obj.(type) {
		case *sockObj:
			o.mu.Lock()
			bound = o.ovl.port != nil
			o.mu.Unlock()
		case *npEnd:
			o.k().mu.Lock()
			bound = o.port != nil
			o.k().mu.Unlock()
		}
		if bound {
			return e.fail(errInvalidParameter) // a handle is associated with one port, once
		}
		if port == nil {
			port = &iocpObj{k: e.k}
			ph = e.handles.add(port)
		}
		switch o := obj.(type) {
		case *sockObj:
			o.mu.Lock()
			o.ovl.port, o.ovl.key = port, key
			o.mu.Unlock()
		case *npEnd:
			o.k().mu.Lock()
			o.port, o.key = port, key
			o.k().mu.Unlock()
		}
		// other handle kinds complete their I/O synchronously: nothing to queue
		return ph
	})
	reg(k, "PostQueuedCompletionStatus", func(e *Emu) uint64 {
		o := e.iocpArg(0)
		if o == nil {
			return e.fail(errInvalidHandle)
		}
		o.post(iocpPacket{n: e.Arg32(1), key: e.Arg(2), ov: e.Arg(3)})
		return 1
	})
	reg(k, "GetQueuedCompletionStatus", func(e *Emu) uint64 {
		nb, kp, op, timeout := e.Arg(1), e.Arg(2), e.Arg(3), e.Arg32(4)
		setOv := func(v uint64) {
			if op != 0 {
				e.Mem.W64(op, v)
			}
		}
		o := e.iocpArg(0)
		if o == nil {
			if e.inWait() { // the port was closed during the wait
				e.endWait()
				setOv(0)
				return e.fail(errAbandonedWait0)
			}
			return e.fail(errInvalidHandle)
		}
		if p := o.take(1); p != nil {
			e.endWaitIf()
			if nb != 0 {
				e.Mem.W32(nb, p[0].n)
			}
			if kp != 0 {
				e.Mem.W64(kp, p[0].key)
			}
			setOv(p[0].ov)
			if code := statusWin32(p[0].st); code != 0 {
				return e.fail(code) // a failed operation: FALSE with *lpOverlapped set
			}
			return 1
		}
		if timeout == 0 || e.inWait() && e.endWait() {
			setOv(0)
			return e.fail(errTimeout258)
		}
		e.block(o.pending, timeout)
		return 0
	})
	reg(k, "GetQueuedCompletionStatusEx", func(e *Emu) uint64 {
		ents, count, removed, timeout, alertable := e.Arg(1), e.Arg32(2), e.Arg(3), e.Arg32(4), e.Arg32(5) != 0
		setRemoved := func(n uint32) {
			if removed != 0 {
				e.Mem.W32(removed, n)
			}
		}
		o := e.iocpArg(0)
		if o == nil {
			if e.inWait() {
				e.endWait()
				setRemoved(0)
				return e.fail(errAbandonedWait0)
			}
			return e.fail(errInvalidHandle)
		}
		if count == 0 || ents == 0 {
			e.endWaitIf()
			return e.fail(errInvalidParameter)
		}
		if ps := o.take(int(count)); ps != nil {
			e.endWaitIf()
			for i, p := range ps {
				a := ents + uint64(i)*sizeofOverlappedEntry
				e.Mem.W64(a, p.key)
				e.Mem.W64(a+8, p.ov)
				e.Mem.W64(a+16, uint64(p.st))
				e.Mem.W64(a+24, uint64(p.n))
			}
			setRemoved(uint32(len(ps)))
			return 1
		}
		if e.runAlertAPCs(alertable) {
			setRemoved(0)
			return e.fail(waitIOCompletion)
		}
		if timeout == 0 || e.inWait() && e.endWait() {
			setRemoved(0)
			return e.fail(errTimeout258)
		}
		e.block(o.pending, timeout)
		e.wakeOnAPC(alertable)
		return 0
	})
	reg(k, "SetFileCompletionNotificationModes", func(e *Emu) uint64 {
		obj := e.handles.get(e.Arg(0))
		if obj == nil {
			return e.fail(errInvalidHandle)
		}
		skip := uint8(e.Arg(1))&fileSkipPortOnSuccess != 0
		switch o := obj.(type) {
		case *sockObj:
			o.mu.Lock()
			o.ovl.skipPort = skip
			o.mu.Unlock()
		case *npEnd:
			o.k().mu.Lock()
			o.skipPort = skip
			o.k().mu.Unlock()
		}
		return 1 // FILE_SKIP_SET_EVENT_ON_HANDLE: handles are never signalled by I/O here
	})
	regWS("ws2_32.dll", "WSAGetOverlappedResult", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			e.endWaitIf()
			return 0
		}
		ov, np, wait, fp := e.Arg(1), e.Arg(2), e.Arg32(3) != 0, e.Arg(4)
		if ov == 0 || np == 0 {
			e.endWaitIf()
			e.SetLastError(wsaEFAULT)
			return 0
		}
		w := uint32(0)
		if wait {
			w = infinite
		}
		st, pending, code := e.ovResult(ov, w, false, true)
		if pending {
			if code != 0 {
				e.SetLastError(code)
			}
			return 0
		}
		e.Mem.W32(np, uint32(e.Mem.R64(ov+8)))
		if fp != 0 {
			e.Mem.W32(fp, e.Mem.R32(ov+16))
		}
		if code := statusWSA(st); code != 0 {
			e.SetLastError(code)
			return 0
		}
		return 1
	})
}
