package win

// Overlapped-I/O results and cancellation for every handle kind.
//
// An overlapped operation leaves its NTSTATUS in OVERLAPPED.Internal
// (STATUS_PENDING until it completes) and its byte count in InternalHigh.
// Files and anonymous pipes complete synchronously; named pipes complete
// on a pool thread (namedpipe.go); sockets complete from pollNet
// (winsock_ovl.go). Completions may also queue a packet on the completion
// port the handle is associated with (iocpObj, CreateIoCompletionPort).

const (
	errTimeout258    = 258  // WAIT_TIMEOUT
	waitIOCompletion = 0xC0 // WAIT_IO_COMPLETION
)

type iocpPacket struct {
	n       uint32
	key, ov uint64
	st      uint32 // NTSTATUS of the operation (0 for posted packets)
}

type iocpObj struct {
	k *Kernel
	q []iocpPacket // under k.mu
}

func (o *iocpObj) post(p iocpPacket) {
	o.k.mu.Lock()
	o.q = append(o.q, p)
	o.k.mu.Unlock()
	o.k.notify()
}

// take removes up to max packets.
func (o *iocpObj) take(max int) []iocpPacket {
	o.k.mu.Lock()
	defer o.k.mu.Unlock()
	n := min(max, len(o.q))
	if n == 0 {
		return nil
	}
	out := append([]iocpPacket(nil), o.q[:n]...)
	o.q = o.q[n:]
	return out
}

func (o *iocpObj) pending() bool {
	o.k.mu.Lock()
	defer o.k.mu.Unlock()
	return len(o.q) > 0
}

// statusWin32 maps an OVERLAPPED status to a Win32 error (0 = success), as
// GetOverlappedResult and GetQueuedCompletionStatus report it: any
// !NT_SUCCESS status (error or warning) is a failure.
func statusWin32(st uint32) uint32 {
	if st&0x80000000 == 0 {
		return 0
	}
	if st&0xFFFF0000 == 0xC0F00000 {
		return st & 0xFFFF // WSA codes stored by wsaStatus are valid Win32 error codes
	}
	return ntToWin(st)
}

// ovResult implements the common part of (WSA)GetOverlappedResult(Ex):
// it returns pending=true after parking the call (or failing with
// ERROR_IO_INCOMPLETE / WAIT_TIMEOUT / WAIT_IO_COMPLETION), otherwise the
// operation's status. host marks the wait as one on host-completed work
// (sockets: never "blocked forever" for the deadlock detector).
func (e *Emu) ovResult(ov uint64, waitMs uint32, alertable, host bool) (st uint32, pending bool, fail uint32) {
	timedOut := false
	if e.inWait() {
		timedOut = e.endWait()
	}
	st = uint32(e.Mem.R64(ov))
	if st != statusPending {
		return st, false, 0
	}
	if e.runAlertAPCs(alertable) {
		return 0, true, waitIOCompletion
	}
	switch {
	case waitMs == 0:
		return 0, true, errIOIncomplete
	case timedOut:
		return 0, true, errTimeout258
	}
	ready := func() bool { return uint32(e.Mem.R64(ov)) != statusPending }
	if host {
		e.blockHost(ready, waitMs)
	} else {
		e.block(ready, waitMs)
	}
	e.wakeOnAPC(alertable)
	return 0, true, 0
}

// getOverlappedResult implements GetOverlappedResult(Ex) for handle h.
func (e *Emu) getOverlappedResult(h, ov, count uint64, waitMs uint32, alertable bool) uint64 {
	if ov == 0 {
		e.endWaitIf()
		return e.fail(errInvalidParameter)
	}
	// named-pipe completions come from guest pool threads: an ordinary wait
	host := e.npEndOf(h) == nil
	st, pending, code := e.ovResult(ov, waitMs, alertable, host)
	if pending {
		if code != 0 {
			return e.fail(code)
		}
		return 0
	}
	if count != 0 {
		e.Mem.W32(count, uint32(e.Mem.R64(ov+8)))
	}
	if code := statusWin32(st); code != 0 {
		return e.fail(code)
	}
	return 1
}

// cancelIo cancels this process's pending operations on handle h (t != nil:
// only those issued by t; ov != 0: only that one). ok is false for an
// invalid handle.
func (e *Emu) cancelIo(h uint64, t *Thread, ov uint64) (n int, ok bool) {
	if x := e.npEndOf(h); x != nil {
		return e.npCancel(x, t, ov), true
	}
	if n, ok := e.cancelSockIo(h, t, ov); ok {
		return n, true
	}
	// other handle kinds complete their I/O synchronously: nothing pending
	return 0, e.handles.get(h) != nil
}

func init() {
	k := dK32
	reg(k, "GetOverlappedResult", func(e *Emu) uint64 {
		w := uint32(0)
		if e.Arg32(3) != 0 {
			w = infinite
		}
		return e.getOverlappedResult(e.Arg(0), e.Arg(1), e.Arg(2), w, false)
	})
	reg(k, "GetOverlappedResultEx", func(e *Emu) uint64 {
		return e.getOverlappedResult(e.Arg(0), e.Arg(1), e.Arg(2), e.Arg32(3), e.Arg32(4) != 0)
	})
	reg(k, "CancelIo", func(e *Emu) uint64 {
		if _, ok := e.cancelIo(e.Arg(0), e.Cur, 0); !ok {
			return e.fail(errInvalidHandle)
		}
		return 1
	})
	reg(k, "CancelIoEx", func(e *Emu) uint64 {
		n, ok := e.cancelIo(e.Arg(0), nil, e.Arg(1))
		switch {
		case !ok:
			return e.fail(errInvalidHandle)
		case n == 0:
			return e.fail(errNotFound) // no matching pending operation
		}
		return 1
	})
}
