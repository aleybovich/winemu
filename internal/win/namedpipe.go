package win

// Named pipes (\\.\pipe\<name>) in the kernel namespace: shared between the
// processes of a session. All pipe state is guarded by the kernel lock
// (Kernel.mu); every state change is followed by Kernel.notify. Blocking
// calls block only the calling thread (e.block, re-executed when ready);
// overlapped calls that cannot complete at once are finished by a pool
// thread (threadpool_wait.go), which writes the OVERLAPPED and sets its
// event. Simplification: buffers are unbounded, so writes never block.

import (
	"slices"
	"strings"
)

const (
	errInvalidFunction   = 1
	errSemTimeout        = 121
	errBadPipe           = 230
	errPipeBusy          = 231
	errNoData            = 232
	errPipeNotConnected  = 233
	errPipeConnected     = 535
	errPipeListening     = 536
	errOperationAborted  = 995
	errCannotImpersonate = 1368

	pipeAccessInbound   = 1
	pipeAccessOutbound  = 2
	pipeNowait          = 1
	pipeReadmodeMessage = 2
	pipeTypeMessage     = 4
	pipeUnlimited       = 255
	fileFlagOverlapped  = 0x40000000
	fileFlagFirstInst   = 0x00080000

	statusPending = 0x103
)

// pipeStatus maps the Win32 result of a pipe operation to the NTSTATUS
// stored in OVERLAPPED.Internal (the reverse of ntStatusWin32).
var pipeStatus = map[uint32]uint32{
	errBrokenPipe:       statusPipeBroken,
	errMoreData:         statusBufferOverflow,
	errNoData:           statusPipeClosing,
	errPipeNotConnected: statusPipeDisconnected,
	errPipeListening:    statusPipeListening,
	errOperationAborted: statusCancelled,
	errBadPipe:          statusInvalidPipeState,
	errPipeBusy:         statusPipeBusy,
}

func ntStatusOfErr(code uint32) uint32 {
	if code == 0 {
		return 0
	}
	if st, ok := pipeStatus[code]; ok {
		return st
	}
	return statusUnsuccessful
}

type npPipe struct {
	k               *Kernel
	key             string
	msgType         bool
	access          uint32 // PIPE_ACCESS_* of the server
	maxInst         int
	outSize, inSize uint32
	timeout         uint32
	insts           []*npInst
}

const (
	npListening    = iota // accepts a client
	npConnected           // client attached
	npClosing             // client closed its end; DisconnectNamedPipe needed
	npDisconnected        // after DisconnectNamedPipe; ConnectNamedPipe needed
)

type npInst struct {
	p            *npPipe
	state        int
	cli          *npEnd
	toSrv, toCli npQueue
	srvClosed    bool
}

// npQueue holds the data of one direction: messages (message-type pipes)
// or chunks (byte-type pipes).
type npQueue struct{ msgs [][]byte }

func (q *npQueue) avail() (n int) {
	for _, m := range q.msgs {
		n += len(m)
	}
	return n
}

// take removes up to n bytes (one message in message mode); more reports a
// message left partly unread. peek leaves the queue unchanged.
func (q *npQueue) take(n int, msg, peek bool) (data []byte, more bool) {
	if msg {
		m := q.msgs[0]
		data = m[:min(n, len(m))]
		more = len(data) < len(m)
		if !peek {
			if more {
				q.msgs[0] = m[len(data):]
			} else {
				q.msgs = q.msgs[1:]
			}
		}
		return append([]byte(nil), data...), more
	}
	i, off := 0, 0
	for len(data) < n && i < len(q.msgs) {
		m := q.msgs[i][off:]
		c := min(n-len(data), len(m))
		data = append(data, m[:c]...)
		if c == len(m) {
			i, off = i+1, 0
		} else {
			off += c
		}
	}
	if !peek {
		q.msgs = q.msgs[i:]
		if off > 0 {
			q.msgs[0] = q.msgs[0][off:]
		}
	}
	return data, false
}

// npEnd is the object behind a pipe handle (server instance or client).
type npEnd struct {
	inst                        *npInst
	server                      bool
	readMsg, nowait, overlapped bool
	refs                        int
	closed                      bool     // last handle closed
	detached                    bool     // client cut off by DisconnectNamedPipe
	pending                     []*npOp  // overlapped operations run by pool threads
	port                        *iocpObj // associated completion port
	key                         uint64
	skipPort                    bool // FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
}

func (x *npEnd) k() *Kernel { return x.inst.p.k }

func (x *npEnd) ref() {
	k := x.k()
	k.mu.Lock()
	x.refs++
	k.mu.Unlock()
}

func (x *npEnd) unref() {
	k := x.k()
	k.mu.Lock()
	x.refs--
	if x.refs > 0 || x.closed {
		k.mu.Unlock()
		return
	}
	x.closed = true
	in := x.inst
	if x.server {
		in.srvClosed = true
		p := in.p
		for i, o := range p.insts {
			if o == in {
				p.insts = append(p.insts[:i], p.insts[i+1:]...)
				break
			}
		}
		if len(p.insts) == 0 && k.names[p.key] == p {
			delete(k.names, p.key)
		}
	} else if in.cli == x {
		in.cli = nil
		in.state = npClosing
	}
	k.mu.Unlock()
	k.notify()
}

// The helpers below run with the kernel lock held.

func (x *npEnd) inQ() *npQueue {
	if x.server {
		return &x.inst.toSrv
	}
	return &x.inst.toCli
}

func (x *npEnd) outQ() *npQueue {
	if x.server {
		return &x.inst.toCli
	}
	return &x.inst.toSrv
}

// connErr is the error of an end that is not connected (0 if it is).
func (x *npEnd) connErr() uint32 {
	if x.closed {
		return errOperationAborted
	}
	if x.server {
		switch x.inst.state {
		case npListening:
			return errPipeListening
		case npDisconnected:
			return errPipeNotConnected
		}
		return 0
	}
	if x.detached {
		return errPipeNotConnected
	}
	return 0
}

func (x *npEnd) peerClosed() bool {
	if x.server {
		return x.inst.state == npClosing
	}
	return x.inst.srvClosed
}

// tryRead takes up to n bytes; block reports that the caller must wait.
func (x *npEnd) tryRead(n int, peek bool) (data []byte, code uint32, block bool) {
	if c := x.connErr(); c != 0 {
		return nil, c, false
	}
	q := x.inQ()
	if !x.readMsg {
		for len(q.msgs) > 0 && len(q.msgs[0]) == 0 { // empty messages carry no bytes
			q.msgs = q.msgs[1:]
		}
	}
	if len(q.msgs) > 0 {
		data, more := q.take(n, x.readMsg, peek)
		if more {
			code = errMoreData
		}
		return data, code, false
	}
	switch {
	case x.peerClosed():
		return nil, errBrokenPipe, false
	case x.nowait:
		return nil, errNoData, false
	}
	return nil, 0, true
}

func (x *npEnd) tryWrite(b []byte) uint32 {
	if c := x.connErr(); c != 0 {
		return c
	}
	if x.peerClosed() {
		return errNoData
	}
	if len(b) > 0 || x.inst.p.msgType {
		q := x.outQ()
		q.msgs = append(q.msgs, append([]byte(nil), b...))
	}
	return 0
}

// ---------------------------------------------------------------------------

// npKey returns the namespace key of a pipe path (\\.\pipe\name).
func npKey(name string) (string, bool) {
	low := strings.ToLower(strings.ReplaceAll(name, "/", `\`))
	for _, pre := range []string{`\\.\pipe\`, `\\?\pipe\`, `\??\pipe\`} {
		if strings.HasPrefix(low, pre) && len(low) > len(pre) {
			return "pipe:" + low[len(pre):], true
		}
	}
	return "", false
}

func (e *Emu) npEndOf(h uint64) *npEnd {
	x, _ := e.handles.get(h).(*npEnd)
	return x
}

func (e *Emu) createNamedPipe(name string, openMode, pipeMode, maxInst, outSz, inSz, timeout uint32, sa uint64) uint64 {
	key, ok := npKey(name)
	if !ok {
		return e.failH(errInvalidName)
	}
	access := openMode & 3
	msgType := pipeMode&pipeTypeMessage != 0
	if access == 0 || maxInst == 0 || maxInst > pipeUnlimited || (!msgType && pipeMode&pipeReadmodeMessage != 0) {
		return e.failH(errInvalidParameter)
	}
	k := e.k
	k.mu.Lock()
	p, _ := k.names[key].(*npPipe)
	if p != nil {
		switch {
		case openMode&fileFlagFirstInst != 0 || p.access != access || p.msgType != msgType:
			k.mu.Unlock()
			return e.failH(errAccessDenied)
		case p.maxInst != pipeUnlimited && len(p.insts) >= p.maxInst:
			k.mu.Unlock()
			return e.failH(errPipeBusy)
		}
	} else {
		p = &npPipe{k: k, key: key, msgType: msgType, access: access, maxInst: int(maxInst),
			outSize: outSz, inSize: inSz, timeout: timeout}
		k.names[key] = p
	}
	in := &npInst{p: p}
	p.insts = append(p.insts, in)
	x := &npEnd{inst: in, server: true, readMsg: pipeMode&pipeReadmodeMessage != 0,
		nowait: pipeMode&pipeNowait != 0, overlapped: openMode&fileFlagOverlapped != 0}
	k.mu.Unlock()
	k.notify() // WaitNamedPipe waiters
	h := e.handles.add(x)
	e.handles.setInherit(h, e.saInherit(sa))
	e.SetLastError(0)
	return h
}

// npConnectClient attaches a new client end to a listening instance of the
// pipe at key (kernel lock held). code is the error when it fails.
func npConnectClient(k *Kernel, key string, access, flags uint32) (x *npEnd, code uint32) {
	p, _ := k.names[key].(*npPipe)
	if p == nil {
		return nil, errFileNotFound
	}
	if (access&(genericRead|fileReadData) != 0 && p.access&pipeAccessOutbound == 0) ||
		(access&(genericWrite|fileWriteData|fileAppendData) != 0 && p.access&pipeAccessInbound == 0) {
		return nil, errAccessDenied
	}
	for _, in := range p.insts {
		if in.state == npListening {
			x = &npEnd{inst: in, overlapped: flags&fileFlagOverlapped != 0}
			in.state, in.cli = npConnected, x
			in.toSrv, in.toCli = npQueue{}, npQueue{}
			return x, 0
		}
	}
	return nil, errPipeBusy
}

func npHasListener(k *Kernel, key string) (exists, listening bool) {
	p, _ := k.names[key].(*npPipe)
	if p == nil {
		return false, false
	}
	for _, in := range p.insts {
		if in.state == npListening {
			return true, true
		}
	}
	return true, false
}

// openPipeClient is CreateFile on a pipe path.
func (e *Emu) openPipeClient(key string, access, flags uint32) uint64 {
	k := e.k
	k.mu.Lock()
	x, code := npConnectClient(k, key, access, flags)
	k.mu.Unlock()
	if x == nil {
		return e.failH(code)
	}
	k.notify()
	e.SetLastError(0)
	return e.handles.add(x)
}

// ---------------------------------------------------------------------------
// overlapped completion

// ovEvent returns the event of an OVERLAPPED (low bit: no IOCP packet).
func (e *Emu) ovEvent(ov uint64) *eventObj {
	o, _ := e.handles.get(e.Mem.R64(ov+24) &^ 1).(*eventObj)
	return o
}

func (e *Emu) setEventObj(o *eventObj, on bool) {
	if o == nil {
		return
	}
	e.k.mu.Lock()
	o.set = on
	e.k.mu.Unlock()
	if on {
		e.k.notify()
	}
}

// ovComplete records a finished overlapped operation on x: OVERLAPPED,
// event and, for an overlapped handle associated with a completion port, a
// packet (not when hEvent's low bit is set, nor for an immediate success
// (sync) after FILE_SKIP_COMPLETION_PORT_ON_SUCCESS).
func (e *Emu) ovComplete(x *npEnd, ov uint64, code uint32, n int, sync bool) {
	st := ntStatusOfErr(code)
	e.Mem.W64(ov+8, uint64(n))
	e.Mem.W64(ov, uint64(st))
	e.setEventObj(e.ovEvent(ov), true)
	if e.Mem.R64(ov+24)&1 != 0 || !x.overlapped {
		return
	}
	k := x.k()
	k.mu.Lock()
	port, key, skip := x.port, x.key, x.skipPort
	k.mu.Unlock()
	if port != nil && !(sync && skip) {
		port.post(iocpPacket{n: uint32(n), key: key, ov: ov, st: st})
	}
}

// npOp is a pipe operation. try runs with the kernel lock held: with
// commit false it only checks (block: it must wait), with commit true it
// performs the operation when it does not have to wait.
//
// A pending overlapped operation is on x.pending (kernel lock) until it
// completes or is cancelled (done; CancelIo completes it itself).
type npOp struct {
	x    *npEnd
	ov   uint64
	try  func(commit bool) (code uint32, n int, block bool)
	e    *Emu    // issuing process (pending operations)
	t    *Thread // issuing thread
	done bool
}

func (a *npOp) ready() bool {
	k := a.x.k()
	k.mu.Lock()
	defer k.mu.Unlock()
	if a.done {
		return true
	}
	_, _, block := a.try(false)
	return !block || a.x.closed
}

// unpend removes a from x.pending (kernel lock held).
func (a *npOp) unpend() {
	a.done = true
	a.x.pending = slices.DeleteFunc(a.x.pending, func(p *npOp) bool { return p == a })
}

// run is the pool-thread side of a pending overlapped operation.
func (a *npOp) run(e *Emu) (poolAction, uint64, uint64, uint64) {
	k := a.x.k()
	k.mu.Lock()
	if a.done { // cancelled: CancelIo completed it
		k.mu.Unlock()
		e.endWaitIf()
		return poolExit, 0, 0, 0
	}
	code, n, block := a.try(true)
	if block && a.x.closed {
		code, block = errOperationAborted, false
	}
	if !block {
		a.unpend()
	}
	k.mu.Unlock()
	if block {
		e.block(a.ready, infinite)
		return poolBlocked, 0, 0, 0
	}
	e.endWaitIf()
	k.notify()
	e.ovComplete(a.x, a.ov, code, n, false)
	return poolExit, 0, 0, 0
}

func (a *npOp) returned(*Emu) {}

// npDo runs a for the calling thread: at once if possible, else blocking
// the thread (re-executed when ready) or, for an OVERLAPPED on a handle
// opened for overlapped I/O, through a pool thread (ERROR_IO_PENDING).
// done turns the outcome into the API result.
func (e *Emu) npDo(a *npOp, done func(code uint32, n int) uint64) uint64 {
	k := a.x.k()
	k.mu.Lock()
	code, n, block := a.try(true)
	k.mu.Unlock()
	if !block {
		e.endWaitIf()
		k.notify()
		if a.ov != 0 && (code == 0 || code == errMoreData) {
			e.ovComplete(a.x, a.ov, code, n, true)
		}
		return done(code, n)
	}
	if a.ov != 0 && a.x.overlapped {
		e.Mem.W64(a.ov, statusPending)
		e.Mem.W64(a.ov+8, 0)
		e.setEventObj(e.ovEvent(a.ov), false)
		a.e, a.t = e, e.Cur
		k.mu.Lock()
		a.x.pending = append(a.x.pending, a)
		k.mu.Unlock()
		if _, err := e.startPoolThread(a); err != nil {
			k.mu.Lock()
			a.unpend()
			k.mu.Unlock()
			return e.fail(errNotEnoughMemory)
		}
		return e.fail(errIOPending)
	}
	e.block(a.ready, infinite)
	return 0
}

// npCancel cancels this process's pending overlapped operations on x (t !=
// nil: only those issued by t; ov != 0: only that one): each completes with
// STATUS_CANCELLED (event, packet) as closing the handle would, and its pool
// thread exits. It returns the number cancelled.
func (e *Emu) npCancel(x *npEnd, t *Thread, ov uint64) int {
	k := x.k()
	k.mu.Lock()
	var hit []*npOp
	for _, a := range slices.Clone(x.pending) {
		if a.e == e && (t == nil || a.t == t) && (ov == 0 || a.ov == ov) {
			a.unpend()
			hit = append(hit, a)
		}
	}
	k.mu.Unlock()
	for _, a := range hit {
		e.ovComplete(x, a.ov, errOperationAborted, 0, false)
	}
	if len(hit) > 0 {
		k.notify() // the pool threads see done and exit
	}
	return len(hit)
}

// ---------------------------------------------------------------------------
// API implementations

// npReadOp reads into buf (out of n bytes) from x.
func (e *Emu) npReadOp(x *npEnd, buf uint64, size uint32, ov uint64) *npOp {
	a := &npOp{x: x, ov: ov}
	a.try = func(commit bool) (uint32, int, bool) {
		data, code, block := x.tryRead(int(size), !commit)
		if block {
			return 0, 0, true
		}
		if commit && len(data) > 0 {
			e.Mem.Write(buf, data)
		}
		return code, len(data), false
	}
	return a
}

// npResult returns the result of a transfer and stores its byte count.
func (e *Emu) npResult(count uint64) func(code uint32, n int) uint64 {
	return func(code uint32, n int) uint64 {
		if count != 0 {
			e.Mem.W32(count, uint32(n))
		}
		if code != 0 {
			return e.fail(code)
		}
		return 1
	}
}

func (e *Emu) npRead(x *npEnd, buf uint64, size uint32, nread, ov uint64) uint64 {
	if nread != 0 {
		e.Mem.W32(nread, 0)
	}
	return e.npDo(e.npReadOp(x, buf, size, ov), e.npResult(nread))
}

func (e *Emu) npWrite(x *npEnd, buf uint64, size uint32, nw, ov uint64) uint64 {
	if nw != 0 {
		e.Mem.W32(nw, 0)
	}
	data := e.Mem.ReadBytes(buf, int(size))
	a := &npOp{x: x, ov: ov, try: func(commit bool) (uint32, int, bool) {
		if !commit {
			return 0, 0, false
		}
		if code := x.tryWrite(data); code != 0 {
			return code, 0, false
		}
		return 0, len(data), false
	}}
	return e.npDo(a, e.npResult(nw))
}

// npFlush waits until the other end has read everything written.
func (e *Emu) npFlush(x *npEnd) uint64 {
	a := &npOp{x: x, try: func(bool) (uint32, int, bool) {
		switch {
		case len(x.outQ().msgs) == 0:
			return 0, 0, false
		case x.connErr() != 0:
			return x.connErr(), 0, false
		case x.peerClosed():
			return errBrokenPipe, 0, false
		}
		return 0, 0, true
	}}
	return e.npDo(a, e.npResult(0))
}

func (e *Emu) npConnect(x *npEnd, ov uint64) uint64 {
	if !x.server {
		e.endWaitIf()
		return e.fail(errInvalidHandle)
	}
	k := x.k()
	in := x.inst
	k.mu.Lock()
	st := in.state
	if st == npConnected || st == npClosing {
		k.mu.Unlock()
		if e.inWait() { // a blocked ConnectNamedPipe whose client arrived
			e.endWait()
			return 1
		}
		if st == npConnected {
			return e.fail(errPipeConnected)
		}
		return e.fail(errNoData)
	}
	in.state = npListening
	k.mu.Unlock()
	k.notify()
	if x.nowait { // TRUE only the first time after a disconnect (MSDN)
		if st == npDisconnected {
			return 1
		}
		return e.fail(errPipeListening)
	}
	a := &npOp{x: x, ov: ov, try: func(bool) (uint32, int, bool) {
		if s := in.state; s == npConnected || s == npClosing {
			return 0, 0, false
		}
		return 0, 0, true
	}}
	return e.npDo(a, e.npResult(0))
}

func (e *Emu) npDisconnect(x *npEnd) uint64 {
	if !x.server {
		return e.fail(errInvalidHandle)
	}
	k := x.k()
	in := x.inst
	k.mu.Lock()
	switch in.state {
	case npListening:
		k.mu.Unlock()
		return e.fail(errPipeListening)
	case npDisconnected:
		k.mu.Unlock()
		return e.fail(errPipeNotConnected)
	}
	if in.cli != nil {
		in.cli.detached = true
		in.cli = nil
	}
	in.toSrv, in.toCli = npQueue{}, npQueue{}
	in.state = npDisconnected
	k.mu.Unlock()
	k.notify()
	return 1
}

func (e *Emu) npPeek(x *npEnd, buf uint64, size uint32, nread, avail, left uint64) uint64 {
	k := x.k()
	k.mu.Lock()
	if c := x.connErr(); c != 0 {
		k.mu.Unlock()
		return e.fail(c)
	}
	q := x.inQ()
	if len(q.msgs) == 0 && x.peerClosed() {
		k.mu.Unlock()
		return e.fail(errBrokenPipe)
	}
	var data []byte
	total, rest := q.avail(), 0
	if len(q.msgs) > 0 {
		data, _ = q.take(int(size), x.inst.p.msgType, true)
		if x.inst.p.msgType {
			rest = len(q.msgs[0]) - len(data)
		}
	}
	k.mu.Unlock()
	if buf != 0 && len(data) > 0 {
		e.Mem.Write(buf, data)
	}
	for _, o := range [][2]uint64{{nread, uint64(len(data))}, {avail, uint64(total)}, {left, uint64(rest)}} {
		if o[0] != 0 {
			e.Mem.W32(o[0], uint32(o[1]))
		}
	}
	return 1
}

// npTxn marks a TransactNamedPipe that already wrote its request.
type npTxn struct{}

func (e *Emu) npTransact(x *npEnd, in uint64, inN uint32, out uint64, outN uint32, nread, ov uint64) uint64 {
	t := e.Cur
	if _, ok := t.xop.(npTxn); !ok || !e.inWait() {
		k := x.k()
		data := e.Mem.ReadBytes(in, int(inN))
		k.mu.Lock()
		code := x.connErr()
		if !x.inst.p.msgType || !x.readMsg {
			code = errBadPipe
		}
		if code == 0 && len(x.inQ().msgs) > 0 {
			code = errPipeBusy
		}
		if code == 0 {
			code = x.tryWrite(data)
		}
		k.mu.Unlock()
		k.notify()
		if code != 0 {
			return e.fail(code)
		}
	}
	if nread != 0 {
		e.Mem.W32(nread, 0)
	}
	t.xop = npTxn{}
	r := e.npDo(e.npReadOp(x, out, outN, ov), e.npResult(nread))
	if !t.waiting {
		t.xop = nil
	}
	return r
}

// npCall is the state of a CallNamedPipe across re-execution.
type npCall struct{ x *npEnd }

func (e *Emu) callNamedPipe(name string, in uint64, inN uint32, out uint64, outN uint32, nread uint64, timeout uint32) uint64 {
	t := e.Cur
	k := e.k
	st, resumed := t.xop.(*npCall)
	resumed = resumed && e.inWait()
	if !resumed || st.x == nil {
		key, ok := npKey(name)
		if !ok {
			t.xop = nil
			e.endWaitIf()
			return e.fail(errFileNotFound)
		}
		k.mu.Lock()
		x, code := npConnectClient(k, key, genericRead|genericWrite, 0)
		var dflt uint32
		if p, _ := k.names[key].(*npPipe); p != nil {
			dflt = p.timeout
		}
		if x != nil {
			x.refs = 1 // held by this call
			x.readMsg = true
		}
		k.mu.Unlock()
		if x == nil {
			switch {
			case code != errPipeBusy:
			case resumed && t.waitTimedOut:
				code = errSemTimeout
			case timeout == 1: // NMPWAIT_NOWAIT
			default:
				ms := timeout
				if ms == 0 { // NMPWAIT_USE_DEFAULT_WAIT
					ms = max(dflt, 50)
				}
				t.xop = &npCall{}
				e.block(func() bool {
					k.mu.Lock()
					defer k.mu.Unlock()
					exists, listening := npHasListener(k, key)
					return listening || !exists
				}, ms)
				return 0
			}
			t.xop = nil
			e.endWaitIf()
			return e.fail(code)
		}
		e.endWaitIf()
		k.notify()
		k.mu.Lock()
		code = errInvalidParameter // CallNamedPipe needs a message-type pipe
		if x.inst.p.msgType {
			code = x.tryWrite(e.Mem.ReadBytes(in, int(inN)))
		}
		k.mu.Unlock()
		if code != 0 {
			t.xop = nil
			x.unref()
			return e.fail(code)
		}
		k.notify()
		st = &npCall{x: x}
	}
	t.xop = st
	if nread != 0 {
		e.Mem.W32(nread, 0)
	}
	res := e.npResult(nread)
	return e.npDo(e.npReadOp(st.x, out, outN, 0), func(code uint32, n int) uint64 {
		t.xop = nil
		st.x.unref()
		return res(code, n)
	})
}

func (e *Emu) waitNamedPipe(name string, timeout uint32) uint64 {
	key, ok := npKey(name)
	if !ok {
		e.endWaitIf()
		return e.fail(errFileNotFound)
	}
	k := e.k
	k.mu.Lock()
	exists, listening := npHasListener(k, key)
	var dflt uint32
	if p, _ := k.names[key].(*npPipe); p != nil {
		dflt = p.timeout
	}
	k.mu.Unlock()
	switch {
	case !exists:
		e.endWaitIf()
		return e.fail(errFileNotFound)
	case listening:
		e.endWaitIf()
		return 1
	case e.inWait() && e.Cur.waitTimedOut:
		e.endWait()
		return e.fail(errSemTimeout)
	}
	if timeout == 0 { // NMPWAIT_USE_DEFAULT_WAIT
		timeout = max(dflt, 50)
	}
	e.block(func() bool {
		k.mu.Lock()
		defer k.mu.Unlock()
		exists, listening := npHasListener(k, key)
		return listening || !exists
	}, timeout)
	return 0
}

func init() {
	k := dK32
	regAW(k, "CreateNamedPipe", func(e *Emu, w bool) uint64 {
		return e.createNamedPipe(e.strArg(0, w), e.Arg32(1), e.Arg32(2), e.Arg32(3), e.Arg32(4), e.Arg32(5), e.Arg32(6), e.Arg(7))
	})
	reg(k, "ConnectNamedPipe", func(e *Emu) uint64 {
		x := e.npEndOf(e.Arg(0))
		if x == nil {
			return e.fail(errInvalidHandle)
		}
		return e.npConnect(x, e.Arg(1))
	})
	reg(k, "DisconnectNamedPipe", func(e *Emu) uint64 {
		x := e.npEndOf(e.Arg(0))
		if x == nil {
			return e.fail(errInvalidHandle)
		}
		return e.npDisconnect(x)
	})
	regAW(k, "WaitNamedPipe", func(e *Emu, w bool) uint64 { return e.waitNamedPipe(e.strArg(0, w), e.Arg32(1)) })
	regAW(k, "CallNamedPipe", func(e *Emu, w bool) uint64 {
		return e.callNamedPipe(e.strArg(0, w), e.Arg(1), e.Arg32(2), e.Arg(3), e.Arg32(4), e.Arg(5), e.Arg32(6))
	})
	reg(k, "TransactNamedPipe", func(e *Emu) uint64 {
		x := e.npEndOf(e.Arg(0))
		if x == nil {
			return e.fail(errInvalidHandle)
		}
		return e.npTransact(x, e.Arg(1), e.Arg32(2), e.Arg(3), e.Arg32(4), e.Arg(5), e.Arg(6))
	})
	reg(k, "GetNamedPipeInfo", func(e *Emu) uint64 {
		x := e.npEndOf(e.Arg(0))
		if x == nil {
			return e.fail(errInvalidHandle)
		}
		p := x.inst.p
		var flags uint32
		if x.server {
			flags |= 1 // PIPE_SERVER_END
		}
		if p.msgType {
			flags |= pipeTypeMessage
		}
		for i, v := range []uint32{flags, p.outSize, p.inSize, uint32(p.maxInst)} {
			if a := e.Arg(1 + i); a != 0 {
				e.Mem.W32(a, v)
			}
		}
		return 1
	})
	reg(k, "SetNamedPipeHandleState", func(e *Emu) uint64 {
		x := e.npEndOf(e.Arg(0))
		if x == nil {
			if fo := e.fileObj(e.Arg(0)); fo != nil && fo.kind == filePipe {
				return 1 // anonymous pipe: byte mode only
			}
			return e.fail(errInvalidHandle)
		}
		if m := e.Arg(1); m != 0 {
			mode := e.Mem.R32(m)
			if mode&pipeReadmodeMessage != 0 && !x.inst.p.msgType {
				return e.fail(errInvalidParameter)
			}
			x.k().mu.Lock()
			x.readMsg, x.nowait = mode&pipeReadmodeMessage != 0, mode&pipeNowait != 0
			x.k().mu.Unlock()
		}
		return 1
	})
	reg(dAdv, "ImpersonateNamedPipeClient", func(e *Emu) uint64 {
		x := e.npEndOf(e.Arg(0))
		if x == nil || !x.server {
			return e.fail(errInvalidHandle)
		}
		x.k().mu.Lock()
		ok := x.inst.state == npConnected
		x.k().mu.Unlock()
		if !ok {
			return e.fail(errCannotImpersonate)
		}
		return 1 // the client runs as the same user: the token is unchanged
	})
}
