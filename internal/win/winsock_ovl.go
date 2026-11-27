//go:build darwin || linux

package win

// Overlapped socket I/O.
//
// An overlapped call first tries the host operation (non-blocking fd). If it
// completes, the call returns success and the completion is indicated at once
// (OVERLAPPED written, hEvent set, a completion packet queued unless
// FILE_SKIP_COMPLETION_PORT_ON_SUCCESS, or the completion routine queued as an
// APC). If it would block, OVERLAPPED.Internal becomes STATUS_PENDING, the
// operation goes on the issuing process's pending list (ovlState.ops) and the
// call fails with WSA_IO_PENDING. pollNet (each scheduler iteration, and at
// once when the host poller of winsock_poller.go sees readiness) select()s
// the fds of the pending operations, retries the ready ones and indicates
// their completion. Operations are per process: they complete on the issuing
// process's goroutine, which owns the guest memory they write.
//
// While a process has pending operations it is never "blocked forever" for
// the deadlock detector (netEventsActive), so every wait for a completion
// (GetQueuedCompletionStatus, the OVERLAPPED event, GetOverlappedResult) is
// a host wait.

import "syscall"

const (
	wsaOperationAborted = 995 // = ERROR_OPERATION_ABORTED
	wsaIOIncomplete     = 996 // = ERROR_IO_INCOMPLETE
	wsaIOPending        = 997 // = ERROR_IO_PENDING

	errOperAborted = 995
)

// socket status table: NTSTATUS <-> WSA error (the Win32 error of each
// status is in ntStatusWin32, kernel32.go).
var sockStatuses = []struct{ st, wsa uint32 }{
	{statusCancelled, wsaOperationAborted},
	{statusBufferOverflow, wsaEMSGSIZE},
	{statusConnReset, wsaECONNRESET},
	{statusRemoteDisconnect, wsaECONNRESET},
	{statusLocalDisconnect, wsaECONNABORTED},
	{statusConnAborted, wsaECONNABORTED},
	{statusConnRefused, wsaECONNREFUSED},
	{statusGracefulDisc, wsaEDISCON},
	{statusIOTimeout, wsaETIMEDOUT},
	{statusNetUnreachable, wsaENETUNREACH},
	{statusHostUnreachable, wsaEHOSTUNREACH},
	{statusAddrAlreadyExists, wsaEADDRINUSE},
	{statusInvalidAddrComp, wsaEADDRNOTAVAIL},
	{statusInvalidParam, wsaEINVAL},
}

const wsaEDISCON = 10101

// wsaStatus maps a WSA error to the NTSTATUS stored in OVERLAPPED.Internal.
// Errors without an NTSTATUS equivalent are stored as 0xC0F0xxxx (custom
// error codes) so the WSA code survives the round trip.
func wsaStatus(code uint32) uint32 {
	if code == 0 {
		return statusSuccess
	}
	for _, x := range sockStatuses {
		if x.wsa == code {
			return x.st
		}
	}
	return 0xC0F00000 | code&0xFFFF
}

// statusWSA maps an OVERLAPPED status back to a WSA error (0 = success).
func statusWSA(st uint32) uint32 {
	if st&0xC0000000 != 0xC0000000 && st != statusBufferOverflow {
		return 0
	}
	if st&0xFFFF0000 == 0xC0F00000 {
		return st & 0xFFFF
	}
	for _, x := range sockStatuses {
		if x.st == st {
			return x.wsa
		}
	}
	return ntToWin(st)
}

type opKind int

const (
	opRecv opKind = iota
	opSend
	opAccept
	opConnect
	opOther // completed at issue (WSAIoctl, DisconnectEx)
)

// ovOp is one pending overlapped operation of this process.
type ovOp struct {
	kind    opKind
	s       *sockObj
	t       *Thread // issuing thread (CancelIo, completion routine)
	ov      uint64  // guest OVERLAPPED
	event   *eventObj
	noPort  bool   // hEvent had its low bit set: no completion packet
	routine uint64 // completion routine (APC) or 0

	addrs []uint64 // WSABUF array, read at issue
	lens  []int64
	total int64
	flags uint32           // MSG_* flags
	to    syscall.Sockaddr // WSASendTo destination
	from  uint64           // WSARecvFrom lpFrom / lpFromlen
	flen  uint64
	done  int    // bytes sent so far (send, ConnectEx data)
	data  []byte // host data to send instead of the buffers (TransmitFile)

	as         *sockObj // AcceptEx: accept socket and output buffer
	buf        uint64
	rxLen      uint32
	lLen, rLen uint32
	accepted   bool
	connected  bool // ConnectEx: connection established, sending data
}

// ovlState is the per-process overlapped-I/O state (owned by its goroutine).
type ovlState struct {
	ops      []*ovOp
	apcs     map[*Thread][]apcCall
	poller   *netPoller
	progress int // completions + recorded network events (poller cooldown)
}

// sockOvl is the overlapped/IOCP state of a socket (guarded by sockObj.mu).
type sockOvl struct {
	port      *iocpObj // associated completion port
	key       uint64   // completion key
	skipPort  bool     // FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
	acceptCtx bool     // AcceptEx'd, SO_UPDATE_ACCEPT_CONTEXT pending
}

// read returns the bytes the op's buffers hold (send data), from offset done.
func (e *Emu) opData(op *ovOp) []byte {
	if op.data != nil {
		return op.data[min(op.done, len(op.data)):]
	}
	b := make([]byte, 0, op.total)
	for i, a := range op.addrs {
		b = append(b, e.Mem.ReadBytes(a, int(op.lens[i]))...)
	}
	return b[min(op.done, len(b)):]
}

// scatter writes received data into the op's buffers.
func (e *Emu) opScatter(op *ovOp, p []byte) {
	for i, a := range op.addrs {
		if len(p) == 0 {
			break
		}
		k := min(int(op.lens[i]), len(p))
		e.Mem.Write(a, p[:k])
		p = p[k:]
	}
}

// complete indicates the completion of op (called with op.s locked): writes
// OVERLAPPED.Internal/InternalHigh, then queues the completion routine, or
// sets the event and queues a completion packet. sync is true when the
// issuing call itself returns success (FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
// then suppresses the packet).
func (e *Emu) complete(op *ovOp, st uint32, n uint32, sync bool) {
	e.net.ovl.progress++
	m := e.Mem
	m.W64(op.ov, uint64(st))
	m.W64(op.ov+8, uint64(n))
	if op.kind == opRecv {
		m.W32(op.ov+16, 0) // flags reported by WSAGetOverlappedResult (no MSG_PARTIAL)
	}
	if op.routine != 0 {
		// void CALLBACK routine(DWORD dwError, DWORD cbTransferred, LPWSAOVERLAPPED, DWORD dwFlags)
		e.queueAPC(op.t, op.routine, uint64(statusWSA(st)), uint64(n), op.ov, 0)
		return
	}
	if op.event != nil {
		e.setNetEvent(op.event, true)
	}
	if p := op.s.ovl.port; p != nil && !op.noPort && !(sync && op.s.ovl.skipPort) {
		p.post(iocpPacket{n: n, key: op.s.ovl.key, ov: op.ov, st: st})
	}
}

// tryOp runs one non-blocking attempt of op (op.s locked; op.as too for
// AcceptEx). again reports that the operation must wait for readiness.
func (e *Emu) tryOp(op *ovOp) (st, n uint32, again bool) {
	s := op.s
	switch op.kind {
	case opRecv:
		return e.tryRecv(op, s.fd)
	case opSend:
		return e.trySend(op, s.fd)
	case opConnect:
		if !op.connected {
			if !fdReady(s.fd, true) {
				return 0, 0, true
			}
			s.connecting = false
			v, err := syscall.GetsockoptInt(s.fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
			switch {
			case err != nil:
				return wsaStatus(wsaErr(err)), 0, false
			case v != 0:
				return wsaStatus(wsaErr(syscall.Errno(v))), 0, false
			}
			op.connected, s.connected = true, true
			s.evEnabled |= fdWrite & s.evMask
		}
		if op.total == 0 {
			return statusSuccess, 0, false
		}
		return e.trySend(op, s.fd)
	case opAccept:
		if !op.accepted {
			syscall.ForkLock.RLock()
			nfd, sa, err := syscall.Accept(s.fd)
			if err == nil {
				syscall.CloseOnExec(nfd)
			}
			syscall.ForkLock.RUnlock()
			if err != nil {
				if isAgain(err) || err == syscall.ECONNABORTED {
					return 0, 0, true
				}
				return wsaStatus(wsaErr(err)), 0, false
			}
			if err := syscall.SetNonblock(nfd, true); err != nil {
				syscall.Close(nfd)
				return wsaStatus(wsaErr(err)), 0, false
			}
			as := op.as
			syscall.Close(as.fd)
			as.fd = nfd
			as.connected, as.bound, as.ovl.acceptCtx = true, true, true
			op.accepted = true
			// local and remote address after the receive data: int32 length + sockaddr
			// (the layout GetAcceptExSockaddrs reads)
			put := func(a uint64, sa syscall.Sockaddr) {
				if sa == nil {
					return
				}
				b := encodeSockaddr(sa)
				e.Mem.W32(a, uint32(len(b)))
				e.Mem.Write(a+4, b)
			}
			if la, err := syscall.Getsockname(nfd); err == nil {
				put(op.buf+uint64(op.rxLen), la)
			}
			put(op.buf+uint64(op.rxLen)+uint64(op.lLen), sa)
		}
		if op.rxLen == 0 {
			return statusSuccess, 0, false
		}
		// receive the first block of data
		op.addrs, op.lens, op.total = []uint64{op.buf}, []int64{int64(op.rxLen)}, int64(op.rxLen)
		return e.tryRecv(op, op.as.fd)
	}
	return statusInvalidParam, 0, false
}

func (e *Emu) tryRecv(op *ovOp, fd int) (st, n uint32, again bool) {
	hf, _ := hostMsgFlags(op.flags)
	p := make([]byte, max(op.total, 1))
	got, _, rflags, sa, err := syscall.Recvmsg(fd, p[:op.total], nil, hf)
	switch {
	case isAgain(err):
		return 0, 0, true
	case err != nil:
		return wsaStatus(wsaErr(err)), 0, false
	}
	e.opScatter(op, p[:got])
	if op.from != 0 && sa != nil {
		e.writeSockaddr(sa, op.from, op.flen)
	}
	if op.kind == opRecv && op.s.typ == wsSockStream {
		op.s.evEnabled |= (fdRead | fdOOB) & op.s.evMask
	}
	if rflags&syscall.MSG_TRUNC != 0 && op.s.typ != wsSockStream {
		return statusBufferOverflow, uint32(got), false
	}
	return statusSuccess, uint32(got), false
}

func (e *Emu) trySend(op *ovOp, fd int) (st, n uint32, again bool) {
	hf, _ := hostMsgFlags(op.flags)
	data := e.opData(op)
	got, err := 0, error(nil)
	if len(data) > 0 || op.s.typ != wsSockStream {
		got, err = syscall.SendmsgN(fd, data, nil, op.to, hf)
	}
	switch {
	case err == syscall.EPIPE:
		return statusConnReset, uint32(op.done), false
	case err != nil && !isAgain(err):
		return wsaStatus(wsaErr(err)), uint32(op.done), false
	}
	op.done += max(got, 0)
	if op.done < int(op.total) && op.s.typ == wsSockStream {
		return 0, 0, true
	}
	if isAgain(err) {
		return 0, 0, true
	}
	return statusSuccess, uint32(op.done), false
}

// startOp issues op (op.s locked by the calling API). It returns done=true
// with the result of an immediate completion (indicated already), or
// done=false when the operation is pending.
func (e *Emu) startOp(op *ovOp, hEvent uint64) (done bool, st, n uint32) {
	e.opEvent(op, hEvent)
	st, n, again := e.tryOp(op)
	if !again {
		if st == statusSuccess || st == statusBufferOverflow {
			e.complete(op, st, n, true)
		}
		return true, st, n
	}
	e.Mem.W64(op.ov, statusPending)
	e.Mem.W64(op.ov+8, 0)
	ns := e.netSt()
	ns.ovl.ops = append(ns.ovl.ops, op)
	return false, 0, 0
}

// opEvent records the issuing thread and OVERLAPPED.hEvent of op (ignored
// with a completion routine; its low bit suppresses the completion packet).
func (e *Emu) opEvent(op *ovOp, hEvent uint64) {
	op.t = e.Cur
	if hEvent != 0 && op.routine == 0 {
		op.noPort = hEvent&1 != 0
		if ev, ok := e.handles.get(hEvent &^ 1).(*eventObj); ok {
			op.event = ev
			e.setNetEvent(ev, false) // the event is reset when the operation starts
		}
	}
}

// indicateNow indicates the immediate successful completion of an
// operation that has no asynchronous part (WSAIoctl, DisconnectEx).
func (e *Emu) indicateNow(s *sockObj, ov, routine uint64, n uint32) {
	op := &ovOp{kind: opOther, s: s, ov: ov, routine: routine}
	e.opEvent(op, e.Mem.R64(ov+24))
	e.complete(op, statusSuccess, n, true)
}

// opWantsWrite reports whether a pending op waits for writability (send,
// connect + its data) rather than readability (recv, accept + first data).
func opWantsWrite(op *ovOp) bool { return op.kind == opSend || op.kind == opConnect }

// pollOverlapped retries the pending operations whose fds are ready
// (called by pollNet on the process's goroutine).
func (e *Emu) pollOverlapped() {
	n := e.net
	if n == nil || len(n.ovl.ops) == 0 {
		return
	}
	ops := n.ovl.ops
	fds := make([]int, len(ops))
	for i, op := range ops {
		op.s.mu.Lock()
		fds[i] = op.s.fd
		if op.kind == opAccept && op.accepted {
			fds[i] = op.as.fd
		}
		op.s.mu.Unlock()
	}
	rd, wr := fdPoll(fds)
	keep := ops[:0:0]
	for i, op := range ops {
		ready := rd[i]
		if opWantsWrite(op) {
			ready = wr[i]
		}
		if !ready && !op.s.isClosed() {
			keep = append(keep, op)
			continue
		}
		if !e.retryOp(op) {
			keep = append(keep, op)
		}
	}
	// operations issued meanwhile (completion routines do not run here) are kept
	n.ovl.ops = append(keep, n.ovl.ops[len(ops):]...)
}

// retryOp retries one pending op; it reports whether the op is finished.
func (e *Emu) retryOp(op *ovOp) bool {
	s := op.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if op.as != nil && op.as != s {
		op.as.mu.Lock()
		defer op.as.mu.Unlock()
	}
	if s.closed || op.as != nil && op.as.closed {
		e.complete(op, statusCancelled, 0, false)
		return true
	}
	st, cnt, again := e.tryOp(op)
	if again {
		return false
	}
	e.complete(op, st, cnt, false)
	return true
}

// cancelOps aborts this process's pending operations on s (CancelIo: those
// of thread t only; CancelIoEx: ov != 0 selects one). It is called with s
// locked and returns the number cancelled.
func (e *Emu) cancelOps(s *sockObj, t *Thread, ov uint64) int {
	n := e.net
	if n == nil {
		return 0
	}
	cnt := 0
	keep := n.ovl.ops[:0:0]
	for _, op := range n.ovl.ops {
		if op.s != s || t != nil && op.t != t || ov != 0 && op.ov != ov {
			keep = append(keep, op)
			continue
		}
		if op.as != nil && op.as != s {
			op.as.mu.Lock()
		}
		e.complete(op, statusCancelled, 0, false)
		if op.as != nil && op.as != s {
			op.as.mu.Unlock()
		}
		cnt++
	}
	n.ovl.ops = keep
	return cnt
}
