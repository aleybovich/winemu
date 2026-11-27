//go:build darwin || linux

package win

// Winsock (ws2_32) on real host sockets.
//
// A guest SOCKET is a kernel handle (e.handles) to a *sockObj that owns a
// host socket fd. The host fd is always non-blocking; guest blocking calls
// use the cooperative-retry pattern: the API tries the host call and, when
// it would block, parks the thread with e.sockWait(ready, timeout) where ready
// polls the fd with a zero-timeout select. Other guest threads keep running
// and the call is re-executed when ready() reports readiness.
//
// WSAEventSelect: the scheduler calls e.pollNet on every iteration
// (throttled); it select()s all event-selected sockets, records network
// events following the Windows re-enabling rules and sets the associated
// event object, so WaitForMultipleObjects & co. wake up. The deadlock
// detector stays quiet only while a thread waits in sockWait (a host wait,
// e.blockHost) or a socket has an active WSAEventSelect (netEventsActive).

import (
	"errors"
	"sync"
	"syscall"
	"time"
)

// Windows constants.
const (
	wsAFUnspec = 0
	wsAFInet   = 2
	wsAFInet6  = 23

	wsSockStream = 1
	wsSockDgram  = 2

	wsaEINTR           = 10004
	wsaEBADF           = 10009
	wsaEACCES          = 10013
	wsaEFAULT          = 10014
	wsaEINVAL          = 10022
	wsaEMFILE          = 10024
	wsaEWOULDBLOCK     = 10035
	wsaEINPROGRESS     = 10036
	wsaEALREADY        = 10037
	wsaENOTSOCK        = 10038
	wsaEDESTADDRREQ    = 10039
	wsaEMSGSIZE        = 10040
	wsaEPROTOTYPE      = 10041
	wsaENOPROTOOPT     = 10042
	wsaEPROTONOSUPPORT = 10043
	wsaESOCKTNOSUPPORT = 10044
	wsaEOPNOTSUPP      = 10045
	wsaEAFNOSUPPORT    = 10047
	wsaEADDRINUSE      = 10048
	wsaEADDRNOTAVAIL   = 10049
	wsaENETDOWN        = 10050
	wsaENETUNREACH     = 10051
	wsaECONNABORTED    = 10053
	wsaECONNRESET      = 10054
	wsaENOBUFS         = 10055
	wsaEISCONN         = 10056
	wsaENOTCONN        = 10057
	wsaESHUTDOWN       = 10058
	wsaETIMEDOUT       = 10060
	wsaECONNREFUSED    = 10061
	wsaEHOSTUNREACH    = 10065
	wsaVERNOTSUPPORTED = 10092
	wsaNOTINITIALISED  = 10093
	wsaTYPENOTFOUND    = 10109
	wsaHOSTNOTFOUND    = 11001
	wsaTRYAGAIN        = 11002
	wsaNORECOVERY      = 11003
	wsaNODATA          = 11004

	// network event bits (FD_*_BIT) and masks
	fdReadBit, fdWriteBit, fdOOBBit, fdAcceptBit, fdConnectBit, fdCloseBit = 0, 1, 2, 3, 4, 5
	fdRead, fdWrite, fdOOB, fdAccept, fdConnect, fdClose                   = 1, 2, 4, 8, 16, 32
	fdAllEvents                                                            = 0x3FF

	sockErr = ^uint64(0) // SOCKET_ERROR / INVALID_SOCKET
)

// sockObj is a kernel object: handle inheritance and DuplicateHandle put the
// same object into several processes, whose goroutines then use it
// concurrently. mu guards every field; a winsock API call holds the lock of
// the sockets it works on for its whole duration (sockArg locks, regWS
// unlocks), ready closures and pollNet lock per check. fd is immutable
// except under mu (AcceptEx/DisconnectEx swap it).
type sockObj struct {
	mu         sync.Mutex
	fd         int
	af, typ    int32 // Windows values
	proto      int32
	nonblock   bool // guest-visible non-blocking mode (FIONBIO / WSAEventSelect)
	overlapped bool // created with WSA_FLAG_OVERLAPPED (overlapped ops: WS-B2)
	listening  bool
	connecting bool // non-blocking connect in progress
	connected  bool
	bound      bool
	shutSend   bool   // shutdown(SD_SEND/SD_BOTH) was called
	connErr    uint32 // result of a finished non-blocking connect (until read by SO_ERROR)
	refs       int
	closed     bool

	// WSAEventSelect state
	evt       *eventObj
	evMask    uint32
	evEnabled uint32 // events that may be recorded (re-enabling rules)
	evPending uint32 // recorded, not yet enumerated
	evErr     [10]int32
	closeSeen bool

	exclusive          bool
	lingerOn, lingerS  uint16
	rcvTimeo, sndTimeo uint32
	sendDone           map[*Thread]int // bytes already sent by a blocked send
	recvDone           map[*Thread]int // bytes already received by a blocked MSG_WAITALL recv

	// evOwner is the process whose pollNet records WSAEventSelect events
	// (the one that called WSAEventSelect, or accepted the socket): a single
	// polling owner even when several processes hold the socket.
	evOwner *netState

	ovl sockOvl // overlapped I/O state (winsock_ovl.go)
}

func (s *sockObj) ref() {
	s.mu.Lock()
	s.refs++
	s.mu.Unlock()
}

func (s *sockObj) unref() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs--
	if s.refs > 0 || s.closed {
		return
	}
	s.closed = true
	syscall.Close(s.fd)
	s.fd = -1
}

// isClosed reads closed under the socket lock (ready closures, pollers).
func (s *sockObj) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

type netState struct {
	started  int
	socks    map[*sockObj]bool
	lastPoll time.Time
	statics  map[string]uint64      // per-process static result buffers (hostent, servent, inet_ntoa, ...)
	peekBuf  []byte                 // scratch buffer for MSG_PEEK probes
	lookups  map[*Thread]*lookupJob // running host name queries (asyncLookup)
	held     []*sockObj             // sockets locked by the running API call (sockArg)
	ovl      ovlState               // pending overlapped operations (winsock_ovl.go)
}

// regWS registers a winsock API: the socket locks the call takes through
// sockArg are released when it returns (also on panics such as process exit).
//
// socket, WSASocketA/W, accept and WSAAccept return a SOCKET (64-bit
// INVALID_SOCKET on failure) and WSACreateEvent a HANDLE; all others return
// int/DWORD/BOOL, whose SOCKET_ERROR is the 32-bit -1 in EAX - callers such
// as Go's syscall package compare the full register with 0xFFFFFFFF.
func regWS(dlls, name string, fn Fn) {
	w := wsWrap(fn)
	switch name {
	case "socket", "WSASocketA", "WSASocketW", "accept", "WSAAccept", "WSACreateEvent":
		reg(dlls, name, w)
	default:
		reg(dlls, name, func(e *Emu) uint64 { return uint64(uint32(w(e))) })
	}
}

// wsWrap wraps a winsock API implementation as regWS does.
func wsWrap(fn Fn) Fn {
	return func(e *Emu) uint64 {
		n := e.netSt()
		mark := len(n.held)
		defer e.releaseSocks(mark)
		return fn(e)
	}
}

// lockSock locks s for the rest of the running API call.
func (e *Emu) lockSock(s *sockObj) {
	n := e.netSt()
	for _, x := range n.held {
		if x == s {
			return // already locked by this call
		}
	}
	s.mu.Lock()
	n.held = append(n.held, s)
	if !n.socks[s] {
		n.socks[s] = true // first use in this process (inherited/duplicated)
	}
}

// unlockSock releases one socket locked by this call before it returns.
func (e *Emu) unlockSock(s *sockObj) {
	n := e.net
	for i, x := range n.held {
		if x == s {
			n.held = append(n.held[:i], n.held[i+1:]...)
			s.mu.Unlock()
			return
		}
	}
}

func (e *Emu) releaseSocks(mark int) {
	n := e.net
	for len(n.held) > mark {
		s := n.held[len(n.held)-1]
		n.held = n.held[:len(n.held)-1]
		s.mu.Unlock()
	}
}

// unlockedCall runs f (which runs guest code: callbacks, nested scheduling)
// with the call's socket locks released, so other threads and processes can
// use those sockets meanwhile; the locks are re-taken afterwards.
func (e *Emu) unlockedCall(f func()) {
	n := e.netSt()
	held := n.held
	n.held = nil
	for i := len(held) - 1; i >= 0; i-- {
		held[i].mu.Unlock()
	}
	defer func() {
		for _, s := range held {
			s.mu.Lock()
		}
		n.held = append(held, n.held...)
	}()
	f()
}

func (e *Emu) netSt() *netState {
	if e.net == nil {
		e.net = &netState{socks: map[*sockObj]bool{}}
	}
	return e.net
}

// netEventsActive reports whether the process waits for host socket
// readiness: pending overlapped operations or an active WSAEventSelect
// (whose event pollNet may set at any time). The scheduler then keeps
// polling instead of treating waiters as blocked forever. An open socket
// nobody selected events on does not count, so real deadlocks are reported.
// idle calls it right before sleeping, so it also arms the host poller
// (winsock_poller.go) that ends the sleep when an fd becomes ready.
func (e *Emu) netEventsActive() bool {
	n := e.net
	if n == nil {
		return false
	}
	active := len(n.ovl.ops) > 0
	for s := range n.socks {
		if active {
			break
		}
		s.mu.Lock()
		active = s.evOwner == n && s.evMask != 0 && s.evt != nil && !s.closed
		s.mu.Unlock()
	}
	if active {
		e.armPoller()
	}
	return active
}

// wsaErr maps a host error to a WSA error code.
func wsaErr(err error) uint32 {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return wsaEINVAL
	}
	switch en {
	case syscall.EAGAIN:
		return wsaEWOULDBLOCK
	case syscall.EINPROGRESS:
		return wsaEWOULDBLOCK
	case syscall.EALREADY:
		return wsaEALREADY
	case syscall.EINTR:
		return wsaEINTR
	case syscall.EBADF:
		return wsaENOTSOCK
	case syscall.EACCES, syscall.EPERM:
		return wsaEACCES
	case syscall.EFAULT:
		return wsaEFAULT
	case syscall.EINVAL:
		return wsaEINVAL
	case syscall.EMFILE, syscall.ENFILE:
		return wsaEMFILE
	case syscall.ENOTSOCK:
		return wsaENOTSOCK
	case syscall.EDESTADDRREQ:
		return wsaEDESTADDRREQ
	case syscall.EMSGSIZE:
		return wsaEMSGSIZE
	case syscall.EPROTOTYPE:
		return wsaEPROTOTYPE
	case syscall.ENOPROTOOPT:
		return wsaENOPROTOOPT
	case syscall.EPROTONOSUPPORT:
		return wsaEPROTONOSUPPORT
	case syscall.ESOCKTNOSUPPORT:
		return wsaESOCKTNOSUPPORT
	case syscall.EOPNOTSUPP:
		return wsaEOPNOTSUPP
	case syscall.EAFNOSUPPORT:
		return wsaEAFNOSUPPORT
	case syscall.EADDRINUSE:
		return wsaEADDRINUSE
	case syscall.EADDRNOTAVAIL:
		return wsaEADDRNOTAVAIL
	case syscall.ENETDOWN:
		return wsaENETDOWN
	case syscall.ENETUNREACH:
		return wsaENETUNREACH
	case syscall.ECONNABORTED:
		return wsaECONNABORTED
	case syscall.ECONNRESET:
		return wsaECONNRESET
	case syscall.ENOBUFS, syscall.ENOMEM:
		return wsaENOBUFS
	case syscall.EISCONN:
		return wsaEISCONN
	case syscall.ENOTCONN:
		return wsaENOTCONN
	case syscall.EPIPE, syscall.ESHUTDOWN:
		return wsaESHUTDOWN
	case syscall.ETIMEDOUT:
		return wsaETIMEDOUT
	case syscall.ECONNREFUSED:
		return wsaECONNREFUSED
	case syscall.EHOSTUNREACH, syscall.EHOSTDOWN:
		return wsaEHOSTUNREACH
	}
	return wsaEINVAL
}

func isAgain(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}

// wsaFail sets the WSA last error and returns SOCKET_ERROR.
func (e *Emu) wsaFail(code uint32) uint64 {
	e.SetLastError(code)
	return sockErr
}

// sockArg returns the socket of argument i, or nil after setting the error.
// A socket closed while a call on it was blocked fails the call with WSAEINTR.
// The socket is locked until the API call returns (regWS).
func (e *Emu) sockArg(i int) *sockObj {
	if s, ok := e.handles.get(e.Arg(i)).(*sockObj); ok {
		e.lockSock(s)
		if !s.closed {
			return s
		}
	}
	if e.inWait() {
		e.endWait()
		e.SetLastError(wsaEINTR)
	} else {
		e.SetLastError(wsaENOTSOCK)
	}
	return nil
}

// resumeWait ends a wait this call was re-executed from; it reports whether
// the wait timed out.
func (e *Emu) resumeWait() bool {
	if e.inWait() {
		return e.endWait()
	}
	return false
}

// fdReady polls one fd: readable (write=false) or writable/errored.
func fdReady(fd int, write bool) bool {
	r, w := fdPoll([]int{fd})
	if write {
		return w[0]
	}
	return r[0]
}

// fdPoll returns readability and writability (incl. error) for each fd.
// Fds that select cannot handle are reported ready so callers retry the
// host call itself.
func fdPoll(fds []int) (rd, wr []bool) {
	rd, wr = make([]bool, len(fds)), make([]bool, len(fds))
	var r, w, x syscall.FdSet
	hi := -1
	for i, fd := range fds {
		if fd < 0 || fd >= len(r.Bits)*fdSetWordBits {
			rd[i], wr[i] = true, true
			continue
		}
		sockFdSet(&r, fd)
		sockFdSet(&w, fd)
		sockFdSet(&x, fd)
		hi = max(hi, fd)
	}
	if hi < 0 {
		return
	}
	for {
		err := hostSelect(hi+1, &r, &w, &x)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			for i := range fds {
				rd[i], wr[i] = true, true
			}
			return
		}
		break
	}
	for i, fd := range fds {
		if fd < 0 || fd >= len(r.Bits)*fdSetWordBits {
			continue
		}
		rd[i] = sockFdIsSet(&r, fd) || sockFdIsSet(&x, fd)
		wr[i] = sockFdIsSet(&w, fd) || sockFdIsSet(&x, fd)
	}
	return
}

// blockSock parks the current call until s is readable/writable, the socket
// is closed, or timeoutMs (0 = infinite) passes; the call is re-executed.
func (e *Emu) blockSock(s *sockObj, write bool, timeoutMs uint32) uint64 {
	e.sockWait(func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closed || fdReady(s.fd, write)
	}, timeoutOrInfinite(timeoutMs))
	return 0
}

// sockWait is the single place where a winsock call parks the current thread
// until host socket state satisfies ready (polled by the scheduler) or
// timeoutMs (infinite allowed) passes; the API call is then re-executed.
// It is a host wait (blockHost), so the deadlock detector stays quiet.
func (e *Emu) sockWait(ready func() bool, timeoutMs uint32) {
	e.blockHost(ready, timeoutMs)
}

// timeoutOrInfinite maps a socket timeout option (0 = none) to a wait timeout.
func timeoutOrInfinite(ms uint32) uint32 {
	if ms == 0 {
		return infinite
	}
	return ms
}
