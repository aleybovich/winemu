//go:build darwin || linux

package win

import "syscall"

const (
	cfAccept = 0
	cfReject = 1
	cfDefer  = 2
)

// accept implements accept and WSAAccept (cond = condition callback or 0).
func (e *Emu) accept(cond uint64) uint64 {
	s := e.sockArg(0)
	if s == nil {
		return sockErr
	}
	e.resumeWait() // accept has no timeout
	addr, lenp := e.Arg(1), e.Arg(2)
	if !s.listening {
		return e.wsaFail(wsaEINVAL)
	}
	if addr != 0 && (lenp == 0 || int64(int32(e.Mem.R32(lenp))) < int64(sockaddrLen(s.af))) {
		return e.wsaFail(wsaEFAULT)
	}
	s.evEnabled |= fdAccept & s.evMask
	syscall.ForkLock.RLock()
	nfd, sa, err := syscall.Accept(s.fd)
	if err == nil {
		syscall.CloseOnExec(nfd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		if isAgain(err) || err == syscall.ECONNABORTED {
			if s.nonblock {
				return e.wsaFail(wsaEWOULDBLOCK)
			}
			return e.blockSock(s, false, 0)
		}
		return e.wsaFail(wsaErr(err))
	}
	if err := syscall.SetNonblock(nfd, true); err != nil {
		syscall.Close(nfd)
		return e.wsaFail(wsaErr(err))
	}
	if cond != 0 {
		switch e.acceptCondition(cond, sa, nfd) {
		case cfAccept:
		case cfDefer:
			syscall.Close(nfd)
			return e.wsaFail(wsaTRYAGAIN)
		default:
			syscall.Close(nfd)
			return e.wsaFail(wsaECONNREFUSED)
		}
	}
	// the accepted socket inherits the listener's properties, incl. WSAEventSelect
	ns := &sockObj{fd: nfd, af: s.af, typ: s.typ, proto: s.proto, overlapped: s.overlapped,
		connected: true, bound: true, nonblock: s.nonblock,
		evt: s.evt, evMask: s.evMask, evEnabled: s.evMask, evOwner: e.netSt()}
	h := e.addSocket(ns)
	if addr != 0 {
		e.writeSockaddr(sa, addr, lenp)
	}
	return h
}

// acceptCondition calls a WSAAccept condition function:
// int CALLBACK cond(LPWSABUF CallerId, LPWSABUF CallerData, LPQOS, LPQOS,
//
//	LPWSABUF CalleeId, LPWSABUF CalleeData, GROUP *g, DWORD_PTR data)
func (e *Emu) acceptCondition(cond uint64, peer syscall.Sockaddr, nfd int) uint64 {
	wsabuf := func(b []byte) uint64 { // WSABUF {ULONG len; CHAR *buf}
		if b == nil {
			return 0
		}
		p := e.heapAlloc(16+uint64(len(b)), true)
		e.Mem.W32(p, uint32(len(b)))
		e.Mem.W64(p+8, p+16)
		e.Mem.Write(p+16, b)
		return p
	}
	var local []byte
	if sa, err := syscall.Getsockname(nfd); err == nil {
		local = encodeSockaddr(sa)
	}
	caller, callee := wsabuf(encodeSockaddr(peer)), wsabuf(local)
	group := e.heapAlloc(8, true)
	var r uint64
	e.unlockedCall(func() { r = e.CallGuest(cond, caller, 0, 0, 0, callee, 0, group, e.Arg(4)) })
	for _, p := range []uint64{caller, callee, group} {
		if p != 0 {
			e.heap.freeBlock(p)
		}
	}
	return uint64(uint32(r))
}

// finishConnect resolves a pending non-blocking connect if the host has
// completed it. It reports whether the connect is no longer in progress.
func (e *Emu) finishConnect(s *sockObj) bool {
	if !s.connecting {
		return true
	}
	if !fdReady(s.fd, true) {
		return false
	}
	s.connecting = false
	v, err := syscall.GetsockoptInt(s.fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	switch {
	case err != nil:
		s.connErr = wsaErr(err)
	case v != 0:
		s.connErr = wsaErr(syscall.Errno(v))
	default:
		s.connected = true
		s.evEnabled |= fdWrite & s.evMask
	}
	return true
}

func (e *Emu) connect() uint64 {
	s := e.sockArg(0)
	if s == nil {
		return sockErr
	}
	if e.inWait() {
		// re-executed blocking connect
		e.resumeWait()
		if s.connecting && !e.finishConnect(s) {
			return e.blockSock(s, true, 0)
		}
		if code := s.connErr; code != 0 {
			s.connErr = 0
			return e.wsaFail(code)
		}
		if s.connected {
			return 0
		}
	}
	switch {
	case s.listening:
		return e.wsaFail(wsaEINVAL)
	case s.connecting:
		if !e.finishConnect(s) {
			return e.wsaFail(wsaEALREADY)
		}
		if s.connErr != 0 {
			return e.wsaFail(s.connErr)
		}
		return e.wsaFail(wsaEISCONN)
	case s.connected && s.typ == wsSockStream:
		return e.wsaFail(wsaEISCONN)
	}
	sa, code := e.readSockaddr(e.Arg(1), int64(int32(e.Arg32(2))))
	if code != 0 {
		return e.wsaFail(code)
	}
	s.connErr = 0
	s.evEnabled |= fdConnect & s.evMask
	err := syscall.Connect(s.fd, sa)
	s.bound = true
	if err == nil {
		s.connected = true
		s.evEnabled |= fdWrite & s.evMask
		if s.evMask&fdConnect != 0 {
			e.postNetEvent(s, fdConnectBit, 0)
		}
		return 0
	}
	if err != syscall.EINPROGRESS && !isAgain(err) {
		if s.evMask&fdConnect != 0 {
			e.postNetEvent(s, fdConnectBit, wsaErr(err))
		}
		return e.wsaFail(wsaErr(err))
	}
	s.connecting = true
	if s.nonblock {
		return e.wsaFail(wsaEWOULDBLOCK)
	}
	return e.blockSock(s, true, 0)
}
