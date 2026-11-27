//go:build darwin || linux

package win

import "syscall"

// Data transfer: send/recv/sendto/recvfrom, ioctlsocket.

const (
	wsMsgOOB       = 1
	wsMsgPeek      = 2
	wsMsgDontRoute = 4
	wsMsgWaitAll   = 8

	wsFIONBIO    = 0x8004667E
	wsFIONREAD   = 0x4004667F
	wsSIOCATMARK = 0x40047307

	peekBufSize = 64 << 10
)

// hostMsgFlags maps Windows MSG_* flags (except MSG_WAITALL, emulated) to
// host flags; ok is false for unsupported flags.
func hostMsgFlags(f uint32) (int, bool) {
	if f&^uint32(wsMsgOOB|wsMsgPeek|wsMsgDontRoute|wsMsgWaitAll) != 0 {
		return 0, false
	}
	h := 0
	if f&wsMsgOOB != 0 {
		h |= syscall.MSG_OOB
	}
	if f&wsMsgPeek != 0 {
		h |= syscall.MSG_PEEK
	}
	if f&wsMsgDontRoute != 0 {
		h |= syscall.MSG_DONTROUTE
	}
	return h, true
}

// peekAvail returns how many bytes (up to peekBufSize) a recv would return
// now (first datagram size for datagram sockets); eof is set for an orderly
// shutdown or a connection error.
func (e *Emu) peekAvail(s *sockObj) (n int, eof bool) {
	ns := e.netSt()
	if ns.peekBuf == nil {
		ns.peekBuf = make([]byte, peekBufSize)
	}
	n, _, err := syscall.Recvfrom(s.fd, ns.peekBuf, syscall.MSG_PEEK)
	switch {
	case err != nil:
		return 0, !isAgain(err)
	case n == 0 && s.typ == wsSockStream:
		return 0, true
	}
	return n, false
}

// sendCommon implements send/sendto (to == nil: connected destination).
func (e *Emu) sendCommon(s *sockObj, buf uint64, n int64, flags uint32, to syscall.Sockaddr) uint64 {
	timedOut := e.resumeWait()
	t := e.Cur
	hf, ok := hostMsgFlags(flags &^ wsMsgWaitAll)
	switch {
	case !ok:
		return e.wsaFail(wsaEOPNOTSUPP)
	case n < 0:
		return e.wsaFail(wsaEFAULT)
	case s.shutSend:
		return e.wsaFail(wsaESHUTDOWN)
	case s.typ == wsSockStream && !s.connected:
		e.finishConnect(s)
		if !s.connected {
			return e.wsaFail(wsaENOTCONN)
		}
	}
	if s.typ == wsSockStream {
		to = nil // ignored for connection-oriented sockets
	}
	done := 0
	if s.sendDone != nil {
		done = s.sendDone[t]
		delete(s.sendDone, t)
	}
	data := e.Mem.ReadBytes(buf+uint64(done), int(n)-done)
	var got int
	var err error
	if len(data) > 0 || s.typ != wsSockStream {
		got, err = syscall.SendmsgN(s.fd, data, nil, to, hf)
	}
	if err != nil && !isAgain(err) {
		if err == syscall.EPIPE {
			return e.wsaFail(wsaECONNRESET)
		}
		return e.wsaFail(wsaErr(err))
	}
	done += max(got, 0)
	if done >= int(n) || (s.nonblock && done > 0) {
		return uint64(done)
	}
	if s.nonblock {
		s.evEnabled |= fdWrite & s.evMask
		return e.wsaFail(wsaEWOULDBLOCK)
	}
	if timedOut {
		return e.wsaFail(wsaETIMEDOUT)
	}
	if s.sendDone == nil {
		s.sendDone = map[*Thread]int{}
	}
	s.sendDone[t] = done
	return e.blockSock(s, true, s.sndTimeo)
}

// recvCommon implements recv/recvfrom; from/fromlen may be 0.
func (e *Emu) recvCommon(s *sockObj, buf uint64, n int64, flags uint32, from, fromlen uint64) uint64 {
	timedOut := e.resumeWait()
	hf, ok := hostMsgFlags(flags)
	switch {
	case !ok:
		return e.wsaFail(wsaEOPNOTSUPP)
	case n < 0:
		return e.wsaFail(wsaEFAULT)
	case s.typ == wsSockStream && !s.connected:
		e.finishConnect(s)
		if !s.connected {
			return e.wsaFail(wsaENOTCONN)
		}
	case s.typ != wsSockStream && !s.bound:
		return e.wsaFail(wsaEINVAL)
	}
	if from != 0 && (fromlen == 0 || int64(int32(e.Mem.R32(fromlen))) < int64(sockaddrLen(s.af))) {
		return e.wsaFail(wsaEFAULT)
	}
	s.evEnabled |= (fdRead | fdOOB) & s.evMask
	// MSG_WAITALL on a blocking stream socket: keep receiving until n bytes
	// or EOF; the bytes received so far survive re-execution in recvDone.
	waitAll := flags&wsMsgWaitAll != 0 && s.typ == wsSockStream && !s.nonblock && flags&wsMsgPeek == 0
	t := e.Cur
	done := 0
	if waitAll && s.recvDone != nil {
		done = s.recvDone[t]
		delete(s.recvDone, t)
	}
	p := make([]byte, n-int64(done))
	got, _, rflags, sa, err := syscall.Recvmsg(s.fd, p, nil, hf)
	if err == nil && got > 0 {
		e.Mem.Write(buf+uint64(done), p[:got])
	}
	if err != nil && !isAgain(err) {
		if done > 0 {
			return uint64(done)
		}
		return e.wsaFail(wsaErr(err))
	}
	if err == nil {
		done += got
		if waitAll && got > 0 && int64(done) < n {
			err = syscall.EAGAIN // wait for the rest
		}
	}
	if err != nil {
		switch {
		case s.nonblock:
			return e.wsaFail(wsaEWOULDBLOCK)
		case timedOut && done > 0:
			return uint64(done)
		case timedOut:
			return e.wsaFail(wsaETIMEDOUT)
		}
		if done > 0 {
			if s.recvDone == nil {
				s.recvDone = map[*Thread]int{}
			}
			s.recvDone[t] = done
		}
		return e.blockSock(s, false, s.rcvTimeo)
	}
	got = done
	if from != 0 && sa != nil {
		e.writeSockaddr(sa, from, fromlen)
	}
	if rflags&syscall.MSG_TRUNC != 0 && s.typ != wsSockStream {
		return e.wsaFail(wsaEMSGSIZE)
	}
	return uint64(got)
}

func init() {
	w := "ws2_32.dll"
	regWS(w, "send", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		return e.sendCommon(s, e.Arg(1), int64(int32(e.Arg32(2))), e.Arg32(3), nil)
	})
	regWS(w, "sendto", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		var to syscall.Sockaddr
		if a := e.Arg(4); a != 0 && s.typ != wsSockStream {
			var code uint32
			if to, code = e.readSockaddr(a, int64(int32(e.Arg32(5)))); code != 0 {
				return e.wsaFail(code)
			}
		}
		if to == nil && s.typ != wsSockStream && !s.connected {
			return e.wsaFail(wsaEDESTADDRREQ)
		}
		r := e.sendCommon(s, e.Arg(1), int64(int32(e.Arg32(2))), e.Arg32(3), to)
		if r != sockErr {
			s.bound = true // implicit bind
		}
		return r
	})
	regWS(w, "recv", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		return e.recvCommon(s, e.Arg(1), int64(int32(e.Arg32(2))), e.Arg32(3), 0, 0)
	})
	regWS(w, "recvfrom", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		return e.recvCommon(s, e.Arg(1), int64(int32(e.Arg32(2))), e.Arg32(3), e.Arg(4), e.Arg(5))
	})
	regWS(w, "ioctlsocket", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		cmd, argp := e.Arg32(1), e.Arg(2)
		if argp == 0 {
			return e.wsaFail(wsaEFAULT)
		}
		switch cmd {
		case wsFIONBIO:
			on := e.Mem.R32(argp) != 0
			if !on && s.evMask != 0 {
				return e.wsaFail(wsaEINVAL)
			}
			s.nonblock = on
		case wsFIONREAD:
			n := 0
			if !s.listening && (s.connected || s.typ != wsSockStream) {
				n, _ = e.peekAvail(s)
			}
			e.Mem.W32(argp, uint32(n))
		case wsSIOCATMARK:
			e.Mem.W32(argp, 1) // no urgent data pending
		default:
			return e.wsaFail(wsaEINVAL)
		}
		return 0
	})
}
