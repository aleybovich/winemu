//go:build darwin || linux

package win

import "syscall"

// WSASend/WSARecv/WSASendTo/WSARecvFrom (non-overlapped), WSARecvEx,
// WSAPoll, WSAIoctl.

const (
	sizeofWSABuf = 16 // ULONG len; CHAR *buf
	sizeofPollFd = 16 // SOCKET fd; SHORT events; SHORT revents
	pollRdNorm   = 0x0100
	pollRdBand   = 0x0200
	pollPri      = 0x0400
	pollWrNorm   = 0x0010
	pollWrBand   = 0x0020
	pollErr      = 0x0001
	pollHup      = 0x0002
	pollNval     = 0x0004
	sioKeepalive = 0x98000004
)

// wsaBufs reads a WSABUF array.
func (e *Emu) wsaBufs(p uint64, n uint32) (addrs []uint64, lens []int64, total int64) {
	for i := uint64(0); i < uint64(n); i++ {
		l := int64(e.Mem.R32(p + sizeofWSABuf*i))
		addrs = append(addrs, e.Mem.R64(p+sizeofWSABuf*i+8))
		lens = append(lens, l)
		total += l
	}
	return
}

// wsaTransfer runs a send/recv over a WSABUF array through a contiguous
// scratch buffer (guest args 1..3: lpBuffers, dwBufferCount, lpNumberOfBytes).
func (e *Emu) wsaTransfer(send bool, s *sockObj, flags uint32, to syscall.Sockaddr, from, fromlen uint64) uint64 {
	bp, cnt, nbytes := e.Arg(1), e.Arg32(2), e.Arg(3)
	if bp == 0 || cnt == 0 {
		return e.wsaFail(wsaEFAULT)
	}
	addrs, lens, total := e.wsaBufs(bp, cnt)
	tmp := e.heapAlloc(uint64(max(total, 1)), false)
	defer e.heap.freeBlock(tmp)
	off := uint64(0)
	if send {
		for i, a := range addrs {
			e.Mem.Write(tmp+off, e.Mem.ReadBytes(a, int(lens[i])))
			off += uint64(lens[i])
		}
	}
	var r uint64
	if send {
		r = e.sendCommon(s, tmp, total, flags, to)
	} else {
		r = e.recvCommon(s, tmp, total, flags, from, fromlen)
	}
	if e.skipRet { // blocked; re-executed later
		return 0
	}
	if r == sockErr && !(e.LastError() == wsaEMSGSIZE && !send) {
		return sockErr
	}
	n := r
	if r == sockErr { // WSAEMSGSIZE: data was received
		n = uint64(total)
	}
	if !send {
		for i, a := range addrs {
			if off >= n {
				break
			}
			k := min(uint64(lens[i]), n-off)
			e.Mem.Write(a, e.Mem.ReadBytes(tmp+off, int(k)))
			off += k
		}
	}
	if nbytes != 0 {
		e.Mem.W32(nbytes, uint32(n))
	}
	if r == sockErr {
		return sockErr
	}
	return 0
}

func (e *Emu) pollOneFd(s *sockObj, events uint16, rd, wr bool) uint16 {
	var rev uint16
	switch {
	case s.connecting:
		if wr {
			e.finishConnect(s)
		}
		if s.connErr != 0 {
			return pollErr | pollHup
		}
		if s.connected && wr {
			rev |= pollWrNorm & events
		}
	case s.listening:
		if rd {
			rev |= pollRdNorm & events
		}
	case s.typ == wsSockStream && !s.connected:
		return 0
	default:
		if rd {
			if _, eof := e.peekAvail(s); eof && s.typ == wsSockStream {
				rev |= pollHup
			} else {
				rev |= (pollRdNorm | pollRdBand) & events
			}
		}
		if wr && rev&pollHup == 0 {
			rev |= (pollWrNorm | pollWrBand) & events
		}
	}
	return rev
}

func init() {
	w := "ws2_32.dll"
	regWS(w, "WSASend", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		if ov := e.Arg(5); ov != 0 && s.overlapped { // non-overlapped sockets ignore lpOverlapped
			return e.ovlTransfer(s, true, e.Arg32(4), 0, nil, 0, 0, ov, e.Arg(6))
		}
		return e.wsaTransfer(true, s, e.Arg32(4), nil, 0, 0)
	})
	regWS(w, "WSASendTo", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		var to syscall.Sockaddr
		if a := e.Arg(5); a != 0 && s.typ != wsSockStream {
			var code uint32
			if to, code = e.readSockaddr(a, int64(int32(e.Arg32(6)))); code != 0 {
				return e.wsaFail(code)
			}
		}
		if ov := e.Arg(7); ov != 0 && s.overlapped {
			return e.ovlTransfer(s, true, e.Arg32(4), 0, to, 0, 0, ov, e.Arg(8))
		}
		return e.wsaTransfer(true, s, e.Arg32(4), to, 0, 0)
	})
	recvFlags := func(e *Emu) (uint32, bool) {
		if e.Arg(4) == 0 {
			e.wsaFail(wsaEFAULT)
			return 0, false
		}
		return e.Mem.R32(e.Arg(4)), true
	}
	regWS(w, "WSARecv", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		f, ok := recvFlags(e)
		if !ok {
			return sockErr
		}
		if ov := e.Arg(5); ov != 0 && s.overlapped {
			return e.ovlTransfer(s, false, f, e.Arg(4), nil, 0, 0, ov, e.Arg(6))
		}
		r := e.wsaTransfer(false, s, f, nil, 0, 0)
		if !e.skipRet && r == 0 {
			e.Mem.W32(e.Arg(4), 0)
		}
		return r
	})
	regWS(w, "WSARecvFrom", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		f, ok := recvFlags(e)
		if !ok {
			return sockErr
		}
		if ov := e.Arg(7); ov != 0 && s.overlapped {
			return e.ovlTransfer(s, false, f, e.Arg(4), nil, e.Arg(5), e.Arg(6), ov, e.Arg(8))
		}
		r := e.wsaTransfer(false, s, f, nil, e.Arg(5), e.Arg(6))
		if !e.skipRet && r == 0 {
			e.Mem.W32(e.Arg(4), 0)
		}
		return r
	})
	// WSARecvEx(s, buf, len, int *flags): recv; MSG_PARTIAL is never set
	regWS("wsock32.dll,mswsock.dll", "WSARecvEx", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		var f uint32
		if p := e.Arg(3); p != 0 {
			f = e.Mem.R32(p)
		}
		r := e.recvCommon(s, e.Arg(1), int64(int32(e.Arg32(2))), f, 0, 0)
		if p := e.Arg(3); p != 0 && !e.skipRet && r != sockErr {
			e.Mem.W32(p, 0)
		}
		return r
	})
	regWS(w, "WSAPoll", func(e *Emu) uint64 {
		arr, n, timeout := e.Arg(0), e.Arg32(1), int32(e.Arg32(2))
		timedOut := e.resumeWait()
		if arr == 0 {
			return e.wsaFail(wsaEFAULT)
		}
		if n == 0 {
			return e.wsaFail(wsaEINVAL)
		}
		type ent struct {
			s      *sockObj
			events uint16
		}
		es := make([]ent, n)
		var fds []int
		for i := range es {
			p := arr + sizeofPollFd*uint64(i)
			ev := e.Mem.R16(p + 8)
			if ev&^(pollRdNorm|pollRdBand|pollPri|pollWrNorm|pollWrBand) != 0 {
				return e.wsaFail(wsaEINVAL)
			}
			s, _ := e.handles.get(e.Mem.R64(p)).(*sockObj)
			if s != nil && s.isClosed() {
				s = nil
			}
			es[i] = ent{s, ev}
			if s != nil {
				s.mu.Lock()
				fds = append(fds, s.fd)
				s.mu.Unlock()
			}
		}
		check := func(write bool) int {
			rd, wr := fdPoll(fds)
			cnt, k := 0, 0
			for i, x := range es {
				var rev uint16 = pollNval
				if x.s != nil {
					x.s.mu.Lock()
					rev = e.pollOneFd(x.s, x.events, rd[k], wr[k])
					x.s.mu.Unlock()
					k++
				}
				if rev != 0 {
					cnt++
				}
				if write {
					e.Mem.W16(arr+sizeofPollFd*uint64(i)+10, rev)
				}
			}
			return cnt
		}
		if c := check(true); c > 0 || timeout == 0 || timedOut {
			return uint64(c)
		}
		ms := uint32(infinite)
		if timeout > 0 {
			ms = uint32(timeout)
		}
		e.sockWait(func() bool { return check(false) > 0 }, ms)
		return 0
	})
	regWS(w, "WSAIoctl", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		r := e.wsaIoctl(s)
		if ov := e.Arg(7); ov != 0 && s.overlapped && r == 0 {
			// overlapped ioctl: completes at once; the completion is indicated
			var n uint32
			if p := e.Arg(6); p != 0 {
				n = e.Mem.R32(p)
			}
			e.indicateNow(s, ov, e.Arg(8), n)
		}
		return r
	})
}

// wsaIoctl implements the WSAIoctl control codes.
func (e *Emu) wsaIoctl(s *sockObj) uint64 {
	code, in, inLen, out, outLen, nret := e.Arg32(1), e.Arg(2), e.Arg32(3), e.Arg(4), e.Arg32(5), e.Arg(6)
	ret := func(n uint32) uint64 {
		if nret != 0 {
			e.Mem.W32(nret, n)
		}
		return 0
	}
	switch code {
	case wsFIONBIO:
		if in == 0 || inLen < 4 {
			return e.wsaFail(wsaEFAULT)
		}
		on := e.Mem.R32(in) != 0
		if !on && s.evMask != 0 {
			return e.wsaFail(wsaEINVAL)
		}
		s.nonblock = on
		return ret(0)
	case wsFIONREAD, wsSIOCATMARK:
		if out == 0 || outLen < 4 {
			return e.wsaFail(wsaEFAULT)
		}
		v := uint32(1)
		if code == wsFIONREAD {
			v = 0
			if !s.listening && (s.connected || s.typ != wsSockStream) {
				n, _ := e.peekAvail(s)
				v = uint32(n)
			}
		}
		e.Mem.W32(out, v)
		return ret(4)
	case sioKeepalive: // struct tcp_keepalive {u_long onoff, keepalivetime, keepaliveinterval} (ms)
		if in == 0 || inLen < 12 {
			return e.wsaFail(wsaEFAULT)
		}
		on, idle, intvl := e.Mem.R32(in), e.Mem.R32(in+4), e.Mem.R32(in+8)
		if err := syscall.SetsockoptInt(s.fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, int(b2u(on != 0))); err != nil {
			return e.wsaFail(wsaErr(err))
		}
		if on != 0 {
			_ = syscall.SetsockoptInt(s.fd, syscall.IPPROTO_TCP, hostTCPKeepIdle, int(max((idle+999)/1000, 1)))   // best effort: hosts clamp ranges
			_ = syscall.SetsockoptInt(s.fd, syscall.IPPROTO_TCP, hostTCPKeepIntvl, int(max((intvl+999)/1000, 1))) // best effort
		}
		return ret(0)
	}
	return e.wsaIoctlExt(s, code, in, inLen, out, outLen, ret)
}
