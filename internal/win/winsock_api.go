//go:build darwin || linux

package win

import "syscall"

// Socket lifecycle and connection management.

const (
	wsaFlagOverlapped    = 0x01
	wsaFromProtocolInfo  = -1
	wsaMaxBacklog        = 4096
	wsaDescription       = "WinSock 2.0"
	wsaSystemStatus      = "Running"
	sizeofWSAData        = 408
	wsaDataDescOffset    = 16
	wsaDataStatusOffset  = 273
	protoInfoAFOffset    = 76
	protoInfoTypeOffset  = 88
	protoInfoProtoOffset = 92
)

func init() {
	w := "ws2_32.dll"
	regWS(w, "WSAStartup", func(e *Emu) uint64 {
		ver, d := uint16(e.Arg(0)), e.Arg(1)
		if ver&0xFF < 1 {
			return wsaVERNOTSUPPORTED
		}
		if d == 0 {
			return wsaEFAULT
		}
		// 64-bit WSADATA: wVersion, wHighVersion, iMaxSockets, iMaxUdpDg,
		// lpVendorInfo, szDescription[257], szSystemStatus[129]
		got := ver
		if ver&0xFF > 2 || (ver&0xFF == 2 && ver>>8 > 2) {
			got = 0x0202
		}
		e.Mem.Fill(d, 0, sizeofWSAData)
		e.Mem.W16(d, got)
		e.Mem.W16(d+2, 0x0202)
		e.Mem.WriteCStr(d+wsaDataDescOffset, wsaDescription)
		e.Mem.WriteCStr(d+wsaDataStatusOffset, wsaSystemStatus)
		e.netSt().started++
		return 0
	})
	regWS(w, "WSACleanup", func(e *Emu) uint64 {
		if e.net == nil || e.net.started == 0 {
			return e.wsaFail(wsaNOTINITIALISED)
		}
		e.net.started--
		return 0
	})
	regWS(w, "WSAGetLastError", func(e *Emu) uint64 { return uint64(e.LastError()) })
	regWS(w, "WSASetLastError", func(e *Emu) uint64 { e.SetLastError(e.Arg32(0)); return 0 })
	regWS(w, "socket", func(e *Emu) uint64 {
		// socket() creates overlapped-capable sockets, like WSASocket(WSA_FLAG_OVERLAPPED)
		return e.newSocket(int32(e.Arg32(0)), int32(e.Arg32(1)), int32(e.Arg32(2)), wsaFlagOverlapped)
	})
	wsaSocket := func(e *Emu) uint64 {
		af, typ, proto := int32(e.Arg32(0)), int32(e.Arg32(1)), int32(e.Arg32(2))
		if e.net == nil || e.net.started == 0 {
			return e.wsaFail(wsaNOTINITIALISED)
		}
		if pi := e.Arg(3); pi != 0 {
			if h, ok := e.socketFromInfo(pi); ok { // a socket shared by WSADuplicateSocket
				return h
			}
			if af == wsaFromProtocolInfo {
				af = int32(e.Mem.R32(pi + protoInfoAFOffset))
			}
			if typ == wsaFromProtocolInfo {
				typ = int32(e.Mem.R32(pi + protoInfoTypeOffset))
			}
			if proto == wsaFromProtocolInfo {
				proto = int32(e.Mem.R32(pi + protoInfoProtoOffset))
			}
		}
		return e.newSocket(af, typ, proto, e.Arg32(5))
	}
	regWS(w, "WSASocketW", wsaSocket)
	regWS(w, "WSASocketA", wsaSocket)
	regWS(w, "closesocket", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		e.cancelOps(s, nil, 0) // this process's pending I/O on s is aborted
		e.unlockSock(s)        // the handle's unref takes the lock
		e.handles.close(e.Arg(0))
		return 0
	})
	regWS(w, "bind", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		sa, code := e.readSockaddr(e.Arg(1), int64(int32(e.Arg32(2))))
		if code != 0 {
			return e.wsaFail(code)
		}
		if s.bound {
			return e.wsaFail(wsaEINVAL)
		}
		if err := syscall.Bind(s.fd, sa); err != nil {
			return e.wsaFail(wsaErr(err))
		}
		s.bound = true
		return 0
	})
	regWS(w, "listen", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		switch {
		case s.typ != wsSockStream:
			return e.wsaFail(wsaEOPNOTSUPP)
		case s.connected || s.connecting:
			return e.wsaFail(wsaEISCONN)
		case !s.bound:
			return e.wsaFail(wsaEINVAL)
		}
		backlog := min(max(int(int32(e.Arg32(1))), 0), wsaMaxBacklog)
		if err := syscall.Listen(s.fd, backlog); err != nil {
			return e.wsaFail(wsaErr(err))
		}
		s.listening = true
		return 0
	})
	regWS(w, "accept", func(e *Emu) uint64 { return e.accept(0) })
	regWS(w, "WSAAccept", func(e *Emu) uint64 { return e.accept(e.Arg(3)) })
	regWS(w, "connect", func(e *Emu) uint64 { return e.connect() })
	regWS(w, "WSAConnect", func(e *Emu) uint64 { return e.connect() }) // caller/callee data and QoS are not supported by TCP/IP
	regWS(w, "getsockname", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		if !s.bound {
			return e.wsaFail(wsaEINVAL)
		}
		sa, err := syscall.Getsockname(s.fd)
		if err != nil {
			return e.wsaFail(wsaErr(err))
		}
		if code := e.writeSockaddrChecked(sa, e.Arg(1), e.Arg(2)); code != 0 {
			return e.wsaFail(code)
		}
		return 0
	})
	regWS(w, "getpeername", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		e.finishConnect(s)
		if !s.connected {
			return e.wsaFail(wsaENOTCONN)
		}
		sa, err := syscall.Getpeername(s.fd)
		if err != nil {
			return e.wsaFail(wsaErr(err))
		}
		if code := e.writeSockaddrChecked(sa, e.Arg(1), e.Arg(2)); code != 0 {
			return e.wsaFail(code)
		}
		return 0
	})
	regWS(w, "shutdown", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		how := e.Arg32(1)
		if how > 2 { // SD_RECEIVE, SD_SEND, SD_BOTH match SHUT_RD, SHUT_WR, SHUT_RDWR
			return e.wsaFail(wsaEINVAL)
		}
		if s.typ == wsSockStream && !s.connected {
			return e.wsaFail(wsaENOTCONN)
		}
		if err := syscall.Shutdown(s.fd, int(how)); err != nil && !(s.typ != wsSockStream && err == syscall.ENOTCONN) {
			return e.wsaFail(wsaErr(err))
		}
		if how != 0 {
			s.shutSend = true
		}
		return 0
	})
	regWS(w, "htons", func(e *Emu) uint64 { v := uint16(e.Arg(0)); return uint64(v>>8 | v<<8) })
	regWS(w, "ntohs", func(e *Emu) uint64 { v := uint16(e.Arg(0)); return uint64(v>>8 | v<<8) })
	regWS(w, "htonl", func(e *Emu) uint64 { return uint64(bswap32(e.Arg32(0))) })
	regWS(w, "ntohl", func(e *Emu) uint64 { return uint64(bswap32(e.Arg32(0))) })

}

// writeSockaddrChecked is writeSockaddr for getsockname/getpeername, where
// both the buffer and the length are mandatory.
func (e *Emu) writeSockaddrChecked(sa syscall.Sockaddr, a, lenp uint64) uint32 {
	if a == 0 || lenp == 0 {
		return wsaEFAULT
	}
	return e.writeSockaddr(sa, a, lenp)
}

// newSocket implements socket/WSASocket; returns the handle or INVALID_SOCKET.
func (e *Emu) newSocket(af, typ, proto int32, flags uint32) uint64 {
	if e.net == nil || e.net.started == 0 {
		return e.wsaFail(wsaNOTINITIALISED)
	}
	haf := hostAF(af)
	if haf < 0 || af == wsAFUnspec {
		return e.wsaFail(wsaEAFNOSUPPORT)
	}
	var htyp int
	switch typ {
	case wsSockStream:
		htyp = syscall.SOCK_STREAM
	case wsSockDgram:
		htyp = syscall.SOCK_DGRAM
	case 3:
		htyp = syscall.SOCK_RAW
	default:
		return e.wsaFail(wsaESOCKTNOSUPPORT)
	}
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(haf, htyp, int(proto))
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return e.wsaFail(wsaErr(err))
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return e.wsaFail(wsaErr(err))
	}
	if af == wsAFInet6 {
		// Windows default: IPV6_V6ONLY is on
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1) // best effort, like the Windows default it mirrors
	}
	s := &sockObj{fd: fd, af: af, typ: typ, proto: proto, overlapped: flags&wsaFlagOverlapped != 0}
	h := e.addSocket(s)
	// socket handles are inheritable unless WSA_FLAG_NO_HANDLE_INHERIT
	e.handles.setInherit(h, flags&wsaFlagNoHandleInherit == 0)
	return h
}

func (e *Emu) addSocket(s *sockObj) uint64 {
	e.netSt().socks[s] = true
	return e.handles.add(s)
}
