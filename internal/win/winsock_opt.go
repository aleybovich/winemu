//go:build darwin || linux

package win

import "syscall"

// getsockopt / setsockopt.

const (
	wsSolSocket   = 0xFFFF
	wsIPProtoIP   = 0
	wsIPProtoTCP  = 6
	wsIPProtoIPv6 = 41

	wsSoAcceptConn    = 0x0002
	wsSoReuseAddr     = 0x0004
	wsSoKeepAlive     = 0x0008
	wsSoBroadcast     = 0x0020
	wsSoLinger        = 0x0080
	wsSoOOBInline     = 0x0100
	wsSoDontLinger    = 0xFFFFFF7F // ~SO_LINGER
	wsSoExclusiveAddr = 0xFFFFFFFB // ~SO_REUSEADDR
	wsSoSndBuf        = 0x1001
	wsSoRcvBuf        = 0x1002
	wsSoSndTimeo      = 0x1005
	wsSoRcvTimeo      = 0x1006
	wsSoError         = 0x1007
	wsSoType          = 0x1008

	wsTCPNoDelay  = 1
	wsIPTOS       = 3
	wsIPTTL       = 4
	wsIPv6V6Only  = 27
	wsIPv6Unicast = 4 // IPV6_UNICAST_HOPS
)

// hostOpt maps an int-valued option to the host (level, name); ok=false if
// the option is not passed through.
func hostOpt(s *sockObj, level, name uint32) (hl, hn int, ok bool) {
	switch level {
	case wsSolSocket:
		switch name {
		case wsSoReuseAddr:
			return syscall.SOL_SOCKET, syscall.SO_REUSEADDR, true
		case wsSoKeepAlive:
			return syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, true
		case wsSoBroadcast:
			return syscall.SOL_SOCKET, syscall.SO_BROADCAST, true
		case wsSoOOBInline:
			return syscall.SOL_SOCKET, syscall.SO_OOBINLINE, true
		case wsSoSndBuf:
			return syscall.SOL_SOCKET, syscall.SO_SNDBUF, true
		case wsSoRcvBuf:
			return syscall.SOL_SOCKET, syscall.SO_RCVBUF, true
		}
	case wsIPProtoTCP:
		if name == wsTCPNoDelay && s.typ == wsSockStream {
			return syscall.IPPROTO_TCP, syscall.TCP_NODELAY, true
		}
	case wsIPProtoIP:
		switch name {
		case wsIPTOS:
			return syscall.IPPROTO_IP, syscall.IP_TOS, true
		case wsIPTTL:
			return syscall.IPPROTO_IP, syscall.IP_TTL, true
		}
	case wsIPProtoIPv6:
		switch name {
		case wsIPv6V6Only:
			return syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, true
		case wsIPv6Unicast:
			return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, true
		}
	}
	return 0, 0, false
}

func knownLevel(level uint32) bool {
	return level == wsSolSocket || level == wsIPProtoIP || level == wsIPProtoTCP || level == wsIPProtoIPv6
}

func init() {
	w := "ws2_32.dll"
	regWS(w, "setsockopt", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		level, name, val, n := e.Arg32(1), e.Arg32(2), e.Arg(3), int32(e.Arg32(4))
		if r, ok := e.setUpdateContext(s, level, name, val, n); ok {
			return r
		}
		if val == 0 || n < 4 {
			return e.wsaFail(wsaEFAULT)
		}
		v := e.Mem.R32(val)
		if level == wsIPProtoIPv6 && s.af != wsAFInet6 {
			return e.wsaFail(wsaEINVAL)
		}
		if level == wsSolSocket {
			switch name {
			case wsSoExclusiveAddr:
				s.exclusive = v != 0
				return 0
			case wsSoSndTimeo:
				s.sndTimeo = v
				return 0
			case wsSoRcvTimeo:
				s.rcvTimeo = v
				return 0
			case wsSoLinger, wsSoDontLinger:
				on, secs := uint16(v), uint16(v>>16)
				if name == wsSoDontLinger {
					on, secs = b2u16(v == 0), s.lingerS
				}
				l := syscall.Linger{Onoff: int32(on), Linger: int32(secs)}
				if err := syscall.SetsockoptLinger(s.fd, syscall.SOL_SOCKET, syscall.SO_LINGER, &l); err != nil {
					return e.wsaFail(wsaErr(err))
				}
				s.lingerOn, s.lingerS = on, secs
				return 0
			}
		}
		hl, hn, ok := hostOpt(s, level, name)
		if !ok {
			if !knownLevel(level) {
				return e.wsaFail(wsaEINVAL)
			}
			return e.wsaFail(wsaENOPROTOOPT)
		}
		if err := syscall.SetsockoptInt(s.fd, hl, hn, int(int32(v))); err != nil {
			return e.wsaFail(wsaErr(err))
		}
		return 0
	})
	regWS(w, "getsockopt", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		level, name, val, lenp := e.Arg32(1), e.Arg32(2), e.Arg(3), e.Arg(4)
		if val == 0 || lenp == 0 || int32(e.Mem.R32(lenp)) < 4 {
			return e.wsaFail(wsaEFAULT)
		}
		if level == wsIPProtoIPv6 && s.af != wsAFInet6 {
			return e.wsaFail(wsaEINVAL)
		}
		out := func(v uint32) uint64 {
			e.Mem.W32(val, v)
			e.Mem.W32(lenp, 4)
			return 0
		}
		if level == wsSolSocket {
			switch name {
			case wsSoExclusiveAddr:
				return out(uint32(b2u(s.exclusive)))
			case wsSoSndTimeo:
				return out(s.sndTimeo)
			case wsSoRcvTimeo:
				return out(s.rcvTimeo)
			case wsSoLinger:
				return out(uint32(s.lingerOn) | uint32(s.lingerS)<<16)
			case wsSoDontLinger:
				return out(uint32(b2u(s.lingerOn == 0)))
			case wsSoType:
				return out(uint32(s.typ))
			case wsSoAcceptConn:
				return out(uint32(b2u(s.listening)))
			case wsSoProtocolInfoA, wsSoProtocolInfoW:
				return e.getProtoInfoOpt(s, name == wsSoProtocolInfoW, val, lenp)
			case wsSoError:
				e.finishConnect(s)
				if c := s.connErr; c != 0 {
					s.connErr = 0
					return out(c)
				}
				v, err := syscall.GetsockoptInt(s.fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
				if err != nil || v == 0 {
					return out(0)
				}
				return out(wsaErr(syscall.Errno(v)))
			}
		}
		hl, hn, ok := hostOpt(s, level, name)
		if !ok {
			if !knownLevel(level) {
				return e.wsaFail(wsaEINVAL)
			}
			return e.wsaFail(wsaENOPROTOOPT)
		}
		v, err := syscall.GetsockoptInt(s.fd, hl, hn)
		if err != nil {
			return e.wsaFail(wsaErr(err))
		}
		if v != 0 && boolOpt(level, name) {
			v = 1 // BOOL options: hosts may report the flag bit
		}
		return out(uint32(int32(v)))
	})
}

func b2u16(b bool) uint16 {
	if b {
		return 1
	}
	return 0
}

// boolOpt reports whether a Windows option is a BOOL (hosts may report the
// flag bit instead of 1).
func boolOpt(level, name uint32) bool {
	switch level {
	case wsSolSocket:
		return name == wsSoReuseAddr || name == wsSoKeepAlive || name == wsSoBroadcast || name == wsSoOOBInline
	case wsIPProtoTCP:
		return name == wsTCPNoDelay
	case wsIPProtoIPv6:
		return name == wsIPv6V6Only
	}
	return false
}
