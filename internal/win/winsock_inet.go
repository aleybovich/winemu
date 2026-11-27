//go:build darwin || linux

package win

import (
	"net/netip"
	"strconv"
	"strings"
)

// parseInetAton parses the BSD inet_aton forms accepted by inet_addr:
// a, a.b, a.b.c, a.b.c.d with decimal, octal (0...) or hex (0x...) parts.
func parseInetAton(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return 0, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return 0, false
		}
		v, err := strconv.ParseUint(p, 0, 32)
		if err != nil {
			return 0, false
		}
		vals[i] = v
	}
	n := len(vals)
	if vals[n-1] > uint64(1)<<(8*(5-n))-1 {
		return 0, false
	}
	r := vals[n-1]
	for i, v := range vals[:n-1] {
		if v > 255 {
			return 0, false
		}
		r |= v << (8 * (3 - i))
	}
	return uint32(r), true
}

func (e *Emu) inetNtop(wide bool) uint64 {
	af, src, dst, size := int32(e.Arg32(0)), e.Arg(1), e.Arg(2), e.Arg(3)
	var a netip.Addr
	switch af {
	case wsAFInet:
		a = netip.AddrFrom4([4]byte(e.Mem.ReadBytes(src, 4)))
	case wsAFInet6:
		a = netip.AddrFrom16([16]byte(e.Mem.ReadBytes(src, 16)))
	default:
		return e.fail(wsaEAFNOSUPPORT)
	}
	s := a.String()
	if dst == 0 || size < uint64(len(s))+1 {
		return e.fail(errInvalidParameter)
	}
	if wide {
		e.Mem.WriteWStr(dst, s)
	} else {
		e.Mem.WriteCStr(dst, s)
	}
	return dst
}

func (e *Emu) inetPton(wide bool) uint64 {
	af, src, dst := int32(e.Arg32(0)), e.Arg(1), e.Arg(2)
	if af != wsAFInet && af != wsAFInet6 {
		return e.wsaFail(wsaEAFNOSUPPORT)
	}
	if src == 0 || dst == 0 {
		return e.wsaFail(wsaEFAULT)
	}
	var s string
	if wide {
		s = e.WStr(src)
	} else {
		s = e.CStr(src)
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || (af == wsAFInet) != a.Is4() {
		return 0
	}
	if af == wsAFInet {
		v := a.As4()
		e.Mem.Write(dst, v[:])
	} else {
		v := a.As16()
		e.Mem.Write(dst, v[:])
	}
	return 1
}

// hostName is the name returned by gethostname (resolves to loopback).
func hostName() string { return wsaHostName }

func init() {
	w := "ws2_32.dll"
	reg(w, "getaddrinfo", func(e *Emu) uint64 { return e.getaddrinfo(false) })
	reg(w, "GetAddrInfoW", func(e *Emu) uint64 { return e.getaddrinfo(true) })
	reg(w, "freeaddrinfo", func(e *Emu) uint64 { e.freeaddrinfo(e.Arg(0)); return 0 })
	reg(w, "FreeAddrInfoW", func(e *Emu) uint64 { e.freeaddrinfo(e.Arg(0)); return 0 })
	reg(w, "GetAddrInfoExW", func(e *Emu) uint64 { e.SetLastError(wsaHOSTNOTFOUND); return wsaHOSTNOTFOUND }) // ADDRINFOEX not supported
	reg(w, "FreeAddrInfoExW", retZero)
	reg(w, "getnameinfo", func(e *Emu) uint64 { return e.getnameinfo(false) })
	reg(w, "GetNameInfoW", func(e *Emu) uint64 { return e.getnameinfo(true) })
	reg(w, "inet_ntop", func(e *Emu) uint64 { return e.inetNtop(false) })
	reg(w, "InetNtopW", func(e *Emu) uint64 { return e.inetNtop(true) })
	regWS(w, "inet_pton", func(e *Emu) uint64 { return e.inetPton(false) })
	regWS(w, "InetPtonW", func(e *Emu) uint64 { return e.inetPton(true) })
	reg(w, "inet_addr", func(e *Emu) uint64 {
		if e.Arg(0) == 0 {
			return 0xFFFFFFFF
		}
		v, ok := parseInetAton(strings.TrimRight(e.CStr(e.Arg(0)), " "))
		if !ok {
			return 0xFFFFFFFF // INADDR_NONE
		}
		return uint64(bswap32(v))
	})
	reg(w, "inet_ntoa", func(e *Emu) uint64 {
		v := e.Arg32(0)
		a := e.static("ntoa")
		e.Mem.WriteCStr(a, netip.AddrFrom4([4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}).String())
		return a
	})
	regWS(w, "gethostname", func(e *Emu) uint64 {
		buf, n := e.Arg(0), int32(e.Arg32(1))
		name := hostName()
		if buf == 0 || n < int32(len(name))+1 {
			return e.wsaFail(wsaEFAULT)
		}
		e.Mem.WriteCStr(buf, name)
		return 0
	})
	regWS(w, "GetHostNameW", func(e *Emu) uint64 {
		buf, n := e.Arg(0), int32(e.Arg32(1))
		name := hostName()
		if buf == 0 || n < int32(len(name))+1 {
			return e.wsaFail(wsaEFAULT)
		}
		e.Mem.WriteWStr(buf, name)
		return 0
	})
	reg(w, "gethostbyname", func(e *Emu) uint64 {
		name := hostName()
		if e.Arg(0) != 0 {
			name = e.CStr(e.Arg(0))
		}
		addrs, code, ok := e.resolveHost(name, true, aiHints{family: wsAFInet})
		if !ok {
			return 0
		}
		if code != 0 {
			return e.fail(code)
		}
		if strings.EqualFold(name, "localhost") || strings.EqualFold(name, hostName()) {
			name = strings.ToLower(name)
		}
		return e.hostent(name, addrs)
	})
	reg(w, "gethostbyaddr", func(e *Emu) uint64 {
		a, n, typ := e.Arg(0), int32(e.Arg32(1)), int32(e.Arg32(2))
		if a == 0 {
			return e.fail(wsaEFAULT)
		}
		if typ != wsAFInet || n < 4 {
			return e.fail(wsaEAFNOSUPPORT)
		}
		ip := netip.AddrFrom4([4]byte(e.Mem.ReadBytes(a, 4)))
		name, code, ok := e.reverseName(ip, niNameReqd)
		if !ok {
			return 0
		}
		if code != 0 {
			return e.fail(code)
		}
		return e.hostent(name, []netip.Addr{ip})
	})
	reg(w, "getservbyname", func(e *Emu) uint64 {
		proto := ""
		if e.Arg(1) != 0 {
			proto = strings.ToLower(e.CStr(e.Arg(1)))
		}
		name := e.CStr(e.Arg(0))
		port, ok := lookupService(name, proto)
		if !ok || e.Arg(0) == 0 {
			return e.fail(wsaNODATA)
		}
		if n, ok := serviceName(port, proto); ok {
			name = n
		}
		return e.servent(name, port, proto)
	})
	reg(w, "getservbyport", func(e *Emu) uint64 {
		port := int(bswap16(uint16(e.Arg(0))))
		proto := ""
		if e.Arg(1) != 0 {
			proto = strings.ToLower(e.CStr(e.Arg(1)))
		}
		name, ok := serviceName(port, proto)
		if !ok {
			return e.fail(wsaNODATA)
		}
		return e.servent(name, port, proto)
	})
	reg(w, "getprotobyname", func(e *Emu) uint64 {
		if e.Arg(0) != 0 {
			n := e.CStr(e.Arg(0))
			for _, p := range protocols {
				if strings.EqualFold(p.name, n) {
					return e.protoent(p.name, p.alias, p.num)
				}
			}
		}
		return e.fail(wsaNODATA)
	})
	reg(w, "getprotobynumber", func(e *Emu) uint64 {
		for _, p := range protocols {
			if p.num == int(int32(e.Arg32(0))) {
				return e.protoent(p.name, p.alias, p.num)
			}
		}
		return e.fail(wsaNODATA)
	})
}

func bswap16(v uint16) uint16 { return v>>8 | v<<8 }

func (e *Emu) servent(name string, port int, proto string) uint64 {
	se := e.static("servent")
	w := &bufWriter{e: e, pos: se + 32}
	if proto == "" {
		proto = "tcp"
	}
	e.Mem.W64(se, w.str(name))
	e.Mem.W64(se+8, w.ptrs())
	e.Mem.W64(se+16, w.str(proto))
	e.Mem.W16(se+24, bswap16(uint16(port)))
	return se
}

func (e *Emu) protoent(name, alias string, num int) uint64 {
	pe := e.static("protoent")
	w := &bufWriter{e: e, pos: pe + 24}
	e.Mem.W64(pe, w.str(name))
	e.Mem.W64(pe+8, w.ptrs(w.str(alias)))
	e.Mem.W16(pe+16, uint16(num))
	return pe
}
