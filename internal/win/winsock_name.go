//go:build darwin || linux

package win

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Name resolution: getaddrinfo/GetAddrInfoW, freeaddrinfo, getnameinfo.
//
// 64-bit Windows addrinfo / ADDRINFOW (48 bytes) - note canonname before addr:
//
//	int ai_flags@0, ai_family@4, ai_socktype@8, ai_protocol@12;
//	size_t ai_addrlen@16; char *ai_canonname@24; sockaddr *ai_addr@32; addrinfo *ai_next@40

const (
	aiPassive      = 0x1
	aiCanonName    = 0x2
	aiNumericHost  = 0x4
	aiNumericServ  = 0x8
	sizeofAddrinfo = 48

	niNoFQDN      = 0x1
	niNumericHost = 0x2
	niNameReqd    = 0x4
	niNumericServ = 0x8
	niDgram       = 0x10

	wsaHostName     = "winemu" // matches GetComputerName ("WINEMU")
	resolverTimeout = 5 * time.Second
)

// hostLookupIP queries the host resolver (replaceable by tests).
var hostLookupIP = func(ctx context.Context, node string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", node)
}

type aiHints struct {
	flags, family, socktype, proto int32
}

// resolveHost returns the addresses for node (hasNode=false: NULL node).
// ok=false: a host query is running and the thread is parked; return at once.
func (e *Emu) resolveHost(node string, hasNode bool, h aiHints) (_ []netip.Addr, _ uint32, ok bool) {
	loop := []netip.Addr{netip.IPv6Loopback(), netip.AddrFrom4([4]byte{127, 0, 0, 1})}
	var addrs []netip.Addr
	switch {
	case !hasNode && h.flags&aiPassive != 0:
		addrs = []netip.Addr{netip.IPv6Unspecified(), netip.IPv4Unspecified()}
	case !hasNode:
		addrs = loop
	default:
		if a, err := netip.ParseAddr(node); err == nil {
			addrs = []netip.Addr{a}
			break
		}
		if h.flags&aiNumericHost != 0 {
			return nil, wsaHOSTNOTFOUND, true
		}
		if strings.EqualFold(node, "localhost") || strings.EqualFold(node, wsaHostName) || node == "" {
			addrs = loop
			break
		}
		ips, err, done := asyncLookup(e, "ip:"+node, func(ctx context.Context) ([]netip.Addr, error) {
			return hostLookupIP(ctx, node)
		})
		if !done {
			return nil, 0, false
		}
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && (de.IsTemporary || de.IsTimeout) {
				return nil, wsaTRYAGAIN, true
			}
			return nil, wsaHOSTNOTFOUND, true
		}
		addrs = ips
	}
	var out []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if (h.family == wsAFInet && !a.Is4()) || (h.family == wsAFInet6 && !a.Is6()) {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, wsaHOSTNOTFOUND, true
	}
	return out, 0, true
}

// resolvePort resolves a service name or number.
func resolvePort(serv string, hasServ bool, h aiHints) (int, uint32) {
	if !hasServ || serv == "" {
		return 0, 0
	}
	if p, err := strconv.ParseUint(serv, 10, 16); err == nil {
		return int(p), 0
	}
	if h.flags&aiNumericServ != 0 {
		return 0, wsaHOSTNOTFOUND
	}
	proto := "tcp"
	if h.socktype == wsSockDgram {
		proto = "udp"
	}
	if p, ok := lookupService(serv, proto); ok {
		return p, 0
	}
	return 0, wsaTYPENOTFOUND
}

func addrToSockaddr(a netip.Addr, port int) []byte {
	if a.Is4() {
		b := make([]byte, sizeofSockaddrIn)
		b[0] = wsAFInet
		b[2], b[3] = byte(port>>8), byte(port)
		v := a.As4()
		copy(b[4:], v[:])
		return b
	}
	b := make([]byte, sizeofSockaddrIn6)
	b[0] = wsAFInet6
	b[2], b[3] = byte(port>>8), byte(port)
	v := a.As16()
	copy(b[8:], v[:])
	if z := a.Zone(); z != "" {
		if n, err := strconv.ParseUint(z, 10, 32); err == nil {
			b[24], b[25], b[26], b[27] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
		} else if ifi, err := net.InterfaceByName(z); err == nil {
			n := uint32(ifi.Index)
			b[24], b[25], b[26], b[27] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
		}
	}
	return b
}

// getaddrinfo implements getaddrinfo/GetAddrInfoW; returns the error code.
func (e *Emu) getaddrinfo(wide bool) uint64 {
	str := func(a uint64) (string, bool) {
		if a == 0 {
			return "", false
		}
		if wide {
			return e.WStr(a), true
		}
		return e.CStr(a), true
	}
	ret := func(code uint32) uint64 { e.SetLastError(code); return uint64(code) }
	node, hasNode := str(e.Arg(0))
	serv, hasServ := str(e.Arg(1))
	var h aiHints
	if hp := e.Arg(2); hp != 0 {
		h = aiHints{int32(e.Mem.R32(hp)), int32(e.Mem.R32(hp + 4)), int32(e.Mem.R32(hp + 8)), int32(e.Mem.R32(hp + 12))}
	}
	res := e.Arg(3)
	switch {
	case res == 0:
		return ret(wsaEINVAL)
	case !hasNode && !hasServ:
		return ret(wsaHOSTNOTFOUND)
	case h.family != wsAFUnspec && h.family != wsAFInet && h.family != wsAFInet6:
		return ret(wsaEAFNOSUPPORT)
	case h.socktype < 0 || h.socktype > 3:
		return ret(wsaESOCKTNOSUPPORT)
	case h.flags&aiCanonName != 0 && !hasNode:
		return ret(wsaEINVAL)
	}
	e.Mem.W64(res, 0)
	addrs, code, ok := e.resolveHost(node, hasNode, h)
	if !ok {
		return 0
	}
	if code != 0 {
		return ret(code)
	}
	port, code := resolvePort(serv, hasServ, h)
	if code != 0 {
		return ret(code)
	}
	proto := h.proto
	if proto == 0 {
		switch h.socktype {
		case wsSockStream:
			proto = 6
		case wsSockDgram:
			proto = 17
		}
	}
	var first, prev uint64
	for i, a := range addrs {
		sa := addrToSockaddr(a, port)
		var canon []byte
		if i == 0 && h.flags&aiCanonName != 0 {
			if wide {
				canon = utf16Bytes(node)
			} else {
				canon = append([]byte(node), 0)
			}
		}
		p := e.heapAlloc(uint64(sizeofAddrinfo+32+len(canon)), true)
		e.Mem.W32(p+4, uint32(familyOf(a)))
		e.Mem.W32(p+8, uint32(h.socktype))
		e.Mem.W32(p+12, uint32(proto))
		e.Mem.W64(p+16, uint64(len(sa)))
		if canon != nil {
			e.Mem.Write(p+sizeofAddrinfo+32, canon)
			e.Mem.W64(p+24, p+sizeofAddrinfo+32)
		}
		e.Mem.Write(p+sizeofAddrinfo, sa)
		e.Mem.W64(p+32, p+sizeofAddrinfo)
		if prev == 0 {
			first = p
		} else {
			e.Mem.W64(prev+40, p)
		}
		prev = p
	}
	e.Mem.W64(res, first)
	return ret(0)
}

func familyOf(a netip.Addr) int32 {
	if a.Is4() {
		return wsAFInet
	}
	return wsAFInet6
}

func utf16Bytes(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return append(b, 0, 0)
}

// freeaddrinfo frees a list built by getaddrinfo (one heap block per node).
func (e *Emu) freeaddrinfo(p uint64) {
	for p != 0 {
		next := e.Mem.R64(p + 40)
		e.heap.freeBlock(p)
		p = next
	}
}
