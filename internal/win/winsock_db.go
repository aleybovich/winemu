//go:build darwin || linux

package win

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// getnameinfo, inet_*, gethostname, gethostbyname/addr, getserv*, getproto*.
//
// Win64 database structs (returned in per-process static buffers):
//
//	hostent  {char *h_name@0; char **h_aliases@8; short h_addrtype@16; short h_length@18; char **h_addr_list@24}
//	servent  {char *s_name@0; char **s_aliases@8; char *s_proto@16; short s_port@24}
//	protoent {char *p_name@0; char **p_aliases@8; short p_proto@16}

const staticBufSize = 1024

// wellKnownServices is a small services database (IANA assignments).
var wellKnownServices = []struct {
	name  string
	port  int
	proto string // "" = tcp and udp
}{
	{"echo", 7, ""}, {"discard", 9, ""}, {"daytime", 13, ""}, {"ftp-data", 20, "tcp"}, {"ftp", 21, "tcp"},
	{"ssh", 22, "tcp"}, {"telnet", 23, "tcp"}, {"smtp", 25, "tcp"}, {"time", 37, ""}, {"domain", 53, ""},
	{"bootps", 67, "udp"}, {"bootpc", 68, "udp"}, {"tftp", 69, "udp"}, {"gopher", 70, "tcp"}, {"finger", 79, "tcp"},
	{"http", 80, "tcp"}, {"kerberos", 88, ""}, {"pop3", 110, "tcp"}, {"sunrpc", 111, ""}, {"nntp", 119, "tcp"},
	{"ntp", 123, "udp"}, {"netbios-ns", 137, ""}, {"netbios-dgm", 138, "udp"}, {"netbios-ssn", 139, "tcp"},
	{"imap", 143, "tcp"}, {"snmp", 161, "udp"}, {"ldap", 389, ""}, {"https", 443, "tcp"}, {"microsoft-ds", 445, "tcp"},
	{"syslog", 514, "udp"}, {"submission", 587, "tcp"}, {"ldaps", 636, "tcp"}, {"imaps", 993, "tcp"}, {"pop3s", 995, "tcp"},
}

func serviceMatches(proto, want string) bool {
	return want == "" || proto == "" || strings.EqualFold(proto, want)
}

// lookupService resolves a service name for proto ("tcp"/"udp"/"").
func lookupService(name, proto string) (int, bool) {
	for _, s := range wellKnownServices {
		if strings.EqualFold(s.name, name) && serviceMatches(s.proto, proto) {
			return s.port, true
		}
	}
	if proto == "" {
		proto = "tcp"
	}
	if p, err := net.LookupPort(proto, name); err == nil {
		return p, true
	}
	return 0, false
}

func serviceName(port int, proto string) (string, bool) {
	for _, s := range wellKnownServices {
		if s.port == port && serviceMatches(s.proto, proto) {
			return s.name, true
		}
	}
	return "", false
}

var protocols = []struct {
	name  string
	num   int
	alias string
}{{"ip", 0, "IP"}, {"icmp", 1, "ICMP"}, {"ggp", 3, "GGP"}, {"tcp", 6, "TCP"}, {"egp", 8, "EGP"},
	{"pup", 12, "PUP"}, {"udp", 17, "UDP"}, {"hmp", 20, "HMP"}, {"xns-idp", 22, "XNS-IDP"},
	{"rdp", 27, "RDP"}, {"ipv6", 41, "IPv6"}, {"ipv6-icmp", 58, "IPv6-ICMP"}, {"rvd", 66, "RVD"}}

// static returns the per-process static buffer for kind, zeroed.
func (e *Emu) static(kind string) uint64 {
	n := e.netSt()
	if n.statics == nil {
		n.statics = map[string]uint64{}
	}
	a := n.statics[kind]
	if a == 0 {
		a = e.heapAlloc(staticBufSize, true)
		n.statics[kind] = a
	}
	e.Mem.Fill(a, 0, staticBufSize)
	return a
}

// bufWriter lays out strings and pointer arrays in a static buffer.
type bufWriter struct {
	e   *Emu
	pos uint64
}

func (w *bufWriter) str(s string) uint64 {
	a := w.pos
	w.e.Mem.WriteCStr(a, s)
	w.pos = (w.pos + uint64(len(s)) + 1 + 7) &^ 7
	return a
}

func (w *bufWriter) bytes(b []byte) uint64 {
	a := w.pos
	w.e.Mem.Write(a, b)
	w.pos = (w.pos + uint64(len(b)) + 7) &^ 7
	return a
}

// ptrs writes a NULL-terminated pointer array.
func (w *bufWriter) ptrs(ps ...uint64) uint64 {
	a := w.pos
	for i, p := range ps {
		w.e.Mem.W64(a+8*uint64(i), p)
	}
	w.pos += 8 * uint64(len(ps)+1)
	return a
}

// hostent builds a hostent (IPv4 only, as gethostbyname) in the static buffer.
func (e *Emu) hostent(name string, addrs []netip.Addr) uint64 {
	he := e.static("hostent")
	w := &bufWriter{e: e, pos: he + 32}
	nameP := w.str(name)
	aliases := w.ptrs()
	var aps []uint64
	for _, a := range addrs {
		if a.Is4() && len(aps) < 16 {
			v := a.As4()
			aps = append(aps, w.bytes(v[:]))
		}
	}
	e.Mem.W64(he, nameP)
	e.Mem.W64(he+8, aliases)
	e.Mem.W16(he+16, wsAFInet)
	e.Mem.W16(he+18, 4)
	e.Mem.W64(he+24, w.ptrs(aps...))
	return he
}

// reverseName returns the host name for a (numeric=false: may consult DNS).
// ok=false: a host query is running and the thread is parked; return at once.
func (e *Emu) reverseName(a netip.Addr, flags uint32) (_ string, _ uint32, ok bool) {
	if flags&niNumericHost == 0 {
		if a.IsLoopback() {
			return "localhost", 0, true
		}
		names, err, done := asyncLookup(e, "addr:"+a.String(), func(ctx context.Context) ([]string, error) {
			return net.DefaultResolver.LookupAddr(ctx, a.String())
		})
		if !done {
			return "", 0, false
		}
		if err == nil && len(names) > 0 {
			n := strings.TrimSuffix(names[0], ".")
			if flags&niNoFQDN != 0 {
				n, _, _ = strings.Cut(n, ".")
			}
			return n, 0, true
		}
		if flags&niNameReqd != 0 {
			return "", wsaHOSTNOTFOUND, true
		}
	}
	return a.String(), 0, true
}

// getnameinfo implements getnameinfo/GetNameInfoW; returns the error code.
func (e *Emu) getnameinfo(wide bool) uint64 {
	ret := func(code uint32) uint64 { e.SetLastError(code); return uint64(code) }
	sa, code := e.readSockaddr(e.Arg(0), int64(int32(e.Arg32(1))))
	if code != 0 {
		return ret(code)
	}
	host, hostLen, serv, servLen, flags := e.Arg(2), e.Arg32(3), e.Arg(4), e.Arg32(5), e.Arg32(6)
	if (host == 0 || hostLen == 0) && (serv == 0 || servLen == 0) {
		return ret(wsaHOSTNOTFOUND)
	}
	b := encodeSockaddr(sa)
	port := int(b[2])<<8 | int(b[3])
	var a netip.Addr
	if b[0] == wsAFInet {
		a = netip.AddrFrom4([4]byte(b[4:8]))
	} else {
		a = netip.AddrFrom16([16]byte(b[8:24]))
		if z := e.Mem.R32(e.Arg(0) + 24); z != 0 && e.Arg32(1) >= sizeofSockaddrIn6 {
			a = a.WithZone(strconv.FormatUint(uint64(z), 10))
		}
	}
	put := func(buf uint64, n uint32, s string) bool {
		if wide {
			if uint32(len(utf16Bytes(s))/2) > n {
				return false
			}
			e.Mem.WriteWStr(buf, s)
			return true
		}
		if uint32(len(s))+1 > n {
			return false
		}
		e.Mem.WriteCStr(buf, s)
		return true
	}
	if host != 0 && hostLen != 0 {
		name, code, ok := e.reverseName(a, flags)
		if !ok {
			return 0
		}
		if code != 0 {
			return ret(code)
		}
		if !put(host, hostLen, name) {
			return ret(wsaEFAULT)
		}
	}
	if serv != 0 && servLen != 0 {
		s := strconv.Itoa(port)
		if flags&niNumericServ == 0 {
			proto := "tcp"
			if flags&niDgram != 0 {
				proto = "udp"
			}
			if n, ok := serviceName(port, proto); ok {
				s = n
			}
		}
		if !put(serv, servLen, s) {
			return ret(wsaEFAULT)
		}
	}
	return ret(0)
}
