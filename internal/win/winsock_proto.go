//go:build darwin || linux

package win

// Transport protocol catalog: WSAEnumProtocolsA/W, getsockopt
// SO_PROTOCOL_INFOA/W and the WSAPROTOCOL_INFO structure.

const (
	sizeofWSAProtoInfoW = 628 // ... szProtocol WCHAR[256] at 116
	sizeofWSAProtoInfoA = 372 // ... szProtocol CHAR[256] at 116
	protoInfoReserved   = 112 // dwProviderReserved
	protoInfoNameOffset = 116

	wsSoProtocolInfoA = 0x2004
	wsSoProtocolInfoW = 0x2005

	xp1Connectionless   = 0x00000001
	xp1GuaranteedDeliv  = 0x00000002
	xp1GuaranteedOrder  = 0x00000004
	xp1MessageOriented  = 0x00000008
	xp1GracefulClose    = 0x00000020
	xp1ExpeditedData    = 0x00000040
	xp1SupportBroadcast = 0x00000200
	xp1SupportMulti     = 0x00000400
	xp1IfsHandles       = 0x00020000
	pflMatchesProtZero  = 0x00000008
)

type wsProto struct {
	af, typ, proto int32
	flags          uint32
	msgSize        uint32
	catalog        uint32
	provider       [16]byte // provider GUID (bytes as laid out in memory)
	name           string
}

var (
	// {E70F1AA0-AB8B-11CF-8CA3-00805F48A192}, {F9EAB0C0-26D4-11D0-BBBF-00AA006C34E4}
	guidTCPIP4 = [16]byte{0xA0, 0x1A, 0x0F, 0xE7, 0x8B, 0xAB, 0xCF, 0x11, 0x8C, 0xA3, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92}
	guidTCPIP6 = [16]byte{0xC0, 0xB0, 0xEA, 0xF9, 0xD4, 0x26, 0xD0, 0x11, 0xBB, 0xBF, 0x00, 0xAA, 0x00, 0x6C, 0x34, 0xE4}

	tcpFlags = uint32(xp1GuaranteedDeliv | xp1GuaranteedOrder | xp1GracefulClose | xp1ExpeditedData | xp1IfsHandles)
	udpFlags = uint32(xp1Connectionless | xp1MessageOriented | xp1SupportBroadcast | xp1SupportMulti | xp1IfsHandles)

	// the catalog, in enumeration order (read-only)
	wsProtocols = []wsProto{
		{wsAFInet, wsSockStream, 6, tcpFlags, 0, 1001, guidTCPIP4, "Tcpip [TCP/IP]"},
		{wsAFInet, wsSockDgram, 17, udpFlags, 0xFFBB, 1002, guidTCPIP4, "Tcpip [UDP/IP]"},
		{wsAFInet6, wsSockStream, 6, tcpFlags, 0, 1003, guidTCPIP6, "Tcpip [TCP/IPv6]"},
		{wsAFInet6, wsSockDgram, 17, udpFlags, 0xFFBB, 1004, guidTCPIP6, "Tcpip [UDP/IPv6]"},
	}
)

// protoFor returns the catalog entry matching a socket (protocol 0 = the
// type's default), or nil.
func protoFor(af, typ, proto int32) *wsProto {
	for i := range wsProtocols {
		p := &wsProtocols[i]
		if p.af == af && p.typ == typ && (proto == 0 || proto == p.proto) {
			return p
		}
	}
	return nil
}

// writeProtoInfo writes a WSAPROTOCOL_INFOA/W at a.
func (e *Emu) writeProtoInfo(a uint64, p *wsProto, wide bool, reserved uint32) {
	size := uint64(sizeofWSAProtoInfoA)
	if wide {
		size = sizeofWSAProtoInfoW
	}
	m := e.Mem
	m.Fill(a, 0, size)
	m.W32(a, p.flags)
	m.W32(a+16, pflMatchesProtZero)
	m.Write(a+20, p.provider[:])
	m.W32(a+36, p.catalog)
	m.W32(a+40, 1) // ProtocolChain.ChainLen = BASE_PROTOCOL
	m.W32(a+72, 2) // iVersion
	m.W32(a+76, uint32(p.af))
	sa := uint32(sockaddrLen(p.af))
	m.W32(a+80, sa) // iMaxSockAddr
	m.W32(a+84, sa) // iMinSockAddr
	m.W32(a+88, uint32(p.typ))
	m.W32(a+92, uint32(p.proto))
	m.W32(a+108, p.msgSize)
	m.W32(a+protoInfoReserved, reserved)
	if wide {
		m.WriteWStr(a+protoInfoNameOffset, p.name)
	} else {
		m.WriteCStr(a+protoInfoNameOffset, p.name)
	}
}

// enumProtocols implements WSAEnumProtocolsA/W(lpiProtocols, buf, *len).
func (e *Emu) enumProtocols(wide bool) uint64 {
	filter, buf, lenp := e.Arg(0), e.Arg(1), e.Arg(2)
	if lenp == 0 {
		return e.wsaFail(wsaEFAULT)
	}
	var want map[int32]bool
	if filter != 0 {
		want = map[int32]bool{}
		for p := filter; ; p += 4 {
			v := int32(e.Mem.R32(p))
			if v == 0 {
				break
			}
			want[v] = true
		}
	}
	var sel []*wsProto
	for i := range wsProtocols {
		if want == nil || want[wsProtocols[i].proto] {
			sel = append(sel, &wsProtocols[i])
		}
	}
	size := uint32(sizeofWSAProtoInfoA)
	if wide {
		size = sizeofWSAProtoInfoW
	}
	need := size * uint32(len(sel))
	if buf == 0 || e.Mem.R32(lenp) < need {
		e.Mem.W32(lenp, need)
		return e.wsaFail(wsaENOBUFS)
	}
	for i, p := range sel {
		e.writeProtoInfo(buf+uint64(i)*uint64(size), p, wide, 0)
	}
	return uint64(len(sel))
}

// getProtoInfoOpt answers getsockopt(SO_PROTOCOL_INFOA/W).
func (e *Emu) getProtoInfoOpt(s *sockObj, wide bool, val, lenp uint64) uint64 {
	size := uint32(sizeofWSAProtoInfoA)
	if wide {
		size = sizeofWSAProtoInfoW
	}
	if e.Mem.R32(lenp) < size {
		return e.wsaFail(wsaEFAULT)
	}
	p := protoFor(s.af, s.typ, s.proto)
	if p == nil {
		return e.wsaFail(wsaENOPROTOOPT)
	}
	e.writeProtoInfo(val, p, wide, 0)
	e.Mem.W32(lenp, size)
	return 0
}

func init() {
	w := "ws2_32.dll"
	regWS(w, "WSAEnumProtocolsW", func(e *Emu) uint64 { return e.enumProtocols(true) })
	regWS(w, "WSAEnumProtocolsA", func(e *Emu) uint64 { return e.enumProtocols(false) })
}
