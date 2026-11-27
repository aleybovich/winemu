//go:build darwin || linux

package win

import "syscall"

// Windows sockaddr layouts:
//
//	sockaddr_in  (16): u16 family=2,  u16 port (BE), [4]addr, [8]zero
//	sockaddr_in6 (28): u16 family=23, u16 port (BE), u32 flowinfo, [16]addr, u32 scope_id
const (
	sizeofSockaddrIn  = 16
	sizeofSockaddrIn6 = 28
)

// hostAF maps a Windows address family to the host one (-1 = unsupported).
func hostAF(af int32) int {
	switch af {
	case wsAFInet:
		return syscall.AF_INET
	case wsAFInet6:
		return syscall.AF_INET6
	case wsAFUnspec:
		return syscall.AF_UNSPEC
	}
	return -1
}

func sockaddrLen(af int32) int {
	if af == wsAFInet6 {
		return sizeofSockaddrIn6
	}
	return sizeofSockaddrIn
}

// readSockaddr decodes a guest sockaddr of namelen bytes; on failure it
// returns a WSA error code.
func (e *Emu) readSockaddr(a uint64, namelen int64) (syscall.Sockaddr, uint32) {
	if a == 0 || namelen < 2 {
		return nil, wsaEFAULT
	}
	port := func() int { b := e.Mem.ReadBytes(a+2, 2); return int(b[0])<<8 | int(b[1]) }
	switch int32(e.Mem.R16(a)) {
	case wsAFInet:
		if namelen < sizeofSockaddrIn {
			return nil, wsaEFAULT
		}
		sa := &syscall.SockaddrInet4{Port: port()}
		copy(sa.Addr[:], e.Mem.ReadBytes(a+4, 4))
		return sa, 0
	case wsAFInet6:
		if namelen < 24 { // the pre-scope_id sockaddr_in6 is 24 bytes
			return nil, wsaEFAULT
		}
		sa := &syscall.SockaddrInet6{Port: port()}
		copy(sa.Addr[:], e.Mem.ReadBytes(a+8, 16))
		if namelen >= sizeofSockaddrIn6 {
			sa.ZoneId = e.Mem.R32(a + 24)
		}
		return sa, 0
	}
	return nil, wsaEAFNOSUPPORT
}

// encodeSockaddr returns the Windows encoding of sa (nil if unsupported).
func encodeSockaddr(sa syscall.Sockaddr) []byte {
	switch v := sa.(type) {
	case *syscall.SockaddrInet4:
		b := make([]byte, sizeofSockaddrIn)
		b[0] = wsAFInet
		b[2], b[3] = byte(v.Port>>8), byte(v.Port)
		copy(b[4:], v.Addr[:])
		return b
	case *syscall.SockaddrInet6:
		b := make([]byte, sizeofSockaddrIn6)
		b[0] = wsAFInet6
		b[2], b[3] = byte(v.Port>>8), byte(v.Port)
		copy(b[8:], v.Addr[:])
		b[24], b[25], b[26], b[27] = byte(v.ZoneId), byte(v.ZoneId>>8), byte(v.ZoneId>>16), byte(v.ZoneId>>24)
		return b
	}
	return nil
}

// writeSockaddr stores sa at a with the in/out length at lenp (an int).
// a == 0 means the caller does not want the address. Returns a WSA error
// code (WSAEFAULT if the buffer is too small).
func (e *Emu) writeSockaddr(sa syscall.Sockaddr, a, lenp uint64) uint32 {
	if a == 0 {
		return 0
	}
	if lenp == 0 {
		return wsaEFAULT
	}
	b := encodeSockaddr(sa)
	if b == nil {
		// unnamed / unknown: report an all-zero address of length 0
		e.Mem.W32(lenp, 0)
		return 0
	}
	if int64(int32(e.Mem.R32(lenp))) < int64(len(b)) {
		return wsaEFAULT
	}
	e.Mem.Write(a, b)
	e.Mem.W32(lenp, uint32(len(b)))
	return 0
}
