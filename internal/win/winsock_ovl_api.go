//go:build darwin || linux

package win

// Overlapped winsock APIs: WSASend/WSARecv(From)/WSASendTo with OVERLAPPED,
// the Microsoft extension functions (AcceptEx, ConnectEx, DisconnectEx,
// GetAcceptExSockaddrs) and the WSAIoctl codes that hand them out.

import (
	"io"
	"syscall"
)

const (
	sioGetExtensionFuncPtr = 0xC8000006
	sioUDPConnReset        = 0x9800000C
	sioUDPNetReset         = 0x9800000F
	sioBaseHandle          = 0x48000022
	sioBSPHandle           = 0x4800001B
	sioBSPHandleSelect     = 0x4800001C
	sioBSPHandlePoll       = 0x4800001D

	wsSoUpdateAcceptCtx  = 0x700B
	wsSoUpdateConnectCtx = 0x7010

	tfDisconnect  = 0x01
	tfReuseSocket = 0x02
)

// ovlTransfer issues an overlapped WSASend/WSASendTo/WSARecv/WSARecvFrom
// (args 1..3: lpBuffers, dwBufferCount, lpNumberOfBytes; flagsPtr: lpFlags).
func (e *Emu) ovlTransfer(s *sockObj, send bool, flags uint32, flagsPtr uint64, to syscall.Sockaddr, from, flen, ov, routine uint64) uint64 {
	bp, cnt, nbytes := e.Arg(1), e.Arg32(2), e.Arg(3)
	if bp == 0 || cnt == 0 {
		return e.wsaFail(wsaEFAULT)
	}
	if send {
		flags &^= wsMsgWaitAll
	}
	if _, ok := hostMsgFlags(flags); !ok {
		return e.wsaFail(wsaEOPNOTSUPP)
	}
	switch {
	case s.typ == wsSockStream && !s.connected:
		e.finishConnect(s)
		if !s.connected {
			return e.wsaFail(wsaENOTCONN)
		}
	case send && s.shutSend:
		return e.wsaFail(wsaESHUTDOWN)
	case !send && s.typ != wsSockStream && !s.bound:
		return e.wsaFail(wsaEINVAL)
	case send && s.typ != wsSockStream && to == nil && !s.connected:
		return e.wsaFail(wsaEDESTADDRREQ)
	}
	if from != 0 && (flen == 0 || int64(int32(e.Mem.R32(flen))) < int64(sockaddrLen(s.af))) {
		return e.wsaFail(wsaEFAULT)
	}
	addrs, lens, total := e.wsaBufs(bp, cnt)
	op := &ovOp{kind: opRecv, s: s, ov: ov, routine: routine, addrs: addrs, lens: lens, total: total,
		flags: flags &^ wsMsgWaitAll, from: from, flen: flen}
	if send {
		op.kind = opSend
		if s.typ != wsSockStream {
			op.to = to
		}
	}
	done, st, n := e.startOp(op, e.Mem.R64(ov+24))
	if send && s.typ != wsSockStream {
		s.bound = true // implicit bind
	}
	if !done {
		return e.wsaFail(wsaIOPending)
	}
	if st != statusSuccess && st != statusBufferOverflow {
		return e.wsaFail(statusWSA(st)) // immediate failure: no completion is indicated
	}
	if nbytes != 0 {
		e.Mem.W32(nbytes, n)
	}
	if flagsPtr != 0 {
		e.Mem.W32(flagsPtr, 0)
	}
	if st == statusBufferOverflow {
		return e.wsaFail(wsaEMSGSIZE)
	}
	return 0
}

// boolResult maps an issued extension call to its BOOL result.
func (e *Emu) boolResult(done bool, st, n uint32, nret uint64) uint64 {
	if !done {
		e.SetLastError(wsaIOPending)
		return 0
	}
	if code := statusWSA(st); code != 0 {
		e.SetLastError(code)
		return 0
	}
	if nret != 0 {
		e.Mem.W32(nret, n)
	}
	return 1
}

func (e *Emu) boolFail(code uint32) uint64 {
	e.SetLastError(code)
	return 0
}

// AcceptEx(sListen, sAccept, lpOutputBuffer, dwReceiveDataLength,
// dwLocalAddressLength, dwRemoteAddressLength, lpdwBytesReceived, lpOverlapped)
func (e *Emu) acceptEx() uint64 {
	ls := e.sockArg(0)
	if ls == nil {
		return 0
	}
	as := e.sockArg(1)
	if as == nil {
		return 0
	}
	buf, rx, ll, rl, nret, ov := e.Arg(2), e.Arg32(3), e.Arg32(4), e.Arg32(5), e.Arg(6), e.Arg(7)
	need := uint32(sockaddrLen(ls.af)) + 16
	switch {
	case ov == 0, !ls.listening, as == ls, as.bound || as.connected || as.listening || as.typ != wsSockStream:
		return e.boolFail(wsaEINVAL)
	case buf == 0 || ll < need || rl < need:
		return e.boolFail(wsaEFAULT)
	}
	ls.evEnabled |= fdAccept & ls.evMask
	op := &ovOp{kind: opAccept, s: ls, as: as, ov: ov, buf: buf, rxLen: rx, lLen: ll, rLen: rl}
	done, st, n := e.startOp(op, e.Mem.R64(ov+24))
	return e.boolResult(done, st, n, nret)
}

// ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped)
func (e *Emu) connectEx() uint64 {
	s := e.sockArg(0)
	if s == nil {
		return 0
	}
	sbuf, slen, nret, ov := e.Arg(3), e.Arg32(4), e.Arg(5), e.Arg(6)
	switch {
	case ov == 0, s.typ != wsSockStream, !s.bound, s.listening:
		return e.boolFail(wsaEINVAL)
	case s.connected:
		return e.boolFail(wsaEISCONN)
	case s.connecting:
		return e.boolFail(wsaEALREADY)
	case slen > 0 && sbuf == 0:
		return e.boolFail(wsaEFAULT)
	}
	sa, code := e.readSockaddr(e.Arg(1), int64(int32(e.Arg32(2))))
	if code != 0 {
		return e.boolFail(code)
	}
	err := syscall.Connect(s.fd, sa)
	if err != nil && err != syscall.EINPROGRESS && !isAgain(err) {
		return e.boolFail(wsaErr(err))
	}
	s.connErr = 0
	op := &ovOp{kind: opConnect, s: s, ov: ov, addrs: []uint64{sbuf}, lens: []int64{int64(slen)}, total: int64(slen)}
	if err == nil {
		op.connected, s.connected = true, true
	} else {
		s.connecting = true
	}
	done, st, n := e.startOp(op, e.Mem.R64(ov+24))
	return e.boolResult(done, st, n, nret)
}

// DisconnectEx(s, lpOverlapped, dwFlags, reserved): graceful close of the
// connection; TF_REUSE_SOCKET makes the socket usable for AcceptEx/ConnectEx
// again. It completes at once.
func (e *Emu) disconnectEx() uint64 {
	s := e.sockArg(0)
	if s == nil {
		return 0
	}
	ov, flags := e.Arg(1), e.Arg32(2)
	switch {
	case flags&^(tfReuseSocket|tfDisconnect) != 0 || e.Arg32(3) != 0:
		return e.boolFail(wsaEINVAL)
	case !s.connected:
		return e.boolFail(wsaENOTCONN)
	}
	e.cancelOps(s, nil, 0)
	_ = syscall.Shutdown(s.fd, syscall.SHUT_WR) // best effort: the peer may be gone
	if flags&tfReuseSocket != 0 {
		haf, htyp := hostAF(s.af), syscall.SOCK_STREAM
		fd, err := syscall.Socket(haf, htyp, int(s.proto))
		if err != nil {
			return e.boolFail(wsaErr(err))
		}
		syscall.CloseOnExec(fd)
		if err := syscall.SetNonblock(fd, true); err != nil {
			syscall.Close(fd)
			return e.boolFail(wsaErr(err))
		}
		syscall.Close(s.fd)
		s.fd = fd
		s.connected, s.connecting, s.bound, s.shutSend, s.closeSeen = false, false, false, false, false
		s.connErr = 0
		s.ovl.acceptCtx = false
	} else {
		s.shutSend = true
	}
	if ov != 0 && s.overlapped {
		e.indicateNow(s, ov, 0, 0)
	}
	return 1
}

// GetAcceptExSockaddrs(lpOutputBuffer, dwReceiveDataLength, dwLocalAddressLength,
// dwRemoteAddressLength, LocalSockaddr**, LocalSockaddrLength*, RemoteSockaddr**, RemoteSockaddrLength*)
func (e *Emu) getAcceptExSockaddrs() uint64 {
	buf, rx, ll := e.Arg(0), e.Arg32(1), e.Arg32(2)
	put := func(area, pp, lp uint64) {
		if pp != 0 {
			e.Mem.W64(pp, area+4)
		}
		if lp != 0 {
			e.Mem.W32(lp, e.Mem.R32(area))
		}
	}
	if buf == 0 {
		return 0
	}
	put(buf+uint64(rx), e.Arg(4), e.Arg(5))
	put(buf+uint64(rx)+uint64(ll), e.Arg(6), e.Arg(7))
	return 0
}

// extension functions handed out by SIO_GET_EXTENSION_FUNCTION_POINTER
var (
	connectExFn    = wsWrap(func(e *Emu) uint64 { return e.connectEx() })
	disconnectExFn = wsWrap(func(e *Emu) uint64 { return e.disconnectEx() })
)

type wsGUID struct {
	d1     uint32
	d2, d3 uint16
	d4     [8]byte
}

var wsExtensions = []struct {
	id   wsGUID
	name string // mswsock.dll export (or extension-only name)
}{
	{wsGUID{0xb5367df1, 0xcbac, 0x11cf, [8]byte{0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}}, "AcceptEx"},
	{wsGUID{0xb5367df2, 0xcbac, 0x11cf, [8]byte{0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}}, "GetAcceptExSockaddrs"},
	{wsGUID{0x25a207b9, 0xddf3, 0x4660, [8]byte{0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}}, "ConnectEx"},
	{wsGUID{0xb5367df0, 0xcbac, 0x11cf, [8]byte{0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}}, "TransmitFile"},
	{wsGUID{0x7fda2e11, 0x8630, 0x436f, [8]byte{0xa0, 0x31, 0xf5, 0x36, 0xa6, 0xee, 0xc1, 0x57}}, "DisconnectEx"},
}

// extensionFn returns a callable guest address for an extension function.
func (e *Emu) extensionFn(name string) uint64 {
	var fn Fn
	switch name {
	case "ConnectEx":
		fn = connectExFn
	case "DisconnectEx":
		fn = disconnectExFn
	default:
		fn = registry["mswsock.dll"].funcs[name].fn
	}
	return e.stub("mswsock.dll", name, fn)
}

// wsaIoctlExt handles the WSAIoctl codes of the extension layer.
func (e *Emu) wsaIoctlExt(s *sockObj, code uint32, in uint64, inLen uint32, out uint64, outLen uint32, ret func(uint32) uint64) uint64 {
	switch code {
	case sioGetExtensionFuncPtr:
		if in == 0 || inLen < 16 || out == 0 || outLen < 8 {
			return e.wsaFail(wsaEFAULT)
		}
		g := wsGUID{e.Mem.R32(in), e.Mem.R16(in + 4), e.Mem.R16(in + 6), [8]byte(e.Mem.ReadBytes(in+8, 8))}
		for _, x := range wsExtensions {
			if x.id == g {
				e.Mem.W64(out, e.extensionFn(x.name))
				return ret(8)
			}
		}
		return e.wsaFail(wsaEINVAL)
	case sioUDPConnReset, sioUDPNetReset:
		// ICMP errors on unconnected datagram sockets: the host never reports them
		if s.typ != wsSockDgram || in == 0 || inLen < 4 {
			return e.wsaFail(wsaEINVAL)
		}
		return ret(0)
	case sioBaseHandle, sioBSPHandle, sioBSPHandleSelect, sioBSPHandlePoll:
		if out == 0 || outLen < 8 {
			return e.wsaFail(wsaEFAULT)
		}
		e.Mem.W64(out, e.Arg(0)) // no layered providers: the socket is its own base
		return ret(8)
	}
	return e.wsaFail(wsaEOPNOTSUPP)
}

// setUpdateContext handles setsockopt(SO_UPDATE_ACCEPT_CONTEXT /
// SO_UPDATE_CONNECT_CONTEXT); handled=false for other options.
func (e *Emu) setUpdateContext(s *sockObj, level, name uint32, val uint64, n int32) (r uint64, handled bool) {
	if level != wsSolSocket {
		return 0, false
	}
	switch name {
	case wsSoUpdateAcceptCtx:
		if val == 0 || n < 8 {
			return e.wsaFail(wsaEFAULT), true
		}
		ls, ok := e.handles.get(e.Mem.R64(val)).(*sockObj)
		if !ok {
			return e.wsaFail(wsaENOTSOCK), true
		}
		if ls != s {
			e.lockSock(ls)
		}
		if !ls.listening || !s.connected {
			return e.wsaFail(wsaEINVAL), true
		}
		s.ovl.acceptCtx = false
		s.nonblock = ls.nonblock
		return 0, true
	case wsSoUpdateConnectCtx:
		if !s.connected {
			return e.wsaFail(wsaENOTCONN), true
		}
		return 0, true
	}
	return 0, false
}

// TransmitFile(hSocket, hFile, nNumberOfBytesToWrite, nNumberOfBytesPerSend,
// lpOverlapped, lpTransmitBuffers, dwFlags): sends head buffer, file range
// and tail buffer. Overlapped: the range starts at OVERLAPPED.Offset and the
// file pointer is not moved; otherwise it starts at (and advances) the file
// pointer. TF_DISCONNECT/TF_REUSE_SOCKET are not supported (WSAEOPNOTSUPP).
func (e *Emu) transmitFile() uint64 {
	s := e.sockArg(0)
	if s == nil {
		return 0
	}
	e.resumeWait() // no timeout
	fh, nb, ov, tfb, flags := e.Arg(1), int64(e.Arg32(2)), e.Arg(4), e.Arg(5), e.Arg32(6)
	if flags&(tfDisconnect|tfReuseSocket) != 0 {
		return e.boolFail(wsaEOPNOTSUPP)
	}
	if !s.connected {
		e.finishConnect(s)
	}
	if s.typ != wsSockStream || !s.connected {
		return e.boolFail(wsaENOTCONN)
	}
	var f *fileObj
	if fh != 0 {
		if f = e.fileObj(fh); f == nil || f.f == nil || f.isDir {
			return e.boolFail(wsaEINVAL)
		}
	}
	overlapped := ov != 0 && s.overlapped
	var data, fileData []byte
	if tfb != 0 {
		data = append(data, e.Mem.ReadBytes(e.Mem.R64(tfb), int(e.Mem.R32(tfb+8)))...)
	}
	if f != nil {
		var off int64
		if overlapped {
			off = int64(e.Mem.R32(ov+16)) | int64(e.Mem.R32(ov+20))<<32
		} else {
			var err error
			if off, err = f.f.Seek(0, io.SeekCurrent); err != nil {
				return e.boolFail(wsaEINVAL)
			}
		}
		fi, err := f.f.Stat()
		if err != nil {
			return e.boolFail(wsaEINVAL)
		}
		n := max(fi.Size()-off, 0)
		if nb != 0 {
			n = min(n, nb)
		}
		fileData = make([]byte, n)
		k, err := f.f.ReadAt(fileData, off)
		if err != nil && err != io.EOF {
			return e.boolFail(wsaENOBUFS)
		}
		fileData = fileData[:k]
		data = append(data, fileData...)
	}
	if tfb != 0 {
		data = append(data, e.Mem.ReadBytes(e.Mem.R64(tfb+16), int(e.Mem.R32(tfb+24)))...)
	}
	if overlapped {
		op := &ovOp{kind: opSend, s: s, ov: ov, data: data, total: int64(len(data))}
		done, st, n := e.startOp(op, e.Mem.R64(ov+24))
		return e.boolResult(done, st, n, 0)
	}
	// blocking: the bytes sent so far survive re-execution in sendDone
	t := e.Cur
	done := s.sendDone[t]
	delete(s.sendDone, t)
	got, err := syscall.SendmsgN(s.fd, data[min(done, len(data)):], nil, nil, 0)
	switch {
	case err == syscall.EPIPE:
		return e.boolFail(wsaECONNRESET)
	case err != nil && !isAgain(err):
		return e.boolFail(wsaErr(err))
	}
	if done += max(got, 0); done < len(data) {
		if s.sendDone == nil {
			s.sendDone = map[*Thread]int{}
		}
		s.sendDone[t] = done
		return e.blockSock(s, true, 0)
	}
	if f != nil {
		if _, err := f.f.Seek(int64(len(fileData)), io.SeekCurrent); err != nil {
			return e.boolFail(wsaEINVAL)
		}
	}
	return 1
}

func init() {
	m := "mswsock.dll"
	regWS(m, "TransmitFile", func(e *Emu) uint64 { return e.transmitFile() })
	regWS(m, "AcceptEx", func(e *Emu) uint64 { return e.acceptEx() })
	regWS(m, "GetAcceptExSockaddrs", func(e *Emu) uint64 { return e.getAcceptExSockaddrs() })
}
