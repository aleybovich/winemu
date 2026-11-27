//go:build darwin || linux

package win

import (
	"syscall"
	"time"
)

// WSAEventSelect network-event recording.
//
// Windows re-enabling rules: once FD_READ/FD_ACCEPT/FD_WRITE/FD_OOB has been
// recorded, it is not recorded again until the matching re-enabling call
// (recv*, accept, send* failing with WSAEWOULDBLOCK). FD_CONNECT and FD_CLOSE
// are recorded once. evEnabled holds the events that may be recorded now.

const (
	sizeofWSANetworkEvents = 44 // long lNetworkEvents; int iErrorCode[10]
	wsaMaxEvents           = 64
	netPollInterval        = 500 * time.Microsecond
)

// postNetEvent records network event bit on s and signals its event.
func (e *Emu) postNetEvent(s *sockObj, bit int, code uint32) {
	m := uint32(1) << bit
	if s.evMask&m == 0 {
		return
	}
	s.evEnabled &^= m
	s.evPending |= m
	e.netSt().ovl.progress++
	s.evErr[bit] = int32(code)
	if s.evt != nil {
		e.setNetEvent(s.evt, true)
	}
}

// setNetEvent is the single place where winsock changes an event object's
// state (network event recorded -> wake waiters; WSAEnumNetworkEvents reset).
// Event state is kernel state: it changes under the kernel lock, and setting
// it notifies waiters in every process.
func (e *Emu) setNetEvent(ev *eventObj, v bool) {
	e.k.mu.Lock()
	ev.set = v
	e.k.mu.Unlock()
	if v {
		e.k.notify()
	}
}

// pollSock records the network events that rd/wr readiness implies.
// Call with s locked.
func (e *Emu) pollSock(s *sockObj, rd, wr bool) {
	if s.closed || s.evMask == 0 {
		return
	}
	en := s.evEnabled
	switch {
	case s.connecting:
		if wr && e.finishConnect(s) && en&fdConnect != 0 {
			e.postNetEvent(s, fdConnectBit, s.connErr)
		}
	case s.listening:
		if rd && en&fdAccept != 0 {
			e.postNetEvent(s, fdAcceptBit, 0)
		}
	case s.connected || s.typ != wsSockStream:
		if rd && s.typ == wsSockStream && !s.closeSeen {
			var b [1]byte
			n, _, err := syscall.Recvfrom(s.fd, b[:], syscall.MSG_PEEK)
			switch {
			case err == nil && n > 0:
				if en&fdRead != 0 {
					e.postNetEvent(s, fdReadBit, 0)
				}
			case err == nil && n == 0:
				s.closeSeen = true
				e.postNetEvent(s, fdCloseBit, 0)
			case err != nil && !isAgain(err):
				s.closeSeen = true
				e.postNetEvent(s, fdCloseBit, wsaErr(err))
			}
		} else if rd && s.typ != wsSockStream && en&fdRead != 0 {
			e.postNetEvent(s, fdReadBit, 0)
		}
		if wr && en&fdWrite != 0 && !s.closeSeen {
			e.postNetEvent(s, fdWriteBit, 0)
		}
	}
}

// pollNet is called by the scheduler; it records network events for all
// event-selected sockets.
func (e *Emu) pollNet(now time.Time) {
	n := e.net
	if n == nil || len(n.socks) == 0 && len(n.ovl.ops) == 0 {
		return
	}
	// the host poller (winsock_poller.go) reports readiness at once
	fired := n.ovl.pollerFired()
	if now.Sub(n.lastPoll) < netPollInterval && !fired {
		return
	}
	if fired {
		before := n.ovl.progress
		defer func() {
			if n.ovl.progress == before { // readiness nobody waits for: do not spin on it
				n.ovl.poller.cooldown = now.Add(2 * time.Millisecond)
			}
		}()
	}
	n.lastPoll = now
	var socks []*sockObj
	var fds []int
	for s := range n.socks {
		s.mu.Lock()
		switch {
		case s.closed:
			delete(n.socks, s) // forget closed sockets (no longer referenced)
		case s.evMask != 0 && s.evOwner == n:
			socks = append(socks, s)
			fds = append(fds, s.fd)
		}
		s.mu.Unlock()
	}
	if len(socks) > 0 {
		rd, wr := fdPoll(fds)
		for i, s := range socks {
			s.mu.Lock()
			e.pollSock(s, rd[i], wr[i])
			s.mu.Unlock()
		}
	}
	e.pollOverlapped()
}

func (e *Emu) pollOne(s *sockObj) {
	rd, wr := fdPoll([]int{s.fd})
	e.pollSock(s, rd[0], wr[0])
}

func init() {
	w := "ws2_32.dll"
	regWS(w, "WSACreateEvent", func(e *Emu) uint64 { return e.handles.add(&eventObj{manual: true}) })
	// event-object calls are the kernel32 ones (same arguments and errors)
	for wsa, k32 := range map[string]string{"WSACloseEvent": "CloseHandle", "WSASetEvent": "SetEvent", "WSAResetEvent": "ResetEvent"} {
		regWS(w, wsa, func(e *Emu) uint64 { return registry[dK32].funcs[k32].fn(e) })
	}
	regWS(w, "WSAEventSelect", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		mask := e.Arg32(2) & fdAllEvents
		var ev *eventObj
		if mask != 0 {
			var ok bool
			if ev, ok = e.handles.get(e.Arg(1)).(*eventObj); !ok {
				return e.wsaFail(wsaEINVAL)
			}
		}
		// cancels any previous selection and clears the network event record
		s.evt, s.evMask, s.evEnabled, s.evPending = ev, mask, mask, 0
		s.evErr = [10]int32{}
		s.nonblock = true
		s.evOwner = e.netSt()
		if mask != 0 {
			e.pollOne(s)
		}
		return 0
	})
	regWS(w, "WSAEnumNetworkEvents", func(e *Emu) uint64 {
		s := e.sockArg(0)
		if s == nil {
			return sockErr
		}
		out := e.Arg(2)
		if out == 0 {
			return e.wsaFail(wsaEFAULT)
		}
		var ev *eventObj
		if h := e.Arg(1); h != 0 {
			var ok bool
			if ev, ok = e.handles.get(h).(*eventObj); !ok {
				return e.wsaFail(wsaEINVAL)
			}
		}
		e.pollOne(s)
		if ev != nil {
			e.setNetEvent(ev, false)
		}
		e.Mem.W32(out, s.evPending)
		for i, c := range s.evErr {
			e.Mem.W32(out+4+4*uint64(i), uint32(c))
		}
		s.evPending = 0
		s.evErr = [10]int32{}
		return 0
	})
	regWS(w, "WSAWaitForMultipleEvents", func(e *Emu) uint64 {
		n := e.Arg32(0)
		if n == 0 || n > wsaMaxEvents || e.Arg(1) == 0 {
			e.endWaitIf()
			e.SetLastError(errInvalidParameter)
			return waitFailed
		}
		hs := make([]uint64, n)
		for i := range hs {
			hs[i] = e.Mem.R64(e.Arg(1) + 8*uint64(i))
		}
		return e.alertWait(e.Arg32(4) != 0, func() uint64 { return e.waitMany(hs, e.Arg32(2) != 0, e.Arg32(3)) })
	})
}
