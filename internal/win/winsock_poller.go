//go:build darwin || linux

package win

// Host readiness poller.
//
// pollNet only runs when the scheduler loops; an idle process sleeps up to
// its poll interval (1 ms growing to 10 ms) between checks. So that a reply
// on a socket wakes it at once, each process that waits for sockets owns one
// poller goroutine: when the process goes idle with pending overlapped
// operations or active WSAEventSelect interest, netEventsActive arms the
// poller with those fds; the goroutine blocks in select(2) on them plus a
// wake-up pipe and, when one becomes ready, sets fired and calls k.notify(),
// which ends the scheduler's sleep; pollNet then runs at once (fired skips
// its throttle). One select per arm: the poller re-arms only when the
// process idles again, and a changed fd set interrupts the running select
// through the pipe first. Owner: the process (Emu); the goroutine exits
// when the process ends (Process.done; a helper goroutine then interrupts a
// running select through the pipe) and closes the pipe. It never touches
// sockets or guest memory - only fd numbers; a closed or reused fd at worst
// causes one spurious wake-up.

import (
	"slices"
	"sync/atomic"
	"syscall"
	"time"
)

type pollFd struct {
	fd    int
	write bool
}

type netPoller struct {
	k            *Kernel
	arm          chan []pollFd
	idle         chan struct{} // one token per finished select
	wakeR, wakeW int
	fired        atomic.Bool

	// owned by the process goroutine
	armed    bool
	set      []pollFd
	cooldown time.Time // no re-arm before this (a wake-up made no progress)
}

func (e *Emu) newPoller() *netPoller {
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return nil // no poller: pollNet's polling still works, with more latency
	}
	for _, fd := range fds {
		syscall.CloseOnExec(fd)
		_ = syscall.SetNonblock(fd, true) // best effort: the drain read must not block
	}
	p := &netPoller{k: e.k, arm: make(chan []pollFd, 1), idle: make(chan struct{}, 1), wakeR: fds[0], wakeW: fds[1]}
	var done <-chan struct{}
	if e.proc != nil {
		done = e.proc.done
	}
	var woken chan struct{}
	if done != nil {
		// A select on fds that never become ready (a socket kept open by a
		// duplicate in another process) must still end with the process.
		woken = make(chan struct{})
		go func() {
			<-done
			_, _ = syscall.Write(p.wakeW, []byte{1}) // best effort: the pipe is non-blocking
			close(woken)
		}()
	}
	go p.run(done, woken)
	return p
}

func (p *netPoller) run(done, woken <-chan struct{}) {
	defer syscall.Close(p.wakeR)
	defer func() {
		if woken != nil {
			<-woken // the exit wake-up has been written: wakeW is no longer used
		}
		syscall.Close(p.wakeW)
	}()
	for {
		var set []pollFd
		select {
		case set = <-p.arm:
		case <-done:
			return
		}
		select {
		case <-done:
			return
		default:
		}
		p.wait(set)
		p.idle <- struct{}{}
	}
}

func (p *netPoller) fire() {
	p.fired.Store(true)
	p.k.notify()
}

// wait selects on set until an fd is ready (fire) or the pipe interrupts.
func (p *netPoller) wait(set []pollFd) {
	var r, w syscall.FdSet
	limit := len(r.Bits) * fdSetWordBits
	hi := p.wakeR
	sockFdSet(&r, p.wakeR)
	for _, x := range set {
		if x.fd < 0 || x.fd >= limit {
			p.fire() // select cannot watch it: let pollNet look now
			return
		}
		if x.write {
			sockFdSet(&w, x.fd)
		} else {
			sockFdSet(&r, x.fd)
		}
		hi = max(hi, x.fd)
	}
	for {
		rr, ww := r, w
		err := hostSelectWait(hi+1, &rr, &ww)
		if err == syscall.EINTR {
			continue
		}
		if err == nil && sockFdIsSet(&rr, p.wakeR) {
			var b [16]byte
			_, _ = syscall.Read(p.wakeR, b[:]) // drain; best effort
			return
		}
		p.fire() // ready, or an fd was closed (EBADF): pollNet sorts it out
		return
	}
}

// pollerFired reports (and clears) a readiness report of the poller.
func (o *ovlState) pollerFired() bool { return o.poller != nil && o.poller.fired.Swap(false) }

// stop interrupts a running select and waits until the goroutine is idle.
func (p *netPoller) stop() {
	if !p.armed {
		return
	}
	select {
	case <-p.idle:
	default:
		_, _ = syscall.Write(p.wakeW, []byte{1}) // best effort: the pipe is non-blocking
		<-p.idle
		var b [16]byte
		_, _ = syscall.Read(p.wakeR, b[:]) // the select may have ended for another reason
	}
	p.armed = false
}

// pollSet lists the fds the idle process waits for: pending overlapped
// operations and WSAEventSelect events that may be recorded now.
func (e *Emu) pollSet() []pollFd {
	n := e.net
	var set []pollFd
	for _, op := range n.ovl.ops {
		op.s.mu.Lock()
		fd := op.s.fd
		if op.kind == opAccept && op.accepted {
			fd = op.as.fd
		}
		op.s.mu.Unlock()
		set = append(set, pollFd{fd, opWantsWrite(op)})
	}
	for s := range n.socks {
		s.mu.Lock()
		if s.evOwner == n && s.evMask != 0 && !s.closed {
			en := s.evEnabled
			if en&(fdRead|fdAccept|fdOOB) != 0 || s.evMask&fdClose != 0 && s.evMask&fdRead == 0 && !s.closeSeen {
				set = append(set, pollFd{s.fd, false})
			}
			if s.connecting && en&fdConnect != 0 || s.connected && en&fdWrite != 0 && !s.closeSeen {
				set = append(set, pollFd{s.fd, true})
			}
		}
		s.mu.Unlock()
	}
	return set
}

// armPoller (re-)arms the poller before the process sleeps.
func (e *Emu) armPoller() {
	n := e.net
	set := e.pollSet()
	p := n.ovl.poller
	if p == nil {
		if len(set) == 0 {
			return
		}
		if p = e.newPoller(); p == nil {
			return
		}
		n.ovl.poller = p
	}
	if p.armed {
		select {
		case <-p.idle:
			p.armed = false
		default:
		}
	}
	if p.armed && slices.Equal(set, p.set) {
		return
	}
	p.stop()
	if len(set) == 0 || time.Now().Before(p.cooldown) {
		return
	}
	p.set, p.armed = set, true
	p.arm <- set
}
