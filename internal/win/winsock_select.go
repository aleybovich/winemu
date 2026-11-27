//go:build darwin || linux

package win

// select / __WSAFDIsSet.
//
// Windows fd_set: u_int fd_count; (4 bytes padding) SOCKET fd_array[64].

const (
	fdSetArrayOffset = 8
	fdSetSize        = 64
)

type selEntry struct {
	set uint64 // guest fd_set address
	h   uint64 // socket handle
	s   *sockObj
	ex  bool // entry is in exceptfds
	wr  bool // entry is in writefds
}

// selReady reports whether entry x is ready (Windows semantics) given the
// host readiness of its fd. Call with x.s locked.
func (e *Emu) selReady(x *selEntry, rd, wr bool) bool {
	s := x.s
	if s.closed {
		return true
	}
	if s.connecting && wr {
		e.finishConnect(s)
	}
	switch {
	case x.ex:
		return s.connErr != 0 // failed non-blocking connect
	case s.listening:
		return !x.wr && rd
	case s.typ == wsSockStream && !s.connected:
		return false // unconnected stream sockets are never ready
	case x.wr:
		return wr && !s.connecting
	}
	return rd
}

// selPoll evaluates all entries once and returns the ready flags.
func (e *Emu) selPoll(es []selEntry) ([]bool, int) {
	fds := make([]int, len(es))
	for i, x := range es {
		x.s.mu.Lock()
		fds[i] = x.s.fd
		x.s.mu.Unlock()
	}
	rd, wr := fdPoll(fds)
	ready := make([]bool, len(es))
	n := 0
	for i := range es {
		s := es[i].s
		s.mu.Lock()
		r := e.selReady(&es[i], rd[i], wr[i])
		s.mu.Unlock()
		if r {
			ready[i] = true
			n++
		}
	}
	return ready, n
}

func init() {
	w := "ws2_32.dll"
	regWS(w, "select", func(e *Emu) uint64 {
		timedOut := e.resumeWait()
		sets := [3]uint64{e.Arg(1), e.Arg(2), e.Arg(3)}
		var es []selEntry
		for k, set := range sets {
			if set == 0 {
				continue
			}
			n := min(e.Mem.R32(set), fdSetSize)
			for i := uint32(0); i < n; i++ {
				h := e.Mem.R64(set + fdSetArrayOffset + 8*uint64(i))
				s, ok := e.handles.get(h).(*sockObj)
				if !ok || s.isClosed() {
					return e.wsaFail(wsaENOTSOCK)
				}
				es = append(es, selEntry{set: set, h: h, s: s, wr: k == 1, ex: k == 2})
			}
		}
		if len(es) == 0 {
			return e.wsaFail(wsaEINVAL)
		}
		ready, n := e.selPoll(es)
		if n == 0 && !timedOut {
			ms := uint32(infinite)
			if tv := e.Arg(4); tv != 0 {
				sec, usec := int64(int32(e.Mem.R32(tv))), int64(int32(e.Mem.R32(tv+4)))
				if sec < 0 || usec < 0 {
					return e.wsaFail(wsaEINVAL)
				}
				total := sec*1000 + (usec+999)/1000
				ms = uint32(min(total, int64(infinite-1)))
			}
			if ms != 0 {
				e.sockWait(func() bool { _, k := e.selPoll(es); return k > 0 }, ms)
				return 0
			}
		}
		// rewrite each set with its ready members
		counts := map[uint64]uint32{}
		for _, set := range sets {
			if set != 0 {
				counts[set] = 0
			}
		}
		for i, x := range es {
			if ready[i] {
				c := counts[x.set]
				e.Mem.W64(x.set+fdSetArrayOffset+8*uint64(c), x.h)
				counts[x.set] = c + 1
			}
		}
		for set, c := range counts {
			e.Mem.W32(set, c)
		}
		return uint64(n)
	})
	regWS(w, "__WSAFDIsSet", func(e *Emu) uint64 {
		h, set := e.Arg(0), e.Arg(1)
		if set == 0 {
			return 0
		}
		n := min(e.Mem.R32(set), fdSetSize)
		for i := uint32(0); i < n; i++ {
			if e.Mem.R64(set+fdSetArrayOffset+8*uint64(i)) == h {
				return 1
			}
		}
		return 0
	})
}
