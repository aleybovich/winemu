package win

// The kernel: state shared by all guest processes of one session (process
// table, ids, named-object namespace, wake-ups, deadlock accounting). Each
// guest process is one Emu on its own goroutine; see docs/multiprocess.md.

import (
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Kernel is shared by every Emu of a session. mu (the kernel lock) protects
// the fields below it and the state of every waitable object: signaled and
// acquire are always called with mu held.
type Kernel struct {
	mu      sync.Mutex
	procs   map[uint32]*Process // live processes
	names   map[string]any      // "event:<name>", "mutex:<name>", "sem:<name>"
	nextID  uint32
	rootPID uint32
	seq     uint64
	live    int // processes started and not yet exited
	blocked int // live processes whose threads are all blocked forever

	luid     atomic.Uint64 // LUID allocator (security_token.go)
	gen      atomic.Uint64 // bumped by notify
	sleepers atomic.Int32
	wmu      sync.Mutex
	wake     chan struct{} // closed (and replaced) by notify when somebody sleeps
}

func newKernel() *Kernel {
	k := &Kernel{procs: map[uint32]*Process{}, names: map[string]any{}, nextID: 0x100,
		rootPID: uint32(os.Getpid()), wake: make(chan struct{})}
	k.luid.Store(0x10000)
	return k
}

// allocID returns a new process/thread id (shared id space, multiples of 4).
func (k *Kernel) allocID() uint32 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.allocIDLocked()
}

func (k *Kernel) allocIDLocked() uint32 {
	for {
		k.nextID += 4
		id := k.nextID
		if id != k.rootPID && k.procs[id] == nil {
			return id
		}
	}
}

// notify wakes every process that sleeps waiting for kernel state changes.
// Call it (without holding mu) after changing anything a waiter may wait for.
func (k *Kernel) notify() {
	k.gen.Add(1)
	if k.sleepers.Load() == 0 {
		return
	}
	k.wmu.Lock()
	close(k.wake)
	k.wake = make(chan struct{})
	k.wmu.Unlock()
}

// sleep waits up to d for a notify, unless one happened since gen was g0.
func (k *Kernel) sleep(g0 uint64, d time.Duration, t *time.Timer) {
	k.sleepers.Add(1)
	defer k.sleepers.Add(-1)
	k.wmu.Lock()
	ch := k.wake
	k.wmu.Unlock()
	if k.gen.Load() != g0 {
		return
	}
	t.Reset(d)
	select {
	case <-ch:
	case <-t.C:
	}
	t.Stop()
}

// Process is the kernel side of one guest process.
type Process struct {
	k      *Kernel
	pid    uint32
	parent uint32
	seq    uint64
	emu    *Emu
	done   chan struct{} // closed when the process has exited

	// under k.mu
	started, exited, blocked bool
	code                     uint32

	killReq  atomic.Bool
	killCode atomic.Uint32

	tokenOnce sync.Once
	token     *tokenObj // primary token (security_token.go), set by tokenOnce

	xp xprocState // cross-process access handshake, job membership (xproc.go)
}

// newProcess registers the process of e (not started yet).
func (k *Kernel) newProcess(e *Emu, pid, parent uint32) *Process {
	k.mu.Lock()
	defer k.mu.Unlock()
	if pid == 0 {
		pid = k.allocIDLocked()
	}
	k.seq++
	p := &Process{k: k, pid: pid, parent: parent, seq: k.seq, emu: e, done: make(chan struct{})}
	k.procs[pid] = p
	return p
}

// Emu returns the process's emulator (hook for cross-process memory access;
// its private state may only be touched while the process is not running).
func (p *Process) Emu() *Emu { return p.emu }

// PID returns the process id.
func (p *Process) PID() uint32 { return p.pid }

// markStarted counts the process as live (before its goroutine starts). It
// reports false if the process was already started or has already exited.
func (p *Process) markStarted() bool {
	k := p.k
	k.mu.Lock()
	defer k.mu.Unlock()
	if p.started || p.exited {
		return false
	}
	p.started = true
	k.live++
	return true
}

// exit records the exit code, signals the process object and wakes waiters.
func (p *Process) exit(code uint32) {
	k := p.k
	k.mu.Lock()
	if p.exited {
		k.mu.Unlock()
		return
	}
	p.exited, p.code = true, code
	if p.blocked {
		p.blocked = false
		k.blocked--
	}
	if p.started {
		k.live--
	}
	delete(k.procs, p.pid)
	k.mu.Unlock()
	close(p.done)
	k.notify()
}

// exitStatus returns (exit code, true) once the process has exited.
func (p *Process) exitStatus() (uint32, bool) {
	p.k.mu.Lock()
	defer p.k.mu.Unlock()
	return p.code, p.exited
}

// requestKill asks the process to terminate with code (TerminateProcess).
// The target acts on it at its next scheduling point.
func (p *Process) requestKill(code uint32) {
	if p.killReq.Load() {
		return
	}
	p.killCode.Store(code)
	p.killReq.Store(true)
	p.k.notify()
}

func (k *Kernel) process(pid uint32) *Process {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.procs[pid]
}

// setBlocked records whether every thread of p waits without a deadline.
func (p *Process) setBlocked(b bool) {
	k := p.k
	k.mu.Lock()
	if p.blocked != b && !p.exited {
		p.blocked = b
		if b {
			k.blocked++
		} else {
			k.blocked--
		}
	}
	k.mu.Unlock()
}

// deadlockVictim reports whether every live process is blocked forever and
// p is the youngest of them (the one that should give up first).
func (p *Process) deadlockVictim() bool {
	k := p.k
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.blocked < k.live || !p.blocked {
		return false
	}
	for _, q := range k.procs {
		if q.started && !q.exited && q.seq > p.seq {
			return false
		}
	}
	return true
}

// endSession terminates every other started process (the root has exited:
// the host exits with it) and waits up to grace for them to finish their
// exit (handles closed, output flushed). A process stuck in a host call
// that cannot be interrupted is abandoned when the host exits.
func (k *Kernel) endSession(code uint32, grace time.Duration) {
	k.mu.Lock()
	var ps []*Process
	for _, q := range k.procs {
		if q.started {
			ps = append(ps, q)
		}
	}
	k.mu.Unlock()
	for _, q := range ps {
		q.requestKill(code)
	}
	t := time.NewTimer(grace)
	defer t.Stop()
	for _, q := range ps {
		select {
		case <-q.done:
		case <-t.C:
			return
		}
	}
}
