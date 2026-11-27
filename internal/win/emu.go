// Package win implements a Windows x64 user-mode environment on top of the
// cpu package: PE loading, threads, structured exceptions and a set of
// high-level emulated system DLLs (kernel32, ucrtbase, msvcrt, ...).
package win

import (
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"winemu/internal/cpu"
	"winemu/internal/mem"
)

// Options configures an emulated process.
type Options struct {
	Prefix  string // host directory holding drive_c
	Trace   bool   // log every API call
	Lenient bool   // unimplemented APIs return 0 instead of aborting
	Verbose bool
	CmdLine string   // raw command line (child processes)
	Cwd     string   // initial Windows current directory
	Env     []string // initial environment (child processes)
	Stdin   *os.File
	Stdout  *os.File
	Stderr  *os.File
}

// Fn is the Go implementation of an emulated API.
type Fn func(e *Emu) uint64

type hleEntry struct {
	dll, name string
	fn        Fn
}

// control-flow panics
type processExit struct{ code uint32 }
type threadExit struct{ code uint32 }
type contextRestored struct{}
type threadGone struct{}

// Thread is one guest thread.
type Thread struct {
	ID         uint32
	Handle     uint64
	CPU        *cpu.CPU
	TEB        uint64
	StackBase  uint64
	StackLimit uint64
	StackAlloc uint64
	crtErrno   uint64 // address of the CRT errno slot (_errno), allocated on first use

	exited   bool
	exitCode uint32
	parked   bool
	gone     atomic.Bool // exited; readable from other processes (exitCode is valid once set)
	emu      *Emu        // owning process

	wait         func() bool
	waitDeadline time.Time
	waitTimedOut bool
	waiting      bool
	waitHint     time.Time // earliest due time of waited-on timers (scheduling hint only)
	waitHost     bool      // waits on host-completed work (blockHost): polled, never "forever"

	suspend    int
	start      uint64
	callFrames []callFrame
	dispatch   []activeDispatch
	unwinds    []*activeUnwind
	param      uint64
	booted     bool
	name       string
	xop        any // state of a builtin blocking across re-execution, or a pool thread's work (threadpool_wait.go)
}

type callFrame struct{ want, saveSP uint64 }

type Emu struct {
	Opt Options
	Mem *mem.Memory

	Cur     *Thread
	threads []*Thread
	rr      int

	modules   []*Module
	modByName map[string]*Module
	exe       *Module

	hle        []*hleEntry
	stubCache  map[string]uint64
	stubNext   uint64
	stubEnd    uint64
	retThunk   uint64
	exitThunk  uint64
	bootThunk  uint64
	builtinTop uint64

	peb, params uint64
	kuser       uint64

	skipRet bool

	heap    *Heap
	handles *Handles
	fs      *FS
	crt     *CRT
	con     *Console
	sec     *secState // security_token.go: thread impersonation tokens (primary token: Process)

	cmdLine  string
	args     []string
	env      []string // "NAME=value"
	exeWin   string   // windows path of the exe
	exeHost  string
	exitCode uint32
	started  time.Time

	tlsModules []*Module
	tlsSlots   [1088]bool
	fls        flsState

	vectored        []uint64
	unhandledFilter uint64
	funcTables      []dynFuncTable

	warned map[string]bool
	tr     *tracer

	rt  *rtState  // runtime-library state (msvcp.go, fiber.go, misc2.go)
	net *netState // winsock state (winsock.go), nil until the first socket

	// multi-process: the shared kernel and this process's entry in it
	k    *Kernel
	proc *Process

	// per-process wait state (formerly package globals)
	cvWaiters  map[uint64][]*cvWaiter
	cvByThread map[*Thread]*cvWaiter
	addrWait   map[*Thread]uint64
	views      map[uint64]*mapView
	excStore   map[*Thread]uint64 // vcruntime per-thread exception slots (misc.go)

	// scheduler idle / deadlock bookkeeping
	idling       bool
	blockedSince time.Time
	blockedGen   uint64
	pollDelay    time.Duration
	idleTimer    *time.Timer
}

// New creates an emulator instance for a root process (one session with its
// own kernel; the process id is the host pid).
func New(opt Options) *Emu {
	k := newKernel()
	return newEmu(opt, k, k.rootPID, 0)
}

// newEmu creates the emulator of one process of kernel k (pid 0: allocate).
func newEmu(opt Options, k *Kernel, pid, parent uint32) *Emu {
	if opt.Stdin == nil {
		opt.Stdin = os.Stdin
	}
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	e := &Emu{
		Opt:       opt,
		Mem:       mem.New(),
		modByName: map[string]*Module{},
		stubCache: map[string]uint64{},
		warned:    map[string]bool{},
		started:   time.Now(),
		k:         k,
		cvWaiters: map[uint64][]*cvWaiter{}, cvByThread: map[*Thread]*cvWaiter{},
		addrWait: map[*Thread]uint64{}, views: map[uint64]*mapView{},
		pollDelay: time.Millisecond, idleTimer: time.NewTimer(time.Hour),
	}
	e.idleTimer.Stop()
	e.proc = k.newProcess(e, pid, parent)
	e.handles = newHandles()
	if opt.Trace {
		e.tr = &tracer{}
	}
	e.hle = append(e.hle, nil) // index 0 unused
	return e
}

func (e *Emu) logf(format string, a ...any) {
	fmt.Fprintf(e.Opt.Stderr, "winemu: "+format+"\n", a...)
}

func (e *Emu) warnOnce(key, format string, a ...any) {
	if e.warned[key] {
		return
	}
	e.warned[key] = true
	if e.Opt.Verbose || e.Opt.Trace {
		e.logf(format, a...)
	}
}

// ---------------------------------------------------------------------------
// hypercalls

const thunkSize = 16

// writeThunk emits the trampoline for hle entry idx at addr.
func (e *Emu) writeThunk(addr uint64, idx uint32) {
	b := [thunkSize]byte{0x0F, 0x04, byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24), 0xC3,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}
	e.Mem.Write(addr, b[:])
}

func (e *Emu) addHLE(dll, name string, fn Fn) uint32 {
	e.hle = append(e.hle, &hleEntry{dll: dll, name: name, fn: fn})
	return uint32(len(e.hle) - 1)
}

// stub allocates a stand-alone thunk (outside any module image).
func (e *Emu) stub(dll, name string, fn Fn) uint64 {
	key := dll + "!" + name
	if a, ok := e.stubCache[key]; ok {
		return a
	}
	if e.stubNext+thunkSize > e.stubEnd {
		r, err := e.Mem.AllocFrom(0x7FF600000000, 0x100000, mem.PageExecuteRead, mem.MemPrivate, "stubs")
		if err != nil {
			panic(err)
		}
		e.stubNext, e.stubEnd = r.Base, r.Base+r.Size
	}
	a := e.stubNext
	e.stubNext += thunkSize
	e.writeThunk(a, e.addHLE(dll, name, fn))
	e.stubCache[key] = a
	return a
}

func (e *Emu) hyper(c *cpu.CPU, idx uint32) {
	if int(idx) >= len(e.hle) || e.hle[idx] == nil {
		c.RIP = c.IP0
		panic(&cpu.Exception{Code: cpu.ExcIllegalInstr, Addr: c.IP0, Msg: "bad hypercall"})
	}
	h := e.hle[idx]
	e.skipRet = false
	e.updateKUSER()
	var r uint64
	if e.tr != nil {
		r = e.traceCall(h)
	} else {
		r = e.callHLE(h)
	}
	if e.skipRet {
		e.skipRet = false
		return
	}
	c.R[cpu.RAX] = r
}

func (e *Emu) callHLE(h *hleEntry) (r uint64) {
	defer func() {
		if x := recover(); x != nil {
			switch v := x.(type) {
			case *mem.Fault:
				c := e.Cur.CPU
				c.RIP = c.IP0
				panic(&cpu.Exception{Code: cpu.ExcAccessViolation, Addr: c.IP0,
					Params: []uint64{b2u(v.Write), v.Addr},
					Msg:    fmt.Sprintf("in %s!%s: %v", h.dll, h.name, v)})
			case processExit, threadExit, contextRestored, threadGone, *cpu.Exception, *guestException:
				panic(x)
			default:
				panic(fmt.Sprintf("internal error in %s!%s: %v\n%s", h.dll, h.name, x, debug.Stack()))
			}
		}
	}()
	return h.fn(e)
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// argument helpers

func (e *Emu) Arg(i int) uint64 {
	c := e.Cur.CPU
	switch i {
	case 0:
		return c.R[cpu.RCX]
	case 1:
		return c.R[cpu.RDX]
	case 2:
		return c.R[cpu.R8]
	case 3:
		return c.R[cpu.R9]
	}
	return e.Mem.R64(c.R[cpu.RSP] + 8 + 8*uint64(i))
}

func (e *Emu) Arg32(i int) uint32 { return uint32(e.Arg(i)) }
func (e *Emu) ArgI(i int) int64   { return int64(int32(e.Arg(i))) }

// ArgF returns floating point argument i as a double (xmm register or stack slot).
func (e *Emu) ArgF(i int) float64 {
	if i < 4 {
		return e.Cur.CPU.X[i].F64(0)
	}
	return f64frombits(e.Arg(i))
}

func (e *Emu) ArgF32(i int) float32 {
	if i < 4 {
		return e.Cur.CPU.X[i].F32(0)
	}
	return f32frombits(uint32(e.Arg(i)))
}

func (e *Emu) RetF(v float64) uint64 {
	var x cpu.Vec
	x.SetF64(0, v)
	e.Cur.CPU.X[0] = x
	return 0
}

func (e *Emu) RetF32(v float32) uint64 {
	var x cpu.Vec
	x.SetF32(0, v)
	e.Cur.CPU.X[0] = x
	return 0
}

func (e *Emu) CStr(a uint64) string { return e.Mem.CStr(a) }
func (e *Emu) WStr(a uint64) string { return e.Mem.WStr(a) }

// SetLastError writes the thread's last-error value in the TEB.
func (e *Emu) SetLastError(v uint32) {
	e.Mem.W32(e.Cur.TEB+0x68, v)
}

func (e *Emu) LastError() uint32 { return e.Mem.R32(e.Cur.TEB + 0x68) }

// fail sets last error and returns 0.
func (e *Emu) fail(code uint32) uint64 {
	e.SetLastError(code)
	return 0
}

// ---------------------------------------------------------------------------
// threads and scheduling

func (e *Emu) newCPU() *cpu.CPU {
	c := cpu.New(e.Mem)
	c.Hyper = e.hyper
	return c
}

func (e *Emu) protect(f func()) (r any) {
	defer func() { r = recover() }()
	f()
	return nil
}

// runnable reports whether t can run now (and resolves expired waits).
func (e *Emu) runnable(t *Thread, now time.Time) bool {
	if t.exited || t.parked || t.suspend > 0 {
		return false
	}
	if !t.waiting {
		return true
	}
	if t.wait != nil && t.wait() {
		return true
	}
	if !t.waitDeadline.IsZero() && !now.Before(t.waitDeadline) {
		t.waitTimedOut = true
		return true
	}
	return false
}

// schedule runs threads until owner reaches its callback sentinel at wantSP,
// or (owner == nil) until every thread has exited.
func (e *Emu) schedule(owner *Thread, wantSP uint64) {
	if !e.proc.xp.held {
		e.lockRun()
		defer e.unlockRun()
	}
	for {
		e.pausePoint()
		if e.proc.killReq.Load() { // TerminateProcess from another process
			panic(processExit{code: e.proc.killCode.Load()})
		}
		if owner != nil {
			if owner.parked && owner.CPU.R[cpu.RSP] == wantSP {
				owner.parked = false
				return
			}
			if owner.exited {
				panic(threadGone{})
			}
		}
		g0 := e.k.gen.Load() // before looking at any wait condition
		now := time.Now()
		e.pollNet(now)
		var pick *Thread
		n := len(e.threads)
		live := 0
		runnableCount := 0
		for i := 0; i < n; i++ {
			t := e.threads[(e.rr+i)%n]
			if t.exited {
				continue
			}
			live++
			if e.runnable(t, now) {
				if pick == nil {
					pick = t
					e.rr = (e.rr + i + 1) % n
				}
				runnableCount++
			}
		}
		if live == 0 {
			if owner != nil {
				panic(threadGone{})
			}
			return
		}
		if pick == nil {
			e.idle(g0, now)
			continue
		}
		if e.idling {
			e.idling = false
			e.blockedSince = time.Time{}
			e.pollDelay = time.Millisecond
			e.proc.setBlocked(false)
		}
		budget := 1_000_000
		if runnableCount > 1 {
			budget = 50_000
		}
		restored := e.runSlice(pick, budget)
		if owner != nil && pick == owner && restored && owner.CPU.R[cpu.RSP] > wantSP && !owner.exited {
			// the owner unwound past the callback frame: abandon the Go frames
			panic(contextRestored{})
		}
	}
}

// idle sleeps while every live thread waits: until the earliest deadline, a
// kernel notification (another process changed a kernel object) or a short
// poll (conditions on shared memory do not notify). When all threads wait
// without deadline it reports the process as blocked forever and, if the
// whole session stays blocked for ~2 s, ends the youngest process as
// deadlocked.
func (e *Emu) idle(g0 uint64, now time.Time) {
	e.idling = true
	var earliest time.Time
	host := e.netEventsActive() // pollNet may set a WSAEventSelect event
	for _, t := range e.threads {
		if t.exited || !t.waiting {
			continue
		}
		host = host || t.waitHost
		for _, d := range []time.Time{t.waitDeadline, t.waitHint} {
			if !d.IsZero() && (earliest.IsZero() || d.Before(earliest)) {
				earliest = d
			}
		}
	}
	if host {
		// host work (sockets, name lookups) can complete at any time: never
		// blocked forever; poll with backoff, sooner if a deadline is due
		e.proc.setBlocked(false)
		e.blockedSince = time.Time{}
		d := e.pollDelay
		if !earliest.IsZero() {
			d = min(d, earliest.Sub(now))
		}
		if d > 0 {
			e.idleSleep(g0, d)
		}
		e.pollDelay = min(2*e.pollDelay, 10*time.Millisecond)
		return
	}
	if !earliest.IsZero() {
		e.proc.setBlocked(false)
		e.blockedSince = time.Time{}
		if d := earliest.Sub(now); d > 0 {
			e.idleSleep(g0, min(d, 50*time.Millisecond))
		}
		return
	}
	e.proc.setBlocked(true)
	if e.blockedSince.IsZero() || e.blockedGen != g0 {
		e.blockedSince, e.blockedGen = now, g0
	} else if now.Sub(e.blockedSince) > 2*time.Second && e.proc.deadlockVictim() {
		e.logf("deadlock: all threads are blocked forever")
		e.dumpThreads()
		panic(processExit{code: 0xC0000194})
	}
	e.idleSleep(g0, e.pollDelay)
	e.pollDelay = min(2*e.pollDelay, 10*time.Millisecond)
}

// hostWait blocks this process's goroutine (all its threads) until cond is
// true, waking on kernel notifications; used where a guest call must block
// like a host read would. It honours TerminateProcess.
func (e *Emu) hostWait(cond func() bool) {
	for {
		if e.proc.killReq.Load() {
			panic(processExit{code: e.proc.killCode.Load()})
		}
		g0 := e.k.gen.Load()
		if cond() {
			return
		}
		e.idleSleep(g0, 10*time.Millisecond)
	}
}

func (e *Emu) dumpThreads() {
	for _, t := range e.threads {
		if t.exited {
			continue
		}
		e.logf("  thread %d: rip=%#x %s", t.ID, t.CPU.RIP, e.symbolize(t.CPU.RIP))
	}
}

// runSlice runs t for up to n instructions, handling faults. It reports
// whether the thread's context was replaced (unwind/longjmp).
func (e *Emu) runSlice(t *Thread, n int) (restored bool) {
	prev := e.Cur
	e.Cur = t
	defer func() { e.Cur = prev }()
	c := t.CPU
	e.updateKUSER()
	r := e.protect(func() { c.Run(n) })
	for r != nil {
		switch v := r.(type) {
		case *cpu.Exception:
			r = e.protect(func() { e.raiseFromCPU(v) })
		case *mem.Fault:
			c.RIP = c.IP0
			ex := &cpu.Exception{Code: cpu.ExcAccessViolation, Addr: c.IP0, Params: []uint64{b2u(v.Write), v.Addr}}
			r = e.protect(func() { e.raiseFromCPU(ex) })
		case *guestException:
			r = e.protect(func() { e.dispatchGuest(v) })
		case contextRestored:
			restored = true
			r = nil
		case threadExit:
			e.finishThread(t, v.code)
			r = nil
		case threadGone:
			if !t.exited {
				e.finishThread(t, 0)
			}
			r = nil
		default:
			panic(r)
		}
	}
	return restored
}

func (e *Emu) finishThread(t *Thread, code uint32) {
	if t.exited {
		return
	}
	t.exited = true
	t.exitCode = code
	t.gone.Store(true)
	e.k.notify()
}

// block suspends the current API call until ready() returns true or the
// timeout (ms; 0xFFFFFFFF = infinite) passes. The API call is re-executed
// when the thread resumes. Returns false if the caller should proceed now.
func (e *Emu) block(ready func() bool, timeoutMs uint32) {
	t := e.Cur
	if !t.waiting {
		t.waiting = true
		t.waitTimedOut = false
		t.waitHost = false
		if timeoutMs != 0xFFFFFFFF {
			t.waitDeadline = time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
		} else {
			t.waitDeadline = time.Time{}
		}
	}
	t.wait = ready
	c := t.CPU
	c.RIP = c.IP0
	c.Stop = true
	e.skipRet = true
}

// blockHost is block for a wait on work completed outside the guest (host
// sockets, name lookups on a host goroutine): ready is polled by the
// scheduler with backoff, and the wait never counts as blocked forever for
// the deadlock detector. Host goroutines that complete such work call
// e.k.notify() to cut the poll short.
func (e *Emu) blockHost(ready func() bool, timeoutMs uint32) {
	e.block(ready, timeoutMs)
	e.Cur.waitHost = true
}

// waitState returns (resumed, timedOut) for a re-executed blocking call and
// clears the wait state.
func (e *Emu) endWait() (timedOut bool) {
	t := e.Cur
	timedOut = t.waitTimedOut
	t.waiting = false
	t.wait = nil
	t.waitTimedOut = false
	t.waitDeadline = time.Time{}
	t.waitHint = time.Time{}
	t.waitHost = false
	return
}

func (e *Emu) inWait() bool { return e.Cur.waiting }

// yield ends the current time slice after this API call returns.
func (e *Emu) yield() { e.Cur.CPU.Stop = true }

// CallGuest calls a guest function with the Windows x64 ABI from inside an
// API implementation and returns RAX.
func (e *Emu) CallGuest(fn uint64, args ...uint64) uint64 {
	t := e.Cur
	c := t.CPU
	saveRIP := c.RIP
	saveIP0 := c.IP0
	saveSP := c.R[cpu.RSP]
	saveStop := c.Stop
	sp := saveSP - 64
	n := len(args)
	if n < 4 {
		n = 4
	}
	sp -= uint64(8 * n)
	sp &^= 15
	for i := 4; i < len(args); i++ {
		e.Mem.W64(sp+uint64(8*i), args[i])
	}
	sp -= 8
	e.Mem.W64(sp, e.retThunk)
	regs := []int{cpu.RCX, cpu.RDX, cpu.R8, cpu.R9}
	for i := 0; i < len(args) && i < 4; i++ {
		c.R[regs[i]] = args[i]
		c.X[i].SetQ(0, args[i])
	}
	c.R[cpu.RSP] = sp
	c.RIP = fn
	want := sp + 8
	t.callFrames = append(t.callFrames, callFrame{want: want, saveSP: saveSP})
	defer func() { t.callFrames = t.callFrames[:len(t.callFrames)-1] }()
	e.schedule(t, want)
	e.Cur = t
	ret := c.R[cpu.RAX]
	c.RIP = saveRIP
	c.IP0 = saveIP0
	c.R[cpu.RSP] = saveSP
	c.Stop = saveStop
	return ret
}

// CallGuestF is CallGuest that also returns XMM0 as a double.
func (e *Emu) CallGuestF(fn uint64, args ...uint64) float64 {
	e.CallGuest(fn, args...)
	return e.Cur.CPU.X[0].F64(0)
}

func (e *Emu) initSpecialThunks() {
	e.retThunk = e.stub("winemu", "__callback_return", func(e *Emu) uint64 {
		e.Cur.parked = true
		e.Cur.CPU.Stop = true
		e.skipRet = true
		return 0
	})
	e.exitThunk = e.stub("winemu", "__thread_return", func(e *Emu) uint64 {
		code := uint32(e.Cur.CPU.R[cpu.RAX])
		if e.Cur == e.threads[0] {
			e.exitProcess(code)
		}
		e.exitThread(code)
		return 0
	})
	e.bootThunk = e.stub("winemu", "__thread_start", func(e *Emu) uint64 {
		t := e.Cur
		e.threadAttach(t)
		c := t.CPU
		c.R[cpu.RCX] = t.param
		c.RIP = t.start
		e.skipRet = true
		return 0
	})
}

// newThread creates a guest thread (not yet started if suspended).
func (e *Emu) newThread(start, param uint64, stackSize uint64) (*Thread, error) {
	if stackSize < 0x100000 {
		stackSize = 0x100000
	}
	stackSize = (stackSize + 0xFFFF) &^ 0xFFFF
	r, err := e.Mem.Alloc(stackSize, mem.PageReadWrite, mem.MemPrivate, "stack")
	if err != nil {
		return nil, err
	}
	tr, err := e.Mem.Alloc(0x10000, mem.PageReadWrite, mem.MemPrivate, "teb")
	if err != nil {
		return nil, err
	}
	t := &Thread{
		ID:         e.k.allocID(),
		emu:        e,
		CPU:        e.newCPU(),
		TEB:        tr.Base,
		StackBase:  r.Base + r.Size,
		StackLimit: r.Base,
		StackAlloc: r.Base,
		start:      start,
		param:      param,
	}
	e.initTEB(t)
	c := t.CPU
	c.GSBase = t.TEB
	sp := t.StackBase - 0x100
	sp &^= 15
	sp -= 8
	e.Mem.W64(sp, e.exitThunk)
	c.R[cpu.RSP] = sp
	c.RIP = e.bootThunk
	e.threads = append(e.threads, t)
	t.Handle = e.handles.add(&threadObj{t: t})
	return t, nil
}

func (e *Emu) exitThread(code uint32) {
	e.threadDetach(e.Cur)
	panic(threadExit{code: code})
}

func (e *Emu) exitProcess(code uint32) {
	panic(processExit{code: code})
}

func (e *Emu) threadByID(id uint32) *Thread {
	for _, t := range e.threads {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// symbolization for diagnostics

func (e *Emu) moduleAt(addr uint64) *Module {
	for _, m := range e.modules {
		if addr >= m.Base && addr < m.Base+m.Size {
			return m
		}
	}
	return nil
}

func (e *Emu) symbolize(addr uint64) string {
	m := e.moduleAt(addr)
	if m == nil {
		if r := e.Mem.FindRegion(addr); r != nil && r.Name == "stubs" {
			idx := e.Mem.R32(addr&^(thunkSize-1) + 2)
			if int(idx) < len(e.hle) && e.hle[idx] != nil {
				return e.hle[idx].dll + "!" + e.hle[idx].name
			}
		}
		return "?"
	}
	if !m.Native {
		off := addr - m.Base
		for name, a := range m.exports {
			if addr >= a && addr < a+thunkSize {
				return m.Name + "!" + name
			}
		}
		return fmt.Sprintf("%s+%#x", m.Name, off)
	}
	// nearest export below
	best := ""
	var bestA uint64
	for name, a := range m.exports {
		if a <= addr && a > bestA {
			best, bestA = name, a
		}
	}
	if best != "" && addr-bestA < 0x10000 {
		return fmt.Sprintf("%s!%s+%#x", m.Name, best, addr-bestA)
	}
	return fmt.Sprintf("%s+%#x", m.Name, addr-m.Base)
}

// ---------------------------------------------------------------------------
// tracing

type tracer struct{ depth int }

func (e *Emu) traceCall(h *hleEntry) uint64 {
	c := e.Cur.CPU
	ret := e.Mem.R64(c.R[cpu.RSP])
	args := fmt.Sprintf("%#x, %#x, %#x, %#x", c.R[cpu.RCX], c.R[cpu.RDX], c.R[cpu.R8], c.R[cpu.R9])
	if h.dll != "winemu" {
		fmt.Fprintf(e.Opt.Stderr, "[%04x] %s!%s(%s) from %s\n", e.Cur.ID, h.dll, h.name, args, e.symbolize(ret))
	}
	r := e.callHLE(h)
	if h.dll != "winemu" && !e.skipRet {
		fmt.Fprintf(e.Opt.Stderr, "[%04x]   %s -> %#x\n", e.Cur.ID, h.name, r)
	}
	return r
}

// sortedKeys is a small helper used when building export tables.
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func lower(s string) string { return strings.ToLower(s) }

// Interrupted is called from a signal handler to restore the terminal.
func (e *Emu) Interrupted() {
	if e.con != nil {
		e.con.restore()
	}
}
