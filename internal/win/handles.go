package win

import (
	"os"
	"sync"
)

const (
	stdInputHandle  = 0x10
	stdOutputHandle = 0x14
	stdErrorHandle  = 0x18

	pseudoProcess = ^uint64(0)     // GetCurrentProcess()
	pseudoThread  = ^uint64(0) - 1 // GetCurrentThread()
	invalidHandle = ^uint64(0)
)

// Handles is a per-process handle table. Values map to (possibly shared)
// kernel objects. It is locked so other processes may insert into it (handle
// inheritance, DuplicateHandle). ref/unref run outside the table lock.
type Handles struct {
	mu      sync.Mutex
	m       map[uint64]any
	next    uint64
	inherit map[uint64]bool // HANDLE_FLAG_INHERIT
}

func newHandles() *Handles {
	return &Handles{m: map[uint64]any{}, next: 0x100, inherit: map[uint64]bool{}}
}

func (h *Handles) add(o any) uint64 {
	h.mu.Lock()
	for h.m[h.next] != nil {
		h.next += 4
	}
	v := h.next
	h.next += 4
	h.m[v] = o
	h.mu.Unlock()
	if r, ok := o.(refcounted); ok {
		r.ref()
	}
	return v
}

// set installs o at value v, releasing any object it replaces.
func (h *Handles) set(v uint64, o any) {
	h.mu.Lock()
	old := h.m[v]
	h.m[v] = o
	h.mu.Unlock()
	if r, ok := o.(refcounted); ok {
		r.ref()
	}
	if r, ok := old.(refcounted); ok {
		r.unref()
	}
}

func (h *Handles) get(v uint64) any {
	h.mu.Lock()
	o := h.m[v]
	h.mu.Unlock()
	return o
}

func (h *Handles) close(v uint64) bool {
	h.mu.Lock()
	o, ok := h.m[v]
	if ok {
		delete(h.m, v)
		delete(h.inherit, v)
	}
	h.mu.Unlock()
	if !ok {
		return false
	}
	if r, ok := o.(refcounted); ok {
		r.unref()
	}
	return true
}

// setInherit sets or clears HANDLE_FLAG_INHERIT on an existing handle.
func (h *Handles) setInherit(v uint64, on bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.m[v]; !ok {
		return false
	}
	if on {
		h.inherit[v] = true
	} else {
		delete(h.inherit, v)
	}
	return true
}

func (h *Handles) inheritable(v uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inherit[v]
}

// snapshotInheritable returns the inheritable handles (value -> object).
func (h *Handles) snapshotInheritable() map[uint64]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[uint64]any{}
	for v := range h.inherit {
		out[v] = h.m[v]
	}
	return out
}

// closeAll closes every handle (process exit).
func (h *Handles) closeAll() {
	h.mu.Lock()
	objs := make([]any, 0, len(h.m))
	for _, o := range h.m {
		objs = append(objs, o)
	}
	h.m = map[uint64]any{}
	h.inherit = map[uint64]bool{}
	h.mu.Unlock()
	for _, o := range objs {
		if r, ok := o.(refcounted); ok {
			r.unref()
		}
	}
}

func (h *Handles) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.m)
}

type refcounted interface {
	ref()
	unref()
}

// waitable objects. signaled and acquire are called with the kernel lock
// (Kernel.mu) held and must not take it; whoever changes the state of a
// waitable must hold the lock and call Kernel.notify afterwards.
type waitable interface {
	signaled(t *Thread) bool
	acquire(t *Thread)
}

// kname makes a named kernel object refcounted by handles: the name leaves
// the namespace when the last handle is closed. The zero value (unnamed,
// no kernel) is a no-op.
type kname struct {
	k    *Kernel
	key  string
	refs int
}

func (n *kname) ref() {
	if n.k == nil {
		return
	}
	n.k.mu.Lock()
	n.refs++
	n.k.mu.Unlock()
}

func (n *kname) unref() {
	if n.k == nil {
		return
	}
	n.k.mu.Lock()
	n.refs--
	if n.refs <= 0 && n.key != "" {
		delete(n.k.names, n.key)
		n.key = ""
	}
	n.k.mu.Unlock()
}

type eventObj struct {
	kname
	manual bool
	set    bool
	name   string
}

func (o *eventObj) signaled(*Thread) bool { return o.set }
func (o *eventObj) acquire(*Thread) {
	if !o.manual {
		o.set = false
	}
}

type mutexObj struct {
	kname
	owner *Thread
	count int
	name  string
}

func (o *mutexObj) signaled(t *Thread) bool {
	return o.owner == nil || o.owner == t || o.owner.gone.Load()
}
func (o *mutexObj) acquire(t *Thread) {
	if o.owner != t {
		o.owner = t
		o.count = 0
	}
	o.count++
}

type semObj struct {
	kname
	count, max int64
	name       string
}

func (o *semObj) signaled(*Thread) bool { return o.count > 0 }
func (o *semObj) acquire(*Thread)       { o.count-- }

// threadObj refers to a thread of any process.
type threadObj struct{ t *Thread }

func (o *threadObj) signaled(*Thread) bool { return o.t.gone.Load() }
func (o *threadObj) acquire(*Thread)       {}

// processObj refers to a process. self (with p == nil) means the process
// that owns the handle.
type processObj struct {
	self bool
	p    *Process
}

func (o *processObj) signaled(*Thread) bool { return o.p != nil && o.p.exited }
func (o *processObj) acquire(*Thread)       {}

type timerObj struct {
	kname
	manual bool
	set    bool
	due    int64 // unix nano
	period int64
	name   string
}

func (o *timerObj) signaled(*Thread) bool {
	if o.set {
		return true
	}
	if o.due != 0 && nowNano() >= o.due {
		o.set = true
		if o.period > 0 {
			o.due += o.period
		} else {
			o.due = 0
		}
		return true
	}
	return false
}
func (o *timerObj) acquire(*Thread) {
	if !o.manual {
		o.set = false
	}
}

// fileObj is an open file, directory, console or pipe.
type fileObj struct {
	f        *os.File
	host     string
	win      string
	kind     int // fileDisk, fileChar, filePipe
	console  int // 0 none, 1 input, 2 output
	isDir    bool
	append   bool
	access   uint32
	delClose bool
	refs     int
	pos      int64 // used for directories / emulated
	pipe     *pipeBuf
	pipeW    bool
	nul      bool
	dirEnts  []os.FileInfo
	dirPos   int
}

const (
	fileUnknown = 0
	fileDisk    = 1
	fileChar    = 2
	filePipe    = 3
)

// fileRefMu guards fileObj.refs: handles to one file object may live in the
// tables of several processes (fileObj is copied by value in places, so it
// cannot carry its own mutex).
var fileRefMu sync.Mutex

func (f *fileObj) ref() {
	fileRefMu.Lock()
	f.refs++
	fileRefMu.Unlock()
}

func (f *fileObj) unref() {
	fileRefMu.Lock()
	f.refs--
	last := f.refs <= 0
	fileRefMu.Unlock()
	if !last {
		return
	}
	if f.pipe != nil {
		f.pipe.closeEnd(f.pipeW)
	}
	if f.f != nil && f.console == 0 {
		f.f.Close()
		if f.delClose {
			os.Remove(f.host)
		}
	}
}

// pipeBuf is an anonymous pipe. Kernel pipes (k != nil, CreatePipe/_popen)
// connect processes: their ends live in different handle tables and their
// state changes wake waiters in other processes.
type pipeBuf struct {
	mu      sync.Mutex
	k       *Kernel
	data    []byte
	closedW bool
	closedR bool
}

func newKernelPipe(k *Kernel) *pipeBuf { return &pipeBuf{k: k} }

func (p *pipeBuf) changed() {
	if p.k != nil {
		p.k.notify()
	}
}

// state returns the number of buffered bytes and whether the write end is closed.
func (p *pipeBuf) state() (n int, closedW bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.data), p.closedW
}

// read takes up to len(b) buffered bytes; eof is set when the pipe is empty
// and the write end closed.
func (p *pipeBuf) read(b []byte) (n int, eof bool) {
	p.mu.Lock()
	n = copy(b, p.data)
	p.data = p.data[n:]
	eof = n == 0 && p.closedW
	p.mu.Unlock()
	return n, eof
}

// write appends b; it fails when the read end is closed.
func (p *pipeBuf) write(b []byte) bool {
	p.mu.Lock()
	ok := !p.closedR
	if ok {
		p.data = append(p.data, b...)
	}
	p.mu.Unlock()
	if ok {
		p.changed()
	}
	return ok
}

func (p *pipeBuf) closeEnd(writeEnd bool) {
	p.mu.Lock()
	if writeEnd {
		p.closedW = true
	} else {
		p.closedR = true
	}
	p.mu.Unlock()
	p.changed()
}

type regKeyObj struct {
	path string
}
