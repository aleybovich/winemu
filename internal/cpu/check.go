package cpu

// Differential checker (WINEMU_ENGINE=check, docs/engine.md): every block runs
// on the block engine, is rolled back, and runs again on the reference
// interpreter; architectural state, stores and faults must agree.

import (
	"fmt"
	"math"
	"reflect"
	"runtime"
	"strings"

	"winemu/internal/mem"
)

// Divergence is raised (via panic) when the engines disagree.
type Divergence struct{ Msg string }

func (d *Divergence) Error() string { return "cpu engine divergence: " + d.Msg }

type archState struct {
	R            [16]uint64
	RIP, Flags   uint64
	X            [16]Vec
	MXCSR        uint32
	FSBase       uint64
	GSBase       uint64
	FPU          FPU
	ICount       uint64
	Stop         bool
	sharedSlice  bool
	codeWritten  bool
	panicked     any
	panicSummary string
}

func (c *CPU) snapshot() archState {
	c.flags()
	return archState{R: c.R, RIP: c.RIP, Flags: c.Flags, X: c.X, MXCSR: c.MXCSR, FSBase: c.FSBase,
		GSBase: c.GSBase, FPU: c.FPU, ICount: c.ICount, Stop: c.Stop, sharedSlice: c.sharedSlice,
		codeWritten: c.Mem.CodeWritten}
}

func (c *CPU) restore(s archState) {
	c.R, c.RIP, c.Flags, c.X, c.MXCSR, c.FSBase, c.GSBase, c.FPU = s.R, s.RIP, s.Flags, s.X, s.MXCSR, s.FSBase, s.GSBase, s.FPU
	c.ICount, c.Stop, c.sharedSlice, c.Mem.CodeWritten = s.ICount, s.Stop, s.sharedSlice, s.codeWritten
	c.InvalidateCode()
}

func summarize(p any) string {
	switch v := p.(type) {
	case nil:
		return ""
	case *mem.Fault:
		return fmt.Sprintf("fault addr=%#x write=%v", v.Addr, v.Write)
	case *Exception:
		return fmt.Sprintf("exception %#x addr=%#x params=%x", v.Code, v.Addr, v.Params)
	}
	return fmt.Sprintf("%T %v", p, p)
}

// run executes f, catching a panic into the returned state.
func (c *CPU) runCaught(f func()) (s archState) {
	defer func() {
		r := recover()
		s = c.snapshot()
		s.panicked, s.panicSummary = r, summarize(r)
		if r != nil {
			s.RIP = c.IP0 // runSlice resets RIP to IP0 for every fault
		}
	}()
	f()
	return
}

func (s *archState) diff(t *archState) string {
	var b strings.Builder
	for i := range s.R {
		if s.R[i] != t.R[i] {
			fmt.Fprintf(&b, " R%d=%#x/%#x", i, s.R[i], t.R[i])
		}
	}
	if s.RIP != t.RIP {
		fmt.Fprintf(&b, " RIP=%#x/%#x", s.RIP, t.RIP)
	}
	if s.Flags != t.Flags {
		fmt.Fprintf(&b, " RFLAGS=%#x/%#x", s.Flags, t.Flags)
	}
	if s.X != t.X || s.MXCSR != t.MXCSR {
		b.WriteString(" XMM/MXCSR")
	}
	if s.FSBase != t.FSBase || s.GSBase != t.GSBase || s.Stop != t.Stop {
		b.WriteString(" FS/GS/Stop")
	}
	f, g := s.FPU, t.FPU
	for i := range f.Regs {
		if math.Float64bits(f.Regs[i]) != math.Float64bits(g.Regs[i]) {
			b.WriteString(" x87")
			break
		}
	}
	if f.Valid != g.Valid || f.Top != g.Top || f.CW != g.CW || f.SW != g.SW {
		b.WriteString(" x87ctl")
	}
	if s.panicSummary != t.panicSummary {
		fmt.Fprintf(&b, " panic=%q/%q", s.panicSummary, t.panicSummary)
	}
	return b.String()
}

// finals maps every byte written by either run to (value after the block
// engine, value after the reference); cur is the reference's memory.
func memDiff(m *mem.Memory, j1, j2 []mem.JournalEntry, eng map[uint64]byte) string {
	orig := map[uint64]byte{}
	for _, j := range [][]mem.JournalEntry{j1, j2} {
		for _, e := range j {
			for i, v := range e.Old {
				if _, ok := orig[e.Addr+uint64(i)]; !ok {
					orig[e.Addr+uint64(i)] = v
				}
			}
		}
	}
	var b strings.Builder
	n := 0
	for a, o := range orig {
		ev, ok := eng[a]
		if !ok {
			ev = o
		}
		if rv := m.R8(a); rv != ev && n < 8 {
			fmt.Fprintf(&b, " mem[%#x]=%#x/%#x", a, ev, rv)
			n++
		}
	}
	return b.String()
}

func journalBytes(m *mem.Memory, j []mem.JournalEntry) map[uint64]byte {
	out := map[uint64]byte{}
	for _, e := range j {
		for i := range e.Old {
			a := e.Addr + uint64(i)
			out[a] = m.R8(a)
		}
	}
	return out
}

// checkBlock runs up to max ops of b under the checker.
func (c *CPU) checkBlock(b *block, max int) int {
	if b.n > max {
		return c.refSteps(max)
	}
	ops := b.ops
	k := len(ops)
	if ops[k-1].ext {
		k--
	}
	n := 0
	if k > 0 {
		left := false
		if n, left = c.checkOps(b, ops[:k], false); left {
			return n // left the block early (side exit, SMC)
		}
	}
	if k == len(ops) {
		return n
	}
	m, _ := c.execOps(ops[k:])
	return n + m
}

// checkOps runs ops on both engines and compares; it leaves the reference's
// state and re-raises its panic, if any.
func (c *CPU) checkOps(b *block, ops []op, pinpoint bool) (int, bool) {
	s0 := c.snapshot()
	base := int(ops[0].cnt) - 1 - int(ops[0].extra) - int(ops[0].pre)
	n, cur, left := 0, 0, false
	c.Mem.BeginJournalPrivate()
	s1 := c.runCaught(func() {
		for cur = range ops {
			if o := &ops[cur]; o.fn(c, o) {
				n, left = int(o.cnt)-base, true
				return
			}
		}
		c.RIP = ops[len(ops)-1].next
		n = int(ops[len(ops)-1].cnt) - base
	})
	j1, _ := c.Mem.EndJournal()
	if _, ok := s1.panicked.(mem.SharedAccess); ok { // shared memory: run once, unchecked
		c.Mem.Undo(j1)
		c.restore(s0)
		return c.execOps(ops)
	}
	if s1.panicked != nil { // the reference must fault in the same instruction
		n = int(ops[cur].cnt) - base
	}
	eng := journalBytes(c.Mem, j1)
	c.Mem.Undo(j1)
	c.restore(s0)
	c.Mem.BeginJournalPrivate()
	s2 := c.runCaught(func() {
		for range n {
			c.refStep()
		}
	})
	j2, _ := c.Mem.EndJournal()
	d := s1.diff(&s2) + memDiff(c.Mem, j1, j2, eng)
	if d != "" {
		if !pinpoint && len(ops) > 1 {
			c.Mem.Undo(j2)
			c.restore(s0)
			c.pinpoint(b, ops)
		}
		o := &ops[0]
		panic(&Divergence{Msg: fmt.Sprintf("block %#x, ops %#x..%#x (first: %s, bytes % x): engine/reference:%s",
			b.ip, o.ip, ops[len(ops)-1].ip, describe(o), c.codeBytes(o.ip), d)})
	}
	if s2.panicked != nil {
		panic(s2.panicked)
	}
	return n, left
}

// pinpoint re-checks ops one at a time to report the first diverging
// instruction (it panics with that Divergence); it returns if none diverges
// on its own or an instruction faults first.
func (c *CPU) pinpoint(b *block, ops []op) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(*Divergence); ok {
				panic(r)
			}
		}
	}()
	for i := range ops {
		c.checkOps(b, ops[i:i+1], true)
	}
}

func (c *CPU) codeBytes(ip uint64) []byte {
	var b []byte
	for i := uint64(0); i < 15; i++ {
		if !c.Mem.Valid(ip + i) {
			break
		}
		b = append(b, c.mc.R8(c.Mem, ip+i))
	}
	return b
}

// describe renders an op for diagnostics.
func describe(o *op) string {
	name := runtime.FuncForPC(reflect.ValueOf(o.fn).Pointer()).Name()
	name = name[strings.LastIndex(name, ".")+1:]
	s := fmt.Sprintf("%s sz=%d r=%d/%d rm=%d/%d sub=%d imm=%#x", name, o.sz, o.r, o.rSh, o.rm, o.rmSh, o.sub, o.imm)
	if o.mem {
		s += fmt.Sprintf(" ea=[%#x", o.disp)
		if o.base != noReg {
			s += fmt.Sprintf("+r%d", o.base)
		}
		if o.idx != noReg {
			s += fmt.Sprintf("+r%d<<%d", o.idx, o.scale)
		}
		s += fmt.Sprintf(" seg%d]", o.seg)
	}
	return s
}
