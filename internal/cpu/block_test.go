package cpu

import (
	"bytes"
	"fmt"
	"testing"

	"winemu/internal/mem"
)

const (
	tCode = 0x400000
	tData = 0x500000 // 64 KiB data region; tData+0x10000 is unmapped
)

// tMachine builds a CPU with code at tCode and a zeroed data region.
func tMachine(t testing.TB, eng Engine, code []byte, setup func(c *CPU)) *CPU {
	t.Helper()
	m := mem.New()
	if _, err := m.Map(tCode, mem.ChunkSize, mem.PageExecuteReadWrite, mem.MemPrivate, "code"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Map(tData, mem.ChunkSize, mem.PageReadWrite, mem.MemPrivate, "data"); err != nil {
		t.Fatal(err)
	}
	m.Write(tCode, code)
	c := New(m)
	c.Engine = eng
	c.RIP = tCode
	c.R[RSP] = tData + 0x8000
	c.Hyper = func(c *CPU, idx uint32) {
		switch idx {
		case 0:
			c.Stop = true
		case 1: // Go-side store into guest memory (like an API writing code)
			c.Mem.W8(c.R[RDI], uint8(c.R[RSI]))
		}
	}
	if setup != nil {
		setup(c)
	}
	return c
}

type outcome struct {
	R             [16]uint64
	RIP, Flags    uint64
	ICount        uint64
	X             [16]Vec
	data          []byte
	panicked      string
	stopped       bool
	ip0           uint64
	faultAddr     uint64
	excCode       uint32
	excAddr       uint64
	excRestoreRIP uint64
}

func runOutcome(c *CPU, n int) (o outcome) {
	defer func() {
		o.R, o.RIP, o.Flags, o.ICount, o.X = c.R, c.RIP, c.Flags, c.ICount, c.X
		o.data = c.Mem.ReadBytes(tData, mem.ChunkSize)
		o.stopped = c.Stop
		if r := recover(); r != nil {
			o.ip0 = c.IP0
			switch v := r.(type) {
			case *mem.Fault:
				o.panicked = "fault"
				o.faultAddr = v.Addr
			case *Exception:
				o.panicked = "exception"
				o.excCode, o.excAddr = v.Code, v.Addr
			default:
				o.panicked = fmt.Sprint(r)
			}
		}
	}()
	c.Run(n)
	return
}

func diffOutcome(a, b outcome) string {
	var s string
	for i := range a.R {
		if a.R[i] != b.R[i] {
			s += fmt.Sprintf(" R%d %#x/%#x", i, a.R[i], b.R[i])
		}
	}
	if a.RIP != b.RIP && a.panicked == "" {
		s += fmt.Sprintf(" RIP %#x/%#x", a.RIP, b.RIP)
	}
	if a.Flags != b.Flags {
		s += fmt.Sprintf(" Flags %#x/%#x", a.Flags, b.Flags)
	}
	if a.ICount != b.ICount || a.stopped != b.stopped {
		s += fmt.Sprintf(" ICount %d/%d stop %v/%v", a.ICount, b.ICount, a.stopped, b.stopped)
	}
	if a.X != b.X {
		s += " XMM"
	}
	if !bytes.Equal(a.data, b.data) {
		s += " memory"
	}
	if a.panicked != b.panicked || a.ip0 != b.ip0 || a.faultAddr != b.faultAddr || a.excCode != b.excCode || a.excAddr != b.excAddr {
		s += fmt.Sprintf(" panic %q@%#x(%#x %#x) / %q@%#x(%#x %#x)", a.panicked, a.ip0, a.faultAddr, a.excCode, b.panicked, b.ip0, b.faultAddr, b.excCode)
	}
	return s
}

// both runs code with the reference and the block engine and compares.
func both(t *testing.T, name string, code []byte, setup func(c *CPU), n int) outcome {
	t.Helper()
	ref := runOutcome(tMachine(t, EngineInterp, code, setup), n)
	for _, eng := range []Engine{EngineBlock, EngineCheck} {
		got := runOutcome(tMachine(t, eng, code, setup), n)
		if d := diffOutcome(ref, got); d != "" {
			t.Errorf("%s (engine %v): ref/new differ:%s", name, eng, d)
		}
	}
	return ref
}

func stop() []byte { return []byte{0x0F, 0x04, 0, 0, 0, 0} }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestBlockLoopMatchesInterp(t *testing.T) {
	// rcx = 100; loop: add rax, rcx; mov [rbx+rcx*8], rax; dec rcx; jnz loop; stop
	code := cat([]byte{0x48, 0xC7, 0xC1, 100, 0, 0, 0},
		[]byte{0x48, 0x01, 0xC8, 0x48, 0x89, 0x04, 0xCB, 0x48, 0xFF, 0xC9, 0x75, 0xF4}, stop())
	setup := func(c *CPU) { c.R[RBX] = tData }
	r := both(t, "loop", code, setup, 1<<20)
	if r.R[RAX] != 5050 || !r.stopped {
		t.Fatalf("reference result rax=%d stopped=%v", r.R[RAX], r.stopped)
	}
	// slice budgets that cut the loop at every position
	for n := 1; n < 40; n++ {
		both(t, fmt.Sprintf("loop budget %d", n), code, setup, n)
	}
}

func TestBlockFaultIsPrecise(t *testing.T) {
	// mov rax, 1; mov rcx, [rbx] (faults: rbx unmapped); mov rdx, 2
	code := cat([]byte{0x48, 0xC7, 0xC0, 1, 0, 0, 0, 0x48, 0x8B, 0x0B, 0x48, 0xC7, 0xC2, 2, 0, 0, 0}, stop())
	r := both(t, "fault", code, func(c *CPU) { c.R[RBX] = tData + mem.ChunkSize }, 100)
	if r.panicked != "fault" || r.ip0 != tCode+7 {
		t.Fatalf("reference: %+v", r)
	}
	// div by zero raises a CPU exception at the instruction
	code = cat([]byte{0x48, 0xFF, 0xC0, 0x48, 0xF7, 0xF1}, stop()) // inc rax; div rcx
	both(t, "div0", code, nil, 100)
}

func TestBlockSelfModifyingCode(t *testing.T) {
	// The store patches the immediate of the very next instruction (same block):
	//   mov byte [rip+1], 7 ; mov eax, imm32(=1) ; stop      -> eax must be 7
	code := cat([]byte{0xC6, 0x05, 0x01, 0, 0, 0, 7}, []byte{0xB8, 1, 0, 0, 0}, stop())
	r := both(t, "smc same block", code, nil, 100)
	if r.R[RAX] != 7 {
		t.Fatalf("reference eax=%d", r.R[RAX])
	}
	// Go-side store from a hypercall into code that already ran once.
	//   loop: mov eax, imm32 ; hyper 1 (writes [rdi]=sil) ; dec ecx ; jnz loop ; stop
	code = cat([]byte{0xB8, 1, 0, 0, 0}, []byte{0x0F, 0x04, 1, 0, 0, 0}, []byte{0xFF, 0xC9, 0x75, 0xF1}, stop())
	setup := func(c *CPU) { c.R[RCX] = 2; c.R[RDI] = tCode + 1; c.R[RSI] = 9 }
	r = both(t, "smc from Go", code, setup, 100)
	if r.R[RAX] != 9 {
		t.Fatalf("reference eax=%d", r.R[RAX])
	}
}

func TestBlockStopAndICount(t *testing.T) {
	code := cat([]byte{0x90, 0x90}, stop(), []byte{0x90})
	r := both(t, "stop", code, nil, 1000)
	if !r.stopped || r.ICount != 3 {
		t.Fatalf("reference icount=%d stopped=%v", r.ICount, r.stopped)
	}
}

func TestBlockCallRetAndRipRelative(t *testing.T) {
	// call f; mov [rip+0x100], rax ; stop ; f: lea rax, [rip-5] ; push rax ; pop rcx ; ret
	code := cat([]byte{0xE8, 0x0D, 0, 0, 0}, []byte{0x48, 0x89, 0x05, 0x00, 0x01, 0, 0}, stop(),
		[]byte{0x48, 0x8D, 0x05, 0xFB, 0xFF, 0xFF, 0xFF, 0x50, 0x59, 0xC3})
	both(t, "call/ret", code, nil, 100)
}

// A jump to a low unmapped address right after the fetch cache was reset
// must raise an access violation, not a Go nil dereference (pre-existing
// interpreter bug: codeBase = ^0 made RIP < 64 KiB hit the nil chunk).
func TestLowRipFaultsAfterInvalidate(t *testing.T) {
	for _, eng := range []Engine{EngineInterp, EngineBlock, EngineCheck} {
		c := tMachine(t, eng, []byte{0x90}, nil)
		c.InvalidateCode()
		c.RIP = 0x10
		o := runOutcome(c, 10)
		if o.panicked != "fault" || o.faultAddr != 0x10 {
			t.Errorf("engine %v: %q fault at %#x", eng, o.panicked, o.faultAddr)
		}
	}
}

// LEA with a register operand is #UD (pre-existing interpreter bug: it
// loaded the stale effective address of the previous instruction).
func TestLeaRegisterOperandIsUD(t *testing.T) {
	// mov rax, [rbx+8] ; lea ecx, edx (8D CA)
	code := cat([]byte{0x48, 0x8B, 0x43, 0x08, 0x8D, 0xCA}, stop())
	r := both(t, "lea reg", code, func(c *CPU) { c.R[RBX] = tData }, 10)
	if r.panicked != "exception" || r.excCode != ExcIllegalInstr || r.ip0 != tCode+4 || r.R[RCX] != 0 {
		t.Fatalf("reference: %q code %#x at %#x rcx=%#x", r.panicked, r.excCode, r.ip0, r.R[RCX])
	}
}
