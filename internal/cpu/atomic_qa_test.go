package cpu

import (
	"sync"
	"testing"

	"winemu/internal/mem"
)

// lock cmpxchg16b incrementing both halves of a 128-bit value from two
// address spaces: exact totals (the instruction is one atomic step).
func TestQAWSDLockCmpxchg16bSharedCounter(t *testing.T) {
	code := []byte{
		0x4C, 0x89, 0xC5, // mov rbp, r8
		0x49, 0x89, 0xC9, // mov r9, rcx
		0x48, 0x8B, 0x45, 0x00, // again: mov rax, [rbp]
		0x48, 0x8B, 0x55, 0x08, // mov rdx, [rbp+8]
		0x48, 0x8D, 0x58, 0x01, // lea rbx, [rax+1]
		0x48, 0x8D, 0x4A, 0x01, // lea rcx, [rdx+1]
		0xF0, 0x48, 0x0F, 0xC7, 0x4D, 0x00, // lock cmpxchg16b [rbp]
		0x75, 0xE8, // jnz again
		0x49, 0xFF, 0xC9, // dec r9
		0x75, 0xE3, // jnz again
	}
	const n = 50000
	s := mem.NewSection(mem.ChunkSize)
	var wg sync.WaitGroup
	var first *mem.Memory
	for i, base := range []uint64{sharedA, sharedB} {
		m := space(t, s, base, code)
		if i == 0 {
			first = m
		}
		c := New(m)
		c.Hyper = func(c *CPU, idx uint32) { c.Stop = true }
		c.RIP = codeBase
		c.R[R8] = base + 0x40
		c.R[RCX] = n
		wg.Add(1)
		go func() { defer wg.Done(); c.Run(1 << 40) }()
	}
	wg.Wait()
	if lo, hi := first.R64(sharedA+0x40), first.R64(sharedA+0x48); lo != 2*n || hi != 2*n {
		t.Fatalf("counter = (%d, %d), want %d each", lo, hi, 2*n)
	}
}
