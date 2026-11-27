package cpu

import (
	"sync"
	"testing"

	"winemu/internal/mem"
)

const (
	codeBase   = 0x400000
	sharedA    = 0x10000000
	sharedB    = 0x30000000 // same section, different address in the second space
	hyperpStop = 0
)

// space builds an address space with private code and a view of s.
func space(t *testing.T, s *mem.Section, sharedBase uint64, code []byte) *mem.Memory {
	t.Helper()
	m := mem.New()
	if _, err := m.Map(codeBase, mem.ChunkSize, mem.PageExecuteReadWrite, mem.MemPrivate, "code"); err != nil {
		t.Fatal(err)
	}
	m.Write(codeBase, append(append([]byte{}, code...), 0x0F, 0x04, hyperpStop, 0, 0, 0))
	if _, err := m.MapSection(sharedBase, s, 0, mem.ChunkSize, mem.PageReadWrite, mem.MemMapped, "shared"); err != nil {
		t.Fatal(err)
	}
	return m
}

// runTwo runs code on two CPUs in two address spaces sharing one section,
// concurrently. RBX = counter address, RSI = lock address, RCX = iterations.
func runTwo(t *testing.T, code []byte, iters uint64) *mem.Memory {
	t.Helper()
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
		c.R[RBX] = base + 0x40
		c.R[RSI] = base + 0x80
		c.R[RCX] = iters
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Run(1 << 40)
		}()
	}
	wg.Wait()
	return first
}

func TestLockXaddSharedCounter(t *testing.T) {
	code := []byte{
		0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0xF0, 0x0F, 0xC1, 0x03, // lock xadd [rbx], eax
		0x48, 0xFF, 0xC9, // dec rcx
		0x75, 0xF2, // jnz loop
	}
	const n = 1000000
	m := runTwo(t, code, n)
	if got := m.R32(sharedA + 0x40); got != 2*n {
		t.Fatalf("counter = %d, want %d", got, 2*n)
	}
}

func TestLockedRMWVariantsSharedCounter(t *testing.T) {
	const n = 100000
	cases := map[string][]byte{
		"lock inc": {0xF0, 0xFF, 0x03, 0x48, 0xFF, 0xC9, 0x75, 0xF8}, // lock inc dword [rbx]; dec rcx; jnz
		"lock add": {0xB8, 0x01, 0, 0, 0, 0xF0, 0x01, 0x03, 0x48, 0xFF, 0xC9, 0x75, 0xF3},
		"lock sub": {0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x29, 0x03, 0x48, 0xFF, 0xC9, 0x75, 0xF3}, // sub -1
		"lock cmpxchg loop": {
			0x8B, 0x03, // again: mov eax, [rbx]
			0x8D, 0x50, 0x01, // lea edx, [rax+1]
			0xF0, 0x0F, 0xB1, 0x13, // lock cmpxchg [rbx], edx
			0x75, 0xF5, // jnz again
			0x48, 0xFF, 0xC9, // dec rcx
			0x75, 0xF0, // jnz again
		},
		"xchg spinlock": {
			0xB8, 0x01, 0, 0, 0, // spin: mov eax, 1
			0x87, 0x06, // xchg [rsi], eax
			0x85, 0xC0, // test eax, eax
			0x75, 0xF5, // jnz spin
			0x8B, 0x03, // mov eax, [rbx]   (plain RMW under the lock)
			0xFF, 0xC0, // inc eax
			0x89, 0x03, // mov [rbx], eax
			0xC7, 0x06, 0, 0, 0, 0, // mov dword [rsi], 0 (release)
			0x48, 0xFF, 0xC9, // dec rcx
			0x75, 0xE4, // jnz spin
		},
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			m := runTwo(t, code, n)
			if got := m.R32(sharedA + 0x40); got != 2*n {
				t.Fatalf("counter = %d, want %d", got, 2*n)
			}
		})
	}
}

// cmpxchg8b increment of a 64-bit counter; R8 holds the counter address.
func TestLockCmpxchg8bSharedCounter(t *testing.T) {
	code := []byte{
		0x4C, 0x89, 0xC5, // mov rbp, r8         (r8 = counter address)
		0x49, 0x89, 0xC9, // mov r9, rcx         (iterations)
		0x8B, 0x45, 0x00, // again: mov eax, [rbp]
		0x8B, 0x55, 0x04, // mov edx, [rbp+4]
		0x8D, 0x58, 0x01, // lea ebx, [rax+1]
		0x89, 0xD1, // mov ecx, edx
		0xF0, 0x0F, 0xC7, 0x4D, 0x00, // lock cmpxchg8b [rbp]
		0x75, 0xEE, // jnz again
		0x49, 0xFF, 0xC9, // dec r9
		0x75, 0xE9, // jnz again
	}
	const n = 100000
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
	if got := first.R64(sharedA + 0x40); got != 2*n {
		t.Fatalf("counter = %d, want %d", got, 2*n)
	}
}

// LOCK on private memory keeps working (single CPU, no shared mapping).
func TestLockXaddPrivate(t *testing.T) {
	m := mem.New()
	if _, err := m.Map(codeBase, 2*mem.ChunkSize, mem.PageExecuteReadWrite, mem.MemPrivate, "code"); err != nil {
		t.Fatal(err)
	}
	m.Write(codeBase, []byte{0xB8, 0x05, 0, 0, 0, 0xF0, 0x0F, 0xC1, 0x03, 0x0F, 0x04, 0, 0, 0, 0})
	c := New(m)
	c.Hyper = func(c *CPU, idx uint32) { c.Stop = true }
	c.RIP = codeBase
	c.R[RBX] = codeBase + mem.ChunkSize
	m.W32(codeBase+mem.ChunkSize, 10)
	c.Run(100)
	if m.R32(codeBase+mem.ChunkSize) != 15 || c.R[RAX] != 10 {
		t.Fatalf("mem %d rax %d, want 15 10", m.R32(codeBase+mem.ChunkSize), c.R[RAX])
	}
}
