package mem

import (
	"sync"
	"testing"
)

const (
	testBaseA = 0x10000000
	testBaseB = 0x20000000 // the same section at a different address
)

func twoViews(t *testing.T, size uint64) (*Memory, *Memory, *Section) {
	t.Helper()
	s := NewSection(size)
	a, b := New(), New()
	if _, err := a.MapSection(testBaseA, s, 0, size, PageReadWrite, MemMapped, "shared"); err != nil {
		t.Fatalf("MapSection A: %v", err)
	}
	if _, err := b.MapSection(testBaseB, s, 0, size, PageReadWrite, MemMapped, "shared"); err != nil {
		t.Fatalf("MapSection B: %v", err)
	}
	return a, b, s
}

func TestSectionCoherentBetweenViews(t *testing.T) {
	a, b, _ := twoViews(t, 3*ChunkSize)
	a.W64(testBaseA+8, 0x1122334455667788)
	if got := b.R64(testBaseB + 8); got != 0x1122334455667788 {
		t.Fatalf("R64 through second view = %#x", got)
	}
	// every access size, aligned and unaligned, inside and across words
	for _, off := range []uint64{0, 1, 2, 3, 5, 6, 7, 13, ChunkSize - 3, ChunkSize - 1, 2*ChunkSize - 5} {
		b.W8(testBaseB+off, 0xA5)
		if a.R8(testBaseA+off) != 0xA5 {
			t.Fatalf("W8/R8 at +%#x", off)
		}
		b.W16(testBaseB+off, 0xBEEF)
		if a.R16(testBaseA+off) != 0xBEEF {
			t.Fatalf("W16/R16 at +%#x = %#x", off, a.R16(testBaseA+off))
		}
		b.W32(testBaseB+off, 0xDEADBEEF)
		if a.R32(testBaseA+off) != 0xDEADBEEF {
			t.Fatalf("W32/R32 at +%#x = %#x", off, a.R32(testBaseA+off))
		}
		b.W64(testBaseB+off, 0x0102030405060708)
		if a.R64(testBaseA+off) != 0x0102030405060708 {
			t.Fatalf("W64/R64 at +%#x = %#x", off, a.R64(testBaseA+off))
		}
	}
	// neighbouring bytes are preserved by sub-word stores
	a.W32(testBaseA+0x100, 0x44332211)
	b.W8(testBaseB+0x101, 0xFF)
	if got := a.R32(testBaseA + 0x100); got != 0x4433FF11 {
		t.Fatalf("byte store clobbered neighbours: %#x", got)
	}
	// bulk operations across a chunk boundary
	msg := []byte("hello, shared world, across the chunk boundary")
	start := uint64(ChunkSize - 10)
	a.Write(testBaseA+start, msg)
	if got := b.ReadBytes(testBaseB+start, len(msg)); string(got) != string(msg) {
		t.Fatalf("Write/Read = %q", got)
	}
	a.WriteCStr(testBaseA+0x200, "cstr")
	if got := b.CStr(testBaseB + 0x200); got != "cstr" {
		t.Fatalf("CStr = %q", got)
	}
	b.Fill(testBaseB+start, 0x5A, 20)
	if got := a.ReadBytes(testBaseA+start, 20); string(got) != "ZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("Fill = %q", got)
	}
	a.Move(testBaseA+0x300, testBaseA+start, 20)
	if got := b.ReadBytes(testBaseB+0x300, 20); string(got) != "ZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("Move = %q", got)
	}
	a.Zero(testBaseA, 2*ChunkSize)
	if b.R64(testBaseB+8) != 0 || b.R8(testBaseB+ChunkSize+5) != 0 {
		t.Fatal("Zero not visible through second view")
	}
}

func TestSectionOffsetAndUnmap(t *testing.T) {
	s := NewSection(4 * ChunkSize)
	a, b := New(), New()
	if _, err := a.MapSection(testBaseA, s, 0, 4*ChunkSize, PageReadWrite, MemMapped, "full"); err != nil {
		t.Fatal(err)
	}
	r, err := b.MapSection(testBaseB, s, 2*ChunkSize, ChunkSize, PageReadWrite, MemMapped, "part")
	if err != nil {
		t.Fatal(err)
	}
	if r.Section != s || r.SectionOff != 2*ChunkSize {
		t.Fatalf("region section fields: %v %#x", r.Section == s, r.SectionOff)
	}
	a.W32(testBaseA+2*ChunkSize+4, 77)
	if b.R32(testBaseB+4) != 77 {
		t.Fatal("offset view does not alias the section")
	}
	if !b.Shared(testBaseB+4) || b.Shared(testBaseB+ChunkSize) {
		t.Fatal("Shared() wrong")
	}
	if !b.Unmap(testBaseB) {
		t.Fatal("Unmap failed")
	}
	func() {
		defer func() {
			if _, ok := recover().(*Fault); !ok {
				t.Fatal("access after Unmap did not fault")
			}
		}()
		b.R32(testBaseB + 4)
	}()
	if a.R32(testBaseA+2*ChunkSize+4) != 77 {
		t.Fatal("unmapping one view lost the section contents")
	}
	// remapping the same section at the same address in a fresh space
	c := New()
	if _, err := c.MapSection(testBaseA, s, 0, 4*ChunkSize, PageReadWrite, MemMapped, "again"); err != nil {
		t.Fatal(err)
	}
	if c.R32(testBaseA+2*ChunkSize+4) != 77 {
		t.Fatal("section lost data")
	}
	// errors
	if _, err := c.MapSection(testBaseA, s, 0, ChunkSize, PageReadWrite, MemMapped, "dup"); err == nil {
		t.Fatal("mapping over an existing region succeeded")
	}
	if _, err := New().MapSection(testBaseA, s, 3*ChunkSize, 2*ChunkSize, PageReadWrite, MemMapped, "big"); err == nil {
		t.Fatal("view beyond the section end succeeded")
	}
	if _, err := New().MapSection(testBaseA, s, 100, ChunkSize, PageReadWrite, MemMapped, "unaligned"); err == nil {
		t.Fatal("unaligned section offset succeeded")
	}
}

func TestPrivateMemoryIsNotShared(t *testing.T) {
	m := New()
	if _, err := m.Map(testBaseA, ChunkSize, PageReadWrite, MemPrivate, "priv"); err != nil {
		t.Fatal(err)
	}
	m.W32(testBaseA, 1)
	if m.Shared(testBaseA) || m.HasShared() {
		t.Fatal("private memory reported as shared")
	}
}

func TestAtomicCAS(t *testing.T) {
	a, b, _ := twoViews(t, ChunkSize)
	for _, sz := range []int{1, 2, 4, 8} {
		for _, off := range []uint64{0x40, 0x41, 0x43, 0x46, 0x47} {
			a.Zero(testBaseA, ChunkSize)
			if !b.AtomicCAS(testBaseB+off, sz, 0, 0x5A) {
				t.Fatalf("size %d off %#x: CAS from 0 failed", sz, off)
			}
			if b.AtomicCAS(testBaseB+off, sz, 0, 0x77) {
				t.Fatalf("size %d off %#x: CAS with stale old value succeeded", sz, off)
			}
			if got := a.AtomicLoad(testBaseA+off, sz); got != 0x5A {
				t.Fatalf("size %d off %#x: AtomicLoad = %#x", sz, off, got)
			}
			if a.R8(testBaseA+off-1) != 0 {
				t.Fatalf("size %d off %#x: CAS clobbered the previous byte", sz, off)
			}
		}
	}
}

// Plain loads/stores and CAS increments from two goroutines on two views:
// exact total and clean under -race.
func TestSectionConcurrentAccess(t *testing.T) {
	a, b, _ := twoViews(t, ChunkSize)
	const n = 100000
	var wg sync.WaitGroup
	inc := func(m *Memory, base uint64) {
		defer wg.Done()
		for i := 0; i < n; i++ {
			for {
				v := m.AtomicLoad(base, 4)
				if m.AtomicCAS(base, 4, v, v+1) {
					break
				}
			}
			m.W8(base+5, byte(i)) // plain sub-word stores next to the counter
			m.W16(base+6, uint16(i))
			_ = m.R64(base)
		}
	}
	wg.Add(2)
	go inc(a, testBaseA)
	go inc(b, testBaseB)
	wg.Wait()
	if got := a.R32(testBaseA); got != 2*n {
		t.Fatalf("counter = %d, want %d", got, 2*n)
	}
}
