package mem

import (
	"sync"
	"testing"
)

// TestConcurrentAccessors runs the accessors the CPU uses on one goroutine
// while another goroutine (Go-side API code, another process) reads, writes,
// maps and unmaps other parts of the same address space. Neither may write
// state the other reads (run with -race).
func TestConcurrentAccessors(t *testing.T) {
	const x, y, z, sh = 0x100000, 0x110000, 0x200000, 0x300000
	m := New()
	if _, err := m.Map(x, 0x20000, PageReadWrite, MemPrivate, "xy"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.MapSection(sh, NewSection(2*ChunkSize), 0, 2*ChunkSize, PageReadWrite, MemMapped, "sh"); err != nil {
		t.Fatal(err)
	}
	m.W8(x, 0) // materialise both private chunks up front
	m.W8(y, 0)
	m.W8(sh, 0)
	m.W8(sh+ChunkSize, 0)

	const n = 2000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the owning CPU
		defer wg.Done()
		var k Cache
		for i := range uint64(n) {
			a := x + i%0x100*8
			k.W64(m, a, i)
			if k.R64(m, a) != i {
				t.Errorf("cpu: lost store at %#x", a)
				return
			}
			k.W32(m, a, uint32(i))
			_ = k.R32(m, a) + uint32(k.R16(m, a)) + uint32(k.R8(m, a))
			k.W16(m, a, uint16(i))
			k.W8(m, a, uint8(i))
			k.W64(m, sh+i%2*ChunkSize, i)
			_ = k.R64(m, sh+i%2*ChunkSize)
		}
	}()
	go func() { // Go-side code
		defer wg.Done()
		b := make([]byte, 16)
		for i := range uint64(n) {
			m.Write(y, b)
			m.W64(y+8, i)
			if m.R64(y+8) != i {
				t.Errorf("go: lost store at %#x", y+8)
				return
			}
			m.Read(y, b)
			m.R64(sh + (i+1)%2*ChunkSize)
			m.Read(sh+ChunkSize-8, b) // straddles both shared chunks
			if !m.Valid(y) {
				t.Errorf("go: %#x not valid", y)
				return
			}
			if _, err := m.Map(z, ChunkSize, PageReadWrite, MemPrivate, "z"); err != nil {
				t.Errorf("go: map: %v", err)
				return
			}
			m.W64(z, i)
			m.FindRegion(z)
			m.Unmap(z)
		}
	}()
	wg.Wait()
}

// TestConcurrentFindRegion: region lookups from two goroutines (the region
// table itself changes only with the process stopped).
func TestConcurrentFindRegion(t *testing.T) {
	m := New()
	bases := []uint64{0x100000, 0x200000}
	for _, b := range bases {
		if _, err := m.Map(b, ChunkSize, PageReadWrite, MemPrivate, "t"); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	wg.Add(len(bases))
	for _, b := range bases {
		go func() {
			defer wg.Done()
			for range 2000 {
				if r := m.FindRegion(b + 8); r == nil || r.Base != b {
					t.Errorf("FindRegion(%#x) = %v", b+8, r)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestCacheInvalidation checks that a Cache never serves a chunk the chunk
// tables no longer hold.
func TestCacheInvalidation(t *testing.T) {
	const a = 0x100000
	fault := func(f func()) (got bool) {
		defer func() { _, got = recover().(*Fault) }()
		f()
		return false
	}
	fill := func(k *Cache, m *Memory) { // the first store materialises; then cache both
		k.W64(m, a, 1)
		k.W64(m, a, 1)
		if k.R64(m, a) != 1 {
			t.Fatal("store lost")
		}
	}
	t.Run("unmap", func(t *testing.T) {
		m := New()
		m.Map(a, ChunkSize, PageReadWrite, MemPrivate, "t")
		var k Cache
		fill(&k, m)
		m.Unmap(a)
		if !fault(func() { k.R64(m, a) }) {
			t.Fatal("read after unmap did not fault")
		}
		if !fault(func() { k.W64(m, a, 2) }) {
			t.Fatal("write after unmap did not fault")
		}
	})
	t.Run("decommit", func(t *testing.T) {
		m := New()
		r, _ := m.Map(a, ChunkSize, PageReadWrite, MemPrivate, "t")
		var k Cache
		fill(&k, m)
		m.SetCommitted(r, a, ChunkSize, false)
		if !fault(func() { k.R64(m, a) }) {
			t.Fatal("read after decommit did not fault")
		}
		m.SetCommitted(r, a, ChunkSize, true)
		if v := k.R64(m, a); v != 0 {
			t.Fatalf("recommitted page reads %#x, want 0", v)
		}
	})
	t.Run("remap", func(t *testing.T) {
		m := New()
		m.Map(a, ChunkSize, PageReadWrite, MemPrivate, "t")
		var k Cache
		fill(&k, m)
		m.Unmap(a)
		m.Map(a, ChunkSize, PageReadWrite, MemPrivate, "t")
		k.W64(m, a, 2)
		if v := m.R64(a); v != 2 {
			t.Fatalf("store went to a stale chunk: memory reads %#x, want 2", v)
		}
	})
	t.Run("disable fast write", func(t *testing.T) {
		m := New()
		m.Map(a, ChunkSize, PageReadWrite, MemPrivate, "t")
		var k Cache
		fill(&k, m)
		m.DisableFastWrite()
		m.BeginJournal()
		k.W64(m, a, 2)
		if j, _ := m.EndJournal(); len(j) != 1 || j[0].Addr != a {
			t.Fatalf("store bypassed the journal: %v", j)
		}
	})
	t.Run("watch", func(t *testing.T) {
		m, hits := watchedMem(t)
		m.CodeWritten = false
		var k Cache
		m.Unmap(0x100000) // drop the watched chunk ...
		m.Map(0x100000, 0x40000, PageExecuteReadWrite, MemPrivate, "t")
		k.W8(m, 0x101000, 1) // ... then materialise and cache the fresh one for stores
		k.W8(m, 0x101000, 1)
		m.WatchCode(0x101000)
		*hits = nil
		k.W8(m, 0x101000, 2)
		if len(*hits) != 1 || !m.CodeWritten {
			t.Fatalf("store through a cached chunk missed the watch: hits %v", *hits)
		}
		k.W8(m, 0x101000, 3) // unwatched again: fast path is back
		if len(*hits) != 1 || k.R8(m, 0x101000) != 3 {
			t.Fatalf("hits %v, value %d", *hits, k.R8(m, 0x101000))
		}
	})
}
