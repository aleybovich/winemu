package mem

import (
	"bytes"
	"testing"
)

func watchedMem(t *testing.T) (*Memory, *[]uint64) {
	t.Helper()
	m := New()
	if _, err := m.Map(0x100000, 0x40000, PageExecuteReadWrite, MemPrivate, "t"); err != nil {
		t.Fatal(err)
	}
	var hits []uint64
	m.OnCodeWrite = func(page uint64) { hits = append(hits, page) }
	m.W8(0x101000, 0x90) // materialise the chunk before watching
	m.WatchCode(0x101234)
	return m, &hits
}

func TestCodeWatchScalarStore(t *testing.T) {
	m, hits := watchedMem(t)
	m.W64(0x100ff8, 1) // same chunk, other page: no hit
	if len(*hits) != 0 || m.CodeWritten {
		t.Fatalf("unexpected hit %v", *hits)
	}
	if m.R64(0x100ff8) != 1 {
		t.Fatal("store lost")
	}
	for _, w := range []func(){
		func() { m.W8(0x101fff, 7) },
		func() { m.W16(0x101000, 7) },
		func() { m.W32(0x101100, 7) },
		func() { m.W64(0x101ffc, 7) }, // straddles into the next page
	} {
		*hits = nil
		m.CodeWritten = false
		m.WatchCode(0x101000)
		w()
		if len(*hits) != 1 || (*hits)[0] != 0x101000 || !m.CodeWritten {
			t.Fatalf("hits=%x written=%v", *hits, m.CodeWritten)
		}
	}
	if m.R32(0x101100) != 7 || m.R8(0x101fff) != 0 || m.R64(0x101ffc) != 7 {
		t.Fatal("stores into watched page lost")
	}
	*hits = nil
	m.W8(0x101000, 1) // page no longer watched: fast path again, no hit
	if len(*hits) != 0 {
		t.Fatalf("hit after unwatch: %x", *hits)
	}
}

func TestCodeWatchBulkPaths(t *testing.T) {
	cases := map[string]func(m *Memory){
		"Write":     func(m *Memory) { m.Write(0x100ffe, []byte{1, 2, 3, 4}) },
		"Fill":      func(m *Memory) { m.Fill(0x100800, 0xCC, 0x1000) },
		"Zero":      func(m *Memory) { m.Zero(0x101800, 8) },
		"ZeroChunk": func(m *Memory) { m.Zero(0x100000, ChunkSize) },
		"Move":      func(m *Memory) { m.Move(0x101010, 0x120000, 16) },
		"Unmap":     func(m *Memory) { m.Unmap(0x100000) },
		"WriteCStr": func(m *Memory) { m.WriteCStr(0x101000, "x") },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			m, hits := watchedMem(t)
			f(m)
			if len(*hits) != 1 || (*hits)[0] != 0x101000 {
				t.Fatalf("hits=%x", *hits)
			}
		})
	}
}

func TestCodeWatchReadDoesNotHit(t *testing.T) {
	m, hits := watchedMem(t)
	_ = m.R64(0x101000)
	b := make([]byte, 16)
	m.Read(0x101000, b)
	if len(*hits) != 0 {
		t.Fatalf("read hit %x", *hits)
	}
}

func TestJournalUndo(t *testing.T) {
	m := New()
	if _, err := m.Map(0x100000, 0x20000, PageReadWrite, MemPrivate, "t"); err != nil {
		t.Fatal(err)
	}
	m.Write(0x100000, []byte("0123456789abcdef"))
	m.DisableFastWrite()
	before := m.ReadBytes(0x100000, 0x20000)
	m.BeginJournal()
	m.W64(0x100004, 0x1111111111111111)
	m.W8(0x100000, 0x22)
	m.Write(0x10fffe, []byte{9, 9, 9, 9}) // crosses a chunk
	m.Fill(0x100100, 0x33, 3)
	j, shared := m.EndJournal()
	if shared {
		t.Fatal("no shared memory touched")
	}
	got := map[uint64]byte{}
	for _, e := range j {
		for i := range e.Old {
			got[e.Addr+uint64(i)] = 1
		}
	}
	if len(got) != 8+1+4+3 {
		t.Fatalf("journal covers %d bytes", len(got))
	}
	m.Undo(j)
	if !bytes.Equal(m.ReadBytes(0x100000, 0x20000), before) {
		t.Fatal("undo did not restore memory")
	}
}

func TestJournalSharedTouch(t *testing.T) {
	m := New()
	s := NewSection(ChunkSize)
	if _, err := m.MapSection(0x200000, s, 0, ChunkSize, PageReadWrite, MemMapped, "s"); err != nil {
		t.Fatal(err)
	}
	m.BeginJournal()
	_ = m.R32(0x200010)
	_, shared := m.EndJournal()
	if !shared {
		t.Fatal("shared read not reported")
	}
}

func TestJournalPrivateAbortsOnShared(t *testing.T) {
	m := New()
	s := NewSection(ChunkSize)
	if _, err := m.MapSection(0x200000, s, 0, ChunkSize, PageReadWrite, MemMapped, "s"); err != nil {
		t.Fatal(err)
	}
	m.BeginJournalPrivate()
	func() {
		defer func() {
			if _, ok := recover().(SharedAccess); !ok {
				t.Error("no SharedAccess panic")
			}
		}()
		m.W32(0x200010, 5)
	}()
	m.EndJournal()
	if m.R32(0x200010) != 0 {
		t.Fatal("aborted store happened")
	}
}

// The one-entry chunk caches must not return a dropped chunk.
func TestChunkCacheDroppedChunks(t *testing.T) {
	m := New()
	if _, err := m.Map(0x100000, ChunkSize, PageReadWrite, MemPrivate, "t"); err != nil {
		t.Fatal(err)
	}
	m.W64(0x100010, 0x1111)
	if m.R64(0x100010) != 0x1111 {
		t.Fatal("store lost")
	}
	m.Unmap(0x100000)
	func() {
		defer func() {
			if _, ok := recover().(*Fault); !ok {
				t.Error("read of unmapped chunk did not fault")
			}
		}()
		m.R64(0x100010)
	}()
	func() {
		defer func() {
			if _, ok := recover().(*Fault); !ok {
				t.Error("write to unmapped chunk did not fault")
			}
		}()
		m.W64(0x100010, 1)
	}()
	if _, err := m.Map(0x100000, ChunkSize, PageReadWrite, MemPrivate, "t2"); err != nil {
		t.Fatal(err)
	}
	if m.R64(0x100010) != 0 {
		t.Fatal("remapped chunk returned old data")
	}
	m.W64(0x100010, 0x2222)
	m.Zero(0x100000, ChunkSize) // drops the whole chunk
	if m.R64(0x100010) != 0 {
		t.Fatal("zeroed chunk returned old data")
	}
	m.W64(0x100018, 3)
	if m.R64(0x100010) != 0 || m.R64(0x100018) != 3 {
		t.Fatal("store after zero lost")
	}
}
