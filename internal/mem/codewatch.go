package mem

// Store-path tracking of pages that hold decoded guest code (docs/engine.md).
//
// The scalar store fast path looks chunks up in w1, a copy of the read table
// l1 without the chunks that contain watched (decoded) pages, so it costs the
// same as before; stores into such chunks take the slow path, where noteWrite
// checks the per-chunk page mask. Every other write path calls noteWrite too.

// JournalEntry records the bytes a store overwrote (differential checker).
type JournalEntry struct {
	Addr uint64
	Old  []byte
}

type journal struct {
	on      bool
	entries []JournalEntry
	shared  bool // a shared-section chunk was accessed
	abort   bool // panic with SharedAccess on such an access
}

// SharedAccess is raised (via panic) by an access to shared-section memory
// while a journal started with BeginJournalPrivate is on.
type SharedAccess struct{}

// wlookup is lookup for stores (w1); like lookup it writes nothing.
func (m *Memory) wlookup(a uint64) *chunk {
	hi := a >> 32
	if hi >= l1Size {
		return nil
	}
	t := m.w1[hi]
	if t == nil {
		return nil
	}
	return t[(a>>16)&(l2Size-1)]
}

func (m *Memory) setW1(a uint64, c *chunk) {
	hi := a >> 32
	t := m.w1[hi]
	if t == nil {
		if c == nil {
			return
		}
		t = new([l2Size]*chunk)
		m.w1[hi] = t
	}
	i := (a >> 16) & (l2Size - 1)
	if old := t[i]; old != nil && old != c {
		m.newGen() // a Cache may hold old for stores
	}
	t[i] = c
}

// publishW1 enters a (newly materialised or no longer watched) chunk into
// the store table unless stores must take the slow path.
func (m *Memory) publishW1(a uint64, c *chunk) {
	if m.noFastW || m.watch[a>>ChunkBits] != 0 {
		return
	}
	m.setW1(a, c)
}

// WatchCode marks the 4 KiB page containing a as holding decoded code: the
// next write to it calls OnCodeWrite(page) and sets CodeWritten.
func (m *Memory) WatchCode(a uint64) {
	if m.watch == nil {
		m.watch = map[uint64]uint16{}
	}
	ci := a >> ChunkBits
	m.watch[ci] |= 1 << ((a & chunkMask) / PageSize)
	m.setW1(a, nil)
}

// noteWrite reports writes to [a, a+n) that hit watched pages.
func (m *Memory) noteWrite(a, n uint64) {
	if len(m.watch) == 0 || n == 0 {
		return
	}
	end := a + n
	for ci := a >> ChunkBits; ci <= (end-1)>>ChunkBits; ci++ {
		mask := m.watch[ci]
		if mask == 0 {
			continue
		}
		cb := ci << ChunkBits
		lo, hi := uint64(0), uint64(ChunkSize-1)
		if a > cb {
			lo = a - cb
		}
		if end-1 < cb+ChunkSize-1 {
			hi = end - 1 - cb
		}
		var bits uint16
		for p := lo / PageSize; p <= hi/PageSize; p++ {
			bits |= 1 << p
		}
		hit := mask & bits
		if hit == 0 {
			continue
		}
		if mask &^= hit; mask == 0 {
			delete(m.watch, ci)
			if c := m.lookup(cb); c != nil {
				m.publishW1(cb, c)
			}
		} else {
			m.watch[ci] = mask
		}
		m.CodeWritten = true
		for p := uint64(0); p < ChunkSize/PageSize; p++ {
			if hit&(1<<p) != 0 && m.OnCodeWrite != nil {
				m.OnCodeWrite(cb + p*PageSize)
			}
		}
	}
}

// DisableFastWrite sends every store through the slow path (checker mode, so
// that the write journal sees all stores).
func (m *Memory) DisableFastWrite() {
	m.noFastW = true
	clear(m.w1[:])
	m.newGen()
}

// BeginJournal starts recording the old contents of every store.
func (m *Memory) BeginJournal() { m.jrn = journal{on: true} }

// BeginJournalPrivate is BeginJournal for code that must not touch shared
// memory: such an access panics with SharedAccess before it happens.
func (m *Memory) BeginJournalPrivate() { m.jrn = journal{on: true, abort: true} }

// EndJournal stops recording; it returns the entries in store order and
// whether shared-section memory was accessed meanwhile.
func (m *Memory) EndJournal() ([]JournalEntry, bool) {
	j := m.jrn
	m.jrn = journal{}
	return j.entries, j.shared
}

// Undo restores journaled stores, newest first.
func (m *Memory) Undo(j []JournalEntry) {
	for i := len(j) - 1; i >= 0; i-- {
		m.Write(j[i].Addr, j[i].Old)
	}
}

// record saves the old bytes of a private store of n bytes at a (within one
// chunk) while the journal is on.
func (m *Memory) record(a uint64, n int) {
	old := make([]byte, n)
	if c := m.lookup(a); c != nil {
		o := a & chunkMask
		copy(old, c[o:o+uint64(n)])
	}
	m.jrn.entries = append(m.jrn.entries, JournalEntry{Addr: a, Old: old})
}
