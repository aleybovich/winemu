package mem

// Commit state of VirtualAlloc reservations. A region made by Reserve tracks
// which 4 KiB pages are committed; access to an uncommitted page faults when
// its chunk is not materialised (a chunk is dropped once none of its pages is
// committed, so the fault is exact at chunk level and for untouched chunks).
// Regions that never called Reserve are committed as a whole.

const PageSize = 0x1000

const fullChunk = 1<<(ChunkSize/PageSize) - 1

// Reserve marks every page of r as reserved but not committed.
func (r *Region) Reserve() { r.commit = make([]uint16, r.Size/ChunkSize) }

// Committed reports whether the page containing a (inside r) is committed.
func (r *Region) Committed(a uint64) bool {
	if r.commit == nil {
		return true
	}
	o := a - r.Base
	return r.commit[o>>ChunkBits]&(1<<((o&chunkMask)/PageSize)) != 0
}

// CommitRun returns the state of the page containing a and the end of the
// run of pages in r with the same state.
func (r *Region) CommitRun(a uint64) (committed bool, end uint64) {
	limit := r.Base + r.Size
	if r.commit == nil {
		return true, limit
	}
	committed = r.Committed(a)
	same := uint16(0)
	if committed {
		same = fullChunk
	}
	for end = a&^(PageSize-1) + PageSize; end < limit; {
		if end&chunkMask == 0 && r.commit[(end-r.Base)>>ChunkBits] == same {
			end += ChunkSize
			continue
		}
		if r.Committed(end) != committed {
			break
		}
		end += PageSize
	}
	return committed, end
}

// SetCommitted commits or decommits the pages of [a, a+n) (page aligned,
// inside r). Decommitted pages read as zero once committed again.
func (m *Memory) SetCommitted(r *Region, a, n uint64, on bool) {
	if r.commit == nil {
		if on {
			return
		}
		r.commit = make([]uint16, r.Size/ChunkSize)
		for i := range r.commit {
			r.commit[i] = fullChunk
		}
	}
	for p := a; p < a+n; p += PageSize {
		o := p - r.Base
		bit := uint16(1) << ((o & chunkMask) / PageSize)
		if on {
			r.commit[o>>ChunkBits] |= bit
		} else {
			r.commit[o>>ChunkBits] &^= bit
		}
	}
	if on {
		return
	}
	m.Zero(a, n)
	for c := a &^ chunkMask; c < a+n; c += ChunkSize {
		if r.commit[(c-r.Base)>>ChunkBits] == 0 {
			m.dropChunks(c, ChunkSize)
		}
	}
}

// AccessibleLen returns how many bytes from a (up to n) are mapped and
// committed.
func (m *Memory) AccessibleLen(a, n uint64) uint64 {
	p, end := a, a+n
	if end < a {
		return 0
	}
	for p < end {
		r := m.FindRegion(p)
		if r == nil {
			break
		}
		ok, next := r.CommitRun(p)
		if !ok {
			break
		}
		p = next
	}
	return min(p, end) - a
}
