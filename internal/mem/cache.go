package mem

import "sync/atomic"

// Cache remembers the last private chunk used for loads and for stores in
// front of a Memory's scalar accessors. The Memory accessors themselves write
// no shared state, so Go-side API code, other processes and the owning thread
// may all use them; a Cache belongs to one goroutine at a time (each
// cpu.CPU owns one). The zero value is empty.
//
// An entry is valid only for the chunk-table generation it was filled under:
// every change that removes a chunk from l1 or w1 (unmap, decommit, code
// watch, DisableFastWrite) gives the Memory a new generation, which discards
// all entries. Generations are unique across all Memory values, so an entry
// never matches another address space. Shared-section chunks are never in
// l1/w1, so never cached.
type Cache struct {
	gen        uint64
	rKey, wKey uint64 // last address of the chunk (0: empty)
	r, w       *chunk
}

// load returns a's cached chunk for loads, or nil (then loadSlow); small
// enough to inline into the accessors.
func (k *Cache) load(m *Memory, a uint64) *chunk {
	if a|chunkMask == k.rKey && k.gen == m.gen.Load() {
		return k.r
	}
	return nil
}

func (k *Cache) loadSlow(m *Memory, a uint64) *chunk {
	g := m.gen.Load()
	c := m.lookup(a)
	if c != nil {
		k.reset(g)
		k.rKey, k.r = a|chunkMask, c
	}
	return c
}

// store is load for stores (then storeSlow).
func (k *Cache) store(m *Memory, a uint64) *chunk {
	if a|chunkMask == k.wKey && k.gen == m.gen.Load() {
		return k.w
	}
	return nil
}

func (k *Cache) storeSlow(m *Memory, a uint64) *chunk {
	g := m.gen.Load()
	c := m.wlookup(a)
	if c != nil {
		k.reset(g)
		k.wKey, k.w = a|chunkMask, c
	}
	return c
}

// reset empties the cache unless it was filled under generation g.
func (k *Cache) reset(g uint64) {
	if k.gen != g {
		*k = Cache{gen: g}
	}
}

// genSeq hands out generations (Memory.newGen).
var genSeq atomic.Uint64

func (m *Memory) newGen() { m.gen.Store(genSeq.Add(1)) }

// The accessors below are Memory.R8 .. Memory.W64 with cached lookups.

func (k *Cache) R8(m *Memory, a uint64) uint8 {
	c := k.load(m, a)
	if c == nil {
		c = k.loadSlow(m, a)
	}
	if c != nil {
		return c[a&chunkMask]
	}
	return uint8(m.readSlow(a, 1))
}

func (k *Cache) R16(m *Memory, a uint64) uint16 {
	if a&chunkMask <= chunkMask-1 {
		c := k.load(m, a)
		if c == nil {
			c = k.loadSlow(m, a)
		}
		if c != nil {
			o := a & chunkMask
			return le.Uint16(c[o : o+2])
		}
	}
	return uint16(m.readSlow(a, 2))
}

func (k *Cache) R32(m *Memory, a uint64) uint32 {
	if a&chunkMask <= chunkMask-3 {
		c := k.load(m, a)
		if c == nil {
			c = k.loadSlow(m, a)
		}
		if c != nil {
			o := a & chunkMask
			return le.Uint32(c[o : o+4])
		}
	}
	return uint32(m.readSlow(a, 4))
}

func (k *Cache) R64(m *Memory, a uint64) uint64 {
	if a&chunkMask <= chunkMask-7 {
		c := k.load(m, a)
		if c == nil {
			c = k.loadSlow(m, a)
		}
		if c != nil {
			o := a & chunkMask
			return le.Uint64(c[o : o+8])
		}
	}
	return m.readSlow(a, 8)
}

func (k *Cache) W8(m *Memory, a uint64, v uint8) {
	c := k.store(m, a)
	if c == nil {
		c = k.storeSlow(m, a)
	}
	if c != nil {
		c[a&chunkMask] = v
		return
	}
	m.writeSlow(a, 1, uint64(v))
}

func (k *Cache) W16(m *Memory, a uint64, v uint16) {
	if a&chunkMask <= chunkMask-1 {
		c := k.store(m, a)
		if c == nil {
			c = k.storeSlow(m, a)
		}
		if c != nil {
			o := a & chunkMask
			le.PutUint16(c[o:o+2], v)
			return
		}
	}
	m.writeSlow(a, 2, uint64(v))
}

func (k *Cache) W32(m *Memory, a uint64, v uint32) {
	if a&chunkMask <= chunkMask-3 {
		c := k.store(m, a)
		if c == nil {
			c = k.storeSlow(m, a)
		}
		if c != nil {
			o := a & chunkMask
			le.PutUint32(c[o:o+4], v)
			return
		}
	}
	m.writeSlow(a, 4, uint64(v))
}

func (k *Cache) W64(m *Memory, a uint64, v uint64) {
	if a&chunkMask <= chunkMask-7 {
		c := k.store(m, a)
		if c == nil {
			c = k.storeSlow(m, a)
		}
		if c != nil {
			o := a & chunkMask
			le.PutUint64(c[o:o+8], v)
			return
		}
	}
	m.writeSlow(a, 8, v)
}
