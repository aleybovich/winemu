package mem

// Shared memory: sections whose chunks can be mapped into several address
// spaces (guest processes running on different goroutines).
//
// Shared chunks are never entered into the private chunk table (Memory.l1),
// so every access to them misses the fast path and lands in the slow paths
// below, which use host atomics. Accesses to private memory are unaffected.
// See docs/multiprocess.md.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Section is shareable backing store, materialised lazily chunk by chunk.
type Section struct {
	size   uint64
	chunks []atomic.Pointer[chunk]
}

// NewSection creates a zero-filled section of size bytes (rounded up to the
// chunk size).
func NewSection(size uint64) *Section {
	size = align(size, ChunkSize)
	return &Section{size: size, chunks: make([]atomic.Pointer[chunk], size/ChunkSize)}
}

// Size returns the section size in bytes.
func (s *Section) Size() uint64 { return s.size }

// busLock serialises the operations that cannot be a single host atomic
// (accesses straddling an 8-byte boundary, 16-byte compare-exchange). It is
// atomic against other locked operations, not against plain stores.
var busLock sync.Mutex

// lockState tracks one LOCK-prefixed instruction (see BeginLocked).
type lockState struct {
	active, have, failed bool
	addr                 uint64
	size                 int
	old                  uint64
}

// MapSection maps [off, off+size) of s at base. base and off must be chunk
// aligned and the range must lie inside the section.
func (m *Memory) MapSection(base uint64, s *Section, off, size uint64, prot, kind uint32, name string) (*Region, error) {
	size = align(size, ChunkSize)
	if off&chunkMask != 0 {
		return nil, fmt.Errorf("unaligned section offset %#x", off)
	}
	if off > s.size || size > s.size-off || size == 0 {
		return nil, fmt.Errorf("view %#x+%#x outside section of %#x bytes", off, size, s.size)
	}
	r, err := m.Map(base, size, prot, kind, name)
	if err != nil {
		return nil, err
	}
	r.Section, r.SectionOff = s, off
	if m.shared == nil {
		m.shared = map[uint64]*shEntry{}
	}
	first := off / ChunkSize
	for i := uint64(0); i < size/ChunkSize; i++ {
		ci := base>>ChunkBits + i
		m.shared[ci] = &shEntry{ci: ci, p: &s.chunks[first+i]}
	}
	return r, nil
}

func (m *Memory) unmapShared(r *Region) {
	for a := r.Base; a < r.Base+r.Size; a += ChunkSize {
		delete(m.shared, a>>ChunkBits)
	}
	m.shLast.Store(nil)
}

// shEntry is a mapped shared chunk: its chunk number in this address space
// and its slot in the section.
type shEntry struct {
	ci uint64
	p  *atomic.Pointer[chunk]
}

// HasShared reports whether any shared section is mapped.
func (m *Memory) HasShared() bool { return len(m.shared) != 0 }

// Shared reports whether a lies in a mapped shared section.
func (m *Memory) Shared(a uint64) bool { return m.sharedChunk(a) != nil }

func (m *Memory) sharedChunk(a uint64) *chunk {
	if m.shared == nil {
		return nil
	}
	ci := a >> ChunkBits
	e := m.shLast.Load()
	if e == nil || e.ci != ci {
		e = m.shared[ci]
		if e == nil {
			return nil
		}
		m.shLast.Store(e)
	}
	p := e.p
	if m.jrn.on {
		m.jrn.shared = true
		if m.jrn.abort {
			panic(SharedAccess{})
		}
	}
	if c := p.Load(); c != nil {
		return c
	}
	n := new(chunk)
	if p.CompareAndSwap(nil, n) {
		return n
	}
	return p.Load()
}

// ---------------------------------------------------------------------------
// atomic primitives on one chunk (o + sz <= ChunkSize)

func p32(c *chunk, o uint64) *uint32 { return (*uint32)(unsafe.Pointer(&c[o])) }
func p64(c *chunk, o uint64) *uint64 { return (*uint64)(unsafe.Pointer(&c[o])) }

func sizeMask(sz int) uint64 { return ^uint64(0) >> (64 - 8*uint(sz)) }

func atomicLoad(c *chunk, o uint64, sz int) uint64 {
	switch {
	case o&3+uint64(sz) <= 4:
		return uint64(atomic.LoadUint32(p32(c, o&^3))>>(8*(o&3))) & sizeMask(sz)
	case o&7+uint64(sz) <= 8:
		return atomic.LoadUint64(p64(c, o&^7)) >> (8 * (o & 7)) & sizeMask(sz)
	}
	var v uint64
	for i := 0; i < sz; i++ {
		v |= atomicLoad(c, o+uint64(i), 1) << (8 * i)
	}
	return v
}

// atomicCAS replaces the sz-byte value at o with nv if it equals old.
func atomicCAS(c *chunk, o uint64, sz int, old, nv uint64) bool {
	mask := sizeMask(sz)
	old, nv = old&mask, nv&mask
	switch {
	case o&3+uint64(sz) <= 4:
		p, sh := p32(c, o&^3), 8*(o&3)
		for {
			w := atomic.LoadUint32(p)
			if uint64(w>>sh)&mask != old {
				return false
			}
			if atomic.CompareAndSwapUint32(p, w, w&^uint32(mask<<sh)|uint32(nv<<sh)) {
				return true
			}
		}
	case o&7+uint64(sz) <= 8:
		p, sh := p64(c, o&^7), 8*(o&7)
		for {
			w := atomic.LoadUint64(p)
			if w>>sh&mask != old {
				return false
			}
			if atomic.CompareAndSwapUint64(p, w, w&^(mask<<sh)|nv<<sh) {
				return true
			}
		}
	}
	busLock.Lock()
	defer busLock.Unlock()
	if atomicLoad(c, o, sz) != old {
		return false
	}
	atomicStore(c, o, sz, nv)
	return true
}

func atomicStore(c *chunk, o uint64, sz int, v uint64) {
	switch {
	case sz == 4 && o&3 == 0:
		atomic.StoreUint32(p32(c, o), uint32(v))
	case sz == 8 && o&7 == 0:
		atomic.StoreUint64(p64(c, o), v)
	case o&3+uint64(sz) <= 4 || o&7+uint64(sz) <= 8:
		for !atomicCAS(c, o, sz, atomicLoad(c, o, sz), v) {
		}
	default:
		for i := 0; i < sz; i++ {
			atomicStore(c, o+uint64(i), 1, v>>(8*i))
		}
	}
}

func copyOutShared(dst []byte, c *chunk, o uint64) int {
	n := min(uint64(len(dst)), ChunkSize-o)
	i := uint64(0)
	for ; i < n && (o+i)&7 != 0; i++ {
		dst[i] = byte(atomicLoad(c, o+i, 1))
	}
	for ; i+8 <= n; i += 8 {
		le.PutUint64(dst[i:], atomic.LoadUint64(p64(c, o+i)))
	}
	for ; i < n; i++ {
		dst[i] = byte(atomicLoad(c, o+i, 1))
	}
	return int(n)
}

func copyInShared(c *chunk, o uint64, src []byte) int {
	n := min(uint64(len(src)), ChunkSize-o)
	i := uint64(0)
	for ; i < n && (o+i)&7 != 0; i++ {
		atomicStore(c, o+i, 1, uint64(src[i]))
	}
	for ; i+8 <= n; i += 8 {
		atomic.StoreUint64(p64(c, o+i), le.Uint64(src[i:]))
	}
	for ; i < n; i++ {
		atomicStore(c, o+i, 1, uint64(src[i]))
	}
	return int(n)
}

// ---------------------------------------------------------------------------
// Memory-level slow paths for shared chunks

// sharedRead reads sz bytes at a if a lies in a shared chunk.
func (m *Memory) sharedRead(a uint64, sz int) (uint64, bool) {
	c := m.sharedChunk(a)
	if c == nil {
		return 0, false
	}
	o := a & chunkMask
	var v uint64
	if o+uint64(sz) <= ChunkSize {
		v = atomicLoad(c, o, sz)
	} else {
		for i := 0; i < sz; i++ {
			v |= uint64(m.R8(a+uint64(i))) << (8 * i)
		}
	}
	if m.lk.active && !m.lk.have {
		m.lk.have, m.lk.addr, m.lk.size, m.lk.old = true, a, sz, v
	}
	return v, true
}

// sharedWrite writes sz bytes at a if a lies in a shared chunk. Inside a
// locked instruction the write to the location read first becomes a CAS
// against the value read; on failure nothing more is written.
func (m *Memory) sharedWrite(a uint64, sz int, v uint64) bool {
	c := m.sharedChunk(a)
	if c == nil {
		return false
	}
	if m.lk.active {
		if m.lk.failed {
			return true
		}
		if m.lk.have && m.lk.addr == a && m.lk.size == sz {
			m.lk.have = false
			if !m.AtomicCAS(a, sz, m.lk.old, v) {
				m.lk.failed = true
			}
			return true
		}
	}
	o := a & chunkMask
	if o+uint64(sz) <= ChunkSize {
		atomicStore(c, o, sz, v)
		return true
	}
	for i := 0; i < sz; i++ {
		m.W8(a+uint64(i), uint8(v>>(8*i)))
	}
	return true
}

// BeginLocked starts a LOCK-prefixed read-modify-write instruction: the first
// shared read is remembered and the matching write is performed as a CAS.
func (m *Memory) BeginLocked() { m.lk = lockState{active: true} }

// EndLocked ends the locked instruction and reports whether its CAS failed
// (the instruction must then be rolled back and re-executed).
func (m *Memory) EndLocked() (failed bool) {
	failed = m.lk.failed
	m.lk = lockState{}
	return failed
}

// AtomicLoad reads sz (1, 2, 4, 8) bytes at a; atomic if a is shared.
func (m *Memory) AtomicLoad(a uint64, sz int) uint64 {
	if c := m.sharedChunk(a); c != nil && a&chunkMask+uint64(sz) <= ChunkSize {
		return atomicLoad(c, a&chunkMask, sz)
	}
	return m.readN(a, sz)
}

// AtomicCAS stores nv at a if the sz-byte value there equals old.
func (m *Memory) AtomicCAS(a uint64, sz int, old, nv uint64) bool {
	if c := m.sharedChunk(a); c != nil && a&chunkMask+uint64(sz) <= ChunkSize {
		return atomicCAS(c, a&chunkMask, sz, old, nv)
	}
	shared := m.Shared(a) || m.Shared(a+uint64(sz)-1)
	if shared {
		busLock.Lock()
		defer busLock.Unlock()
	}
	if m.readN(a, sz) != old&sizeMask(sz) {
		return false
	}
	m.writeN(a, sz, nv)
	return true
}

// CAS128 is CMPXCHG16B on shared memory (serialised on the bus lock). It
// returns the value found and whether the exchange happened.
func (m *Memory) CAS128(a, oldLo, oldHi, newLo, newHi uint64) (lo, hi uint64, ok bool) {
	busLock.Lock()
	defer busLock.Unlock()
	lo, hi = m.AtomicLoad(a, 8), m.AtomicLoad(a+8, 8)
	if lo != oldLo || hi != oldHi {
		return lo, hi, false
	}
	m.W64(a, newLo)
	m.W64(a+8, newHi)
	return lo, hi, true
}

func (m *Memory) readN(a uint64, sz int) uint64 {
	switch sz {
	case 1:
		return uint64(m.R8(a))
	case 2:
		return uint64(m.R16(a))
	case 4:
		return uint64(m.R32(a))
	}
	return m.R64(a)
}

func (m *Memory) writeN(a uint64, sz int, v uint64) {
	switch sz {
	case 1:
		m.W8(a, uint8(v))
	case 2:
		m.W16(a, uint16(v))
	case 4:
		m.W32(a, uint32(v))
	default:
		m.W64(a, v)
	}
}
