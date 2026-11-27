// Package mem implements the guest's 64-bit virtual address space.
//
// Memory is organised in 64 KiB chunks (the Windows allocation granularity)
// addressed through a two-level table. Chunks are created lazily on first
// touch inside a reserved region, so large reservations cost nothing until
// they are used.
package mem

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"sync/atomic"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	ChunkBits = 16
	ChunkSize = 1 << ChunkBits
	chunkMask = ChunkSize - 1
	l2Bits    = 16
	l2Size    = 1 << l2Bits
	l1Size    = 1 << 15 // covers 47-bit user address space
	MaxAddr   = uint64(l1Size) << 32
)

type chunk = [ChunkSize]byte

// Protection flags (Windows PAGE_* values).
const (
	PageNoAccess         = 0x01
	PageReadOnly         = 0x02
	PageReadWrite        = 0x04
	PageWriteCopy        = 0x08
	PageExecute          = 0x10
	PageExecuteRead      = 0x20
	PageExecuteReadWrite = 0x40
)

// Region kinds (Windows MEM_* type values).
const (
	MemPrivate = 0x20000
	MemMapped  = 0x40000
	MemImage   = 0x1000000
)

// Region is one VirtualAlloc-style reservation.
type Region struct {
	Base, Size uint64
	Prot       uint32
	Kind       uint32
	Name       string

	Section    *Section // non-nil for a view of a shared section
	SectionOff uint64

	commit []uint16 // committed 4 KiB pages, one bit each, per chunk; nil: all committed (commit.go)
}

// Fault is raised (via panic) on an access to unmapped memory.
type Fault struct {
	Addr  uint64
	Write bool
}

func (f *Fault) Error() string {
	op := "read"
	if f.Write {
		op = "write"
	}
	return fmt.Sprintf("access violation: %s at 0x%x", op, f.Addr)
}

type Memory struct {
	l1      [l1Size]*[l2Size]*chunk
	regions []*Region              // sorted by Base
	last    atomic.Pointer[Region] // FindRegion's last hit (any goroutine may update it)
	hint    uint64

	// shared section chunks by chunk number (see section.go)
	shared map[uint64]*shEntry
	shLast atomic.Pointer[shEntry] // sharedChunk's last hit (any goroutine may update it)
	lk     lockState

	// store-path code tracking (codewatch.go)
	w1          [l1Size]*[l2Size]*chunk // l1 without chunks holding watched code pages
	watch       map[uint64]uint16       // chunk number -> watched 4 KiB pages
	noFastW     bool
	jrn         journal
	OnCodeWrite func(page uint64) // called when a store hits a watched page (then unwatched)
	CodeWritten bool              // set by such a store; cleared by the CPU
	Code        any               // per-address-space decoded-code cache (owned by package cpu)

	// gen changes (newGen) whenever a chunk leaves l1 or w1; a Cache filled
	// under another generation is discarded (cache.go).
	gen atomic.Uint64
}

func New() *Memory {
	m := &Memory{hint: 0x100000}
	m.newGen()
	return m
}

// ---------------------------------------------------------------------------
// region management

func (m *Memory) Regions() []*Region { return m.regions }

// FindRegion returns the region containing addr, or nil.
func (m *Memory) FindRegion(addr uint64) *Region {
	if r := m.last.Load(); r != nil && addr-r.Base < r.Size {
		return r
	}
	i := sort.Search(len(m.regions), func(i int) bool { return m.regions[i].Base+m.regions[i].Size > addr })
	if i < len(m.regions) && m.regions[i].Base <= addr {
		m.last.Store(m.regions[i])
		return m.regions[i]
	}
	return nil
}

func align(v, a uint64) uint64 { return (v + a - 1) &^ (a - 1) }

// IsFree reports whether [base, base+size) overlaps no region.
func (m *Memory) IsFree(base, size uint64) bool {
	if base == 0 || base+size > MaxAddr || base+size < base {
		return false
	}
	for _, r := range m.regions {
		if base < r.Base+r.Size && r.Base < base+size {
			return false
		}
	}
	return true
}

// Map reserves [base, base+size). base must be chunk aligned and free.
func (m *Memory) Map(base, size uint64, prot uint32, kind uint32, name string) (*Region, error) {
	size = align(size, ChunkSize)
	if base&chunkMask != 0 {
		return nil, fmt.Errorf("unaligned map at %#x", base)
	}
	if !m.IsFree(base, size) {
		return nil, fmt.Errorf("address range %#x+%#x in use", base, size)
	}
	r := &Region{Base: base, Size: size, Prot: prot, Kind: kind, Name: name}
	i := sort.Search(len(m.regions), func(i int) bool { return m.regions[i].Base > base })
	m.regions = append(m.regions, nil)
	copy(m.regions[i+1:], m.regions[i:])
	m.regions[i] = r
	return r, nil
}

// Alloc reserves size bytes anywhere (bottom-up search from a hint).
func (m *Memory) Alloc(size uint64, prot uint32, kind uint32, name string) (*Region, error) {
	return m.AllocFrom(m.hint, size, prot, kind, name)
}

func (m *Memory) AllocFrom(start, size uint64, prot uint32, kind uint32, name string) (*Region, error) {
	size = align(size, ChunkSize)
	addr := align(start, ChunkSize)
	for _, r := range m.regions {
		end := r.Base + r.Size
		if end <= addr {
			continue
		}
		if r.Base >= addr+size {
			break
		}
		addr = align(end, ChunkSize)
	}
	if addr+size > MaxAddr {
		if start != 0x10000 {
			return m.AllocFrom(0x10000, size, prot, kind, name)
		}
		return nil, fmt.Errorf("out of address space")
	}
	return m.Map(addr, size, prot, kind, name)
}

// Unmap releases the region starting exactly at base.
func (m *Memory) Unmap(base uint64) bool {
	for i, r := range m.regions {
		if r.Base == base {
			if r.Section != nil {
				m.unmapShared(r)
			} else {
				m.dropChunks(r.Base, r.Size)
			}
			m.regions = append(m.regions[:i], m.regions[i+1:]...)
			m.last.CompareAndSwap(r, nil)
			return true
		}
	}
	return false
}

func (m *Memory) dropChunks(base, size uint64) {
	m.noteWrite(base, size)
	for a := base; a < base+size; a += ChunkSize {
		if t := m.l1[a>>32]; t != nil {
			t[(a>>16)&(l2Size-1)] = nil
		}
		m.setW1(a, nil)
	}
	m.newGen()
}

// Zero clears a range (used for MEM_DECOMMIT).
func (m *Memory) Zero(base, size uint64) {
	m.noteWrite(base, size)
	for size > 0 {
		off := base & chunkMask
		n := uint64(ChunkSize) - off
		if n > size {
			n = size
		}
		if sc := m.sharedChunk(base); sc != nil {
			copyInShared(sc, off, make([]byte, n))
		} else if off == 0 && n == ChunkSize {
			if t := m.l1[base>>32]; t != nil {
				t[(base>>16)&(l2Size-1)] = nil
			}
			m.setW1(base, nil)
			m.newGen()
		} else if c := m.lookup(base); c != nil {
			clear(c[off : off+n])
		}
		base += n
		size -= n
	}
}

// ---------------------------------------------------------------------------
// chunk lookup

// lookup returns a's private chunk from l1, or nil. It writes nothing: any
// goroutine may call the Memory accessors (the CPU's cached ones are in
// cache.go).
func (m *Memory) lookup(a uint64) *chunk {
	hi := a >> 32
	if hi >= l1Size {
		return nil
	}
	t := m.l1[hi]
	if t == nil {
		return nil
	}
	return t[(a>>16)&(l2Size-1)]
}

// chunkFor returns the chunk for a, materialising it if a lies inside a
// reserved region. It panics with *Fault otherwise.
func (m *Memory) chunkFor(a uint64, write bool) *chunk {
	if c := m.lookup(a); c != nil {
		return c
	}
	if r := m.FindRegion(a); r == nil || !r.Committed(a) {
		panic(&Fault{Addr: a, Write: write})
	}
	hi := a >> 32
	t := m.l1[hi]
	if t == nil {
		t = new([l2Size]*chunk)
		m.l1[hi] = t
	}
	c := new(chunk)
	t[(a>>16)&(l2Size-1)] = c
	m.publishW1(a, c)
	return c
}

// Valid reports whether addr is mapped and committed.
func (m *Memory) Valid(a uint64) bool {
	r := m.FindRegion(a)
	return r != nil && r.Committed(a)
}

// CodeChunk is used by the CPU's instruction fetcher.
// Code in a shared chunk is fetched without atomics.
func (m *Memory) CodeChunk(a uint64) *[ChunkSize]byte {
	if c := m.lookup(a); c != nil {
		return c
	}
	if c := m.sharedChunk(a); c != nil {
		return c
	}
	return m.chunkFor(a, false)
}

// ---------------------------------------------------------------------------
// scalar access

var le = binary.LittleEndian

func (m *Memory) R8(a uint64) uint8 {
	c := m.lookup(a)
	if c == nil {
		return uint8(m.readSlow(a, 1))
	}
	return c[a&chunkMask]
}

func (m *Memory) W8(a uint64, v uint8) {
	c := m.wlookup(a)
	if c == nil {
		m.writeSlow(a, 1, uint64(v))
		return
	}
	c[a&chunkMask] = v
}

func (m *Memory) R16(a uint64) uint16 {
	if a&chunkMask <= chunkMask-1 {
		if c := m.lookup(a); c != nil {
			o := a & chunkMask
			return le.Uint16(c[o : o+2])
		}
	}
	return uint16(m.readSlow(a, 2))
}

func (m *Memory) R32(a uint64) uint32 {
	if a&chunkMask <= chunkMask-3 {
		if c := m.lookup(a); c != nil {
			o := a & chunkMask
			return le.Uint32(c[o : o+4])
		}
	}
	return uint32(m.readSlow(a, 4))
}

func (m *Memory) R64(a uint64) uint64 {
	if a&chunkMask <= chunkMask-7 {
		if c := m.lookup(a); c != nil {
			o := a & chunkMask
			return le.Uint64(c[o : o+8])
		}
	}
	return m.readSlow(a, 8)
}

func (m *Memory) W16(a uint64, v uint16) {
	if a&chunkMask <= chunkMask-1 {
		if c := m.wlookup(a); c != nil {
			o := a & chunkMask
			le.PutUint16(c[o:o+2], v)
			return
		}
	}
	m.writeSlow(a, 2, uint64(v))
}

func (m *Memory) W32(a uint64, v uint32) {
	if a&chunkMask <= chunkMask-3 {
		if c := m.wlookup(a); c != nil {
			o := a & chunkMask
			le.PutUint32(c[o:o+4], v)
			return
		}
	}
	m.writeSlow(a, 4, uint64(v))
}

func (m *Memory) W64(a uint64, v uint64) {
	if a&chunkMask <= chunkMask-7 {
		if c := m.wlookup(a); c != nil {
			o := a & chunkMask
			le.PutUint64(c[o:o+8], v)
			return
		}
	}
	m.writeSlow(a, 8, v)
}

// readSlow handles chunk misses: shared chunks, lazy materialisation, faults
// and accesses crossing a chunk boundary.
func (m *Memory) readSlow(a uint64, sz int) uint64 {
	if v, ok := m.sharedRead(a, sz); ok {
		return v
	}
	o := a & chunkMask
	if o+uint64(sz) <= ChunkSize {
		c := m.chunkFor(a, false)
		switch sz {
		case 1:
			return uint64(c[o])
		case 2:
			return uint64(le.Uint16(c[o:]))
		case 4:
			return uint64(le.Uint32(c[o:]))
		}
		return le.Uint64(c[o:])
	}
	var b [8]byte
	m.Read(a, b[:sz])
	return le.Uint64(b[:])
}

func (m *Memory) writeSlow(a uint64, sz int, v uint64) {
	if m.sharedWrite(a, sz, v) {
		return
	}
	o := a & chunkMask
	var b [8]byte
	le.PutUint64(b[:], v)
	if o+uint64(sz) <= ChunkSize {
		c := m.chunkFor(a, true)
		m.noteWrite(a, uint64(sz))
		if m.jrn.on {
			m.record(a, sz)
		}
		copy(c[o:], b[:sz])
		return
	}
	m.Write(a, b[:sz])
}

// ---------------------------------------------------------------------------
// bulk access

func (m *Memory) Read(a uint64, dst []byte) {
	for len(dst) > 0 {
		if sc := m.sharedChunk(a); sc != nil {
			n := copyOutShared(dst, sc, a&chunkMask)
			dst = dst[n:]
			a += uint64(n)
			continue
		}
		c := m.chunkFor(a, false)
		o := a & chunkMask
		n := copy(dst, c[o:])
		dst = dst[n:]
		a += uint64(n)
	}
}

func (m *Memory) Write(a uint64, src []byte) {
	for len(src) > 0 {
		if sc := m.sharedChunk(a); sc != nil {
			n := copyInShared(sc, a&chunkMask, src)
			src = src[n:]
			a += uint64(n)
			continue
		}
		c := m.chunkFor(a, true)
		o := a & chunkMask
		n := min(len(src), ChunkSize-int(o))
		m.noteWrite(a, uint64(n))
		if m.jrn.on {
			m.record(a, n)
		}
		copy(c[o:], src)
		src = src[n:]
		a += uint64(n)
	}
}

func (m *Memory) ReadBytes(a uint64, n int) []byte {
	b := make([]byte, n)
	m.Read(a, b)
	return b
}

// Fill writes n copies of v starting at a.
func (m *Memory) Fill(a uint64, v byte, n uint64) {
	for n > 0 {
		o := a & chunkMask
		k := uint64(ChunkSize) - o
		if k > n {
			k = n
		}
		if sc := m.sharedChunk(a); sc != nil {
			b := make([]byte, k)
			for i := range b {
				b[i] = v
			}
			copyInShared(sc, o, b)
			a += k
			n -= k
			continue
		}
		c := m.chunkFor(a, true)
		m.noteWrite(a, k)
		if m.jrn.on {
			m.record(a, int(k))
		}
		s := c[o : o+k]
		if v == 0 {
			clear(s)
		} else {
			for i := range s {
				s[i] = v
			}
		}
		a += k
		n -= k
	}
}

// Move copies n bytes from src to dst with memmove semantics.
func (m *Memory) Move(dst, src, n uint64) {
	if n == 0 || dst == src {
		return
	}
	if n <= 4096 {
		b := make([]byte, n)
		m.Read(src, b)
		m.Write(dst, b)
		return
	}
	buf := make([]byte, 65536)
	if dst < src || dst >= src+n {
		for off := uint64(0); off < n; {
			k := n - off
			if k > uint64(len(buf)) {
				k = uint64(len(buf))
			}
			m.Read(src+off, buf[:k])
			m.Write(dst+off, buf[:k])
			off += k
		}
	} else {
		for end := n; end > 0; {
			k := end
			if k > uint64(len(buf)) {
				k = uint64(len(buf))
			}
			m.Read(src+end-k, buf[:k])
			m.Write(dst+end-k, buf[:k])
			end -= k
		}
	}
}

// ---------------------------------------------------------------------------
// strings

// CStrBytes reads a NUL-terminated byte string.
func (m *Memory) CStrBytes(a uint64) []byte {
	var out []byte
	for {
		o := a & chunkMask
		var s []byte
		if sc := m.sharedChunk(a); sc != nil {
			s = make([]byte, ChunkSize-o)
			copyOutShared(s, sc, o)
		} else {
			s = m.chunkFor(a, false)[o:]
		}
		for i, b := range s {
			if b == 0 {
				return append(out, s[:i]...)
			}
		}
		out = append(out, s...)
		a += uint64(len(s))
		if len(out) > 1<<28 {
			return out
		}
	}
}

func (m *Memory) CStr(a uint64) string {
	if a == 0 {
		return ""
	}
	return string(m.CStrBytes(a))
}

// CStrN reads at most n bytes, stopping at NUL.
func (m *Memory) CStrN(a uint64, n int) []byte {
	out := make([]byte, 0, 16)
	for i := 0; i < n; i++ {
		b := m.R8(a + uint64(i))
		if b == 0 {
			break
		}
		out = append(out, b)
	}
	return out
}

// WStrUnits reads a NUL-terminated UTF-16 string as code units.
func (m *Memory) WStrUnits(a uint64) []uint16 {
	var out []uint16
	for {
		v := m.R16(a)
		if v == 0 {
			return out
		}
		out = append(out, v)
		a += 2
	}
}

func (m *Memory) WStr(a uint64) string {
	if a == 0 {
		return ""
	}
	return string(utf16.Decode(m.WStrUnits(a)))
}

func (m *Memory) WStrN(a uint64, n int) string {
	u := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		v := m.R16(a + uint64(2*i))
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}

// WriteCStr writes s plus a NUL terminator.
func (m *Memory) WriteCStr(a uint64, s string) {
	b := make([]byte, len(s)+1)
	copy(b, s)
	m.Write(a, b)
}

// WriteWStr writes s as UTF-16 plus a NUL terminator; returns units written (excl NUL).
func (m *Memory) WriteWStr(a uint64, s string) int {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u)+2)
	for i, v := range u {
		le.PutUint16(b[2*i:], v)
	}
	m.Write(a, b)
	return len(u)
}

func (m *Memory) WriteUnits(a uint64, u []uint16) {
	b := make([]byte, 2*len(u))
	for i, v := range u {
		le.PutUint16(b[2*i:], v)
	}
	m.Write(a, b)
}

// UTF16Len returns the UTF-16 length of s.
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// ValidUTF8 is re-exported for convenience.
func ValidUTF8(b []byte) bool { return utf8.Valid(b) }

// R64Float reads a little-endian double.
func (m *Memory) R64Float(a uint64) float64 { return math.Float64frombits(m.R64(a)) }
