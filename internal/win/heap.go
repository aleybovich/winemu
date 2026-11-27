package win

import (
	"winemu/internal/mem"
)

type heapBlock struct {
	size uint64 // requested size
	cap  uint64 // rounded capacity
	heap uint64
	big  bool
}

// Heap is a simple size-class allocator backing HeapAlloc and malloc.
type Heap struct {
	e           *Emu
	processHeap uint64
	cur, end    uint64
	blocks      map[uint64]*heapBlock
	free        map[uint64][]uint64
	heaps       map[uint64]bool
}

const bigBlock = 256 << 10

func newHeap(e *Emu) *Heap {
	h := &Heap{e: e, blocks: map[uint64]*heapBlock{}, free: map[uint64][]uint64{}, heaps: map[uint64]bool{}}
	r, err := e.Mem.Alloc(0x10000, mem.PageReadWrite, mem.MemPrivate, "heap-handle")
	if err != nil {
		panic(err)
	}
	h.processHeap = r.Base
	h.heaps[r.Base] = true
	return h
}

func roundCap(n uint64) uint64 {
	if n < 16 {
		return 16
	}
	if n <= 1024 {
		return (n + 15) &^ 15
	}
	// geometric classes above 1K reduce fragmentation of free lists
	c := uint64(1024)
	for c < n {
		c += c / 4
		c = (c + 15) &^ 15
	}
	return c
}

func (h *Heap) alloc(heap, size uint64, zero bool) uint64 {
	if size > 1<<40 {
		return 0
	}
	cp := roundCap(size)
	if cp >= bigBlock {
		r, err := h.e.Mem.Alloc(cp, mem.PageReadWrite, mem.MemPrivate, "heap-big")
		if err != nil {
			return 0
		}
		h.blocks[r.Base] = &heapBlock{size: size, cap: r.Size, heap: heap, big: true}
		return r.Base
	}
	if l := h.free[cp]; len(l) > 0 {
		a := l[len(l)-1]
		h.free[cp] = l[:len(l)-1]
		h.blocks[a] = &heapBlock{size: size, cap: cp, heap: heap}
		if zero {
			h.e.Mem.Fill(a, 0, cp)
		}
		return a
	}
	if h.cur+cp > h.end {
		sz := uint64(4 << 20)
		r, err := h.e.Mem.Alloc(sz, mem.PageReadWrite, mem.MemPrivate, "heap")
		if err != nil {
			return 0
		}
		h.cur, h.end = r.Base, r.Base+r.Size
	}
	a := h.cur
	h.cur += cp
	h.blocks[a] = &heapBlock{size: size, cap: cp, heap: heap}
	return a // fresh memory is already zero
}

func (h *Heap) freeBlock(a uint64) bool {
	b := h.blocks[a]
	if b == nil {
		return false
	}
	delete(h.blocks, a)
	if b.big {
		h.e.Mem.Unmap(a)
		for _, t := range h.e.threads {
			t.CPU.InvalidateCode()
		}
		return true
	}
	h.free[b.cap] = append(h.free[b.cap], a)
	return true
}

func (h *Heap) size(a uint64) (uint64, bool) {
	b := h.blocks[a]
	if b == nil {
		return 0, false
	}
	return b.size, true
}

func (h *Heap) realloc(heap, a, size uint64, zero bool) uint64 {
	if a == 0 {
		return h.alloc(heap, size, zero)
	}
	b := h.blocks[a]
	if b == nil {
		return 0
	}
	if size <= b.cap && !b.big && size > b.cap/2 {
		old := b.size
		b.size = size
		if zero && size > old {
			h.e.Mem.Fill(a+old, 0, size-old)
		}
		return a
	}
	n := h.alloc(heap, size, zero)
	if n == 0 {
		return 0
	}
	cp := b.size
	if size < cp {
		cp = size
	}
	h.e.Mem.Move(n, a, cp)
	h.freeBlock(a)
	return n
}

func (h *Heap) destroy(heap uint64) {
	for a, b := range h.blocks {
		if b.heap == heap {
			h.freeBlock(a)
		}
	}
	delete(h.heaps, heap)
}

// convenience wrappers on Emu

func (e *Emu) heapAlloc(size uint64, zero bool) uint64 {
	return e.heap.alloc(e.heap.processHeap, size, zero)
}

func (e *Emu) heapAllocRaw(size uint64) uint64 { return e.heapAlloc(size, true) }

func (e *Emu) heapSize(a uint64) uint64 {
	s, _ := e.heap.size(a)
	return s
}

// allocCStr copies s into a new heap block.
func (e *Emu) allocCStr(s string) uint64 {
	a := e.heapAlloc(uint64(len(s)+1), false)
	e.Mem.WriteCStr(a, s)
	return a
}

func (e *Emu) allocWStr(s string) uint64 {
	a := e.heapAlloc(uint64(2*mem.UTF16Len(s)+2), false)
	e.Mem.WriteWStr(a, s)
	return a
}
