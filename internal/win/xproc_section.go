package win

// File mappings (sections) and views, shareable between processes.
//
// A pagefile-backed or writable file-backed mapping owns a mem.Section;
// every view of it, in any process, maps the same chunks, so views are
// coherent (docs/multiprocess.md, "Shared memory and atomics"). File content
// is loaded into the section chunk by chunk when a view first covers it and
// written back by FlushViewOfFile / UnmapViewOfFile / process exit. Read-only
// and copy-on-write file mappings have no section: their views are private
// copies (nothing to keep coherent, and private memory stays on the fast
// path). The mapping object is refcounted by handles and views; the name
// leaves the namespace and the file is released with the last reference.

import (
	"strings"
	"sync"

	"winemu/internal/mem"
)

const (
	errFileInvalid     = 1006
	errMappedAlignment = 1132
	errInvalidAddress  = 487

	fileMapCopy    = 0x1
	fileMapWrite   = 0x2
	fileMapExecute = 0x20
)

type mappingObj struct {
	kname
	name string
	size uint64
	prot uint32       // page protection (low byte of flProtect)
	file *fileObj     // nil: pagefile-backed
	sec  *mem.Section // nil: views are private copies of the file

	mu     sync.Mutex // guards loaded
	loaded []bool     // file-backed section: chunk read from the file
}

func (o *mappingObj) unref() {
	k := o.k
	if k == nil {
		return
	}
	k.mu.Lock()
	o.refs--
	last := o.refs == 0
	if last && o.key != "" {
		delete(k.names, o.key)
		o.key = ""
	}
	k.mu.Unlock()
	if last && o.file != nil {
		o.file.unref()
	}
}

func protWritable(p uint32) bool { return p == mem.PageReadWrite || p == mem.PageExecuteReadWrite }
func protExec(p uint32) bool     { return p >= mem.PageExecute }

type mapView struct {
	addr, size uint64
	mo         *mappingObj
	off        uint64
	writable   bool // writes go back to the file
}

// objName is the namespace key part of an object name: "Local\" names the
// session namespace, which is the default.
func objName(name string) string { return strings.TrimPrefix(name, `Local\`) }

func (e *Emu) createFileMapping(hf, sa uint64, flProt uint32, size uint64, name string) uint64 {
	prot := flProt & 0xFF
	switch prot {
	case mem.PageReadOnly, mem.PageReadWrite, mem.PageWriteCopy, mem.PageExecuteRead, mem.PageExecuteReadWrite, 0x80:
	default:
		return e.fail(errInvalidParameter)
	}
	key := ""
	if name != "" {
		key = "mapping:" + objName(name)
		if o := e.openNamed(key); o != nil {
			e.SetLastError(errAlreadyExists)
			return e.handleFor(o, e.saInherit(sa))
		}
	}
	mo := &mappingObj{name: name, size: size, prot: prot}
	if hf != invalidHandle && hf != 0 {
		fo := e.fileObj(hf)
		if fo == nil || fo.f == nil {
			return e.fail(errInvalidHandle)
		}
		st, err := fo.f.Stat()
		if err != nil {
			return e.fail(errInvalidHandle)
		}
		if size == 0 {
			size = uint64(st.Size())
		} else if size > uint64(st.Size()) && protWritable(prot) {
			if err := fo.f.Truncate(int64(size)); err != nil {
				return e.fail(errAccessDenied)
			}
		}
		if size == 0 {
			return e.fail(errFileInvalid)
		}
		mo.size, mo.file = size, fo
		fo.ref()
		if protWritable(prot) {
			mo.sec = mem.NewSection(size)
			mo.loaded = make([]bool, mo.sec.Size()/mem.ChunkSize)
		}
	} else {
		if size == 0 {
			return e.fail(errInvalidParameter)
		}
		mo.sec = mem.NewSection(size)
	}
	o, existed := e.createNamed(key, mo)
	if existed { // created by another process meanwhile
		if mo.file != nil {
			mo.file.unref()
		}
		e.SetLastError(errAlreadyExists)
	} else {
		e.SetLastError(0)
	}
	return e.handleFor(o, e.saInherit(sa))
}

func (e *Emu) mapViewOfFile(hm uint64, access uint32, off, size, base uint64) uint64 {
	mo, ok := e.handles.get(hm).(*mappingObj)
	if !ok {
		return e.fail(errInvalidHandle)
	}
	if off%mem.ChunkSize != 0 || base%mem.ChunkSize != 0 {
		return e.fail(errMappedAlignment)
	}
	write := access&fileMapWrite != 0
	if write && !protWritable(mo.prot) || access&fileMapExecute != 0 && !protExec(mo.prot) {
		return e.fail(errAccessDenied)
	}
	if off >= mo.size {
		return e.fail(errInvalidParameter)
	}
	if size == 0 {
		size = mo.size - off
	} else if size > mo.size-off {
		return e.fail(errAccessDenied)
	}
	prot := uint32(mem.PageReadOnly)
	if write || access&fileMapCopy != 0 {
		prot = mem.PageReadWrite
	}
	if access&fileMapExecute != 0 {
		prot <<= 4 // PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE
	}
	asz := (size + mem.ChunkSize - 1) &^ (mem.ChunkSize - 1)
	if base == 0 {
		r, err := e.Mem.Alloc(asz, prot, mem.MemMapped, "view")
		if err != nil {
			return e.fail(errNotEnoughMemory)
		}
		base = r.Base
		e.Mem.Unmap(base)
	} else if !e.Mem.IsFree(base, asz) {
		return e.fail(errInvalidAddress)
	}
	v := &mapView{addr: base, size: size, mo: mo, off: off}
	if mo.sec != nil {
		if _, err := e.Mem.MapSection(base, mo.sec, off, asz, prot, mem.MemMapped, "view"); err != nil {
			return e.fail(errNotEnoughMemory)
		}
		v.writable = mo.file != nil
		e.loadSection(mo, base, off, asz)
		if e.Cur != nil {
			e.yield() // the next slice runs with the shared-memory step loop
		}
	} else {
		if _, err := e.Mem.Map(base, asz, prot, mem.MemMapped, "view"); err != nil {
			return e.fail(errNotEnoughMemory)
		}
		buf := make([]byte, size)
		n, _ := mo.file.f.ReadAt(buf, int64(off)) // short read past EOF: zeros
		e.Mem.Write(base, buf[:n])
	}
	mo.ref()
	e.views[base] = v
	return base
}

// loadSection fills the not yet loaded chunks of a file-backed section
// covered by the view [off, off+n) at base.
func (e *Emu) loadSection(mo *mappingObj, base, off, n uint64) {
	if mo.file == nil {
		return
	}
	mo.mu.Lock()
	defer mo.mu.Unlock()
	buf := make([]byte, mem.ChunkSize)
	for c := off / mem.ChunkSize; c < (off+n)/mem.ChunkSize; c++ {
		if mo.loaded[c] {
			continue
		}
		mo.loaded[c] = true
		k, _ := mo.file.f.ReadAt(buf, int64(c*mem.ChunkSize)) // short read past EOF: zeros
		e.Mem.Write(base+c*mem.ChunkSize-off, buf[:k])
	}
}

// viewAt returns the view containing addr.
func (e *Emu) viewAt(addr uint64) *mapView {
	for _, v := range e.views {
		if addr >= v.addr && addr < v.addr+v.size {
			return v
		}
	}
	return nil
}

// flushView writes [addr, addr+n) of a view back to its file.
func (e *Emu) flushView(v *mapView, addr, n uint64) {
	if !v.writable {
		return
	}
	end := min(addr+n, v.addr+v.size)
	if fileEnd := v.addr + v.mo.size - v.off; end > fileEnd {
		end = fileEnd
	}
	if end <= addr {
		return
	}
	buf := e.Mem.ReadBytes(addr, int(end-addr))
	v.mo.file.f.WriteAt(buf, int64(v.off+addr-v.addr))
}

func (e *Emu) unmapView(v *mapView) {
	e.flushView(v, v.addr, v.size)
	delete(e.views, v.addr)
	e.Mem.Unmap(v.addr)
	for _, t := range e.threads {
		t.CPU.InvalidateCode()
	}
	v.mo.unref()
}

// unmapAllViews is the view part of process exit.
func (e *Emu) unmapAllViews() {
	for _, v := range e.views {
		e.unmapView(v)
	}
}

func init() {
	k := dK32
	regAW(k, "CreateFileMapping", func(e *Emu, w bool) uint64 {
		return e.createFileMapping(e.Arg(0), e.Arg(1), e.Arg32(2), uint64(e.Arg32(3))<<32|uint64(e.Arg32(4)), e.strArg(5, w))
	})
	regAW(k, "CreateFileMappingNuma", func(e *Emu, w bool) uint64 {
		return e.createFileMapping(e.Arg(0), e.Arg(1), e.Arg32(2), uint64(e.Arg32(3))<<32|uint64(e.Arg32(4)), e.strArg(5, w))
	})
	regAW(k, "OpenFileMapping", func(e *Emu, w bool) uint64 {
		name := e.strArg(2, w)
		if name == "" {
			return e.fail(errInvalidParameter)
		}
		o := e.openNamed("mapping:" + objName(name))
		if o == nil {
			return e.fail(errFileNotFound)
		}
		return e.handleFor(o, e.Arg32(1) != 0)
	})
	off := func(e *Emu) uint64 { return uint64(e.Arg32(2))<<32 | uint64(e.Arg32(3)) }
	reg(k, "MapViewOfFile", func(e *Emu) uint64 {
		return e.mapViewOfFile(e.Arg(0), e.Arg32(1), off(e), e.Arg(4), 0)
	})
	reg(k, "MapViewOfFileEx", func(e *Emu) uint64 {
		return e.mapViewOfFile(e.Arg(0), e.Arg32(1), off(e), e.Arg(4), e.Arg(5))
	})
	reg(k, "MapViewOfFileExNuma", func(e *Emu) uint64 {
		return e.mapViewOfFile(e.Arg(0), e.Arg32(1), off(e), e.Arg(4), e.Arg(5))
	})
	unmap := func(e *Emu) uint64 {
		v := e.viewAt(e.Arg(0))
		if v == nil {
			return e.fail(errInvalidAddress)
		}
		e.unmapView(v)
		return 1
	}
	reg(k, "UnmapViewOfFile", unmap)
	reg(k, "UnmapViewOfFileEx", unmap)
	reg(k, "FlushViewOfFile", func(e *Emu) uint64 {
		a, n := e.Arg(0), e.Arg(1)
		v := e.viewAt(a)
		if v == nil {
			return e.fail(errInvalidAddress)
		}
		if n == 0 {
			n = v.addr + v.size - a
		}
		e.flushView(v, a, n)
		return 1
	})
}
