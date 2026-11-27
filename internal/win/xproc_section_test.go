package win

import (
	"os"
	"path/filepath"
	"testing"
)

func TestXprocNamedSection(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	m1 := h.call(dK32, "CreateFileMappingW", invalidHandle, 0, pageRW, 0, 0x20000, h.wstr(`Local\xp-sec`))
	if m1 == 0 || h.lastError() != 0 {
		t.Fatalf("create: err %d", h.lastError())
	}
	m2 := h.call(dK32, "CreateFileMappingW", invalidHandle, 0, pageRW, 0, 0x1000, h.wstr("xp-sec"))
	if m2 == 0 || h.lastError() != errAlreadyExists ||
		h.E.handles.get(m2) != h.E.handles.get(m1) {
		t.Fatalf("existing: err %d", h.lastError())
	}
	if g := h.call(dK32, "CreateFileMappingW", invalidHandle, 0, pageRW, 0, 0x1000, h.wstr(`Global\xp-sec`)); g == 0 || h.lastError() != 0 {
		t.Fatalf("Global\\ is another namespace: err %d", h.lastError())
	}
	if h.call(dK32, "CreateFileMappingW", invalidHandle, 0, pageRW, 0, 0, 0) != 0 || h.lastError() != errInvalidParameter {
		t.Fatal("pagefile mapping of size 0")
	}
	if h.call(dK32, "CreateFileMappingW", invalidHandle, 0, 0x99, 0, 0x1000, 0) != 0 || h.lastError() != errInvalidParameter {
		t.Fatal("bad protection")
	}
	const base = 0x41000000
	if r := h.call(dK32, "MapViewOfFileEx", m1, 0xF001F, 0, 0, 0, base); r != base {
		t.Fatalf("MapViewOfFileEx = %#x err %d", r, h.lastError())
	}
	if h.call(dK32, "MapViewOfFileEx", m1, 0xF001F, 0, 0, 0, base) != 0 || h.lastError() != errInvalidAddress {
		t.Fatalf("occupied base: err %d", h.lastError())
	}
	if h.call(dK32, "MapViewOfFileEx", m1, 0xF001F, 0, 0, 0, base+0x1000) != 0 || h.lastError() != errMappedAlignment {
		t.Fatalf("unaligned base: err %d", h.lastError())
	}
	if h.call(dK32, "MapViewOfFile", m1, 2, 0, 0, 0x30000) != 0 || h.lastError() != errAccessDenied {
		t.Fatalf("view past the end: err %d", h.lastError())
	}
	info := h.alloc(48)
	if h.call(dK32, "VirtualQuery", base+0x10, info, 48) != 48 || h.r32(info+40) != 0x40000 || h.r64(info+8) != base {
		t.Fatalf("VirtualQuery type %#x base %#x", h.r32(info+40), h.r64(info+8))
	}
	// the other process opens it by name and maps it at the same address
	bm := b.call(dK32, "OpenFileMappingW", 0xF001F, 0, b.wstr("xp-sec"))
	if bm == 0 || b.call(dK32, "MapViewOfFileEx", bm, 0xF001F, 0, 0, 0x10000, base) != base {
		t.Fatalf("child open/map: err %d", b.lastError())
	}
	b.w32(base+0x100, 0xC0FFEE)
	h.w32(base+0x104, 0xBEEF)
	if h.r32(base+0x100) != 0xC0FFEE || b.r32(base+0x104) != 0xBEEF {
		t.Fatal("views not coherent")
	}
	if b.call(dK32, "OpenFileMappingW", 4, 0, b.wstr("xp-none")) != 0 || b.lastError() != errFileNotFound {
		t.Fatal("open missing")
	}
	// lifetime: the views keep the section (and its name) alive
	for _, hm := range []uint64{m1, m2} {
		h.call(dK32, "CloseHandle", hm)
	}
	b.call(dK32, "CloseHandle", bm)
	if o := h.call(dK32, "OpenFileMappingW", 4, 0, h.wstr("xp-sec")); o == 0 {
		t.Fatal("name gone while views exist")
	} else {
		h.call(dK32, "CloseHandle", o)
	}
	if h.call(dK32, "UnmapViewOfFile", base+0x20) != 1 || b.call(dK32, "UnmapViewOfFile", base) != 1 {
		t.Fatal("unmap")
	}
	if h.call(dK32, "UnmapViewOfFile", base) != 0 || h.lastError() != errInvalidAddress {
		t.Fatal("unmap twice")
	}
	if h.call(dK32, "OpenFileMappingW", 4, 0, h.wstr("xp-sec")) != 0 {
		t.Fatal("name survives the last reference")
	}
}

func TestXprocFileMapping(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	host := filepath.Join(h.dir, "prefix", "drive_c", "map.bin")
	if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := h.call(dK32, "CreateFileW", h.wstr(`C:\map.bin`), 0xC0000000, 3, 0, 3, 0, 0)
	if f == invalidHandle {
		t.Fatalf("CreateFileW err %d", h.lastError())
	}
	ro := h.call(dK32, "CreateFileMappingW", f, 0, 2, 0, 0, 0)
	if h.call(dK32, "MapViewOfFile", ro, 2, 0, 0, 0) != 0 || h.lastError() != errAccessDenied {
		t.Fatal("write view of a read-only mapping")
	}
	v := h.call(dK32, "MapViewOfFile", ro, 4, 0, 0, 0)
	if v == 0 || string(h.read(v, 10)) != "0123456789" {
		t.Fatalf("read-only view %q", h.read(v, 10))
	}
	rw := h.call(dK32, "CreateFileMappingW", f, 0, pageRW, 0, 0, 0)
	hb := procHandle(h, b)
	out := h.alloc(8)
	h.call(dK32, "DuplicateHandle", pseudoProcess, rw, hb, out, 0, 0, 2)
	w := h.call(dK32, "MapViewOfFile", rw, 6, 0, 0, 0)
	bw := b.call(dK32, "MapViewOfFile", h.r64(out), 6, 0, 0, 0)
	if w == 0 || bw == 0 || string(b.read(bw, 10)) != "0123456789" {
		t.Fatalf("rw views %#x %#x", w, bw)
	}
	b.write(bw+2, []byte("AB"))
	if string(h.read(w, 4)) != "01AB" {
		t.Fatalf("file views not coherent: %q", h.read(w, 4))
	}
	if b.call(dK32, "FlushViewOfFile", bw, 0) != 1 {
		t.Fatal("flush")
	}
	if got, _ := os.ReadFile(host); string(got) != "01AB456789" {
		t.Fatalf("file after flush %q", got)
	}
	h.write(w+9, []byte("Z"))
	h.call(dK32, "UnmapViewOfFile", w)
	if got, _ := os.ReadFile(host); string(got) != "01AB45678Z" {
		t.Fatalf("file after unmap %q", got)
	}
	if h.call(dK32, "FlushViewOfFile", 0x10, 0) != 0 || h.lastError() != errInvalidAddress {
		t.Fatal("flush of a non-view")
	}
	empty := filepath.Join(filepath.Dir(host), "empty.bin")
	os.WriteFile(empty, nil, 0o644)
	ef := h.call(dK32, "CreateFileW", h.wstr(`C:\empty.bin`), 0x80000000, 3, 0, 3, 0, 0)
	if h.call(dK32, "CreateFileMappingW", ef, 0, 2, 0, 0, 0) != 0 || h.lastError() != errFileInvalid {
		t.Fatalf("empty file: err %d", h.lastError())
	}
}
