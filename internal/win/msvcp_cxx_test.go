package win

import (
	"fmt"
	"testing"

	"winemu/internal/mem"
)

// rttiImage lays out MSVC x64 RTTI metadata (image-relative RVAs) in a
// guest region, the way the compiler emits it into an image.
type rttiImage struct {
	h          *testEmu
	base, next uint64
	td         map[string]uint64
	chd        map[string]uint64
}

func newRTTIImage(h *testEmu) *rttiImage {
	r, err := h.E.Mem.Alloc(0x10000, mem.PageReadWrite, mem.MemPrivate, "rtti image")
	if err != nil {
		h.t.Fatal(err)
	}
	return &rttiImage{h: h, base: r.Base, next: r.Base + 0x100, td: map[string]uint64{}, chd: map[string]uint64{}}
}

func (r *rttiImage) take(n uint64) uint64 {
	a := r.next
	r.next += (n + 15) &^ 15
	return a
}

func (r *rttiImage) rva(a uint64) uint32 { return uint32(a - r.base) }

func (r *rttiImage) typeDesc(name string) uint64 {
	if a, ok := r.td[name]; ok {
		return a
	}
	a := r.take(16 + uint64(len(name)) + 1)
	r.h.E.Mem.WriteCStr(a+16, ".?AV"+name+"@@")
	r.td[name] = a
	return a
}

// base describes one entry of a class hierarchy: class name, number of
// bases contained below it in the array, displacement and attributes.
type rttiBase struct {
	name      string
	contained uint32
	mdisp     int32
	attr      uint32
}

// class builds the class hierarchy descriptor of bases[0] (the class itself).
func (r *rttiImage) class(attrs uint32, bases ...rttiBase) uint64 {
	m := r.h.E.Mem
	chd := r.take(16)
	arr := r.take(4 * uint64(len(bases)))
	m.W32(chd+4, attrs)
	m.W32(chd+8, uint32(len(bases)))
	m.W32(chd+12, r.rva(arr))
	for i, b := range bases {
		bcd := r.take(28)
		m.W32(bcd, r.rva(r.typeDesc(b.name)))
		m.W32(bcd+4, b.contained)
		m.W32(bcd+8, uint32(b.mdisp))
		m.W32(bcd+12, 0xFFFFFFFF) // pdisp -1
		m.W32(bcd+20, b.attr)
		m.W32(arr+4*uint64(i), r.rva(bcd))
	}
	r.chd[bases[0].name] = chd
	return chd
}

// vtable creates a vftable for the subobject at offset off of class cls and
// returns the address of its first slot.
func (r *rttiImage) vtable(cls string, off uint32) uint64 {
	m := r.h.E.Mem
	col := r.take(24)
	m.W32(col, 1)
	m.W32(col+4, off)
	m.W32(col+12, r.rva(r.typeDesc(cls)))
	m.W32(col+16, r.rva(r.chd[cls]))
	m.W32(col+20, r.rva(col))
	vt := r.take(16)
	m.W64(vt, col)
	return vt + 8
}

// cxxThrow is what a vectored handler saw of a C++ exception.
type cxxThrow struct {
	code             uint32
	nparams          uint32
	magic, obj, ti   uint64
	imageBase        uint64
	types            []string // catchable type names, most derived first
	what             string
	sizes, copyFuncs []uint32
}

var vehSeq int

// catchThrow runs dll!name and returns the C++ exception it raised.
func catchThrow(t *testing.T, h *testEmu, dll, name string, args ...uint64) cxxThrow {
	t.Helper()
	var got *cxxThrow
	vehSeq++
	veh := h.E.stub("test", fmt.Sprintf("veh%d", vehSeq), func(e *Emu) uint64 {
		m := e.Mem
		rec := m.R64(e.Arg(0))
		c := &cxxThrow{code: m.R32(rec), nparams: m.R32(rec + 0x18), magic: m.R64(rec + 0x20),
			obj: m.R64(rec + 0x28), ti: m.R64(rec + 0x30), imageBase: m.R64(rec + 0x38)}
		if c.code == 0xE06D7363 {
			cta := c.imageBase + uint64(m.R32(c.ti+12))
			for i := range uint64(m.R32(cta)) {
				ct := c.imageBase + uint64(m.R32(cta+4+4*i))
				c.types = append(c.types, m.CStr(c.imageBase+uint64(m.R32(ct+4))+16))
				c.sizes = append(c.sizes, m.R32(ct+20))
				c.copyFuncs = append(c.copyFuncs, m.R32(ct+24))
			}
			if p := m.R64(c.obj + 8); p != 0 {
				c.what = m.CStr(p)
			}
		}
		got = c
		return 0 // EXCEPTION_CONTINUE_SEARCH
	})
	hv := h.call(dK32, "AddVectoredExceptionHandler", 1, veh)
	defer h.call(dK32, "RemoveVectoredExceptionHandler", hv)
	_, exited, code := h.tryCall(dll, name, args...)
	if !exited || got == nil {
		t.Fatalf("%s did not throw (exited %v code %#x)", name, exited, code)
	}
	if got.code != 0xE06D7363 || got.nparams != 4 || got.magic != 0x19930520 || code != 0xE06D7363 {
		t.Fatalf("%s: record code %#x nparams %d magic %#x, exit %#x", name, got.code, got.nparams, got.magic, code)
	}
	return *got
}

func TestRTtypeid(t *testing.T) {
	h := newTestEmu(t)
	r := newRTTIImage(h)
	r.class(0, rttiBase{"A", 0, 0, 0x40})
	r.class(0, rttiBase{"B", 1, 0, 0x40}, rttiBase{"A", 0, 0, 0x40})
	obj := h.alloc(16)
	h.w64(obj, r.vtable("B", 0))
	if got := h.call(dVc, "__RTtypeid", obj); got != r.typeDesc("B") {
		t.Fatalf("__RTtypeid = %#x, want B's type descriptor %#x", got, r.typeDesc("B"))
	}
	if x := catchThrow(t, h, dVc, "__RTtypeid", 0); x.types[0] != ".?AVbad_typeid@std@@" || x.what != "Attempted a typeid of nullptr pointer!" {
		t.Fatalf("typeid(nullptr) threw %v %q", x.types, x.what)
	}
	bad := h.alloc(16)
	h.w64(bad, 0x10) // vftable[-1] is unreadable
	x := catchThrow(t, h, dVc, "__RTtypeid", bad)
	if len(x.types) != 3 || x.types[0] != ".?AV__non_rtti_object@std@@" || x.types[1] != ".?AVbad_typeid@std@@" || x.types[2] != ".?AVexception@std@@" {
		t.Fatalf("no-RTTI object threw %v %q", x.types, x.what)
	}
}

func TestRTDynamicCast(t *testing.T) {
	h := newTestEmu(t)
	r := newRTTIImage(h)
	r.class(0, rttiBase{"A", 0, 0, 0x40})
	r.class(0, rttiBase{"D", 0, 0, 0x40})
	r.class(0, rttiBase{"X", 0, 0, 0x40})
	r.class(0, rttiBase{"B", 1, 0, 0x40}, rttiBase{"A", 0, 0, 0x40})
	// class C : A, D  -- D subobject at offset 8 (multiple inheritance)
	r.class(1, rttiBase{"C", 2, 0, 0x40}, rttiBase{"A", 0, 0, 0x40}, rttiBase{"D", 0, 8, 0x40})
	b := h.alloc(16)
	h.w64(b, r.vtable("B", 0))
	c := h.alloc(16)
	h.w64(c, r.vtable("C", 0))
	h.w64(c+8, r.vtable("C", 8))
	td := r.typeDesc
	cast := func(p, src, dst uint64) uint64 { return h.call(dVc, "__RTDynamicCast", p, 0, src, dst, 0) }

	if got := cast(b, td("A"), td("B")); got != b {
		t.Fatalf("SI downcast A->B = %#x, want %#x", got, b)
	}
	if got := cast(b, td("A"), td("X")); got != 0 {
		t.Fatalf("SI cast to unrelated = %#x, want 0", got)
	}
	if got := cast(0, td("A"), td("B")); got != 0 {
		t.Fatalf("cast of nullptr = %#x", got)
	}
	if got := cast(c+8, td("D"), td("C")); got != c {
		t.Fatalf("MI downcast D->C = %#x, want %#x", got, c)
	}
	if got := cast(c+8, td("D"), td("A")); got != c {
		t.Fatalf("MI cross-cast D->A = %#x, want %#x", got, c)
	}
	if got := cast(c, td("A"), td("D")); got != c+8 {
		t.Fatalf("MI cross-cast A->D = %#x, want %#x", got, c+8)
	}
	if got := h.call(dVc, "__RTCastToVoid", c+8); got != c {
		t.Fatalf("__RTCastToVoid = %#x, want %#x", got, c)
	}
	if got := h.call(dVc, "__RTCastToVoid", 0); got != 0 {
		t.Fatalf("__RTCastToVoid(nullptr) = %#x", got)
	}
	x := catchThrow(t, h, dVc, "__RTDynamicCast", b, 0, td("A"), td("X"), 1)
	if x.types[0] != ".?AVbad_cast@std@@" || x.what != "Bad dynamic_cast!" {
		t.Fatalf("reference cast threw %v %q", x.types, x.what)
	}
}

// The std exceptions winemu throws carry real MSVC throw metadata and RTTI.
func TestThrowCError(t *testing.T) {
	h := newTestEmu(t)
	const name = "?_Throw_C_error@std@@YAXH@Z"
	x := catchThrow(t, h, dMsvcp, name, thrdBusy)
	want := []string{".?AVsystem_error@std@@", ".?AV_System_error@std@@", ".?AVruntime_error@std@@", ".?AVexception@std@@"}
	if len(x.types) != 4 || x.types[0] != want[0] || x.types[3] != want[3] || x.what != "device or resource busy" {
		t.Fatalf("_Throw_C_error(busy) threw %v %q", x.types, x.what)
	}
	if x.sizes[0] != 40 || x.sizes[3] != 24 || x.copyFuncs[0] == 0 {
		t.Fatalf("catchable sizes %v copy %v", x.sizes, x.copyFuncs)
	}
	// error_code{16 /* errc::device_or_resource_busy */, &generic_category()}
	cat := h.r64(x.obj + 32)
	if h.r32(x.obj+24) != 16 || cat == 0 || h.r64(cat+8) != 3 {
		t.Fatalf("error_code = {%d, %#x (addr %d)}", h.r32(x.obj+24), cat, h.r64(cat+8))
	}
	// RTTI of the thrown object.
	if td := h.call(dVc, "__RTtypeid", x.obj); h.readAStr(td+16) != want[0] {
		t.Fatalf("typeid(thrown) = %q", h.readAStr(td+16))
	}
	// what() through the vftable, the category's name() through its vftable.
	if s := h.readAStr(h.E.CallGuest(h.r64(h.r64(x.obj)+8), x.obj)); s != "device or resource busy" {
		t.Fatalf("what() = %q", s)
	}
	if s := h.readAStr(h.E.CallGuest(h.r64(h.r64(cat)+8), cat)); s != "generic" {
		t.Fatalf("category name() = %q", s)
	}
	for code, msg := range map[uint64]string{thrdNomem: "resource unavailable try again", thrdTimedout: "resource unavailable try again", thrdError: "invalid argument"} {
		if x := catchThrow(t, h, dMsvcp, name, code); x.what != msg {
			t.Fatalf("_Throw_C_error(%d) what %q, want %q", code, x.what, msg)
		}
	}
}

func TestXGetLastErrorAndXlength(t *testing.T) {
	h := newTestEmu(t)
	h.setLastError(5)
	x := catchThrow(t, h, dMsvcp, "?_XGetLastError@std@@YAXXZ")
	cat := h.r64(x.obj + 32)
	if x.types[0] != ".?AVsystem_error@std@@" || h.r32(x.obj+24) != 5 || h.r64(cat+8) != 7 || x.what != "Access is denied." {
		t.Fatalf("_XGetLastError threw %v code %d cat addr %d what %q", x.types, h.r32(x.obj+24), h.r64(cat+8), x.what)
	}
	x = catchThrow(t, h, dMsvcp, "?_Xlength_error@std@@YAXPEBD@Z", h.astr("string too long"))
	if len(x.types) != 3 || x.types[0] != ".?AVlength_error@std@@" || x.types[1] != ".?AVlogic_error@std@@" || x.what != "string too long" {
		t.Fatalf("_Xlength_error threw %v %q", x.types, x.what)
	}
	if r := h.call(dMsvcp, "?uncaught_exception@std@@YA_NXZ"); r&0xFF != 0 {
		t.Fatalf("uncaught_exception = %d", r)
	}
}

const (
	epCreate  = "?__ExceptionPtrCreate@@YAXPEAX@Z"
	epDestroy = "?__ExceptionPtrDestroy@@YAXPEAX@Z"
	epCopy    = "?__ExceptionPtrCopy@@YAXPEAXPEBX@Z"
	epAssign  = "?__ExceptionPtrAssign@@YAXPEAXPEBX@Z"
	epToBool  = "?__ExceptionPtrToBool@@YA_NPEBX@Z"
	epCompare = "?__ExceptionPtrCompare@@YA_NPEBX0@Z"
	epSwap    = "?__ExceptionPtrSwap@@YAXPEAX0@Z"
	epCurrent = "?__ExceptionPtrCurrentException@@YAXPEAX@Z"
	epRethrow = "?__ExceptionPtrRethrow@@YAXPEBX@Z"
	epCopyExc = "?__ExceptionPtrCopyException@@YAXPEAXPEBX1@Z"
)

func TestExceptionPtr(t *testing.T) {
	h := newTestEmu(t)
	a, b, c := h.alloc(16), h.alloc(16), h.alloc(16)
	h.w64(a, 0xDEAD)
	h.call(dMsvcp, epCreate, a)
	if h.r64(a) != 0 || h.r64(a+8) != 0 || h.call(dMsvcp, epToBool, a)&0xFF != 0 {
		t.Fatalf("created exception_ptr not null: %x", h.read(a, 16))
	}
	h.call(dMsvcp, epCurrent, b) // no exception is being handled
	if h.call(dMsvcp, epToBool, b)&0xFF != 0 {
		t.Fatal("current_exception() outside a handler is not null")
	}
	if x := catchThrow(t, h, dMsvcp, epRethrow, a); x.types[0] != ".?AVbad_exception@std@@" {
		t.Fatalf("rethrow(null) threw %v", x.types)
	}

	// make_exception_ptr(std::length_error("boom"))
	x := catchThrow(t, h, dMsvcp, "?_Xlength_error@std@@YAXPEBD@Z", h.astr("boom"))
	h.call(dMsvcp, epCopyExc, a, x.obj, x.ti)
	rec := h.r64(a)
	if rec == 0 || h.r32(rec) != 0xE06D7363 || h.r32(rec+0x18) != 4 || h.r64(rec+0x20) != 0x19930520 ||
		h.r64(rec+0x30) != x.ti || h.r64(rec+0x38) != x.imageBase {
		t.Fatalf("exception record %x", h.read(rec, 0x40))
	}
	held := h.r64(rec + 0x28)
	if held == x.obj || h.readAStr(h.r64(held+8)) != "boom" || h.r64(held) != h.r64(x.obj) {
		t.Fatalf("held object %#x (thrown %#x) what %q", held, x.obj, h.readAStr(h.r64(held+8)))
	}
	if len(h.E.rtl().excPtrs) != 1 {
		t.Fatalf("control blocks = %d", len(h.E.rtl().excPtrs))
	}

	h.call(dMsvcp, epCopy, b, a)
	if h.r64(b) != rec || h.call(dMsvcp, epCompare, a, b)&0xFF != 1 || h.call(dMsvcp, epCompare, a, c)&0xFF != 0 {
		t.Fatal("copy does not share the record")
	}
	h.call(dMsvcp, epCreate, c)
	h.call(dMsvcp, epSwap, b, c)
	if h.r64(c) != rec || h.r64(b) != 0 {
		t.Fatal("swap")
	}
	h.call(dMsvcp, epAssign, b, c)
	h.call(dMsvcp, epAssign, b, b) // self-assignment keeps it alive
	h.call(dMsvcp, epDestroy, a)
	h.call(dMsvcp, epDestroy, c)
	if h.r64(b) != rec || len(h.E.rtl().excPtrs) != 1 {
		t.Fatal("record released while still referenced")
	}

	// rethrow_exception throws a copy of the held object.
	y := catchThrow(t, h, dMsvcp, epRethrow, b)
	if y.types[0] != ".?AVlength_error@std@@" || y.what != "boom" || y.obj == held || y.ti != x.ti {
		t.Fatalf("rethrow threw %v %q obj %#x", y.types, y.what, y.obj)
	}
	h.call(dMsvcp, epCreate, a)
	h.call(dMsvcp, epAssign, b, a)
	if h.r64(b) != 0 || len(h.E.rtl().excPtrs) != 0 {
		t.Fatalf("last reference dropped: b %#x, control blocks %d", h.r64(b), len(h.E.rtl().excPtrs))
	}
}

// A guest-defined, simple (memcpy-copied) exception type.
func TestExceptionPtrSimpleType(t *testing.T) {
	h := newTestEmu(t)
	r := newRTTIImage(h)
	ct := r.take(28)
	h.w32(ct, 1) // CT_IsSimpleType
	h.w32(ct+4, r.rva(r.typeDesc("int")))
	h.w32(ct+12, 0xFFFFFFFF)
	h.w32(ct+20, 8)
	cta := r.take(8)
	h.w32(cta, 1)
	h.w32(cta+4, r.rva(ct))
	ti := r.take(16)
	h.w32(ti+12, r.rva(cta))
	h.E.modules = append(h.E.modules, &Module{Name: "rtti.dll", Base: r.base, Size: 0x10000})
	obj := h.alloc(8)
	h.w64(obj, 0x1122334455667788)
	p := h.alloc(16)
	h.call(dMsvcp, epCopyExc, p, obj, ti)
	rec := h.r64(p)
	if held := h.r64(rec + 0x28); held == obj || h.r64(held) != 0x1122334455667788 || h.r64(rec+0x38) != r.base {
		t.Fatalf("simple copy: held %#x value %#x base %#x", held, h.r64(held), h.r64(rec+0x38))
	}
	h.call(dMsvcp, epDestroy, p)
	if len(h.E.rtl().excPtrs) != 0 {
		t.Fatal("not released")
	}
}

// current_exception() copies the record being handled: the chain link
// (ExceptionRecord, +0x08) is dropped, ExceptionAddress (+0x10) is kept and
// the thrown object is copied.
func TestExceptionPtrCurrentException(t *testing.T) {
	h := newTestEmu(t)
	x := catchThrow(t, h, dMsvcp, "?_Xlength_error@std@@YAXPEBD@Z", h.astr("cur"))
	src := h.alloc(excRecordSize)
	h.w32(src, 0xE06D7363)
	h.w32(src+4, 1)
	h.w64(src+0x08, 0x1234000) // chained record
	h.w64(src+0x10, 0x5678000) // ExceptionAddress
	h.w32(src+0x18, 4)
	h.w64(src+0x20, 0x19930520)
	h.w64(src+0x28, x.obj)
	h.w64(src+0x30, x.ti)
	h.w64(src+0x38, x.imageBase)
	h.w64(h.call(dVc, "__current_exception"), src)
	p := h.alloc(16)
	h.call(dMsvcp, epCurrent, p)
	rec := h.r64(p)
	if rec == 0 || rec == src || h.r64(rec+0x08) != 0 || h.r64(rec+0x10) != 0x5678000 {
		t.Fatalf("record %#x: chain %#x address %#x", rec, h.r64(rec+0x08), h.r64(rec+0x10))
	}
	if held := h.r64(rec + 0x28); held == x.obj || h.readAStr(h.r64(held+8)) != "cur" {
		t.Fatalf("held object %#x", held)
	}
	h.call(dMsvcp, epDestroy, p)
	if len(h.E.rtl().excPtrs) != 0 {
		t.Fatal("not released")
	}
}

// Private (not visible) bases and virtual bases located through the vbtable.
func TestRTDynamicCastPrivateAndVirtualBase(t *testing.T) {
	h := newTestEmu(t)
	r := newRTTIImage(h)
	r.class(0, rttiBase{"A", 0, 0, 0x40})
	// class P : private A (single inheritance)
	r.class(0, rttiBase{"P", 1, 0, 0x40}, rttiBase{"A", 0, 0, 0x40 | 0x01})
	p := h.alloc(16)
	h.w64(p, r.vtable("P", 0))
	td := r.typeDesc
	cast := func(p, src, dst uint64) uint64 { return h.call(dVc, "__RTDynamicCast", p, 0, src, dst, 0) }
	if got := cast(p, td("P"), td("A")); got != 0 {
		t.Fatalf("cast to a private base = %#x, want 0", got)
	}

	// class V : virtual A, CHD attributes SI / VI / MI|VI. Layout: +0 V's
	// vfptr, +8 vbptr (vbtable {-8, 8}: A at vbptr+8), +16 the A subobject.
	for _, attrs := range []uint32{0, 2, 3} {
		r.class(attrs, rttiBase{"V", 1, 0, 0x40}, rttiBase{"A", 0, 0, 0x40})
		chd := r.chd["V"]
		bcdA := r.base + uint64(h.r32(r.base+uint64(h.r32(chd+12))+4))
		h.w32(bcdA+12, 8) // pdisp: vbptr at +8
		h.w32(bcdA+16, 4) // vdisp: vbtable[1]
		vbt := r.take(8)
		h.w32(vbt, 0xFFFFFFF8)
		h.w32(vbt+4, 8)
		v := h.alloc(32)
		h.w64(v, r.vtable("V", 0))
		h.w64(v+8, vbt)
		h.w64(v+16, r.vtable("V", 16))
		if got := cast(v, td("V"), td("A")); got != v+16 {
			t.Fatalf("attrs %d: V->virtual A = %#x, want %#x", attrs, got, v+16)
		}
		if got := cast(v+16, td("A"), td("V")); got != v {
			t.Fatalf("attrs %d: virtual A->V = %#x, want %#x", attrs, got, v)
		}
	}
}
