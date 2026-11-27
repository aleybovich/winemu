package win

import (
	"encoding/binary"
	"testing"
)

const (
	errAlreadyFiberT  = 1280
	errAlreadyThreadT = 1281
)

// storeRAX returns raw code: <load> into rax, then mov [slot], rax.
func storeRAX(load []byte, slot uint64) gcall {
	b := append([]byte{}, load...)
	b = append(b, 0x48, 0xB9) // mov rcx, imm64
	b = binary.LittleEndian.AppendUint64(b, slot)
	return gcall{raw: append(b, 0x48, 0x89, 0x01)} // mov [rcx], rax
}

var (
	loadFiber     = []byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0, 0, 0}      // mov rax, gs:[0x20]  (GetCurrentFiber)
	loadFiberData = append(append([]byte{}, loadFiber...), 0x48, 0x8B, 0x00) // mov rax, [rax]      (GetFiberData)
	loadRSP       = []byte{0x48, 0x89, 0xE0}                                 // mov rax, rsp
	loadStackBase = []byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x08, 0, 0, 0}      // mov rax, gs:[0x08]
)

func TestFiberConvert(t *testing.T) {
	h := newTestEmu(t)
	teb := h.E.Cur.TEB
	if h.call(dK32, "IsThreadAFiber")&0xFF != 0 {
		t.Fatal("thread is a fiber before conversion")
	}
	h.setLastError(0)
	if r := h.call(dK32, "ConvertFiberToThread"); r != 0 || h.lastError() != errAlreadyThreadT {
		t.Fatalf("ConvertFiberToThread on a thread = %d, lastError %d", r, h.lastError())
	}
	f := h.call(dK32, "ConvertThreadToFiber", 0x55)
	if f == 0 || h.r64(teb+0x20) != f || h.r64(f) != 0x55 || h.call(dK32, "IsThreadAFiber")&0xFF != 1 {
		t.Fatalf("ConvertThreadToFiber = %#x, TEB FiberData %#x, data %#x", f, h.r64(teb+0x20), h.r64(f))
	}
	if r := h.call(dK32, "ConvertThreadToFiber", 0); r != 0 || h.lastError() != errAlreadyFiberT {
		t.Fatalf("second ConvertThreadToFiber = %#x, lastError %d", r, h.lastError())
	}
	if r := h.call(dK32, "ConvertFiberToThread"); r != 1 || h.call(dK32, "IsThreadAFiber")&0xFF != 0 {
		t.Fatalf("ConvertFiberToThread = %d", r)
	}
	h.setLastError(0)
	if r := h.call(dK32, "ConvertThreadToFiberEx", 0, 2); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("ConvertThreadToFiberEx(bad flags) = %#x, lastError %d", r, h.lastError())
	}
	f = h.call(dK32, "ConvertThreadToFiberEx", 0x66, 1) // FIBER_FLAG_FLOAT_SWITCH
	if f == 0 || h.r64(f) != 0x66 {
		t.Fatalf("ConvertThreadToFiberEx = %#x", f)
	}
}

func TestFiberSwitch(t *testing.T) {
	h := newTestEmu(t)
	teb := h.E.Cur.TEB
	threadStackBase := h.r64(teb + 8)
	main := h.call(dK32, "ConvertThreadToFiber", 0x55)
	slots, flag := h.alloc(32), h.alloc(8)
	sw := h.export(dK32, "SwitchToFiber")
	routine := h.code(0,
		storeRAX(loadFiber, slots), storeRAX(loadFiberData, slots+8), storeRAX(loadRSP, slots+16), storeRAX(loadStackBase, slots+24),
		h.setByte(flag, 1), gcall{fn: sw, args: []uint64{main}},
		h.setByte(flag, 2), gcall{fn: sw, args: []uint64{main}},
		gcall{}) // loop
	f := h.call(dK32, "CreateFiber", 0, routine, 0x77)
	if f == 0 || h.r64(f) != 0x77 {
		t.Fatalf("CreateFiber = %#x", f)
	}
	h.call(dK32, "SwitchToFiber", f)
	sp, base := h.r64(slots+16), h.r64(slots+24)
	if h.r32(flag) != 1 || h.r64(slots) != f || h.r64(slots+8) != 0x77 {
		t.Fatalf("in fiber: flag %d GetCurrentFiber %#x GetFiberData %#x", h.r32(flag), h.r64(slots), h.r64(slots+8))
	}
	if base == threadStackBase || sp >= base || sp < base-0x100000 || sp&15 != 0 { // rsp after the routine's "sub rsp, 40"
		t.Fatalf("fiber stack: rsp %#x, TEB StackBase %#x (thread %#x)", sp, base, threadStackBase)
	}
	if h.r64(teb+0x20) != main || h.r64(teb+8) != threadStackBase || h.E.Cur.StackBase != threadStackBase {
		t.Fatalf("back in main fiber: TEB FiberData %#x StackBase %#x", h.r64(teb+0x20), h.r64(teb+8))
	}
	h.call(dK32, "SwitchToFiber", f)
	if h.r32(flag) != 2 {
		t.Fatalf("second switch: flag %d", h.r32(flag))
	}
	h.call(dK32, "SwitchToFiber", f)
	if h.r32(flag) != 1 {
		t.Fatalf("third switch (looped): flag %d", h.r32(flag))
	}
	h.call(dK32, "SwitchToFiber", main) // switching to the running fiber is a no-op
	f2 := h.call(dK32, "CreateFiberEx", 0x1000, 0x20000, 1, routine, 0x88)
	if f2 == 0 || h.r64(f2) != 0x88 {
		t.Fatalf("CreateFiberEx = %#x", f2)
	}
	h.call(dK32, "DeleteFiber", f)
	h.call(dK32, "DeleteFiber", f2)
	if n := len(h.E.rtl().fibers); n != 1 {
		t.Fatalf("fibers left after DeleteFiber: %d, want 1 (main)", n)
	}
	if h.call(dK32, "ConvertFiberToThread") != 1 || len(h.E.rtl().fibers) != 0 {
		t.Fatal("ConvertFiberToThread did not release the main fiber")
	}
}

// Inside a CreateFiber fiber the TEB stack fields describe the fiber's own
// stack: StackLimit (+0x10) and DeallocationStack (+0x1478) at its
// allocation base, below StackBase; back in the thread they are restored.
func TestFiberTEBStackFields(t *testing.T) {
	h := newTestEmu(t)
	teb := h.E.Cur.TEB
	limit, dealloc := h.r64(teb+0x10), h.r64(teb+0x1478)
	main := h.call(dK32, "ConvertThreadToFiber", 0)
	slots := h.alloc(24)
	routine := h.code(0,
		storeRAX(loadStackBase, slots),
		storeRAX([]byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x10, 0, 0, 0}, slots+8),     // mov rax, gs:[0x10]
		storeRAX([]byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x78, 0x14, 0, 0}, slots+16), // mov rax, gs:[0x1478]
		gcall{fn: h.export(dK32, "SwitchToFiber"), args: []uint64{main}}, gcall{})
	f := h.call(dK32, "CreateFiber", 0x10000, routine, 0)
	h.call(dK32, "SwitchToFiber", f)
	base, lim, dst := h.r64(slots), h.r64(slots+8), h.r64(slots+16)
	if lim == limit || lim >= base || dst != lim || h.r64(f+0x20) != dst {
		t.Fatalf("in fiber: StackBase %#x StackLimit %#x DeallocationStack %#x (thread limit %#x)", base, lim, dst, limit)
	}
	if h.r64(teb+0x10) != limit || h.r64(teb+0x1478) != dealloc {
		t.Fatalf("thread fields not restored: limit %#x dealloc %#x", h.r64(teb+0x10), h.r64(teb+0x1478))
	}
}
