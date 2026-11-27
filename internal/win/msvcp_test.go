package win

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winemu/internal/mem"
)

// export returns the address of dll!name.
func (h *testEmu) export(dll, name string) uint64 {
	h.t.Helper()
	m, err := h.E.LoadDLL(dll)
	if err != nil {
		h.t.Fatalf("LoadDLL(%s): %v", dll, err)
	}
	a, ok := h.E.GetExport(m, name, 0, false)
	if !ok {
		h.t.Fatalf("%s!%s not registered", dll, name)
	}
	return a
}

// gcall is one call of a generated guest function: fn(args...) (<= 4 args).
type gcall struct {
	fn   uint64
	args []uint64
	raw  []byte // emitted as is instead of a call (fn must be 0)
}

// code assembles a guest function (Win64 ABI) that performs the calls in
// order and returns ret. A call with fn == 0 is "jump back to the start"
// (an endless loop), so it must be last.
func (h *testEmu) code(ret uint32, calls ...gcall) uint64 {
	h.t.Helper()
	var b []byte
	imm := func(op []byte, v uint64) {
		b = append(b, op...)
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	b = append(b, 0x48, 0x83, 0xEC, 0x28) // sub rsp, 40
	start := len(b)
	loop := false
	for _, c := range calls {
		if c.raw != nil {
			b = append(b, c.raw...)
			continue
		}
		if c.fn == 0 {
			loop = true
			break
		}
		regs := [][]byte{{0x48, 0xB9}, {0x48, 0xBA}, {0x49, 0xB8}, {0x49, 0xB9}} // mov rcx/rdx/r8/r9, imm64
		for i, a := range c.args {
			imm(regs[i], a)
		}
		imm([]byte{0x48, 0xB8}, c.fn) // mov rax, imm64
		b = append(b, 0xFF, 0xD0)     // call rax
	}
	if loop {
		rel := start - (len(b) + 5)
		b = append(b, 0xE9)
		b = binary.LittleEndian.AppendUint32(b, uint32(int32(rel)))
	}
	b = append(b, 0x48, 0x83, 0xC4, 0x28, 0xB8) // add rsp, 40; mov eax, imm32
	b = binary.LittleEndian.AppendUint32(b, ret)
	b = append(b, 0xC3)
	r, err := h.E.Mem.Alloc(uint64(len(b)), mem.PageExecuteReadWrite, mem.MemPrivate, "test code")
	if err != nil {
		h.t.Fatal(err)
	}
	h.write(r.Base, b)
	return r.Base
}

// setByte returns a call that stores v into the byte at a.
func (h *testEmu) setByte(a uint64, v byte) gcall {
	return gcall{fn: h.export(dNt, "RtlFillMemory"), args: []uint64{a, 1, uint64(v)}}
}

func TestMtxLayoutLockUnlock(t *testing.T) {
	h := newTestEmu(t)
	me := uint32(h.call(dK32, "GetCurrentThreadId"))
	for _, typ := range []uint64{mtxPlain, 2 /* _Mtx_try: std::mutex */} {
		m := h.alloc(mtxSize)
		h.call(dMsvcp, "_Mtx_init_in_situ", m, typ)
		if h.r32(m) != uint32(typ) || h.r32(m+mtxOffOwner) != 0xFFFFFFFF || h.r32(m+mtxOffCount) != 0 || h.r64(m+mtxOffSRW) != 0 {
			t.Fatalf("type %#x: init layout %x", typ, h.read(m, mtxSize))
		}
		if r := h.call(dMsvcp, "_Mtx_lock", m); r != thrdSuccess {
			t.Fatalf("type %#x: _Mtx_lock = %d", typ, r)
		}
		if h.r32(m+mtxOffOwner) != me || h.r32(m+mtxOffCount) != 1 || h.r64(m+mtxOffSRW) == 0 {
			t.Fatalf("type %#x: locked layout owner %#x count %d srw %#x", typ, h.r32(m+mtxOffOwner), h.r32(m+mtxOffCount), h.r64(m+mtxOffSRW))
		}
		if h.call(dMsvcp, "_Mtx_current_owns", m)&0xFF != 1 {
			t.Fatalf("type %#x: _Mtx_current_owns = false", typ)
		}
		if r := h.call(dMsvcp, "_Mtx_unlock", m); r != thrdSuccess || h.r32(m+mtxOffCount) != 0 || h.r64(m+mtxOffSRW) != 0 {
			t.Fatalf("type %#x: _Mtx_unlock = %d count %d srw %#x", typ, r, h.r32(m+mtxOffCount), h.r64(m+mtxOffSRW))
		}
		if h.call(dMsvcp, "_Mtx_current_owns", m)&0xFF != 0 {
			t.Fatalf("type %#x: _Mtx_current_owns after unlock", typ)
		}
		if r := h.call(dMsvcp, "_Mtx_unlock", m); r != thrdError || h.r32(m+mtxOffCount) != 0 {
			t.Fatalf("type %#x: unlock of unowned = %d count %d", typ, r, h.r32(m+mtxOffCount))
		}
	}
}

func TestMtxTrylockRecursive(t *testing.T) {
	h := newTestEmu(t)
	// std::mutex (_Mtx_try): relocking by the owner fails with _Thrd_busy.
	m := h.alloc(mtxSize)
	h.call(dMsvcp, "_Mtx_init_in_situ", m, 2)
	if r := h.call(dMsvcp, "_Mtx_trylock", m); r != thrdSuccess {
		t.Fatalf("trylock free = %d", r)
	}
	if r := h.call(dMsvcp, "_Mtx_trylock", m); r != thrdBusy || h.r32(m+mtxOffCount) != 1 {
		t.Fatalf("trylock owned non-recursive = %d count %d, want busy 1", r, h.r32(m+mtxOffCount))
	}
	if r := h.call(dMsvcp, "_Mtx_lock", m); r != thrdBusy {
		t.Fatalf("relock non-recursive = %d, want busy", r)
	}
	h.call(dMsvcp, "_Mtx_unlock", m)

	// std::recursive_mutex (_Mtx_try | _Mtx_recursive).
	rm := h.alloc(mtxSize)
	h.call(dMsvcp, "_Mtx_init_in_situ", rm, 0x102)
	for i := 1; i <= 3; i++ {
		if r := h.call(dMsvcp, "_Mtx_trylock", rm); r != thrdSuccess || h.r32(rm+mtxOffCount) != uint32(i) {
			t.Fatalf("recursive trylock %d = %d count %d", i, r, h.r32(rm+mtxOffCount))
		}
	}
	for i := 2; i >= 0; i-- {
		h.call(dMsvcp, "_Mtx_unlock", rm)
		if h.r32(rm+mtxOffCount) != uint32(i) || (i > 0) != (h.r64(rm+mtxOffSRW) != 0) {
			t.Fatalf("recursive unlock -> count %d srw %#x", h.r32(rm+mtxOffCount), h.r64(rm+mtxOffSRW))
		}
	}

	// Held by another thread: trylock is busy, timedlock times out.
	h.w64(m+mtxOffSRW, 1)
	h.w32(m+mtxOffOwner, 0x4242)
	h.w32(m+mtxOffCount, 1)
	if r := h.call(dMsvcp, "_Mtx_trylock", m); r != thrdBusy {
		t.Fatalf("trylock held elsewhere = %d, want busy", r)
	}
	ts := h.alloc(16)
	dl := time.Now().Add(60 * time.Millisecond)
	h.w64(ts, uint64(dl.Unix()))
	h.w32(ts+8, uint32(dl.Nanosecond()))
	start := time.Now()
	if r := h.call(dMsvcp, "_Mtx_timedlock", m, ts); r != thrdTimedout || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("timedlock held elsewhere = %d after %v, want timedout after ~60ms", r, time.Since(start))
	}
	if h.r32(m+mtxOffOwner) != 0x4242 || h.r32(m+mtxOffCount) != 1 {
		t.Fatalf("timedlock failure changed the mutex")
	}
}

// A zero-filled mutex (constexpr std::mutex) is valid and unlocked.
func TestMtxZeroInitialized(t *testing.T) {
	h := newTestEmu(t)
	m := h.alloc(mtxSize)
	h.w32(m, 2)
	if r := h.call(dMsvcp, "_Mtx_lock", m); r != thrdSuccess {
		t.Fatalf("lock = %d", r)
	}
	if r := h.call(dMsvcp, "_Mtx_unlock", m); r != thrdSuccess || h.r64(m+mtxOffSRW) != 0 {
		t.Fatalf("unlock = %d", r)
	}
}

func TestMtxInitDestroyHeap(t *testing.T) {
	h := newTestEmu(t)
	pp := h.alloc(8)
	if r := h.call(dMsvcp, "_Mtx_init", pp, 0x102); r != thrdSuccess || h.r64(pp) == 0 || h.r32(h.r64(pp)) != 0x102 {
		t.Fatalf("_Mtx_init = %d %#x", r, h.r64(pp))
	}
	h.call(dMsvcp, "_Mtx_destroy", h.r64(pp))
	h.call(dMsvcp, "_Mtx_destroy", 0)
	if r := h.call(dMsvcp, "_Cnd_init", pp); r != thrdSuccess || h.r64(pp) == 0 {
		t.Fatalf("_Cnd_init = %d %#x", r, h.r64(pp))
	}
	h.call(dMsvcp, "_Cnd_destroy", h.r64(pp))
	h.call(dMsvcp, "_Cnd_destroy", 0)
}

// Another guest thread blocks in _Mtx_lock until the owner unlocks.
func TestMtxContention(t *testing.T) {
	h := newTestEmu(t)
	m, flag := h.alloc(mtxSize), h.alloc(8)
	h.call(dMsvcp, "_Mtx_init_in_situ", m, 2)
	lock, unlock := h.export(dMsvcp, "_Mtx_lock"), h.export(dMsvcp, "_Mtx_unlock")
	worker := h.code(0, gcall{fn: lock, args: []uint64{m}}, h.setByte(flag, 1), gcall{fn: unlock, args: []uint64{m}})
	h.call(dMsvcp, "_Mtx_lock", m)
	th := h.call(dK32, "CreateThread", 0, 0, worker, 0, 0, 0)
	h.call(dK32, "Sleep", 50)
	if h.r32(flag) != 0 {
		t.Fatal("worker acquired a locked mutex")
	}
	h.call(dMsvcp, "_Mtx_unlock", m)
	if r := h.call(dK32, "WaitForSingleObject", th, 2000); r != waitObject0 {
		t.Fatalf("worker wait = %#x", r)
	}
	if h.r32(flag) != 1 || h.r32(m+mtxOffCount) != 0 || h.r64(m+mtxOffSRW) != 0 {
		t.Fatalf("after worker: flag %d count %d srw %#x", h.r32(flag), h.r32(m+mtxOffCount), h.r64(m+mtxOffSRW))
	}
}

func TestCndWaitSignalTimedwait(t *testing.T) {
	h := newTestEmu(t)
	me := uint32(h.call(dK32, "GetCurrentThreadId"))
	m, c, flag := h.alloc(mtxSize), h.alloc(cndSize), h.alloc(8)
	h.call(dMsvcp, "_Mtx_init_in_situ", m, 2)
	h.call(dMsvcp, "_Cnd_init_in_situ", c)
	lock, unlock := h.export(dMsvcp, "_Mtx_lock"), h.export(dMsvcp, "_Mtx_unlock")
	for _, wake := range []string{"_Cnd_signal", "_Cnd_broadcast"} {
		h.w32(flag, 0)
		worker := h.code(0, gcall{fn: lock, args: []uint64{m}}, h.setByte(flag, 1),
			gcall{fn: h.export(dMsvcp, wake), args: []uint64{c}}, gcall{fn: unlock, args: []uint64{m}})
		h.call(dMsvcp, "_Mtx_lock", m)
		th := h.call(dK32, "CreateThread", 0, 0, worker, 0, 0, 0)
		for h.r32(flag) == 0 {
			if r := h.call(dMsvcp, "_Cnd_wait", c, m); r != thrdSuccess {
				t.Fatalf("%s: _Cnd_wait = %d", wake, r)
			}
			if h.r32(m+mtxOffOwner) != me || h.r32(m+mtxOffCount) != 1 || h.r64(m+mtxOffSRW) == 0 {
				t.Fatalf("%s: mutex not reacquired after wait", wake)
			}
		}
		h.call(dMsvcp, "_Mtx_unlock", m)
		if r := h.call(dK32, "WaitForSingleObject", th, 2000); r != waitObject0 {
			t.Fatalf("%s: worker wait = %#x", wake, r)
		}
	}

	// Nobody signals: the timed wait times out and still reacquires the mutex.
	h.call(dMsvcp, "_Mtx_lock", m)
	ts := h.alloc(16)
	dl := time.Now().Add(50 * time.Millisecond)
	h.w64(ts, uint64(dl.Unix()))
	h.w32(ts+8, uint32(dl.Nanosecond()))
	start := time.Now()
	if r := h.call(dMsvcp, "_Cnd_timedwait", c, m, ts); r != thrdTimedout || time.Since(start) < 30*time.Millisecond {
		t.Fatalf("_Cnd_timedwait = %d after %v, want timedout", r, time.Since(start))
	}
	if h.r32(m+mtxOffOwner) != me || h.r32(m+mtxOffCount) != 1 {
		t.Fatalf("mutex not reacquired after timeout")
	}
	if h.call(dMsvcp, "_Cnd_signal", c) != thrdSuccess || h.call(dMsvcp, "_Cnd_broadcast", c) != thrdSuccess {
		t.Fatal("signal without waiters failed")
	}
}

func TestExecuteOnce(t *testing.T) {
	h := newTestEmu(t)
	const name = "?_Execute_once@std@@YAHAEAUonce_flag@1@P6AHPEAX1PEAPEAX@Z1@Z"
	flag, ran := h.alloc(8), h.alloc(8)
	ok := h.code(1, h.setByte(ran, 1))
	if r := h.call(dMsvcp, name, flag, ok, 0); r != 1 || h.r32(ran) != 1 {
		t.Fatalf("first _Execute_once = %d ran %d", r, h.r32(ran))
	}
	h.w32(ran, 0)
	if r := h.call(dMsvcp, name, flag, ok, 0); r != 1 || h.r32(ran) != 0 {
		t.Fatalf("second _Execute_once = %d ran %d, want 1 0", r, h.r32(ran))
	}
	// A failing callback (an exception in call_once) leaves the flag unset.
	flag2 := h.alloc(8)
	bad := h.code(0, h.setByte(ran, 2))
	if r := h.call(dMsvcp, name, flag2, bad, 0); r != 0 || h.r32(ran) != 2 || h.r64(flag2) != 0 {
		t.Fatalf("failing callback: ret %d ran %d flag %#x", r, h.r32(ran), h.r64(flag2))
	}
	if r := h.call(dMsvcp, name, flag2, ok, 0); r != 1 || h.r32(ran) != 1 {
		t.Fatalf("retry after failure = %d ran %d", r, h.r32(ran))
	}
}

// TestMSRuntimeDLLsAlwaysBuiltin: the Microsoft C/C++ runtime DLLs are
// always emulated, even when a file of that name sits next to the exe or is
// loaded by explicit path (no Microsoft DLL may ever be executed).
func TestMSRuntimeDLLsAlwaysBuiltin(t *testing.T) {
	h := newTestEmu(t)
	names := []string{"msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll", "msvcp140_atomic_wait.dll",
		"msvcp140_codecvt_ids.dll", "vcruntime140.dll", "vcruntime140_1.dll", "concrt140.dll",
		"ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-core-synch-l1-2-0.dll"}
	for _, n := range names {
		// not a PE: loading it natively would fail
		if err := os.WriteFile(filepath.Join(h.dir, n), []byte("not a Microsoft DLL"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range names {
		for _, req := range []string{n, h.E.fs.toWin(filepath.Join(h.dir, n))} {
			m, err := h.E.LoadDLL(req)
			if err != nil || m == nil || m.Native {
				t.Errorf("LoadDLL(%s) = %v, %v; want a builtin module", req, m, err)
			}
		}
	}
}

// TestCxxFrameHandlerWarning: the warning for the unimplemented MSVC C++
// frame handler must not advise installing Microsoft DLLs.
func TestCxxFrameHandlerWarning(t *testing.T) {
	h := newTestEmu(t, func(o *Options) { o.Verbose = true })
	h.call(dVc, "__CxxFrameHandler3", 0, 0, 0, 0)
	msg := h.stderr()
	if !strings.Contains(msg, "not implemented") || strings.Contains(msg, "copy") || strings.Contains(msg, "Redistributable") {
		t.Errorf("warning = %q", msg)
	}
}

// _Cnd_timedwait with a NULL target time waits without a timeout (MSVC
// cond.cpp), and is woken by _Cnd_signal.
func TestCndTimedwaitNullTarget(t *testing.T) {
	h := newTestEmu(t)
	m, c, flag := h.alloc(mtxSize), h.alloc(cndSize), h.alloc(8)
	h.call(dMsvcp, "_Mtx_init_in_situ", m, 2)
	h.call(dMsvcp, "_Cnd_init_in_situ", c)
	worker := h.code(0, gcall{fn: h.export(dMsvcp, "_Mtx_lock"), args: []uint64{m}}, h.setByte(flag, 1),
		gcall{fn: h.export(dMsvcp, "_Cnd_signal"), args: []uint64{c}}, gcall{fn: h.export(dMsvcp, "_Mtx_unlock"), args: []uint64{m}})
	h.call(dMsvcp, "_Mtx_lock", m)
	th := h.call(dK32, "CreateThread", 0, 0, worker, 0, 0, 0)
	for h.r32(flag) == 0 {
		if r := h.call(dMsvcp, "_Cnd_timedwait", c, m, 0); r != thrdSuccess {
			t.Fatalf("_Cnd_timedwait(NULL) = %d", r)
		}
	}
	h.call(dMsvcp, "_Mtx_unlock", m)
	if r := h.call(dK32, "WaitForSingleObject", th, 2000); r != waitObject0 {
		t.Fatalf("worker wait = %#x", r)
	}
}

// The in-situ layouts by literal offset (MSVC x64 _Mtx_internal_imp_t /
// _Cnd_internal_imp_t), independent of the implementation's constants.
func TestMtxCndLiteralLayout(t *testing.T) {
	h := newTestEmu(t)
	me := uint32(h.call(dK32, "GetCurrentThreadId"))
	m := h.alloc(80)
	h.call(dMsvcp, "_Mtx_init_in_situ", m, 0x102)
	if h.r32(m) != 0x102 || h.r32(m+72) != 0xFFFFFFFF || h.r32(m+76) != 0 {
		t.Fatalf("init: type %#x owner %#x count %d", h.r32(m), h.r32(m+72), h.r32(m+76))
	}
	h.call(dMsvcp, "_Mtx_lock", m)
	h.call(dMsvcp, "_Mtx_lock", m)
	if h.r32(m+72) != me || h.r32(m+76) != 2 || h.r64(m+16) == 0 {
		t.Fatalf("locked: owner %#x count %d srw %#x", h.r32(m+72), h.r32(m+76), h.r64(m+16))
	}
	if h.call(dMsvcp, "_Mtx_getconcrtcs", m) != m+8 {
		t.Fatal("_Mtx_getconcrtcs")
	}
	h.call(dMsvcp, "_Mtx_unlock", m)
	h.call(dMsvcp, "_Mtx_unlock", m)
	if h.r32(m+72) != 0xFFFFFFFF || h.r64(m+16) != 0 {
		t.Fatal("not released")
	}

	// The CONDITION_VARIABLE is at +8: a waiter in _Cnd_wait is woken by
	// kernel32 WakeConditionVariable on that address.
	c, flag := h.alloc(72), h.alloc(8)
	h.call(dMsvcp, "_Cnd_init_in_situ", c)
	worker := h.code(0, gcall{fn: h.export(dMsvcp, "_Mtx_lock"), args: []uint64{m}}, h.setByte(flag, 1),
		gcall{fn: h.export(dK32, "WakeConditionVariable"), args: []uint64{c + 8}},
		gcall{fn: h.export(dMsvcp, "_Mtx_unlock"), args: []uint64{m}})
	h.call(dMsvcp, "_Mtx_lock", m)
	th := h.call(dK32, "CreateThread", 0, 0, worker, 0, 0, 0)
	for h.r32(flag) == 0 {
		h.call(dMsvcp, "_Cnd_wait", c, m)
	}
	h.call(dMsvcp, "_Mtx_unlock", m)
	if r := h.call(dK32, "WaitForSingleObject", th, 2000); r != waitObject0 {
		t.Fatalf("worker wait = %#x", r)
	}
}
