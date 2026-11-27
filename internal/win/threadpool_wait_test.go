package win

import "testing"

const (
	wtExecuteInWaitThread = 4
)

// procAddr returns the address of a registered export (used as a guest
// callback: e.g. SetEvent(ctx) has the WAITORTIMERCALLBACK shape).
func procAddr(h *testEmu, dll, name string) uint64 {
	h.t.Helper()
	m, err := h.E.LoadDLL(dll)
	if err != nil {
		h.t.Fatal(err)
	}
	a, ok := h.E.GetExport(m, name, 0, false)
	if !ok {
		h.t.Fatalf("%s!%s not registered", dll, name)
	}
	return a
}

func regWait(h *testEmu, obj, cb, ctx uint64, ms, flags uint32) uint64 {
	h.t.Helper()
	p := h.alloc(8)
	if r := h.call(dK32, "RegisterWaitForSingleObject", p, obj, cb, ctx, uint64(ms), uint64(flags)); r != 1 {
		h.t.Fatalf("RegisterWaitForSingleObject = %d err %d", r, h.lastError())
	}
	wh := h.r64(p)
	if wh == 0 {
		h.t.Fatal("no wait handle")
	}
	return wh
}

func TestRegisterWaitFiresOnceOnSignal(t *testing.T) {
	h := newTestEmu(t)
	trig := h.call(dK32, "CreateEventW", 0, 1, 0, 0) // manual: stays signalled
	done := h.call(dK32, "CreateEventW", 0, 0, 0, 0) // auto
	wh := regWait(h, trig, procAddr(h, dK32, "SetEvent"), done, infinite, wtExecuteOnlyOnce|wtExecuteInWaitThread)
	if r := h.call(dK32, "WaitForSingleObject", done, 100); r != waitTimeout {
		t.Fatalf("fired before signal: %#x", r)
	}
	h.call(dK32, "SetEvent", trig)
	if r := h.call(dK32, "WaitForSingleObject", done, 2000); r != 0 {
		t.Fatalf("callback not run: %#x", r)
	}
	// manual event stays set, but WT_EXECUTEONLYONCE: no second call
	if r := h.call(dK32, "WaitForSingleObject", done, 200); r != waitTimeout {
		t.Fatalf("callback ran twice: %#x", r)
	}
	if r := h.call(dK32, "UnregisterWaitEx", wh, invalidHandle); r != 1 {
		t.Fatalf("UnregisterWaitEx = %d err %d", r, h.lastError())
	}
	// the handle is gone
	if r := h.call(dK32, "UnregisterWait", wh); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("second unregister = %d err %d", r, h.lastError())
	}
}

func TestRegisterWaitRepeatsAndAcquires(t *testing.T) {
	h := newTestEmu(t)
	sem := h.call(dK32, "CreateSemaphoreW", 0, 0, 10, 0)
	done := h.call(dK32, "CreateEventW", 0, 0, 0, 0)
	wh := regWait(h, sem, procAddr(h, dK32, "SetEvent"), done, infinite, 0)
	for i := range 3 {
		h.call(dK32, "ReleaseSemaphore", sem, 1, 0)
		if r := h.call(dK32, "WaitForSingleObject", done, 2000); r != 0 {
			t.Fatalf("round %d: %#x", i, r)
		}
	}
	// each callback acquired one count: the semaphore is empty
	if r := h.call(dK32, "WaitForSingleObject", sem, 0); r != waitTimeout {
		t.Fatalf("semaphore not acquired by the wait: %#x", r)
	}
	if r := h.call(dK32, "UnregisterWait", wh); r != 1 {
		t.Fatalf("UnregisterWait = %d err %d", r, h.lastError())
	}
	h.call(dK32, "ReleaseSemaphore", sem, 1, 0)
	if r := h.call(dK32, "WaitForSingleObject", done, 200); r != waitTimeout {
		t.Fatalf("callback after unregister: %#x", r)
	}
	if r := h.call(dK32, "WaitForSingleObject", sem, 0); r != 0 {
		t.Fatalf("count taken after unregister: %#x", r)
	}
}

func TestRegisterWaitTimeout(t *testing.T) {
	h := newTestEmu(t)
	never := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	done := h.call(dK32, "CreateEventW", 0, 0, 0, 0)
	wh := regWait(h, never, procAddr(h, dK32, "SetEvent"), done, 50, wtExecuteOnlyOnce)
	if r := h.call(dK32, "WaitForSingleObject", done, 2000); r != 0 {
		t.Fatalf("timeout callback not run: %#x", r)
	}
	// completion event: signalled once callbacks are done
	ce := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	if r := h.call(dK32, "UnregisterWaitEx", wh, ce); r != 1 {
		t.Fatalf("UnregisterWaitEx(event) = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "WaitForSingleObject", ce, 2000); r != 0 {
		t.Fatalf("completion event not set: %#x", r)
	}
}

func TestRegisterWaitErrors(t *testing.T) {
	h := newTestEmu(t)
	p := h.alloc(8)
	cb := procAddr(h, dK32, "SetEvent")
	if r := h.call(dK32, "RegisterWaitForSingleObject", p, 0x7FF0, cb, 0, infinite, 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("bad object: %d err %d", r, h.lastError())
	}
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	if r := h.call(dK32, "RegisterWaitForSingleObject", 0, ev, cb, 0, infinite, 0); r != 0 || h.lastError() != errInvalidParameter {
		t.Fatalf("null out: %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "UnregisterWait", 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("UnregisterWait(0) = %d err %d", r, h.lastError())
	}
	if r := h.call(dK32, "UnregisterWaitEx", ev, 0); r != 0 || h.lastError() != errInvalidHandle {
		t.Fatalf("UnregisterWaitEx(non-wait) = %d err %d", r, h.lastError())
	}
}
