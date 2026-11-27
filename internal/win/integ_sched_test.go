//go:build darwin || linux

package win

import (
	"context"
	"testing"
	"time"
)

// Integration of host waits (winsock, name lookups) with the multi-process
// scheduler: blockHost, idle and kernel notifications.

// sleepWoken runs k.sleep(g0, 5 s) the way an idle scheduler of another
// process would and reports whether it was woken well before the timeout.
func sleepWoken(e *Emu, g0 uint64) <-chan bool {
	r := make(chan bool, 1)
	tm := time.NewTimer(time.Hour)
	tm.Stop()
	go func() {
		start := time.Now()
		e.k.sleep(g0, 5*time.Second, tm)
		r <- time.Since(start) < 2*time.Second
	}()
	return r
}

// A finished host name lookup notifies the kernel, so a sleeping scheduler
// wakes at once; the re-executed call then ends the host wait.
func TestIntegLookupCompletionNotifies(t *testing.T) {
	h := wsaInit(t)
	e := h.E
	release := make(chan struct{})
	query := func(context.Context) (int, error) { <-release; return 7, nil }
	if _, _, ok := asyncLookup(e, "k", query); ok || !e.Cur.waitHost {
		t.Fatalf("first call: ok=%v waitHost=%v, want parked host wait", ok, e.Cur.waitHost)
	}
	woken := sleepWoken(e, e.k.gen.Load())
	time.Sleep(20 * time.Millisecond)
	close(release)
	if !<-woken {
		t.Fatal("lookup completion did not notify the kernel")
	}
	v, err, ok := asyncLookup(e, "k", query)
	if !ok || err != nil || v != 7 {
		t.Fatalf("re-executed call = %v, %v, %v", v, err, ok)
	}
	if e.Cur.waiting || e.Cur.waitHost {
		t.Fatalf("after resume: waiting=%v waitHost=%v", e.Cur.waiting, e.Cur.waitHost)
	}
}

// Setting a WSAEventSelect event wakes schedulers sleeping in other
// processes (the event may be shared); resetting it need not.
func TestIntegSetNetEventNotifies(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	ev := &eventObj{manual: true}
	woken := sleepWoken(b.E, b.E.k.gen.Load())
	time.Sleep(20 * time.Millisecond)
	h.E.setNetEvent(ev, true)
	if !<-woken {
		t.Fatal("setNetEvent(true) did not notify the kernel")
	}
	if !ev.set {
		t.Fatal("event not set")
	}
}

// With a thread in a host wait, idle polls with backoff but never sleeps
// past the earliest wait deadline.
func TestIntegIdleHostWaitCappedByDeadline(t *testing.T) {
	h := newTestEmu(t)
	e := h.E
	th := e.threads[0]
	th.waiting, th.waitHost = true, true
	th.wait = func() bool { return false }
	th.waitDeadline = time.Now().Add(5 * time.Millisecond)
	t.Cleanup(func() {
		th.waiting, th.waitHost, th.wait, th.waitDeadline = false, false, nil, time.Time{}
	})
	e.pollDelay = 3 * time.Second
	start := time.Now()
	e.idle(e.k.gen.Load(), time.Now())
	if el := time.Since(start); el > time.Second {
		t.Fatalf("idle slept %v past a 5 ms deadline", el)
	}
	if e.proc.blocked {
		t.Fatal("a host wait marked the process blocked forever")
	}
}

// A completed socket wait must not leave the thread marked as a host wait:
// a later INFINITE wait on an event nobody can set is still a deadlock.
func TestIntegSocketWaitThenDeadlock(t *testing.T) {
	h := wsaInit(t)
	ls, _ := listener4(t, h)
	set := h.alloc(16) // fd_set{1, ls}
	h.w32(set, 1)
	h.w64(set+8, ls)
	tv := h.alloc(8) // 50 ms
	h.w32(tv+4, 50_000)
	if r := h.call(ws2, "select", 0, set, 0, 0, tv); r != 0 {
		t.Fatalf("select = %d, want timeout 0 (err %d)", r, h.lastError())
	}
	if h.call(ws2, "closesocket", ls) != 0 {
		t.Fatalf("closesocket err %d", h.lastError())
	}
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, 0)
	_, exited, code := guestRun(t, h, 20*time.Second, dK32, "WaitForSingleObject", ev, infinite)
	if !exited || code != 0xC0000194 {
		t.Fatalf("exited=%v code=%#x, want deadlock termination 0xC0000194", exited, code)
	}
}

// One process in a host wait (accept) keeps a sibling that waits INFINITE on
// an event from being reported as deadlocked; the event is set once accept
// returns.
func TestIntegHostWaitKeepsSiblingAlive(t *testing.T) {
	h := wsaInit(t)
	b := sibling(t, h)
	h.E.proc.markStarted() // both are live processes from the kernel's view
	b.E.proc.markStarted()
	ev := h.call(dK32, "CreateEventW", 0, 1, 0, h.wstr("qa_integ_host_wait"))
	bev := b.call(dK32, "OpenEventW", 0x1F0003, 0, b.wstr("qa_integ_host_wait"))
	if ev == 0 || bev == 0 {
		t.Fatalf("named event: %#x / %#x", ev, bev)
	}
	ls, port := listener4(t, h)
	dialLater(t, port, 3*time.Second)
	type res struct {
		r      uint64
		exited bool
		code   uint32
	}
	bDone := make(chan res, 1)
	go func() {
		r, x, c := b.tryCall(dK32, "WaitForSingleObject", bev, infinite)
		bDone <- res{r, x, c}
	}()
	r, exited, code := guestRun(t, h, 20*time.Second, ws2, "accept", ls, 0, 0)
	if exited || r == sockErr {
		t.Fatalf("accept = %#x exited=%v code=%#x", r, exited, code)
	}
	h.call(dK32, "SetEvent", ev)
	select {
	case br := <-bDone:
		if br.exited || br.r != 0 {
			t.Fatalf("sibling wait = %#x exited=%v code=%#x", br.r, br.exited, br.code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sibling wait did not return")
	}
}
