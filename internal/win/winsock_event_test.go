//go:build darwin || linux

package win

import "testing"

// waitEnum waits up to ms for ev, then enumerates s's network events.
func waitEnum(t *testing.T, h *testEmu, s, ev uint64, ms uint64) (events uint32, ne uint64) {
	t.Helper()
	h.call(dK32, "WaitForSingleObject", ev, ms)
	ne = h.alloc(44)
	if r := h.call(ws2, "WSAEnumNetworkEvents", s, ev, ne); r != 0 {
		t.Fatalf("WSAEnumNetworkEvents err %d", h.lastError())
	}
	return h.r32(ne), ne
}

func TestWSAEventSelectAcceptReadClose(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	ev := h.call(ws2, "WSACreateEvent")
	if ev == 0 {
		t.Fatal("WSACreateEvent")
	}
	if r := h.call(ws2, "WSAEventSelect", ls, ev, fdAccept|fdClose); r != 0 {
		t.Fatalf("WSAEventSelect err %d", h.lastError())
	}
	if r := h.call(dK32, "WaitForSingleObject", ev, 0); r != waitTimeout {
		t.Fatalf("event set before any connection: %#x", r)
	}
	c1 := h.call(ws2, "socket", 2, 1, 6)
	c2 := h.call(ws2, "socket", 2, 1, 6)
	h.call(ws2, "connect", c1, sin(h, loop4, port), 16)
	h.call(ws2, "connect", c2, sin(h, loop4, port), 16)
	if r := h.call(ws2, "WSAWaitForMultipleEvents", 1, h.wptrs(ev), 0, 1000, 0); r != 0 {
		t.Fatalf("WSAWaitForMultipleEvents = %#x", r)
	}
	if got, _ := waitEnum(t, h, ls, ev, 0); got != fdAccept {
		t.Fatalf("events = %#x, want FD_ACCEPT", got)
	}
	// not re-recorded until accept is called, although c2 is still pending
	if got, _ := waitEnum(t, h, ls, ev, 30); got != 0 {
		t.Fatalf("events after enumerate = %#x, want 0", got)
	}
	s := h.call(ws2, "accept", ls, 0, 0)
	if s == sockErr {
		t.Fatalf("accept err %d", h.lastError())
	}
	if got, _ := waitEnum(t, h, ls, ev, 1000); got != fdAccept {
		t.Fatalf("events after accept = %#x, want FD_ACCEPT (c2)", got)
	}
	// accepted socket inherits WSAEventSelect -> it is non-blocking; FIONBIO off fails
	a := h.alloc(4)
	if r := h.call(ws2, "ioctlsocket", s, fionbio, a); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEINVAL {
		t.Fatalf("FIONBIO(0) on event-selected socket = %#x err %d", r, h.lastError())
	}
	ev2 := h.call(ws2, "WSACreateEvent")
	h.call(ws2, "WSAEventSelect", s, ev2, fdRead|fdWrite|fdClose)
	if got, _ := waitEnum(t, h, s, ev2, 1000); got != fdWrite {
		t.Fatalf("initial events = %#x, want FD_WRITE", got)
	}
	h.call(ws2, "send", c1, h.astr("abcdef"), 6, 0)
	if got, _ := waitEnum(t, h, s, ev2, 1000); got != fdRead {
		t.Fatalf("events after send = %#x, want FD_READ", got)
	}
	h.call(ws2, "send", c1, h.astr("gh"), 2, 0)
	if got, _ := waitEnum(t, h, s, ev2, 30); got != 0 {
		t.Fatalf("FD_READ re-recorded without recv: %#x", got)
	}
	buf := h.alloc(16)
	if r := h.call(ws2, "recv", s, buf, 3, 0); r != 3 {
		t.Fatalf("recv = %d err %d", int32(r), h.lastError())
	}
	if got, _ := waitEnum(t, h, s, ev2, 1000); got != fdRead {
		t.Fatalf("events after partial recv = %#x, want FD_READ", got)
	}
	h.call(ws2, "recv", s, buf, 16, 0)
	h.call(ws2, "closesocket", c1)
	got, ne := waitEnum(t, h, s, ev2, 1000)
	if got&fdClose == 0 || h.r32(ne+4+4*fdCloseBit) != 0 {
		t.Fatalf("events after peer close = %#x err %d, want FD_CLOSE/0", got, h.r32(ne+4+4*fdCloseBit))
	}
	if h.call(dK32, "WaitForSingleObject", ev2, 0) != waitTimeout {
		t.Fatal("WSAEnumNetworkEvents did not reset the event")
	}
	if r := h.call(ws2, "WSAEventSelect", s, 0x7FF0, fdRead); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEINVAL {
		t.Fatalf("WSAEventSelect(bad event) = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "WSAEnumNetworkEvents", s, 0, 0); uint32(r) != 0xFFFFFFFF || h.lastError() != wsaEFAULT {
		t.Fatalf("WSAEnumNetworkEvents(NULL) = %#x err %d", r, h.lastError())
	}
}

func TestWSAEventSelectConnect(t *testing.T) {
	h := wsaInit(t)
	ls, port := listener4(t, h)
	c := h.call(ws2, "socket", 2, 1, 6)
	ev := h.call(ws2, "WSACreateEvent")
	h.call(ws2, "WSAEventSelect", c, ev, fdConnect|fdWrite)
	if r := h.call(ws2, "connect", c, sin(h, loop4, port), 16); r != 0 && h.lastError() != wsaEWOULDBLOCK {
		t.Fatalf("connect = %#x err %d", r, h.lastError())
	}
	var got uint32
	for i := 0; i < 3 && got != fdConnect|fdWrite; i++ {
		g, ne := waitEnum(t, h, c, ev, 1000)
		if g&fdConnect != 0 && h.r32(ne+4+4*fdConnectBit) != 0 {
			t.Fatalf("FD_CONNECT error %d", h.r32(ne+4+4*fdConnectBit))
		}
		got |= g
	}
	if got != fdConnect|fdWrite {
		t.Fatalf("events = %#x, want FD_CONNECT|FD_WRITE", got)
	}
	h.call(ws2, "closesocket", ls)
	// refused connect is reported through FD_CONNECT's error code
	c2 := h.call(ws2, "socket", 2, 1, 6)
	ev2 := h.call(ws2, "WSACreateEvent")
	h.call(ws2, "WSAEventSelect", c2, ev2, fdConnect)
	h.call(ws2, "connect", c2, sin(h, loop4, port), 16)
	g, ne := waitEnum(t, h, c2, ev2, 1000)
	if g != fdConnect || h.r32(ne+4+4*fdConnectBit) != wsaECONNREFUSED {
		t.Fatalf("refused: events %#x err %d", g, h.r32(ne+4+4*fdConnectBit))
	}
}

func TestWSAEventObjects(t *testing.T) {
	h := wsaInit(t)
	ev := h.call(ws2, "WSACreateEvent")
	if h.call(ws2, "WSASetEvent", ev) != 1 || h.call(dK32, "WaitForSingleObject", ev, 0) != 0 {
		t.Fatal("WSASetEvent")
	}
	if h.call(dK32, "WaitForSingleObject", ev, 0) != 0 {
		t.Fatal("WSA event must be manual-reset")
	}
	if h.call(ws2, "WSAResetEvent", ev) != 1 || h.call(ws2, "WSAWaitForMultipleEvents", 1, h.wptrs(ev), 1, 10, 0) != waitTimeout {
		t.Fatal("WSAResetEvent / timeout")
	}
	if r := h.call(ws2, "WSAWaitForMultipleEvents", 0, h.wptrs(ev), 0, 0, 0); uint32(r) != waitFailed || h.lastError() != errInvalidParameter {
		t.Fatalf("WSAWaitForMultipleEvents(0) = %#x err %d", r, h.lastError())
	}
	if h.call(ws2, "WSACloseEvent", ev) != 1 {
		t.Fatal("WSACloseEvent")
	}
	if h.call(ws2, "WSACloseEvent", ev) != 0 || h.lastError() != errInvalidHandle {
		t.Fatal("WSACloseEvent(closed)")
	}
	if h.call(ws2, "WSASetEvent", 0x7FF0) != 0 || h.lastError() != errInvalidHandle {
		t.Fatal("WSASetEvent(bogus)")
	}
}

// wptrs allocates an array of 64-bit values (handle arrays).
func (h *testEmu) wptrs(vs ...uint64) uint64 {
	a := h.alloc(8 * len(vs))
	for i, v := range vs {
		h.w64(a+8*uint64(i), v)
	}
	return a
}
