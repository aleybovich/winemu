//go:build darwin || linux

package win

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// slowResolver replaces the host resolver for one test: every lookup takes
// d and then returns addrs (none: not found).
func slowResolver(t *testing.T, d time.Duration, addrs ...netip.Addr) {
	t.Helper()
	old := hostLookupIP
	hostLookupIP = func(ctx context.Context, node string) ([]netip.Addr, error) {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if len(addrs) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: node, IsNotFound: true}
		}
		return addrs, nil
	}
	t.Cleanup(func() { hostLookupIP = old })
}

// A slow host name lookup in one guest thread must not stall the others.
func TestWinsockLookupDoesNotStallOtherThreads(t *testing.T) {
	slowResolver(t, 1500*time.Millisecond, netip.MustParseAddr("10.1.2.3"))
	h := wsaInit(t)
	ws := h.call(dK32, "LoadLibraryA", h.astr(ws2))
	ghbn := h.call(dK32, "GetProcAddress", ws, h.astr("gethostbyname"))
	th := h.call(dK32, "CreateThread", 0, 0, ghbn, h.astr("slow.example"), 0, 0)
	if th == 0 {
		t.Fatalf("CreateThread err %d", h.lastError())
	}
	start := time.Now()
	for range 5 {
		h.call(dK32, "Sleep", 10) // lets the resolver thread run
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("main thread stalled %v while another thread resolved a name", el)
	}
	if r := h.call(dK32, "WaitForSingleObject", th, 10000); r != 0 {
		t.Fatalf("resolver thread wait = %#x", r)
	}
	code := h.alloc(4)
	h.call(dK32, "GetExitCodeThread", th, code)
	if h.r32(code) == 0 {
		t.Fatalf("gethostbyname in thread returned NULL")
	}
	// the result is delivered to the re-executed call: getaddrinfo on main
	res := h.alloc(8)
	if r := h.call(ws2, "getaddrinfo", h.astr("slow.example"), 0, 0, res); r != 0 {
		t.Fatalf("getaddrinfo = %d", r)
	}
	sa := h.r64(h.r64(res) + 32) // ai_addr (Win64 layout)
	if got := h.read(sa+4, 4); got[0] != 10 || got[3] != 3 {
		t.Fatalf("getaddrinfo address %v, want 10.1.2.3", got)
	}
	h.call(ws2, "freeaddrinfo", h.r64(res))
}

// Real resolver: an unresolvable name fails with WSAHOST_NOT_FOUND (or
// WSATRY_AGAIN when no DNS is reachable) and leaves *res NULL.
func TestWinsockLookupInvalidName(t *testing.T) {
	h := wsaInit(t)
	res := h.alloc(8)
	h.w64(res, 0x1234)
	r := h.call(ws2, "getaddrinfo", h.astr("nonexistent.invalid"), 0, 0, res)
	if (r != wsaHOSTNOTFOUND && r != wsaTRYAGAIN) || h.lastError() != uint32(r) || h.r64(res) != 0 {
		t.Fatalf("getaddrinfo = %d err %d res %#x", r, h.lastError(), h.r64(res))
	}
	if p := h.call(ws2, "gethostbyname", h.astr("nonexistent.invalid")); p != 0 {
		t.Fatalf("gethostbyname = %#x, want NULL", p)
	}
}
