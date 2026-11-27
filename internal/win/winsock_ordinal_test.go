//go:build darwin || linux

package win

import "testing"

// TestWinsockConsumerOrdinals pins, independently of ws2Ordinals /
// wsock32Ordinals, every by-ordinal import a real consumer uses to the
// function the classic Winsock numbering assigns it. Each must be
// implemented (no unimplemented stub) and resolve to the same address as
// the by-name export.
func TestWinsockConsumerOrdinals(t *testing.T) {
	common := map[uint32]string{
		1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 6: "getsockname", 7: "getsockopt",
		8: "htonl", 9: "htons", 13: "listen", 15: "ntohs", 16: "recv", 17: "recvfrom", 18: "select",
		19: "send", 20: "sendto", 21: "setsockopt", 22: "shutdown", 23: "socket",
		51: "gethostbyaddr", 52: "gethostbyname", 55: "getservbyname", 56: "getservbyport",
		111: "WSAGetLastError", 112: "WSASetLastError", 115: "WSAStartup", 116: "WSACleanup",
	}
	want := map[string]map[uint32]string{
		"ws2_32.dll":  {10: "ioctlsocket", 11: "inet_addr", 12: "inet_ntoa"},
		"wsock32.dll": {10: "inet_addr", 11: "inet_ntoa", 12: "ioctlsocket", 151: "__WSAFDIsSet"},
	}
	for _, m := range want {
		for o, n := range common {
			m[o] = n
		}
	}
	h := wsaInit(t)
	for dll, ords := range want {
		mod := h.call(dK32, "LoadLibraryA", h.astr(dll))
		if mod == 0 {
			t.Fatalf("LoadLibrary(%s) err %d", dll, h.lastError())
		}
		for o, n := range ords {
			if d := registry[dll].funcs[n]; d == nil || d.fn == nil {
				t.Errorf("%s!%s (ordinal %d) not implemented", dll, n, o)
				continue
			}
			byOrd := h.call(dK32, "GetProcAddress", mod, uint64(o))
			byName := h.call(dK32, "GetProcAddress", mod, h.astr(n))
			if byOrd == 0 || byOrd != byName {
				t.Errorf("%s: #%d -> %#x, want %s (%#x)", dll, o, byOrd, n, byName)
			}
		}
	}
	if d := registry["ws2_32.dll"].funcs["inet_ntop"]; d == nil || d.fn == nil {
		t.Errorf("ws2_32!inet_ntop not implemented")
	}
}
