//go:build darwin || linux

package win

import (
	"sort"
	"testing"
)

// wsRet64 lists the winsock exports whose C return type is pointer-sized
// (SOCKET, HANDLE, pointers); every other export returns int/BOOL/DWORD/
// u_long/u_short and must leave the upper 32 bits of RAX clear.
var wsRet64 = map[string]bool{
	"socket": true, "WSASocketA": true, "WSASocketW": true, "accept": true, "WSAAccept": true,
	"WSACreateEvent": true, "gethostbyname": true, "gethostbyaddr": true, "getservbyname": true,
	"getservbyport": true, "getprotobyname": true, "getprotobynumber": true, "inet_ntoa": true,
	"inet_ntop": true, "InetNtopW": true, "WSAAsyncGetHostByAddr": true, "WSAAsyncGetHostByName": true,
	"WSAAsyncGetProtoByNumber": true, "WSAAsyncGetProtoByName": true, "WSAAsyncGetServByPort": true,
	"WSAAsyncGetServByName": true, "WSASetBlockingHook": true, "getnetbyname": true,
	"rcmd": true, "rexec": true, "rresvport": true,
}

// wsSkipSweep are exports that block or have no failure path with the
// sweep's arguments.
var wsSkipSweep = map[string]bool{}

// Every non-pointer-returning ws2_32/wsock32/mswsock export, called with an
// invalid socket and NULL pointers, returns a value whose upper 32 bits are
// zero (SOCKET_ERROR = 0x00000000FFFFFFFF, not 64-bit -1).
func TestWinsockReturnWidthSweep(t *testing.T) {
	for _, dll := range []string{"ws2_32.dll", "wsock32.dll", "mswsock.dll"} {
		tb := registry[dll]
		if tb == nil {
			continue
		}
		names := make([]string, 0, len(tb.funcs))
		for n := range tb.funcs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if wsRet64[n] || wsSkipSweep[n] {
				continue
			}
			h := wsaInit(t)
			r, exited, _ := h.tryCall(dll, n, 0x7770, 0, 0, 0, 0, 0, 0, 0, 0, 0)
			if exited {
				continue
			}
			if r>>32 != 0 {
				t.Errorf("%s!%s(bad args) = %#x: upper 32 bits set for a 32-bit return type", dll, n, r)
			}
		}
	}
}

// regWS keeps the full 64 bits for exports returning a pointer-sized type
// (WSACreateEvent returns a HANDLE) and truncates the rest to 32 bits.
func TestRegWSReturnWidth(t *testing.T) {
	h := wsaInit(t)
	var big uint64 = 0x1_2345_6789
	for _, n := range []string{"WSACreateEvent", "socket", "accept", "send"} {
		regWS("qa_width_test.dll", n, func(*Emu) uint64 { return big })
		got := registry["qa_width_test.dll"].funcs[n].fn(h.E)
		want := big
		if !wsRet64[n] {
			want = uint64(uint32(big))
		}
		if got != want {
			t.Errorf("regWS(%s) returned %#x, want %#x", n, got, want)
		}
	}
	delete(registry, "qa_width_test.dll")
}
