//go:build !darwin && !linux

package win

import "time"

// Hosts without the BSD socket layer used by winsock.go: winsock calls
// fail with WSAENETDOWN.

type netState struct{}

func (e *Emu) pollNet(time.Time)     {}
func (e *Emu) netEventsActive() bool { return false }

// alertWait: no overlapped sockets, so no completion routines to run.
func (e *Emu) alertWait(_ bool, wait func() uint64) uint64 { return wait() }

func (e *Emu) runAlertAPCs(bool) bool { return false }
func (e *Emu) wakeOnAPC(bool)         {}

func (e *Emu) cancelSockIo(uint64, *Thread, uint64) (int, bool) { return 0, false }

func init() {
	w := "ws2_32.dll"
	reg(w, "WSAStartup", func(e *Emu) uint64 { return 10050 })
	reg(w, "WSACleanup", retZero)
	reg(w, "WSAGetLastError", func(e *Emu) uint64 { return uint64(e.LastError()) })
	reg(w, "WSASetLastError", func(e *Emu) uint64 { e.SetLastError(e.Arg32(0)); return 0 })
	for _, n := range []string{"socket", "WSASocketW", "WSASocketA", "getaddrinfo", "GetAddrInfoW"} {
		reg(w, n, func(e *Emu) uint64 { e.SetLastError(10050); return ^uint64(0) })
	}
}
