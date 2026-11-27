package tests

// Cross-workstream integration (WS-B1 sockets + WS-D processes).

import (
	"testing"
	"time"
)

func TestIntegProcessSockets(t *testing.T) {
	r := runGuest(t, "integ_proc_sock.exe", guestOpts{Timeout: 30 * time.Second})
	want := "accept=1\nparent got=ping\nsend=4\nreader got=bye\nwait=0 child code=7\n"
	if r.Code != 0 || r.Stdout != want || r.Stderr != "" {
		t.Fatalf("code %#x\nstdout:\n%s\nwant:\n%s\nstderr:\n%s", r.Code, r.Stdout, want, r.Stderr)
	}
}
