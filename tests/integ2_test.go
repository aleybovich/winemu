package tests

// Cross-workstream integration of WS-E1 (sections, suspended start,
// VirtualAllocEx, DuplicateHandle, jobs), WS-E2 (named pipes, builtin cmd)
// and WS-B1/B2 (WSADuplicateSocket, overlapped sockets):
// testdata/src/c/integ_e1_e2_b2.c.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegE1E2B2(t *testing.T) {
	dir := t.TempDir()
	r := runGuest(t, "integ_e1_e2_b2.exe", guestOpts{Dir: dir, Timeout: 60 * time.Second})
	want := strings.Join([]string{
		"section=1 pipe=1 listen=1",
		"suspended injob=1 reserve=1 dupsock=0 dupevent=1",
		"resume=1", // previous suspend count of the CREATE_SUSPENDED child
		"pipe got [mapped at parent address: hello from parent]",
		"tcp reply [child got [ping]]",
		"event=0 child=0 counter=1",
		"cmd=0 log [injob=1 greeting=hello from parent counter=1]", // cmd's child joined the job
		"alive=258 after close=0 code=0",                           // kill-on-close
	}, "\n") + "\n"
	if r.Code != 0 || r.Stdout != want || r.Stderr != "" {
		t.Fatalf("code %d\nstdout:\n%s\nwant:\n%s\nstderr:\n%s", r.Code, r.Stdout, want, r.Stderr)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "integ_e1e2b2.log")); err != nil || !strings.HasPrefix(string(b), "injob=1 ") {
		t.Fatalf("log %q %v", b, err)
	}
}
