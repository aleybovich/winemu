package tests

// WS-E1 QA: testdata/src/c/xproc_qa.c.

import (
	"strings"
	"testing"
	"time"
)

func runXprocQA(t *testing.T, mode string, want ...string) {
	t.Helper()
	r := runGuest(t, "xproc_qa.exe", guestOpts{Args: []string{mode}, Timeout: 30 * time.Second})
	w := strings.Join(want, "\n") + "\n"
	if r.Code != 0 || r.Stdout != w || r.Stderr != "" {
		t.Fatalf("code %d\nstdout:\n%s\nwant:\n%s\nstderr:\n%s", r.Code, r.Stdout, w, r.Stderr)
	}
}

// A child that never idles must still let another process read its memory.
func TestXprocQABusyTarget(t *testing.T) {
	runXprocQA(t, "spin", "rpm busy child ok=50 code=0")
}

// MEM_RESERVE pages fault; a vectored handler commits them on demand.
func TestXprocQAReserveCommitOnFault(t *testing.T) {
	runXprocQA(t, "reserve",
		"reserved state=0x2000 protect=0",
		"faults=4 sum=10 committed state=0x1000 size=0x1000",
		"decommit=1 state=0x2000 release=1",
	)
}
