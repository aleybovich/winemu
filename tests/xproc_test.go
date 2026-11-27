package tests

// WS-E1: cross-process memory & handles (testdata/src/c/xproc.c).

import (
	"strings"
	"testing"
	"time"
)

func runXproc(t *testing.T, mode string, want ...string) {
	t.Helper()
	r := runGuest(t, "xproc.exe", guestOpts{Args: []string{mode}, Timeout: 60 * time.Second})
	w := strings.Join(want, "\n") + "\n"
	if r.Code != 0 || r.Stdout != w || r.Stderr != "" {
		t.Fatalf("code %d\nstdout:\n%s\nwant:\n%s\nstderr:\n%s", r.Code, r.Stdout, w, r.Stderr)
	}
}

// Suspended child, VirtualAllocEx reservation, named section mapped at the
// same fixed address in both processes, shared counter, duplicated event.
func TestXprocSharedMemory(t *testing.T) {
	runXproc(t, "shm",
		"create=1 err=0",
		"reserve same=1",
		"query=1 reserved=1",
		"wpm=1/18 rpm=1/18 written by parent",
		"dup=1",
		"resume=1",                               // previous suspend count
		"event=0 child=0 code=0 counter=2000000", // child code 0: every child check passed
	)
}

func TestXprocJob(t *testing.T) {
	runXproc(t, "job",
		"setinfo=1",
		"before assign injob=0",
		"assign=1",
		"after assign injob=1",
		"ready=0",
		"grandchild injob=1 breakaway err=5", // ERROR_ACCESS_DENIED without BREAKAWAY_OK
		"active=2 total=2",
		"child alive=258",
		"after close child=0 grandchild=0", // kill-on-close
	)
}

func TestXprocCreateProcessAsUser(t *testing.T) {
	runXproc(t, "asuser",
		"asuser=1 code=9",
		"bad token=0 err=6", // ERROR_INVALID_HANDLE
	)
}

// Exit code bit 0/1: the child could SetEvent the inherited value of a/b.
func TestXprocHandleList(t *testing.T) {
	runXproc(t, "handlelist",
		"all: code=3 a=0 b=0",
		"probe=0 err=122 size>0=1", // ERROR_INSUFFICIENT_BUFFER size probe
		"init=1 update=1",
		"list: code=1 a=0 b=258",
	)
}
