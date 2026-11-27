package tests

// WS-D: in-process child processes (testdata/src/c/mp_proc.c).

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestMultiprocessParentChild(t *testing.T) {
	r := runGuest(t, "mp_proc.exe", guestOpts{Args: []string{"parent"}, Timeout: 30 * time.Second})
	out := regexp.MustCompile(`(?m)^child \d+\n`).ReplaceAllString(r.Stdout, "")
	want := strings.Join([]string{
		"wait=0 code=7 pidmatch=1", // INFINITE wait on a child running past the deadlock window
		"thread wait=0",
		"running code=259",
		"open=1 same=1",
		"terminate=1",
		"terminated wait=0 code=42",
		"terminate again=0 err=5",
		"open stale=0 err=87",
		"event wait=0 child code=0",               // inherited handle, identical value
		"uninherited child code=106 signaled=258", // ERROR_INVALID_HANDLE in the child
		"waitall=0 codes=1,2",
	}, "\n") + "\n"
	if r.Code != 0 || out != want || r.Stderr != "" {
		t.Fatalf("code %d\nstdout:\n%s\nwant:\n%s\nstderr:\n%s", r.Code, out, want, r.Stderr)
	}
}

// The host exits with the root's exit code when the root exits; the child
// (still sleeping) is terminated and never prints.
func TestMultiprocessOrphanChild(t *testing.T) {
	r := runGuest(t, "mp_proc.exe", guestOpts{Args: []string{"orphan"}, Timeout: 30 * time.Second})
	if r.Code != 3 || r.Stdout != "parent done\n" {
		t.Fatalf("code %d stdout %q stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}

// A deadlocked child is ended by the detector; its waiting parent is not.
func TestMultiprocessDeadlockedChild(t *testing.T) {
	r := runGuest(t, "mp_proc.exe", guestOpts{Args: []string{"waitdeadlocked"}, Timeout: 30 * time.Second})
	if r.Code != 0 || r.Stdout != "wait=0 code=0xc0000194\n" || !strings.Contains(r.Stderr, "deadlock") {
		t.Fatalf("code %d stdout %q stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}

// qa_c_smoke "spawn" waits INFINITE for a child that sleeps far longer than
// the deadlock window: this must not be reported as a deadlock.
func TestMultiprocessInfiniteWaitNotDeadlock(t *testing.T) {
	r := runGuest(t, "qa_c_smoke.exe", guestOpts{Args: []string{"spawn"}, Timeout: 4 * time.Second, ExpectTimeout: true})
	if !r.TimedOut || strings.Contains(r.Stderr, "deadlock") {
		t.Fatalf("TimedOut %v stdout %q stderr %q", r.TimedOut, r.Stdout, r.Stderr)
	}
}
