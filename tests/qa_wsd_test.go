package tests

// WS-D QA guest tests (testdata/src/c/qa_wsd.c).

import (
	"testing"
	"time"
)

// A read on an empty kernel pipe blocks only the calling thread.
func TestQAWSDPipeReadBlocksThreadOnly(t *testing.T) {
	for _, api := range []string{"readfile", "crtread", "ntread"} {
		t.Run(api, func(t *testing.T) {
			r := runGuest(t, "qa_wsd.exe", guestOpts{Args: []string{"pipethread", api}, Timeout: 8 * time.Second})
			want := api + " wait=0 got=1 byte=x mainran=1000\n"
			if r.TimedOut || r.Code != 0 || r.Stdout != want {
				t.Fatalf("timedOut %v code %d stdout %q want %q stderr %q", r.TimedOut, r.Code, r.Stdout, want, r.Stderr)
			}
		})
	}
}

// CreateFile's bInheritHandle decides whether a child (bInheritHandles=TRUE)
// can use the same handle value.
func TestQAWSDCreateFileInheritable(t *testing.T) {
	r := runGuest(t, "qa_wsd.exe", guestOpts{Args: []string{"inheritfile"}, Timeout: 20 * time.Second})
	want := "inherit=1 child=11 write=1 content=inherited+parent\n" +
		"inherit=0 child=106 write=1 content=+parent\n" // ERROR_INVALID_HANDLE in the child
	if r.Code != 0 || r.Stdout != want {
		t.Fatalf("code %d stdout %q want %q stderr %q", r.Code, r.Stdout, want, r.Stderr)
	}
}

// The host exits when the root process exits, with its code, ending every
// other guest process (children and grandchildren that would run forever).
func TestQAWSDRootExitEndsSession(t *testing.T) {
	start := time.Now()
	r := runGuest(t, "qa_wsd.exe", guestOpts{Args: []string{"rootexit"}, Timeout: 15 * time.Second})
	if r.TimedOut || r.Code != 9 || r.Stdout != "root done\n" {
		t.Fatalf("timedOut %v code %d stdout %q stderr %q", r.TimedOut, r.Code, r.Stdout, r.Stderr)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("host exit took %v", el)
	}
}

// TerminateProcess ends a process blocked in a host-style wait (CRT stream
// read on an empty pipe).
func TestQAWSDTerminateBlockedInRead(t *testing.T) {
	r := runGuest(t, "qa_wsd.exe", guestOpts{Args: []string{"terminatehost"}, Timeout: 20 * time.Second})
	if r.Code != 0 || r.Stdout != "terminate=1 wait=0 code=77\n" {
		t.Fatalf("code %d stdout %q stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}
