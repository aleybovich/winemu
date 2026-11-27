package tests

// WS0 QA: guest-test plumbing (C build path, args/stdin/env/exit code, timeouts).

import (
	"os"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestQAWS0CGuestPlumbing(t *testing.T) {
	r := runGuest(t, "qa_c_smoke.exe", guestOpts{
		Args:  []string{"echo", "7", "a b", `q"x`, ""},
		Stdin: "line1\nline2",
		Env:   map[string]string{"QA_VAR": "v=1 2"},
	})
	want := "argc=6 wargc=6\narg[0]=a b\narg[1]=q\"x\narg[2]=\nstdin=line1\nline2\nQA_VAR=v=1 2\n"
	if r.Code != 7 || r.Stdout != want || r.Stderr != "to stderr\n" {
		t.Fatalf("code %d\nstdout %q\nwant   %q\nstderr %q", r.Code, r.Stdout, want, r.Stderr)
	}

	// unset variable, empty stdin, exit code 0
	r = runGuest(t, "qa_c_smoke.exe", guestOpts{Args: []string{"echo", "0"}})
	if r.Code != 0 || r.Stdout != "argc=3 wargc=3\nstdin=\nQA_VAR=(unset)\n" {
		t.Fatalf("code %d stdout %q", r.Code, r.Stdout)
	}
}

// processAlive reports whether host pid exists (and is not a zombie we own).
func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("process %d still running after the guest timed out", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestQAWS0Timeout(t *testing.T) {
	start := time.Now()
	r := runGuest(t, "qa_c_smoke.exe", guestOpts{Args: []string{"sleep", "600000"}, Timeout: 1500 * time.Millisecond, ExpectTimeout: true})
	if el := time.Since(start); !r.TimedOut || el > 10*time.Second {
		t.Fatalf("TimedOut %v after %v", r.TimedOut, el)
	}
	if r.Stdout != "sleeping\n" {
		t.Fatalf("stdout before timeout = %q", r.Stdout)
	}
	waitGone(t, r.Pid)

	// A timed-out guest that started a child (in-process): runGuest must
	// still return promptly and the host process must be gone.
	start = time.Now()
	r = runGuest(t, "qa_c_smoke.exe", guestOpts{Args: []string{"spawn"}, Timeout: 3 * time.Second, ExpectTimeout: true})
	if el := time.Since(start); !r.TimedOut || el > 15*time.Second {
		t.Fatalf("spawn: TimedOut %v after %v, stdout %q", r.TimedOut, el, r.Stdout)
	}
	m := regexp.MustCompile(`child=(\d+)`).FindStringSubmatch(r.Stdout)
	if m == nil {
		t.Fatalf("spawn: no child pid in stdout %q (stderr %q)", r.Stdout, r.Stderr)
	}
	waitGone(t, r.Pid)
	// Child processes run inside the same winemu host (docs/multiprocess.md);
	// their guest pids are kernel ids, distinct from the root's (host) pid.
	child, err := strconv.Atoi(m[1])
	if err != nil || child == os.Getpid() || child == r.Pid {
		t.Fatalf("unexpected child pid %q", m[1])
	}
}
