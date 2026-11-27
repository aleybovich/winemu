package tests

import (
	"strings"
	"testing"
	"time"
)

// Message-mode named pipe served by a signal thread with an overlapped
// ConnectNamedPipe; a child process talks to it with CallNamedPipe.
func TestIPCNamedPipeMessageCall(t *testing.T) {
	r := runGuest(t, "ipc_pipe.exe", guestOpts{Args: []string{"msg"}, Timeout: 30 * time.Second})
	want := "call a -> b n=1\ncall b -> c n=1\ncall c -> d n=1\nmissing ok=0 err=2\nclient code=7 served=3\n"
	if r.Code != 0 || r.Stdout != want {
		t.Fatalf("code %d stdout %q stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}

// Byte-mode pipe with two instances served concurrently to two clients in
// other processes; a closed client is a broken pipe for the server.
func TestIPCNamedPipeMultiInstance(t *testing.T) {
	r := runGuest(t, "ipc_pipe.exe", guestOpts{Args: []string{"multi"}, Timeout: 30 * time.Second})
	lines := strings.Split(strings.TrimSpace(r.Stdout), "\n")
	got := map[string]bool{}
	for _, l := range lines {
		got[l] = true
	}
	if r.Code != 0 || len(lines) != 3 || !got["ack client 1"] || !got["ack client 2"] || !got["clients 11 12 instances 109 109"] {
		t.Fatalf("code %d stdout %q stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}

// Builtin cmd.exe with quoting and redirections, _popen in both modes,
// system() (blocking only the calling thread), RegisterWaitForSingleObject
// on a child process handle.
func TestIPCCmdPopenSystemRegisterWait(t *testing.T) {
	r := runGuest(t, "ipc_cmd.exe", guestOpts{Args: []string{"run"}, Timeout: 60 * time.Second})
	log := "log: arg[0]=a b\nlog: arg[1]=c\nlog: to stderr\nlog: stdin=-1\n"
	want := strings.Join([]string{
		`comspec=C:\windows\system32\cmd.exe`,
		"cmd ok=1 code=42",
		"cmd ok=1 code=42",
		strings.TrimSuffix(log+log, "\n"),
		"popen: ipc_cmd child 1.0",
		"pclose=0",
		"cat got 13 [to child more] eof=1 err=0",
		"pclose w=5",
		"system=3 ticked=1",
		"system exit=4",
		"system missing=1",
		"system(NULL)=1",
		"regwait ok=1 wait=0 fired=1 code=3",
		"unregister=1",
		"ctrl=1",
	}, "\n") + "\n"
	if r.Code != 0 || r.Stdout != want || !strings.Contains(r.Stderr, "'no_such_program_xyz' is not recognized") {
		t.Fatalf("code %d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Stdout, r.Stderr)
	}
}
