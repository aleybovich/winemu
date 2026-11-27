package tests

// Helpers for guest tests: run one Windows program from testdata/bin under
// the winemu binary built by TestMain (e2e_test.go).
//
//	r := runGuest(t, "example_env.exe", guestOpts{
//		Args:    []string{"a", "b"},           // program arguments
//		Stdin:   "input",                      // standard input
//		Env:     map[string]string{"FOO": "1"}, // guest env vars (passed as WINEMU_ENV_FOO)
//		Flags:   []string{"-lenient"},         // winemu flags, before the exe
//		Timeout: 10 * time.Second,             // default 60s; the test fails on timeout
//		Dir:     dir,                          // host working dir (default: a fresh t.TempDir())
//	})
//	r.Code, r.Stdout, r.Stderr, r.Pid  // exit code (low 8 bits), output, host pid of winemu
//
// Each run gets its own fresh prefix (-prefix <tmp>/prefix). A missing exe
// fails the test with a hint to run `make testbins`. On timeout (and after a
// normal exit) winemu's whole process group, including child winemu
// processes started by guest CreateProcess, is killed. Unix hosts only.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type guestOpts struct {
	Args    []string
	Stdin   string
	Env     map[string]string
	Flags   []string
	Timeout time.Duration
	Dir     string
	// ExpectTimeout makes a timeout a normal outcome (r.TimedOut) instead
	// of a test failure, e.g. for servers that run until killed.
	ExpectTimeout bool
}

type guestResult struct {
	Code           int
	Stdout, Stderr string
	Pid            int
	TimedOut       bool // only with guestOpts.ExpectTimeout
}

func runGuest(t *testing.T, exe string, o guestOpts) guestResult {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "testdata", "bin", exe))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s not built (run `make testbins`): %v", exe, err)
	}
	work := t.TempDir()
	if o.Dir == "" {
		o.Dir = work
	}
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	// Stdio goes through files, not pipes: a child winemu inherits the std
	// handles, and a pipe it holds open would keep cmd.Wait blocked after
	// the guest exited or was killed.
	ioDir := t.TempDir()
	stdinPath, stdoutPath, stderrPath := filepath.Join(ioDir, "stdin"), filepath.Join(ioDir, "stdout"), filepath.Join(ioDir, "stderr")
	if err := os.WriteFile(stdinPath, []byte(o.Stdin), 0o644); err != nil {
		t.Fatal(err)
	}
	stdin, err := os.Open(stdinPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()
	args := append(append([]string{"-prefix", filepath.Join(work, "prefix")}, o.Flags...), path)
	cmd := exec.CommandContext(ctx, winemuBin, append(args, o.Args...)...)
	cmd.Dir = o.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Env = os.Environ()
	for k, v := range o.Env {
		cmd.Env = append(cmd.Env, "WINEMU_ENV_"+k+"="+v)
	}
	// winemu and the child winemu processes it spawns for guest
	// CreateProcess share a new process group; kill all of them on timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	err = cmd.Run()
	r := guestResult{}
	if cmd.Process != nil {
		r.Pid = cmd.Process.Pid
		// Reap children the guest left running. ESRCH (none left) is expected.
		_ = syscall.Kill(-r.Pid, syscall.SIGKILL)
	}
	r.Stdout, r.Stderr = readFile(t, stdoutPath), readFile(t, stderrPath)
	if ctx.Err() != nil {
		if o.ExpectTimeout {
			r.TimedOut = true
			return r
		}
		t.Fatalf("%s timed out after %v\nstdout:\n%s\nstderr:\n%s", exe, o.Timeout, r.Stdout, r.Stderr)
	}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.Code = ee.ExitCode()
	case err != nil:
		t.Fatalf("running %s: %v", exe, err)
	}
	return r
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
