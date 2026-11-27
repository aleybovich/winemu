package tests

import (
	"testing"
	"time"
)

// A program addressed without extension in a dotted directory
// (rel.1.0\bin\kid) is found by CreateProcess, system, _popen and cmd /C:
// testdata/src/c/exepath_dotdir.c.
func TestExePathDottedDir(t *testing.T) {
	r := runGuest(t, "exepath_dotdir.exe", guestOpts{Timeout: 60 * time.Second})
	want := "kid argc=2\ncreateprocess rel=7\n" +
		"kid argc=2\ncreateprocess abs=7\n" +
		"createprocess missing=1002\n" + // ERROR_FILE_NOT_FOUND
		"kid argc=2\nsystem=7\n" +
		"popen [kid argc=2] close=7\n" +
		"kid argc=2\ncmd=7\n"
	if r.Code != 0 || r.Stdout != want {
		t.Fatalf("code %d\nstdout:\n%s\nwant:\n%s\nstderr:\n%s", r.Code, r.Stdout, want, r.Stderr)
	}
}
