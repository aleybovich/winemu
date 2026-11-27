package tests

import (
	"strings"
	"testing"
)

// syscall.Errno.Error under winemu (testdata/src/go/formatmsg_errno): system
// texts without the trailing CRLF, inserts left as-is, and Go's fallback for
// a code without a message (FormatMessageW fails).
func TestFormatMessageGoErrno(t *testing.T) {
	r := runGuest(t, "formatmsg_errno.exe", guestOpts{})
	if r.Code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Stdout, r.Stderr)
	}
	want := []string{
		"10061=No connection could be made because the target machine actively refused it.",
		"2=The system cannot find the file specified.",
		"193=%1 is not a valid Win32 application.",
		"57005=winapi error #57005",
	}
	got := strings.Split(strings.TrimRight(strings.ReplaceAll(r.Stdout, "\r\n", "\n"), "\n"), "\n")
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
