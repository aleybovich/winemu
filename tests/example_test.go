package tests

import (
	"fmt"
	"testing"
)

// Example guest test (testdata/src/go/example_env).
func TestExampleGoGuest(t *testing.T) {
	r := runGuest(t, "example_env.exe", guestOpts{Env: map[string]string{"WINEMU_EXAMPLE": "hello"}})
	want := fmt.Sprintf("pid=%d\nWINEMU_EXAMPLE=hello\n", r.Pid)
	if r.Code != 3 || r.Stdout != want || r.Stderr != "to stderr\n" {
		t.Fatalf("code %d, stdout %q (want %q), stderr %q", r.Code, r.Stdout, want, r.Stderr)
	}
}
