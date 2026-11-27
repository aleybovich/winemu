package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFiberGuest(t *testing.T) {
	r := runGuest(t, "rt_fiber.exe", guestOpts{})
	want := "trace: 10 20 11 21 12 22\nacc: 1.5 3.0 local: 10.00\nok\n"
	if r.Code != 0 || r.Stdout != want {
		t.Fatalf("code %d\nstdout %q\nwant   %q\nstderr %s", r.Code, r.Stdout, want, r.Stderr)
	}
}

// pgBundle is the embedded-postgres Windows bundle with MSVC-built DLLs
// (override with WINEMU_PG_BUNDLE).
const pgBundle = "/Users/leyboan1/dev/eventhub/cme-eventhub/src/go/cph2.api/releases/win-amd64/cph2.api.0.67.7-FAT/postgres/embedded-postgres-binaries-windows-amd64-17.2.0.txz"

func TestNativeMSVCDLLs(t *testing.T) {
	archive := pgBundle
	if p := os.Getenv("WINEMU_PG_BUNDLE"); p != "" {
		archive = p
	}
	if _, err := os.Stat(archive); err != nil {
		t.Skipf("PG bundle not available: %v", err)
	}
	dir := t.TempDir()
	cmd := exec.Command("tar", "-xJf", archive, "-C", dir, "bin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("extracting %s: %v\n%s", archive, err, out)
	}
	bin := filepath.Join(dir, "bin")
	r := runGuest(t, "rt_nativedlls.exe", guestOpts{
		Dir:     bin,
		Env:     map[string]string{"DLL_DIR": "Z:" + strings.ReplaceAll(bin, "/", `\`)},
		Timeout: 5 * time.Minute,
	})
	want := []string{"u_init: U_ZERO_ERROR\n", "upper: \"HELLO, WÖRLD SS\" 15 U_ZERO_ERROR\n", "openssl: OpenSSL 3.", "RAND_bytes: 1 random=true\n"}
	for _, w := range want {
		if !strings.Contains(r.Stdout, w) {
			t.Fatalf("missing %q\ncode %d\nstdout:\n%s\nstderr:\n%s", w, r.Code, r.Stdout, r.Stderr)
		}
	}
	if r.Code != 0 {
		t.Fatalf("code %d\nstderr:\n%s", r.Code, r.Stderr)
	}
}
