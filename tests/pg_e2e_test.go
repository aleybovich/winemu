package tests

// PostgreSQL end-to-end (plan §1.1, §1.2): initdb, pg_ctl start -w, a wire
// protocol client session and pg_ctl stop -w, all driven by one root guest
// (testdata/src/go/pg_e2e). Slow, so opt-in: WINEMU_INTEGRATION=1. The
// bundle defaults to the cph2.api release copy; override with WINEMU_PG_BUNDLE.

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const defaultPGBundle = "/Users/leyboan1/dev/eventhub/cme-eventhub/src/go/cph2.api/releases/win-amd64/cph2.api.0.67.7-FAT/postgres/embedded-postgres-binaries-windows-amd64-17.2.0.txz"

// winPath maps a host path to the guest's Z: drive.
func winPath(h string) string { return `Z:` + strings.ReplaceAll(h, "/", `\`) }

func TestPostgresE2E(t *testing.T) {
	if os.Getenv("WINEMU_INTEGRATION") != "1" {
		t.Skip("set WINEMU_INTEGRATION=1 to run")
	}
	bundle := os.Getenv("WINEMU_PG_BUNDLE")
	if bundle == "" {
		bundle = defaultPGBundle
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Skipf("PostgreSQL bundle not available: %v", err)
	}
	// A dotted directory name, like the release folders the bundle ships in.
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pg := filepath.Join(work, "pg.17.2")
	if err := os.MkdirAll(pg, 0o755); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	if out, err := exec.Command("tar", "-xJf", bundle, "-C", pg).CombinedOutput(); err != nil {
		t.Fatalf("extract %s: %v\n%s", bundle, err, out)
	}
	t.Logf("extract: %.1fs", time.Since(t0).Seconds())

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	t0 = time.Now()
	r := runGuest(t, "pg_e2e.exe", guestOpts{
		Dir:     work,
		Timeout: 20 * time.Minute,
		Env:     map[string]string{"PG_BUNDLE": winPath(pg), "PG_WORK": winPath(work), "PG_PORT": strconv.Itoa(port)},
	})
	t.Logf("guest: %.1fs, code %d\nstdout:\n%s\nstderr:\n%s", time.Since(t0).Seconds(), r.Code, r.Stdout, r.Stderr)
	if b, err := os.ReadFile(filepath.Join(work, "server.log")); err == nil {
		t.Logf("server.log:\n%s", b)
	}
	for _, want := range []string{
		"initdb: ok", "Success.", "pg_ctl start: ok", "server started",
		`query "SELECT version()" -> [["PostgreSQL 17.2`, `query "SELECT 1+1" -> [["2"]]`,
		"client: ok", "pg_ctl stop: ok", "server stopped",
	} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(r.Stderr, "unhandled exception") {
		t.Errorf("a guest process crashed: %s", r.Stderr)
	}
	if r.Code != 0 || strings.Contains(r.Stdout, "restricted token") {
		t.Errorf("code %d (restricted-token message present: %v)", r.Code, strings.Contains(r.Stdout, "restricted token"))
	}
}
