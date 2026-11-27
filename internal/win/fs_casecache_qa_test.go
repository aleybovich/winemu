package win

import (
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A tool that restores a directory's modification time after changing it
// (tar, rsync -t, cp -p) must not make a cached listing look current.
func TestResolveCaseMtimeRestored(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "D")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	must(os.Mkdir(d, 0o755))
	must(os.WriteFile(filepath.Join(d, "a"), nil, 0o644))
	must(os.Chtimes(d, old, old))
	if got, want := resolveCase(filepath.Join(root, "d", "zz")), resolveCaseWalk(filepath.Join(root, "d", "zz")); got != want {
		t.Fatalf("prime: %s, want %s", got, want)
	}
	must(os.WriteFile(filepath.Join(d, "New"), nil, 0o644))
	must(os.Chtimes(d, old, old))
	for _, q := range []string{"d/new", "D/NEW"} {
		h := filepath.Join(root, q)
		got := resolveCase(h)
		if want := resolveCaseWalk(h); got != want {
			t.Errorf("resolveCase(%s) = %s, want %s", q, got, want)
		}
		if _, err := os.Lstat(got); err != nil {
			t.Errorf("resolveCase(%s) = %s does not exist", q, got)
		}
	}
}

// Changes made by another (host) process between guest calls, case-only
// renames and deep trees: every resolution matches the uncached walk.
func TestResolveCaseHostChanges(t *testing.T) {
	root := t.TempDir()
	p := func(s string) string { return filepath.Join(root, s) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	deep := "A/b/C/d/E/f/G/h"
	must(os.MkdirAll(p(deep), 0o755))
	check := func(step string, qs ...string) {
		t.Helper()
		for _, q := range qs {
			h := p(q)
			if got, want := resolveCase(h), resolveCaseWalk(h); got != want {
				t.Errorf("after %s: resolveCase(%s) = %s, want %s", step, q, got, want)
			}
		}
	}
	qs := []string{"a/B/c/D/e/F/g/H/x", "A/b/C/d/E/f/G/h/X", "a/b/c/d/e/f/g/h"}
	check("mkdir", qs...)
	for i := range 20 { // rapid same-tick churn, alternating case
		n := "x"
		if i%2 == 1 {
			n = "X"
		}
		must(os.WriteFile(p(deep+"/"+n), nil, 0o644))
		check("create "+n, qs...)
		if i%3 == 0 {
			must(os.Rename(p(deep+"/"+n), p(deep+"/tmp")))
			must(os.Rename(p(deep+"/tmp"), p(deep+"/"+n)))
			check("rename round trip", qs...)
		}
		must(os.Remove(p(deep + "/" + n)))
		check("remove "+n, qs...)
	}
	must(os.Rename(p("A/b/C"), p("A/b/c")))
	check("case-only rename of a middle dir", qs...)
	must(os.Rename(p("A/b/c"), p("A/b/C")))
	check("case-only rename back", qs...)
}

// caseSensitive reports whether dir's filesystem distinguishes case; the
// case-correction path is unreachable on a case-insensitive one.
func caseSensitive(t *testing.T, dir string) bool {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "probe"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filepath.Join(dir, "probe"))
	_, err := os.Lstat(filepath.Join(dir, "PROBE"))
	return err != nil
}

// An exactly matching name wins over an earlier case variant.
func TestResolveCaseExactWins(t *testing.T) {
	root := t.TempDir()
	if !caseSensitive(t, root) {
		t.Skip("needs a case-sensitive filesystem (TMPDIR)")
	}
	for _, n := range []string{"A", "a", "B"} {
		if err := os.WriteFile(filepath.Join(root, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for q, want := range map[string]string{"a": "a", "A": "A", "b": "B"} {
		if got := resolveCase(filepath.Join(root, q)); got != filepath.Join(root, want) {
			t.Errorf("resolveCase(%s) = %s, want %s", q, got, want)
		}
	}
}

// A cached listing that is wrong although the directory looks unchanged (a
// filesystem with an unreliable clock) is detected by verifying the match,
// then re-read once.
func TestResolveCaseStaleListing(t *testing.T) {
	root := t.TempDir()
	if !caseSensitive(t, root) {
		t.Skip("needs a case-sensitive filesystem (TMPDIR)")
	}
	d := filepath.Join(root, "D")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "FILE"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(d)
	if err != nil {
		t.Fatal(err)
	}
	dirCache.Lock()
	dirCache.m[d] = &dirListing{mtime: changeTime(st), listed: time.Now().Add(time.Hour), names: []string{"File"}}
	dirCache.Unlock()
	if got, want := resolveCase(filepath.Join(d, "file")), filepath.Join(d, "FILE"); got != want {
		t.Errorf("resolveCase(D/file) = %s, want %s", got, want)
	}
}

// On a filesystem with whole-second timestamps a change in the same second
// as the listing must not be missed.
func TestResolveCaseSameSecond(t *testing.T) {
	root := t.TempDir()
	if !caseSensitive(t, root) {
		t.Skip("needs a case-sensitive filesystem (TMPDIR)")
	}
	for range 3 {
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 50*time.Millisecond)))
		d, err := os.MkdirTemp(root, "s")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "X1"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		resolveCase(filepath.Join(d, "x1"))
		time.Sleep(300 * time.Millisecond)
		if err := os.WriteFile(filepath.Join(d, "X2"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if got, want := resolveCase(filepath.Join(d, "x2")), filepath.Join(d, "X2"); got != want {
			t.Errorf("resolveCase(x2) = %s, want %s", got, want)
		}
	}
}

// Random same-tick churn (creates, removes, case-only renames, nested dirs;
// some done by a host shell process) checked against the uncached walk after
// every step.
func TestQAResolveCaseRandomOps(t *testing.T) {
	root := t.TempDir()
	if !caseSensitive(t, root) {
		t.Skip("needs a case-sensitive filesystem (TMPDIR)")
	}
	names := []string{"a", "A", "b", "B"}
	var qs []string
	for _, x := range names {
		for _, y := range names {
			qs = append(qs, x, filepath.Join(x, y), filepath.Join(x, y, "f"))
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	pick := func() string { return names[rng.IntN(len(names))] }
	for i := range 300 {
		p := filepath.Join(root, pick())
		if rng.IntN(2) == 0 {
			p = filepath.Join(p, pick())
		}
		q := filepath.Join(filepath.Dir(p), pick())
		shell := i%10 == 0
		op := rng.IntN(4) // ops may fail (missing source, file in the way): that is part of the churn
		switch {
		case shell && op == 0:
			_ = exec.Command("mkdir", "-p", p).Run()
		case shell && op == 1:
			_ = exec.Command("rm", "-rf", p).Run()
		case shell:
			_ = exec.Command("mv", p, q).Run()
		case op == 0:
			_ = os.MkdirAll(p, 0o755)
		case op == 1:
			_ = os.WriteFile(filepath.Join(p, "f"), nil, 0o644)
		case op == 2:
			_ = os.RemoveAll(p)
		default:
			_ = os.Rename(p, q) // case-only or to a sibling
		}
		for _, s := range qs {
			h := filepath.Join(root, s)
			if got, want := resolveCase(h), resolveCaseWalk(h); got != want {
				t.Fatalf("step %d: resolveCase(%s) = %s, want %s", i, s, got, want)
			}
		}
	}
}
