package win

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// resolveCaseWalk is the uncached reference: walk every component from the
// root, lstat-ing it and listing its directory when it does not exist.
func resolveCaseWalk(h string) string {
	if _, err := os.Lstat(h); err == nil {
		return h
	}
	parts := strings.Split(filepath.Clean(h), string(filepath.Separator))
	cur := string(filepath.Separator)
	for i, part := range parts {
		if part == "" {
			continue
		}
		next := filepath.Join(cur, part)
		if _, err := os.Lstat(next); err == nil {
			cur = next
			continue
		}
		ents, err := os.ReadDir(cur)
		found := false
		if err == nil {
			for _, en := range ents {
				if strings.EqualFold(en.Name(), part) {
					cur = filepath.Join(cur, en.Name())
					found = true
					break
				}
			}
		}
		if !found {
			return filepath.Join(append([]string{cur}, parts[i:]...)...)
		}
	}
	return cur
}

// TestResolveCaseMatchesWalk mutates a tree in quick succession (no delay:
// every change lands in the same timestamp tick as the previous listing) and
// checks after every step that the cached resolution equals the full walk.
func TestResolveCaseMatchesWalk(t *testing.T) {
	root := t.TempDir()
	queries := []string{
		"Dir", "dir", "DIR/file.TXT", "dir/FILE.txt", "dir/sub/x", "Dir/Sub/X", "dir/missing",
		"nodir/file", "DIR/other", "dir/Other/deep/y", "Dir/Link", "dir/link/z",
	}
	check := func(step string) {
		t.Helper()
		for _, q := range queries {
			h := filepath.Join(root, q)
			if got, want := resolveCase(h), resolveCaseWalk(h); got != want {
				t.Errorf("after %s: resolveCase(%s) = %s, want %s", step, q, got, want)
			}
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	p := func(s string) string { return filepath.Join(root, s) }
	check("empty")
	must(os.Mkdir(p("Dir"), 0o755))
	check("mkdir Dir")
	must(os.WriteFile(p("Dir/File.txt"), nil, 0o644))
	check("create File.txt")
	must(os.Rename(p("Dir/File.txt"), p("Dir/file.TXT2")))
	check("rename to file.TXT2")
	must(os.Rename(p("Dir/file.TXT2"), p("Dir/FILE.TXT")))
	check("rename to FILE.TXT")
	must(os.Remove(p("Dir/FILE.TXT")))
	check("delete")
	must(os.MkdirAll(p("Dir/SUB"), 0o755))
	must(os.WriteFile(p("Dir/SUB/X"), nil, 0o644))
	check("mkdir SUB/X")
	must(os.Symlink(p("Dir/SUB"), p("Dir/LINK")))
	must(os.WriteFile(p("Dir/SUB/z"), nil, 0o644))
	check("symlink")
	must(os.Remove(p("Dir/LINK")))
	must(os.Symlink(p("nowhere"), p("Dir/LINK")))
	check("dangling symlink")
	must(os.RemoveAll(p("Dir/SUB")))
	check("rmdir SUB")
	must(os.Rename(p("Dir"), p("dIR")))
	check("rename dir")
	must(os.MkdirAll(p("dIR/OTHER/Deep"), 0o755))
	check("mkdir deep")
	must(os.RemoveAll(p("dIR")))
	check("remove all")
}

// TestResolveCaseConcurrent resolves from several goroutines while others
// mutate the directory (run with -race).
func TestResolveCaseConcurrent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "D"), 0o755); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				name := filepath.Join(root, "D", fmt.Sprintf("F%d_%d", g, i))
				if g%2 == 0 {
					os.WriteFile(name, nil, 0o644)
				}
				got := resolveCase(filepath.Join(root, "d", fmt.Sprintf("f%d_%d", g, i)))
				if g%2 == 0 {
					if _, err := os.Lstat(got); err != nil {
						t.Errorf("resolved %s does not exist", got)
						return
					}
					os.Remove(name)
				}
			}
		}()
	}
	wg.Wait()
}
