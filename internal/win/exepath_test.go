package win

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWinExt(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`prog`, ""},
		{`prog.exe`, ".exe"},
		{`prog.`, "."},
		{`a.b\prog`, ""},
		{`Z:\tmp\x.2s08\postgres\bin\initdb`, ""},
		{`C:/rel.1/dir/prog`, ""},
		{`C:\a.b/prog.com`, ".com"},
		{`C:a.b`, ".b"},
		{`a.b\prog.tar.gz`, ".gz"},
	} {
		if got := winExt(c.in); got != c.want {
			t.Errorf("winExt(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// dottedDir creates <tmp>/rel.1.0/bin holding the given files; it returns
// the host directory and its Windows path.
func dottedDir(t *testing.T, h *testEmu, files ...string) (string, string) {
	t.Helper()
	host := filepath.Join(t.TempDir(), "rel.1.0", "bin")
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(host, f), []byte("MZ"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return host, h.E.fs.toWin(host)
}

// CreateProcess appends .exe when the last path component has no extension,
// whatever dots the directories contain.
func TestSearchExeDottedDir(t *testing.T) {
	h := newTestEmu(t)
	host, win := dottedDir(t, h, "prog.exe", "prog.com", "data.txt")
	want := filepath.Join(host, "prog.exe")
	for _, name := range []string{win + `\prog`, win + `/prog`, win + `\prog.exe`} {
		if got := h.E.searchExe(name); got != want {
			t.Errorf("searchExe(%q) = %q, want %q", name, got, want)
		}
	}
	if got := h.E.searchExe(win + `\data.txt`); got != filepath.Join(host, "data.txt") {
		t.Errorf("explicit extension: %q", got)
	}
	if got := h.E.searchExe(win + `\data`); got != "" {
		t.Errorf("data has no .exe: %q", got)
	}
	h.E.fs.cwd = win
	if got := h.E.searchExe("prog"); got != want {
		t.Errorf("bare name from dotted cwd: %q", got)
	}
}

// cmd tries the PATHEXT extensions in order (.COM before .EXE by default).
func TestCmdFindExeDottedDirPathext(t *testing.T) {
	h := newTestEmu(t)
	host, win := dottedDir(t, h, "prog.exe", "prog.com", "only.exe")
	if got := h.E.cmdFindExe(win + `\prog`); got != filepath.Join(host, "prog.com") {
		t.Errorf("cmd path prog: %q", got)
	}
	if got := h.E.cmdFindExe(win + `\only`); got != filepath.Join(host, "only.exe") {
		t.Errorf("cmd path only: %q", got)
	}
	h.E.fs.cwd = win
	if got := h.E.cmdFindExe("prog"); got != filepath.Join(host, "prog.com") {
		t.Errorf("cmd bare prog: %q", got)
	}
	h.E.setEnv("PATHEXT", ".EXE;.COM")
	if got := h.E.cmdFindExe("prog"); got != filepath.Join(host, "prog.exe") {
		t.Errorf("cmd PATHEXT=.EXE;.COM: %q", got)
	}
}

// SearchPath appends lpExtension only when the file name has no extension.
func TestSearchPathDottedDir(t *testing.T) {
	h := newTestEmu(t)
	_, win := dottedDir(t, h, "prog.exe")
	buf := h.alloc(1024)
	for _, c := range []struct{ path, name string }{
		{win, "prog"},
		{"", win + `\prog`},
	} {
		var lp uint64
		if c.path != "" {
			lp = h.wstr(c.path)
		}
		n := h.call(dK32, "SearchPathW", lp, h.wstr(c.name), h.wstr(".exe"), 512, buf, 0)
		if got := h.E.Mem.WStr(buf); n == 0 || got != win+`\prog.exe` {
			t.Errorf("SearchPathW(%q, %q) = %d %q err %d", c.path, c.name, n, got, h.lastError())
		}
	}
}

// LoadLibrary appends .dll only when the module's file name has no extension.
func TestNormDLLDottedDir(t *testing.T) {
	for in, want := range map[string]string{
		`C:\rel.1.0\bin\libpq`:     "libpq.dll",
		`C:/rel.1.0/bin/libpq`:     "libpq.dll",
		`C:\rel.1.0\bin\icu.67.so`: "icu.67.so",
		`KERNEL32`:                 "kernel32.dll",
	} {
		if got := normDLL(in); got != want {
			t.Errorf("normDLL(%q) = %q, want %q", in, got, want)
		}
	}
}
