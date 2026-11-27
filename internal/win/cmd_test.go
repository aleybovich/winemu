package win

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCmdSwitches(t *testing.T) {
	for _, c := range []struct {
		in, cmd string
		s, ok   bool
	}{
		{`C:\windows\system32\cmd.exe /D /C ""a.exe" x"`, `""a.exe" x"`, false, true},
		{`cmd /s/c "x"`, `"x"`, true, true},
		{`"C:\windows\system32\cmd.exe" /c   echo hi`, `echo hi`, false, true},
		{`cmd.exe /E:ON /K dir`, `dir`, false, true},
		{`cmd.exe`, ``, false, false},
	} {
		cmd, s, ok := cmdSwitches(c.in)
		if cmd != c.cmd || s != c.s || ok != c.ok {
			t.Errorf("%q: got %q %v %v", c.in, cmd, s, ok)
		}
	}
}

func TestCmdQuoteRules(t *testing.T) {
	isExe := func(p string) bool { return p == `C:\my app\run.exe` }
	for _, c := range []struct {
		in   string
		s    bool
		want string
	}{
		// rule 1: two quotes around an existing exe name with whitespace: kept
		{`"C:\my app\run.exe"`, false, `"C:\my app\run.exe"`},
		// /S always strips
		{`"C:\my app\run.exe"`, true, `C:\my app\run.exe`},
		// more than two quotes: strip the first and the last
		{`""a.exe" -D "d" < "NUL" >> "l" 2>&1"`, false, `"a.exe" -D "d" < "NUL" >> "l" 2>&1`},
		// two quotes but no whitespace inside: stripped
		{`"C:\x\p.exe" -V`, false, `C:\x\p.exe -V`},
		// text after the last quote is kept
		{`"a b" tail`, false, `a b tail`},
		{`echo hi`, false, `echo hi`},
	} {
		if got := cmdStripQuotes(c.in, c.s, isExe); got != c.want {
			t.Errorf("%q /S=%v: got %q want %q", c.in, c.s, got, c.want)
		}
	}
}

func TestCmdParse(t *testing.T) {
	words, redirs, err := cmdParse(`"a.exe" -D "x y" < "NUL" >> "log.txt" 2>&1`)
	if err != nil {
		t.Fatal(err)
	}
	var raw []string
	for _, w := range words {
		raw = append(raw, w.raw)
	}
	if !reflect.DeepEqual(raw, []string{`"a.exe"`, `-D`, `"x y"`}) || words[0].val != "a.exe" || words[2].val != "x y" {
		t.Fatalf("words %+v", words)
	}
	want := []cmdRedir{{fd: 0, op: "<", target: "NUL"}, {fd: 1, op: ">>", target: "log.txt"}, {fd: 2, op: ">&", dup: 1}}
	if !reflect.DeepEqual(redirs, want) {
		t.Fatalf("redirs %+v", redirs)
	}
	words, redirs, err = cmdParse(`x2>o a^&b 1>"e f" 2> err`)
	if err != nil || len(words) != 2 || words[0].val != "x2" || words[1].val != "a&b" {
		t.Fatalf("words %+v err %v", words, err)
	}
	want = []cmdRedir{{fd: 1, op: ">", target: "o"}, {fd: 1, op: ">", target: "e f"}, {fd: 2, op: ">", target: "err"}}
	if !reflect.DeepEqual(redirs, want) {
		t.Fatalf("redirs %+v", redirs)
	}
	for _, bad := range []string{`a | b`, `a & b`, `a >`, `a && b`} {
		if _, _, err := cmdParse(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestCmdExpandVars(t *testing.T) {
	env := map[string]string{"x": "1", "path": `C:\p`}
	get := func(n string) (string, bool) { v, ok := env[strings.ToLower(n)]; return v, ok }
	if got := cmdExpand(`a %X% %Path%\b %nope% 100%`, get); got != `a 1 C:\p\b %nope% 100%` {
		t.Fatalf("got %q", got)
	}
}

// cmd.exe resolves to the builtin; CreateProcess on it runs /C commands,
// with redirections and the exit code of the command.
func TestCmdBuiltinProcess(t *testing.T) {
	h := newTestEmu(t)
	h.E.proc.markStarted()
	host := h.E.searchExe("cmd")
	if !h.E.isBuiltinCmd(host) {
		t.Fatalf("cmd resolves to %q", host)
	}
	if c, _ := h.E.getEnv("COMSPEC"); !strings.EqualFold(c, builtinCmdPath) {
		t.Fatalf("COMSPEC %q", c)
	}
	si, pi, code := h.alloc(104), h.alloc(24), h.alloc(4)
	h.w32(si, 104)
	run := func(cmdline string) uint32 {
		t.Helper()
		if r := h.call(dK32, "CreateProcessW", 0, h.wstr(cmdline), 0, 0, 0, 0, 0, 0, si, pi); r != 1 {
			t.Fatalf("CreateProcess(%s) err %d", cmdline, h.lastError())
		}
		if r := h.call(dK32, "WaitForSingleObject", h.r64(pi), 5000); r != 0 {
			t.Fatalf("wait %#x", r)
		}
		h.call(dK32, "GetExitCodeProcess", h.r64(pi), code)
		return h.r32(code)
	}
	if c := run(`cmd.exe /d /c exit 7`); c != 7 {
		t.Fatalf("exit code %d", c)
	}
	if c := run(`C:\Windows\System32\cmd.exe /C "echo hello>C:\o.txt"`); c != 0 {
		t.Fatalf("echo code %d", c)
	}
	if c := run(`cmd /c echo more>>C:\o.txt`); c != 0 {
		t.Fatalf("echo code %d", c)
	}
	b, err := os.ReadFile(filepath.Join(h.E.Opt.Prefix, "drive_c", "o.txt"))
	if err != nil || string(b) != "hello\r\nmore\r\n" {
		t.Fatalf("o.txt %q %v", b, err)
	}
	start := time.Now()
	if c := run(`cmd /c nosuchprogram 2>NUL`); c != 1 || time.Since(start) > 5*time.Second {
		t.Fatalf("missing program code %d", c)
	}
}
