// End-to-end tests: run the prebuilt Windows test programs in testdata/bin
// under winemu and compare their output with golden files.
//
//	go test ./tests/            # run
//	go test ./tests/ -update    # regenerate golden files
package tests

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

var winemuBin string

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "winemu-test")
	if err != nil {
		panic(err)
	}
	winemuBin = filepath.Join(dir, "winemu")
	cmd := exec.Command("go", "build", "-o", winemuBin, "../cmd/winemu")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("building winemu: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type testCase struct {
	name  string
	exe   string
	args  []string
	stdin string
	code  int
	inBin bool // run in testdata/bin: cmd.exe (system, _popen) finds programs in the current directory or PATH
}

var cases = []testCase{
	{name: "hello", exe: "hello.exe", args: []string{"a", "b", "c"}, code: 42},
	{name: "crt", exe: "t_crt.exe", args: []string{"arg1"}},
	{name: "cpp", exe: "t_cpp.exe"},
	{name: "win32", exe: "t_win.exe"},
	{name: "dll", exe: "usedll.exe"},
	{name: "input", exe: "t_input.exe", stdin: "Ada Lovelace\n36 1.65\nline one\nline two\nlast line no newline"},
	{name: "process", exe: "parent.exe", inBin: true},
	{name: "go", exe: "gohello.exe"},
	{name: "bench", exe: "t_bench.exe"},
}

func TestPrograms(t *testing.T) {
	bin, _ := filepath.Abs("../testdata/bin")
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			prefix := filepath.Join(work, "prefix")
			args := append([]string{"-prefix", prefix, filepath.Join(bin, tc.exe)}, tc.args...)
			cmd := exec.Command(winemuBin, args...)
			cmd.Dir = work
			if tc.inBin {
				cmd.Dir = bin
			}
			cmd.Stdin = strings.NewReader(tc.stdin)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			err := cmd.Run()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("run: %v", err)
			}
			if code != tc.code {
				t.Errorf("exit code %d, want %d\n%s", code, tc.code, out.String())
			}
			golden := filepath.Join("..", "testdata", "golden", tc.name+".txt")
			got := normalize(out.String())
			if *update {
				os.WriteFile(golden, []byte(got), 0o644)
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("missing golden file (run with -update): %v", err)
			}
			if got != string(want) {
				t.Errorf("output mismatch on %s/%s\n--- got ---\n%s\n--- want ---\n%s", runtime.GOOS, runtime.GOARCH, got, want)
			}
		})
	}
}

// normalize removes run-specific details.
func normalize(s string) string {
	lines := strings.Split(s, "\n")
	out := lines[:0]
	for _, l := range lines {
		if strings.HasPrefix(l, "winemu: stats") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
