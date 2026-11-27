package win

// Unit-test harness for emulated Windows APIs.
//
// newTestEmu builds an Emu whose environment matches a real process start
// (prefix in a temp dir, KUSER_SHARED_DATA, process heap, CRT, PEB with
// process parameters and environment, ntdll/kernel32/kernelbase loaded, and
// a main thread with TEB and a 1 MiB stack as e.Cur), but without loading an
// .exe. APIs are invoked the way a guest would invoke them: through the
// export thunk of the builtin DLL (LoadDLL + GetExport) via CallGuest, so the
// Win64 ABI (RCX, RDX, R8, R9, then [RSP+8+8*i]), the hypercall path, fault
// conversion, blocking calls (e.block) and other guest threads all behave as
// in a real run. Typical setup cost is a few milliseconds.
//
// API (all helpers fail the test via t.Fatalf on misuse):
//
//	h := newTestEmu(t, opts ...func(*Options))  // e.g. withStdin("abc\n")
//	h.E                                         // the *Emu (white-box access)
//	h.call(dll, name string, args ...uint64) uint64
//	    // calls dll!name; fails the test if it is not registered or if the
//	    // call terminates the process (unhandled exception, ExitProcess, ...)
//	h.tryCall(dll, name, args...) (ret uint64, exited bool, code uint32)
//	    // like call, but reports process termination instead of failing
//	h.lastError() uint32 / h.setLastError(v uint32)
//	h.alloc(n int) uint64                       // zeroed guest memory, 16-byte aligned, RW
//	h.astr(s) uint64 / h.wstr(s) uint64         // alloc + write NUL-terminated ANSI / UTF-16
//	h.readAStr(a) string / h.readWStr(a) string // read NUL-terminated ANSI / UTF-16
//	h.readWStrN(a, n) string                    // read n UTF-16 units
//	h.write(a, []byte) / h.read(a, n) []byte
//	h.w16/w32/w64(a, v) / h.r16/r32/r64(a)
//	h.stdout() string / h.stderr() string       // what the guest wrote to the std handles
//
// Constants for arguments: pass Win32 NULL as 0, booleans as 0/1, negative
// ints as uint64(int64(-1)) or ^uint64(0). Each harness Emu has its own
// kernel (session), so harness tests may use t.Parallel.
//
// Example:
//
//	func TestGetLastError(t *testing.T) {
//		h := newTestEmu(t)
//		h.call(dK32, "SetLastError", 1234)
//		if got := h.call(dK32, "GetLastError"); got != 1234 {
//			t.Fatalf("GetLastError = %d, want 1234", got)
//		}
//	}

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"winemu/internal/mem"
)

type testEmu struct {
	t   testing.TB
	E   *Emu
	dir string

	scratchNext, scratchEnd uint64
	outF, errF              *os.File
}

// withStdin makes the guest's standard input read s.
func withStdin(s string) func(*Options) {
	return func(o *Options) {
		f, err := os.CreateTemp("", "winemu-stdin")
		if err != nil {
			panic(err)
		}
		os.Remove(f.Name())
		if _, err := f.WriteString(s); err != nil {
			panic(err)
		}
		if _, err := f.Seek(0, 0); err != nil {
			panic(err)
		}
		o.Stdin = f
	}
}

func newTestEmu(t testing.TB, opts ...func(*Options)) *testEmu {
	t.Helper()
	dir := t.TempDir()
	h := &testEmu{t: t, dir: dir}
	open := func(name string) *os.File {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("harness: %v", err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	stdin := open("stdin")
	h.outF, h.errF = open("stdout"), open("stderr")
	opt := Options{Prefix: filepath.Join(dir, "prefix"), Stdin: stdin, Stdout: h.outF, Stderr: h.errF}
	for _, o := range opts {
		o(&opt)
	}
	e := New(opt)
	h.E = e

	// Same set-up as Run (process.go), without loading an exe.
	if _, err := e.setupProcess(filepath.Join(dir, "test.exe"), nil, 1<<20); err != nil {
		t.Fatalf("harness: setupProcess: %v", err)
	}
	return h
}

// tryCall invokes dll!name with the given integer/pointer arguments.
func (h *testEmu) tryCall(dll, name string, args ...uint64) (ret uint64, exited bool, code uint32) {
	h.t.Helper()
	m, err := h.E.LoadDLL(dll)
	if err != nil {
		h.t.Fatalf("harness: LoadDLL(%s): %v", dll, err)
	}
	addr, ok := h.E.GetExport(m, name, 0, false)
	if !ok {
		h.t.Fatalf("harness: %s!%s is not registered", dll, name)
	}
	main := h.E.Cur
	defer func() {
		h.E.Cur = main
		if r := recover(); r != nil {
			pe, ok := r.(processExit)
			if !ok {
				panic(r)
			}
			exited, code = true, pe.code
		}
	}()
	return h.E.CallGuest(addr, args...), false, 0
}

// call invokes dll!name and fails the test if the process terminates.
func (h *testEmu) call(dll, name string, args ...uint64) uint64 {
	h.t.Helper()
	r, exited, code := h.tryCall(dll, name, args...)
	if exited {
		h.t.Fatalf("%s!%s terminated the process with code %#x\nstderr:\n%s", dll, name, code, h.stderr())
	}
	return r
}

func (h *testEmu) lastError() uint32     { return h.E.LastError() }
func (h *testEmu) setLastError(v uint32) { h.E.SetLastError(v) }

// alloc returns n zeroed bytes of read/write guest memory, 16-byte aligned.
func (h *testEmu) alloc(n int) uint64 {
	h.t.Helper()
	size := (uint64(max(n, 1)) + 15) &^ 15
	if h.scratchNext+size > h.scratchEnd {
		rs := max(size, 1<<20)
		r, err := h.E.Mem.Alloc(rs, mem.PageReadWrite, mem.MemPrivate, "test scratch")
		if err != nil {
			h.t.Fatalf("harness: alloc(%d): %v", n, err)
		}
		h.scratchNext, h.scratchEnd = r.Base, r.Base+r.Size
	}
	a := h.scratchNext
	h.scratchNext += size
	return a
}

func (h *testEmu) astr(s string) uint64 {
	a := h.alloc(len(s) + 1)
	h.E.Mem.WriteCStr(a, s)
	return a
}

func (h *testEmu) wstr(s string) uint64 {
	u := utf16.Encode([]rune(s))
	a := h.alloc(2*len(u) + 2)
	h.E.Mem.WriteUnits(a, append(u, 0))
	return a
}

func (h *testEmu) readAStr(a uint64) string { return h.E.Mem.CStr(a) }
func (h *testEmu) readWStr(a uint64) string { return h.E.Mem.WStr(a) }

func (h *testEmu) readWStrN(a uint64, n int) string {
	u := make([]uint16, n)
	for i := range u {
		u[i] = h.E.Mem.R16(a + uint64(2*i))
	}
	return string(utf16.Decode(u))
}

func (h *testEmu) write(a uint64, b []byte)    { h.E.Mem.Write(a, b) }
func (h *testEmu) read(a uint64, n int) []byte { return h.E.Mem.ReadBytes(a, n) }
func (h *testEmu) w16(a uint64, v uint16)      { h.E.Mem.W16(a, v) }
func (h *testEmu) w32(a uint64, v uint32)      { h.E.Mem.W32(a, v) }
func (h *testEmu) w64(a uint64, v uint64)      { h.E.Mem.W64(a, v) }
func (h *testEmu) r16(a uint64) uint16         { return h.E.Mem.R16(a) }
func (h *testEmu) r32(a uint64) uint32         { return h.E.Mem.R32(a) }
func (h *testEmu) r64(a uint64) uint64         { return h.E.Mem.R64(a) }
func (h *testEmu) stdout() string              { return h.readFile(h.outF) }
func (h *testEmu) stderr() string              { return h.readFile(h.errF) }

func (h *testEmu) readFile(f *os.File) string {
	h.E.crt.flushAll()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		h.t.Fatalf("harness: %v", err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// self-tests / examples

func TestHarnessLastError(t *testing.T) {
	h := newTestEmu(t)
	h.call(dK32, "SetLastError", 1234)
	if got := h.call(dK32, "GetLastError"); got != 1234 {
		t.Fatalf("GetLastError = %d, want 1234", got)
	}
	if got := h.lastError(); got != 1234 {
		t.Fatalf("lastError() = %d, want 1234", got)
	}
}

func TestHarnessGetCurrentProcessId(t *testing.T) {
	h := newTestEmu(t)
	if got := h.call(dK32, "GetCurrentProcessId"); got != uint64(os.Getpid()) {
		t.Fatalf("GetCurrentProcessId = %d, want %d", got, os.Getpid())
	}
}

// MultiByteToWideChar takes 6 arguments, so this also checks stack slots.
func TestHarnessStackArgs(t *testing.T) {
	h := newTestEmu(t)
	src := h.astr("héllo")
	dst := h.alloc(64)
	const cpUTF8 = 65001
	n := h.call(dK32, "MultiByteToWideChar", cpUTF8, 0, src, ^uint64(0), dst, 32)
	if n != 6 || h.readWStr(dst) != "héllo" {
		t.Fatalf("MultiByteToWideChar = %d %q, want 6 \"héllo\"", n, h.readWStr(dst))
	}
	h.setLastError(0)
	if n := h.call(dK32, "MultiByteToWideChar", cpUTF8, 0, src, ^uint64(0), dst, 2); n != 0 || h.lastError() != errInsufficientBuf {
		t.Fatalf("small buffer: ret %d lastError %d, want 0 / %d", n, h.lastError(), errInsufficientBuf)
	}
}

func TestHarnessProcessExit(t *testing.T) {
	h := newTestEmu(t)
	_, exited, code := h.tryCall(dK32, "ExitProcess", 7)
	if !exited || code != 7 {
		t.Fatalf("ExitProcess: exited=%v code=%d, want true 7", exited, code)
	}
}

func TestHarnessStdout(t *testing.T) {
	h := newTestEmu(t, withStdin(""))
	out := h.call(dK32, "GetStdHandle", uint64(0xFFFFFFF5)) // STD_OUTPUT_HANDLE (DWORD -11)
	msg := "hi\n"
	written := h.alloc(4)
	if r := h.call(dK32, "WriteFile", out, h.astr(msg), uint64(len(msg)), written, 0); r == 0 {
		t.Fatalf("WriteFile failed, lastError %d", h.lastError())
	}
	if got := h.stdout(); !strings.Contains(got, msg) || h.r32(written) != 3 {
		t.Fatalf("stdout %q written %d", got, h.r32(written))
	}
}

func TestHarnessMemoryHelpers(t *testing.T) {
	h := newTestEmu(t)
	a := h.alloc(32)
	h.w16(a, 0x1122)
	h.w32(a+4, 0x33445566)
	h.w64(a+8, 0x778899AABBCCDDEE)
	if h.r16(a) != 0x1122 || h.r32(a+4) != 0x33445566 || h.r64(a+8) != 0x778899AABBCCDDEE {
		t.Fatalf("scalar round trip: %#x %#x %#x", h.r16(a), h.r32(a+4), h.r64(a+8))
	}
	h.write(a+16, []byte{1, 2, 3})
	if got := h.read(a+16, 4); string(got) != "\x01\x02\x03\x00" {
		t.Fatalf("read = %v", got)
	}
	if got := h.readAStr(h.astr("ansi")); got != "ansi" {
		t.Fatalf("readAStr = %q", got)
	}
	w := h.wstr("wide€")
	if h.readWStr(w) != "wide€" || h.readWStrN(w, 2) != "wi" {
		t.Fatalf("readWStr = %q, readWStrN = %q", h.readWStr(w), h.readWStrN(w, 2))
	}
	if n := h.call(dK32, "lstrlenW", w); n != 5 {
		t.Fatalf("lstrlenW = %d, want 5", n)
	}
}
