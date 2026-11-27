package win

import (
	"os"
	"path/filepath"
	"testing"
)

// APIs whose real kernel32 implementation used to be shadowed by a misc.go
// stub (duplicate registration); these pin the documented behaviour.

func TestSetConsoleCtrlHandlerAddRemove(t *testing.T) {
	h := newTestEmu(t)
	const h1, h2 = 0x7000_1000, 0x7000_2000
	if h.call(dK32, "SetConsoleCtrlHandler", h1, 1) != 1 || h.call(dK32, "SetConsoleCtrlHandler", h1, 1) != 1 {
		t.Fatal("add failed")
	}
	// removing one registration of a handler added twice leaves the other
	if h.call(dK32, "SetConsoleCtrlHandler", h1, 0) != 1 {
		t.Fatalf("remove failed, err %d", h.lastError())
	}
	if got := h.E.con.ctrlHandlers; len(got) != 1 || got[0] != h1 {
		t.Fatalf("handlers after one removal = %#x, want [h1]", got)
	}
	if h.call(dK32, "SetConsoleCtrlHandler", h1, 0) != 1 {
		t.Fatalf("second remove failed, err %d", h.lastError())
	}
	// removal is by handler address: h1 goes, h2 stays
	h.call(dK32, "SetConsoleCtrlHandler", h1, 1)
	h.call(dK32, "SetConsoleCtrlHandler", h2, 1)
	if h.call(dK32, "SetConsoleCtrlHandler", h1, 0) != 1 {
		t.Fatalf("remove h1 failed, err %d", h.lastError())
	}
	if got := h.E.con.ctrlHandlers; len(got) != 1 || got[0] != h2 {
		t.Fatalf("handlers after removing h1 = %#x, want [h2]", got)
	}
	h.call(dK32, "SetConsoleCtrlHandler", h2, 0)
	// removing a handler that is not registered fails
	for _, fn := range []uint64{h1, h2} {
		h.setLastError(0)
		if h.call(dK32, "SetConsoleCtrlHandler", fn, 0) != 0 || h.lastError() != errInvalidParameter {
			t.Errorf("remove unregistered %#x: want FALSE/ERROR_INVALID_PARAMETER, err %d", fn, h.lastError())
		}
	}
	// NULL handler: set / clear the ignore-CTRL+C attribute, always succeeds
	for _, add := range []uint64{1, 0} {
		if h.call(dK32, "SetConsoleCtrlHandler", 0, add) != 1 {
			t.Errorf("SetConsoleCtrlHandler(NULL, %d) failed", add)
		}
	}
	if len(h.E.con.ctrlHandlers) != 0 {
		t.Errorf("NULL handler was registered: %#x", h.E.con.ctrlHandlers)
	}
}

func TestCreateWaitableTimerExWFlags(t *testing.T) {
	h := newTestEmu(t)
	for _, c := range []struct {
		flags  uint64
		manual bool
	}{{0, false}, {1, true}, {2, false}, {3, true}} { // MANUAL_RESET=1, HIGH_RESOLUTION=2
		h.setLastError(5)
		th := h.call(dK32, "CreateWaitableTimerExW", 0, 0, c.flags, 0x1F0003)
		o, ok := h.E.handles.get(th).(*timerObj)
		if !ok {
			t.Fatalf("flags %d: no timer handle (err %d)", c.flags, h.lastError())
		}
		if o.manual != c.manual || h.lastError() != 0 {
			t.Errorf("flags %d: manual=%v err=%d, want manual=%v err=0", c.flags, o.manual, h.lastError(), c.manual)
		}
		h.call(dK32, "CloseHandle", th)
	}
}

func TestSetProcessPriorityBoostHandle(t *testing.T) {
	h := newTestEmu(t)
	if h.call(dK32, "SetProcessPriorityBoost", pseudoProcess, 1) != 1 {
		t.Errorf("current process: failed, err %d", h.lastError())
	}
	if h.call(dK32, "SetProcessPriorityBoost", 0x12344, 1) != 0 || h.lastError() != errInvalidHandle {
		t.Errorf("bad handle: want FALSE/ERROR_INVALID_HANDLE, err %d", h.lastError())
	}
}

func TestGetSystemDirectoryWSize(t *testing.T) {
	h := newTestEmu(t)
	const dir = `C:\windows\system32`
	n := uint64(len(dir))
	buf := h.alloc(64)
	if got := h.call(dK32, "GetSystemDirectoryW", 0, 0); got != n+1 {
		t.Errorf("size probe = %d, want %d (length incl. NUL)", got, n+1)
	}
	if got := h.call(dK32, "GetSystemDirectoryW", buf, n); got != n+1 {
		t.Errorf("buffer without room for NUL = %d, want %d", got, n+1)
	}
	if got := h.call(dK32, "GetSystemDirectoryW", buf, n+1); got != n || h.readWStr(buf) != dir {
		t.Errorf("exact buffer = %d %q, want %d %q", got, h.readWStr(buf), n, dir)
	}
	if got := h.call(dK32, "GetSystemDirectoryA", buf, 64); got != n || h.readAStr(buf) != dir {
		t.Errorf("A = %d %q", got, h.readAStr(buf))
	}
}

// copyTestDLL places testdata/bin/mylib.dll next to the harness exe.
func copyTestDLL(t *testing.T, h *testEmu) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bin", "mylib.dll"))
	if err != nil {
		t.Skipf("mylib.dll not built: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "mylib.dll"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLibraryExWArgs(t *testing.T) {
	h := newTestEmu(t)
	k32 := h.wstr("kernel32.dll")
	for _, c := range []struct {
		name        string
		file, flags uint64
	}{
		{"hFile not NULL", 0x44, 0},
		{"ALTERED_SEARCH_PATH with SEARCH_SYSTEM32", 0, 0x8 | 0x800},
		{"ALTERED_SEARCH_PATH with SEARCH_DEFAULT_DIRS", 0, 0x8 | 0x1000},
	} {
		h.setLastError(0)
		if h.call(dK32, "LoadLibraryExW", k32, c.file, c.flags) != 0 || h.lastError() != errInvalidParameter {
			t.Errorf("%s: want NULL/ERROR_INVALID_PARAMETER, err %d", c.name, h.lastError())
		}
	}
	h.setLastError(0)
	if h.call(dK32, "LoadLibraryExW", 0, 0, 0) != 0 || h.lastError() != errInvalidParameter {
		t.Errorf("NULL name: err %d", h.lastError())
	}
	// a system DLL is found with LOAD_LIBRARY_SEARCH_SYSTEM32
	if h.call(dK32, "LoadLibraryExW", k32, 0, 0x800) != h.call(dK32, "GetModuleHandleW", k32) {
		t.Errorf("SEARCH_SYSTEM32 kernel32: err %d", h.lastError())
	}
}

func TestLoadLibraryExWSearchSystem32SkipsAppDir(t *testing.T) {
	h := newTestEmu(t)
	copyTestDLL(t, h)
	name := h.wstr("mylib.dll")
	if h.call(dK32, "LoadLibraryExW", name, 0, 0x800) != 0 || h.lastError() != errModNotFound {
		t.Errorf("SEARCH_SYSTEM32 found a DLL from the application dir (err %d)", h.lastError())
	}
	if h.call(dK32, "LoadLibraryExW", name, 0, 0x200) == 0 { // SEARCH_APPLICATION_DIR
		t.Errorf("SEARCH_APPLICATION_DIR: err %d", h.lastError())
	}
}

func TestLoadLibraryExWNoInit(t *testing.T) {
	for _, c := range []struct {
		name  string
		flags uint64
		tag   uint64
	}{
		{"AS_DATAFILE", 0x2, 1},
		{"AS_DATAFILE_EXCLUSIVE", 0x40, 1},
		{"AS_IMAGE_RESOURCE", 0x20, 2},
		{"AS_IMAGE_RESOURCE|AS_DATAFILE", 0x22, 2},
		{"DONT_RESOLVE_DLL_REFERENCES", 0x1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newTestEmu(t)
			copyTestDLL(t, h)
			name := h.wstr("mylib.dll")
			hm := h.call(dK32, "LoadLibraryExW", name, 0, c.flags)
			m := h.E.modByName["mylib.dll"]
			if hm == 0 || m == nil {
				t.Fatalf("load failed, err %d", h.lastError())
			}
			if hm != m.Base|c.tag {
				t.Errorf("handle %#x, want base %#x | %d", hm, m.Base, c.tag)
			}
			if m.initDone {
				t.Error("DllMain ran")
			}
			// a normal load afterwards initialises it and returns the plain base
			if got := h.call(dK32, "LoadLibraryW", name); got != m.Base || !m.initDone {
				t.Errorf("LoadLibraryW after = %#x initDone=%v", got, m.initDone)
			}
			// once loaded as an image, a data-file load returns the module
			if got := h.call(dK32, "LoadLibraryExW", name, 0, c.flags); got != m.Base {
				t.Errorf("reload = %#x, want %#x", got, m.Base)
			}
		})
	}
}
