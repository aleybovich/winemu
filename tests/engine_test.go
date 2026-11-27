package tests

import (
	"testing"
	"time"
)

// TestEngineSMC: self-modifying code through guest stores, a store into the
// running block, WriteProcessMemory and free/realloc; precise RIP/registers
// at an access violation (docs/engine.md). Runs under every WINEMU_ENGINE.
func TestEngineSMC(t *testing.T) {
	r := runGuest(t, "engine_smc.exe", guestOpts{})
	want := "store: 11 12\nsame block: 7\nsame block again: 7\nwpm: 13\nrealloc: 14\n" +
		"fault: rip ok 1 rax 0x1234 after 0x1235\n"
	if r.Code != 0 || r.Stdout != want {
		t.Fatalf("code %d\nstdout %q\nwant   %q\nstderr %s", r.Code, r.Stdout, want, r.Stderr)
	}
}

// TestEngineXSMC: code hot in the block cache rewritten by VirtualProtect +
// store, by WriteProcessMemory from another process, and through another
// process's view of a shared section (testdata/src/c/engine_xsmc.c).
func TestEngineXSMC(t *testing.T) {
	for mode, want := range map[string]string{
		"protect": "protect: 41 42\n",
		"wpm":     "wpm: child exit 0 seen 52\n",
		"section": "section: child exit 0 seen 62\n",
	} {
		t.Run(mode, func(t *testing.T) {
			r := runGuest(t, "engine_xsmc.exe", guestOpts{Args: []string{mode}, Timeout: 60 * time.Second})
			if r.Code != 0 || r.Stdout != want {
				t.Fatalf("code %d\nstdout %q\nwant   %q\nstderr %s", r.Code, r.Stdout, want, r.Stderr)
			}
		})
	}
}
