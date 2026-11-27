package win

import (
	"os"
	"testing"
	"time"
)

// Every blocking console read path (raw ReadFile / _read, _getch) releases
// the reader's run lock, like ReadConsole (TestXprocConsoleReadReleasesRunLock).
func TestConsoleRawReadsReleaseRunLock(t *testing.T) {
	for _, c := range []struct {
		name string
		read func(b *testEmu, buf, n uint64) uint64
		ok   func(b *testEmu, r, buf, n uint64) bool
	}{
		{"ReadFile", func(b *testEmu, buf, n uint64) uint64 {
			return b.call(dK32, "ReadFile", stdInputHandle, buf, 64, n, 0)
		}, func(b *testEmu, r, buf, n uint64) bool { return r == 1 && b.r32(n) > 0 && b.read(buf, 1)[0] == 'h' }},
		{"_read", func(b *testEmu, buf, n uint64) uint64 {
			return b.call(dUcrt, "_read", 0, buf, 64)
		}, func(b *testEmu, r, buf, n uint64) bool { return int32(r) > 0 && b.read(buf, 1)[0] == 'h' }},
		{"_getch", func(b *testEmu, buf, n uint64) uint64 {
			return b.call(dUcrt, "_getch")
		}, func(b *testEmu, r, buf, n uint64) bool { return r == 'h' }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newTestEmu(t)
			pr, pw, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer pr.Close()
			defer pw.Close()
			saved := h.E.Opt.Stdin
			h.E.Opt.Stdin = pr
			b := sibling(t, h)
			h.E.Opt.Stdin = saved
			buf, n := b.alloc(64), b.alloc(4)
			done := make(chan uint64, 1)
			go func() { done <- c.read(b, buf, n) }()
			time.Sleep(50 * time.Millisecond) // b is now inside the host read
			hb, dst := procHandle(h, b), h.alloc(8)
			got := make(chan uint64, 1)
			go func() { got <- h.call(dK32, "ReadProcessMemory", hb, buf, dst, 8, 0) }()
			select {
			case r := <-got:
				if r != 1 {
					t.Fatalf("ReadProcessMemory = %d, err %d", r, h.lastError())
				}
			case <-time.After(2 * time.Second):
				if _, err := pw.Write([]byte("x\r\n")); err != nil {
					t.Fatal(err)
				}
				<-got
				<-done
				t.Fatal("ReadProcessMemory stalled behind a blocking console read")
			}
			if _, err := pw.Write([]byte("hi\r\n")); err != nil {
				t.Fatal(err)
			}
			if r := <-done; !c.ok(b, r, buf, n) {
				t.Fatalf("%s = %d", c.name, r)
			}
		})
	}
}
