package win

import (
	"os"
	"sync"
	"testing"
	"time"
)

// Integration of WS-E1's run lock with the other workstreams' blocking paths.

// A console read blocks on the host; the reading process must not hold its
// run lock meanwhile, or every other process touching it stalls.
func TestXprocConsoleReadReleasesRunLock(t *testing.T) {
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
	go func() { done <- b.call(dK32, "ReadConsoleA", stdInputHandle, buf, 64, n, 0) }()
	time.Sleep(50 * time.Millisecond) // b is now inside the host read
	hb := procHandle(h, b)
	dst := h.alloc(8)
	got := make(chan uint64, 1)
	go func() { got <- h.call(dK32, "ReadProcessMemory", hb, buf, dst, 8, 0) }()
	select {
	case r := <-got:
		if r != 1 {
			t.Fatalf("ReadProcessMemory = %d, err %d", r, h.lastError())
		}
	case <-time.After(2 * time.Second):
		pw.Write([]byte("x\r\n"))
		<-got
		t.Fatal("ReadProcessMemory stalled behind a blocking console read")
	}
	pw.Write([]byte("hi\r\n"))
	if r := <-done; r != 1 || b.r32(n) != 4 || string(b.read(buf, 2)) != "hi" {
		t.Fatalf("ReadConsoleA = %d, n %d", r, b.r32(n))
	}
}

// withProcess releases the caller's run lock while it waits for the target;
// the held flag must say so, so nested lock users (pausePoint, idleSleep,
// withProcess) do not unlock an unlocked mutex.
func TestXprocWithProcessClearsHeld(t *testing.T) {
	h := newTestEmu(t)
	b, c := sibling(t, h), sibling(t, h)
	h.E.lockRun()
	defer h.E.unlockRun()
	var inner bool
	h.E.withProcess(b.E.proc, func(*Emu) {
		inner = h.E.proc.xp.held
		h.E.withProcess(c.E.proc, func(*Emu) {}) // nested, other target
	})
	if inner {
		t.Fatal("held still set while the run lock is released")
	}
	if !h.E.proc.xp.held {
		t.Fatal("held not restored")
	}
}

// ResumeThread racing TerminateProcess on a CREATE_SUSPENDED child: the child
// is either started (and then killed) or ended unstarted - never started
// after being ended (which would leak the kernel's live-process count).
func TestXprocResumeTerminateRace(t *testing.T) {
	h := newTestEmu(t)
	killer := sibling(t, h)
	killer.E.proc.markStarted()
	base := func() int { h.E.k.mu.Lock(); defer h.E.k.mu.Unlock(); return h.E.k.live }
	live0 := base()
	for i := range 100 {
		b := sibling(t, h)
		b.E.threads[0].suspend = 1
		th := h.E.handles.add(&threadObj{t: b.E.threads[0]})
		hb := killer.E.handles.add(&processObj{p: b.E.proc})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); h.call(dK32, "ResumeThread", th) }()
		go func() { defer wg.Done(); killer.call(dK32, "TerminateProcess", hb, 7) }()
		wg.Wait()
		select {
		case <-b.E.proc.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: child never exited", i)
		}
		h.call(dK32, "CloseHandle", th)
		killer.call(dK32, "CloseHandle", hb)
		time.Sleep(time.Millisecond) // let a started child's goroutine finish
		if l := base(); l != live0 {
			t.Fatalf("iteration %d: live processes %d, want %d", i, l, live0)
		}
	}
}

// Processes started by the builtin cmd (and system/_popen through it) join
// the job of their creator, like CreateProcess children.
func TestXprocCmdChildrenJoinJob(t *testing.T) {
	h := newTestEmu(t)
	h.E.proc.markStarted()
	jh := h.call(dK32, "CreateJobObjectW", 0, 0)
	if h.call(dK32, "AssignProcessToJobObject", jh, pseudoProcess) != 1 {
		t.Fatalf("assign: err %d", h.lastError())
	}
	si, pi, code := h.alloc(104), h.alloc(24), h.alloc(4)
	h.w32(si, 104)
	if r := h.call(dK32, "CreateProcessW", 0, h.wstr(`cmd /d /c cmd /d /c exit 3`), 0, 0, 0, 0, 0, 0, si, pi); r != 1 {
		t.Fatalf("CreateProcess err %d", h.lastError())
	}
	if r := h.call(dK32, "WaitForSingleObject", h.r64(pi), 5000); r != 0 {
		t.Fatalf("wait %#x", r)
	}
	if h.call(dK32, "GetExitCodeProcess", h.r64(pi), code); h.r32(code) != 3 {
		t.Fatalf("exit code %d", h.r32(code))
	}
	info := h.alloc(48)
	if h.call(dK32, "QueryInformationJobObject", jh, jobBasicAccounting, info, 48, 0) != 1 {
		t.Fatalf("query err %d", h.lastError())
	}
	if n := h.r32(info + 36); n != 3 { // self, cmd, inner cmd
		t.Fatalf("TotalProcesses %d, want 3", n)
	}
}

// DuplicateHandle moves B2's refcounted sockets and E2's named-pipe ends into
// another process: the object survives closing the source and works there.
func TestXprocDuplicateSocketAndPipeAcross(t *testing.T) {
	h := wsaInit(t)
	b := sibling(t, h)
	h.E.proc.markStarted()
	b.E.proc.markStarted()
	if r := b.call(ws2, "WSAStartup", 0x0202, b.alloc(408)); r != 0 {
		t.Fatalf("WSAStartup = %d", r)
	}
	hb := procHandle(h, b)
	const dupSame, dupClose = 2, 1
	out := h.alloc(8)
	s := h.call(ws2, "socket", 2, 1, 6)
	if h.call(dK32, "DuplicateHandle", pseudoProcess, s, hb, out, 0, 0, dupSame|dupClose) != 1 {
		t.Fatalf("DuplicateHandle(socket) err %d", h.lastError())
	}
	if h.E.handles.get(s) != nil {
		t.Fatal("source socket handle not closed")
	}
	bs := h.r64(out)
	so := b.E.handles.get(bs).(*sockObj)
	if r := b.call(ws2, "bind", bs, sin(b, [4]byte{127, 0, 0, 1}, 0), 16); r != 0 {
		t.Fatalf("bind in target = %#x", r)
	}
	if b.call(ws2, "closesocket", bs) != 0 || !so.closed {
		t.Fatal("closing the last handle must close the socket")
	}

	const name = `\\.\pipe\xproc-dup`
	ps := h.mkPipe(name, tPipeDuplex, tPipeMsg, tUnlimited)
	if h.call(dK32, "DuplicateHandle", pseudoProcess, ps, hb, out, 0, 0, dupSame|dupClose) != 1 {
		t.Fatalf("DuplicateHandle(pipe) err %d", h.lastError())
	}
	bp := h.r64(out)
	done := make(chan string, 1)
	go func() {
		if b.call(dK32, "ConnectNamedPipe", bp, 0) == 0 && b.lastError() != errPipeConnected {
			done <- "connect failed"
			return
		}
		_, got, _ := b.readH(bp, 4)
		b.writeH(bp, got+"!")
		b.call(dK32, "FlushFileBuffers", bp)
		done <- got
	}()
	in, res, n := h.alloc(4), h.alloc(4), h.alloc(4)
	h.write(in, []byte("ab"))
	if r := h.call(dK32, "CallNamedPipeW", h.wstr(name), in, 2, res, 4, n, 2000); r != 1 || string(h.read(res, int(h.r32(n)))) != "ab!" {
		t.Fatalf("CallNamedPipe = %d err %d", r, h.lastError())
	}
	if got := <-done; got != "ab" {
		t.Fatalf("server got %q", got)
	}
}
