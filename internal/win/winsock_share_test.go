//go:build darwin || linux

package win

import (
	"bytes"
	"sync"
	"testing"
)

// WSADuplicateSocketW in the parent + WSASocketW(FROM_PROTOCOL_INFO) in the
// target: the target gets a working descriptor for the same connection, even
// after the parent closed its own.
func TestWSADuplicateSocket(t *testing.T) {
	h := wsaInit(t)
	b := sibling(t, h)
	if r := b.call(ws2, "WSAStartup", 0x0202, b.alloc(408)); r != 0 {
		t.Fatalf("child WSAStartup = %d", r)
	}
	c, s := tcpPair(t, h)
	info := h.alloc(sizeofProtoInfoW)
	if r := h.call(ws2, "WSADuplicateSocketW", s, 0x7FFFFFF0, info); r != sockErr32 || h.lastError() != wsaEINVAL {
		t.Fatalf("unknown pid = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "WSADuplicateSocketW", s, uint64(b.E.proc.pid), 0); r != sockErr32 || h.lastError() != wsaEFAULT {
		t.Fatalf("NULL info = %#x err %d", r, h.lastError())
	}
	if r := h.call(ws2, "WSADuplicateSocketW", s, uint64(b.E.proc.pid), info); r != 0 {
		t.Fatalf("WSADuplicateSocketW err %d", h.lastError())
	}
	if h.r32(info+protoInfoAFOffset) != 2 || h.r32(info+protoInfoTypeOffset) != 1 || h.r32(info)&xp1IFSHandles == 0 {
		t.Fatalf("info: af %d type %d", h.r32(info+protoInfoAFOffset), h.r32(info+protoInfoTypeOffset))
	}
	raw := h.read(info, sizeofProtoInfoW) // "passed to the child" (shared memory, pipe, ...)
	h.call(ws2, "closesocket", s)
	// the info is for process b only
	if r := h.call(ws2, "WSASocketW", ^uint64(0), ^uint64(0), ^uint64(0), info, 0, 1); r != sockErr || h.lastError() != wsaEINVAL {
		t.Fatalf("WSASocket from info in another process = %#x err %d", r, h.lastError())
	}
	binfo := b.alloc(sizeofProtoInfoW)
	b.write(binfo, raw)
	bs := b.call(ws2, "WSASocketW", ^uint64(0), ^uint64(0), ^uint64(0), binfo, 0, 1)
	if bs == sockErr {
		t.Fatalf("WSASocketW(FROM_PROTOCOL_INFO) err %d", b.lastError())
	}
	sendAll(t, b, bs, []byte("from child"))
	buf := h.alloc(64)
	if n := h.call(ws2, "recv", c, buf, 64, 0); string(h.read(buf, int(n))) != "from child" {
		t.Fatalf("parent recv %d %q", int64(n), h.read(buf, max(int(int64(n)), 0)))
	}
	sendAll(t, h, c, []byte("to child"))
	bb := b.alloc(64)
	if n := b.call(ws2, "recv", bs, bb, 64, 0); string(b.read(bb, int(n))) != "to child" {
		t.Fatalf("child recv %d", int64(n))
	}
	if r := b.call(ws2, "WSASocketW", ^uint64(0), ^uint64(0), ^uint64(0), binfo, 0, 1); r != sockErr || b.lastError() != wsaEINVAL {
		t.Fatalf("second use of the info = %#x err %d", r, b.lastError())
	}
	// closing the last descriptor closes the connection
	b.call(ws2, "closesocket", bs)
	if n := h.call(ws2, "recv", c, buf, 64, 0); n != 0 {
		t.Fatalf("recv after last close = %d err %d, want EOF", int64(n), h.lastError())
	}
}

// Sockets are inheritable unless created with WSA_FLAG_NO_HANDLE_INHERIT.
func TestSocketInheritFlag(t *testing.T) {
	h := wsaInit(t)
	a := h.call(ws2, "socket", 2, 1, 6)
	b := h.call(ws2, "WSASocketW", 2, 1, 6, 0, 0, 0x81)
	if !h.E.handles.inheritable(a) || h.E.handles.inheritable(b) {
		t.Fatalf("inheritable: socket %v, NO_HANDLE_INHERIT %v", h.E.handles.inheritable(a), h.E.handles.inheritable(b))
	}
}

// One socket object in two processes (handle inheritance): both use it
// concurrently from their own goroutines (run with -race).
func TestSharedSocketConcurrent(t *testing.T) {
	h := wsaInit(t)
	b := sibling(t, h)
	b.call(ws2, "WSAStartup", 0x0202, b.alloc(408))
	c, s := tcpPair(t, h)
	b.E.handles.set(s, h.E.handles.get(s)) // as CreateProcess(bInheritHandles) does
	h.E.proc.markStarted()
	b.E.proc.markStarted()
	const rounds = 200
	var wg sync.WaitGroup
	for _, x := range []*testEmu{h, b} {
		wg.Add(1)
		go func(x *testEmu) {
			defer wg.Done()
			p := x.alloc(4)
			x.write(p, []byte("abcd"))
			for range rounds {
				if r := x.call(ws2, "send", s, p, 4, 0); r != 4 {
					t.Errorf("send = %d err %d", int64(r), x.lastError())
					return
				}
				opt, ol := x.alloc(4), x.alloc(4)
				x.w32(ol, 4)
				x.call(ws2, "getsockopt", s, wsSolSocket, wsSoError, opt, ol)
			}
		}(x)
	}
	wg.Wait()
	buf := h.alloc(4096)
	var got []byte
	for len(got) < 2*rounds*4 {
		n := h.call(ws2, "recv", c, buf, 4096, 0)
		if int64(n) <= 0 {
			t.Fatalf("recv = %d after %d", int64(n), len(got))
		}
		got = append(got, h.read(buf, int(n))...)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte("abcd"), 2*rounds)) {
		t.Fatal("stream corrupted")
	}
}
