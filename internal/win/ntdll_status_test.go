package win

import "testing"

func TestRtlGetLastNtStatus(t *testing.T) {
	h := newTestEmu(t)
	h.w32(h.E.Cur.TEB+0x1250, 0xC0000056)
	if r := h.call(dNt, "RtlGetLastNtStatus"); r != 0xC0000056 {
		t.Fatalf("RtlGetLastNtStatus = %#x", r)
	}
}

func TestNtFlushBuffersFileEx(t *testing.T) {
	h := newTestEmu(t)
	f := h.call(dK32, "CreateFileW", h.wstr(`C:\flush.txt`), genericWrite, 0, 0, 2, 0x80, 0)
	iosb := h.alloc(16)
	h.w64(iosb, 0xDEAD)
	if r := h.call(dNt, "NtFlushBuffersFileEx", f, 0, 0, 0, iosb); r != 0 || h.r64(iosb) != 0 {
		t.Fatalf("flush = %#x iosb %#x", r, h.r64(iosb))
	}
	if r := h.call(dNt, "NtFlushBuffersFileEx", 0x7FF0, 0, 0, 0, iosb); r != 0xC0000008 {
		t.Fatalf("bad handle = %#x", r)
	}
}
