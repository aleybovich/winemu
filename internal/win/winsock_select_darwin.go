package win

import "syscall"

const fdSetWordBits = 32

func sockFdSet(s *syscall.FdSet, fd int) { s.Bits[fd/fdSetWordBits] |= 1 << (uint(fd) % fdSetWordBits) }
func sockFdIsSet(s *syscall.FdSet, fd int) bool {
	return s.Bits[fd/fdSetWordBits]&(1<<(uint(fd)%fdSetWordBits)) != 0
}

func hostSelect(n int, r, w, x *syscall.FdSet) error {
	return syscall.Select(n, r, w, x, &syscall.Timeval{})
}

// host TCP keepalive idle/interval options (seconds)
const hostTCPKeepIdle, hostTCPKeepIntvl = syscall.TCP_KEEPALIVE, syscall.TCP_KEEPINTVL

// hostSelectWait is select without timeout (blocks until an fd is ready).
func hostSelectWait(n int, r, w *syscall.FdSet) error {
	return syscall.Select(n, r, w, nil, nil)
}
