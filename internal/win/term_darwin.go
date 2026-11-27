//go:build darwin

package win

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	ioctlGetTermios = syscall.TIOCGETA
	ioctlSetTermios = syscall.TIOCSETA
)

func fdSetAdd(s *syscall.FdSet, fd int) { s.Bits[fd/32] |= 1 << (uint(fd) % 32) }

func inputReady(f *os.File) bool {
	fd := int(f.Fd())
	var s syscall.FdSet
	fdSetAdd(&s, fd)
	tv := syscall.Timeval{}
	err := syscall.Select(fd+1, &s, nil, nil, &tv)
	if err != nil {
		return false
	}
	return s.Bits[fd/32]&(1<<(uint(fd)%32)) != 0
}

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}
