//go:build linux

package win

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	ioctlGetTermios = syscall.TCGETS
	ioctlSetTermios = syscall.TCSETS
)

func fdSetAdd(s *syscall.FdSet, fd int) { s.Bits[fd/64] |= 1 << (uint(fd) % 64) }

func inputReady(f *os.File) bool {
	fd := int(f.Fd())
	var s syscall.FdSet
	fdSetAdd(&s, fd)
	tv := syscall.Timeval{}
	n, err := syscall.Select(fd+1, &s, nil, nil, &tv)
	return err == nil && n > 0
}

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}
