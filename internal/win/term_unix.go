//go:build linux || darwin

package win

import (
	"os"
	"syscall"
	"unsafe"
)

func setRaw(f *os.File) (any, bool) {
	var t syscall.Termios
	if err := ioctl(f.Fd(), ioctlGetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, false
	}
	saved := t
	t.Lflag &^= syscall.ICANON | syscall.ECHO
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	if err := ioctl(f.Fd(), ioctlSetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, false
	}
	return &saved, true
}

func restoreTerm(f *os.File, s any) {
	if t, ok := s.(*syscall.Termios); ok {
		ioctl(f.Fd(), ioctlSetTermios, unsafe.Pointer(t))
	}
}

type winsize struct{ Row, Col, X, Y uint16 }

func termSize(f *os.File) (int, int, bool) {
	var ws winsize
	if err := ioctl(f.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil || ws.Col == 0 {
		return 0, 0, false
	}
	return int(ws.Col), int(ws.Row), true
}
