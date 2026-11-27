//go:build darwin

package win

import (
	"syscall"
	"time"
)

func statTimes(s *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(s.Atimespec.Sec, s.Atimespec.Nsec), time.Unix(s.Birthtimespec.Sec, s.Birthtimespec.Nsec)
}

func diskFree(path string) (free, total uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 100 << 30, 200 << 30
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize)
}

// statusChangeTime is the inode change time (st_ctime): it moves on every
// change to the entry, including a utimes() that sets the mtime back.
func statusChangeTime(s *syscall.Stat_t) time.Time {
	return time.Unix(s.Ctimespec.Sec, s.Ctimespec.Nsec)
}
