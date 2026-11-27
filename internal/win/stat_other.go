//go:build !linux && !darwin

package win

import (
	"syscall"
	"time"
)

func statTimes(s *syscall.Stat_t) (atime, ctime time.Time) { return time.Now(), time.Now() }
func diskFree(path string) (free, total uint64)            { return 100 << 30, 200 << 30 }
