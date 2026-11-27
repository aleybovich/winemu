//go:build !linux && !darwin

package win

import "os"

func inputReady(f *os.File) bool           { return false }
func setRaw(f *os.File) (any, bool)        { return nil, false }
func restoreTerm(f *os.File, s any)        {}
func termSize(f *os.File) (int, int, bool) { return 0, 0, false }
