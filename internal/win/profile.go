package win

import (
	"os"
	"runtime/pprof"
)

var profFile *os.File

func startProfile(path string) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	profFile = f
	pprof.StartCPUProfile(f)
}

func stopProfile() {
	if profFile != nil {
		pprof.StopCPUProfile()
		profFile.Close()
	}
}
