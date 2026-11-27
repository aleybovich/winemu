// Prints syscall.Errno texts, which Go obtains from FormatMessageW
// (FROM_SYSTEM | ARGUMENT_ARRAY | IGNORE_INSERTS), falling back to
// "winapi error #N" when the call fails.
package main

import (
	"fmt"
	"syscall"
)

func main() {
	for _, n := range []uint32{10061, 2, 193, 0xDEAD} {
		fmt.Printf("%d=%s\n", n, syscall.Errno(n).Error())
	}
}
