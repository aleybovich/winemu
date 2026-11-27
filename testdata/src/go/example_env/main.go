// example_env is the example Go guest program for tests/example_test.go:
// it prints its process id and the value of WINEMU_EXAMPLE, then exits 3.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("pid=%d\n", os.Getpid())
	fmt.Printf("WINEMU_EXAMPLE=%s\n", os.Getenv("WINEMU_EXAMPLE"))
	fmt.Fprintln(os.Stderr, "to stderr")
	os.Exit(3)
}
