// security_user is the guest program for tests/security_test.go: it prints
// what os/user reports for the current user (user.Current, user.LookupId on
// its Uid, user.LookupGroupId on its Gid) next to GetUserNameW and
// USERPROFILE, one "key=value" per line. Errors are printed as key=ERR:...
package main

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
	"unsafe"
)

func getUserName() string {
	proc := syscall.NewLazyDLL("advapi32.dll").NewProc("GetUserNameW")
	buf := make([]uint16, 256)
	n := uint32(len(buf))
	if r, _, err := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return "ERR:" + err.Error()
	}
	return syscall.UTF16ToString(buf)
}

func main() {
	fmt.Printf("GetUserNameW=%s\n", getUserName())
	fmt.Printf("USERPROFILE=%s\n", os.Getenv("USERPROFILE"))
	u, err := user.Current()
	if err != nil {
		fmt.Printf("current=ERR:%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("current.Username=%s\ncurrent.Uid=%s\ncurrent.Gid=%s\ncurrent.HomeDir=%s\ncurrent.Name=%s\n", u.Username, u.Uid, u.Gid, u.HomeDir, u.Name)
	l, err := user.LookupId(u.Uid)
	if err != nil {
		fmt.Printf("lookup=ERR:%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("lookup.Username=%s\nlookup.Uid=%s\nlookup.Gid=%s\nlookup.HomeDir=%s\nlookup.Name=%s\n", l.Username, l.Uid, l.Gid, l.HomeDir, l.Name)
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		fmt.Printf("group=ERR:%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("group.Name=%s\n", g.Name)
}
