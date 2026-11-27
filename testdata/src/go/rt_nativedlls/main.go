// Command rt_nativedlls loads MSVC-built native DLLs from the directory in
// %DLL_DIR% and calls into them: ICU 67 (icuuc67.dll: u_init, u_strToUpper)
// and OpenSSL 3 (libcrypto-3-x64.dll: OpenSSL_version, RAND_bytes).
package main

import (
	"fmt"
	"os"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func cstr(p uintptr) string {
	if p == 0 {
		return "<null>"
	}
	var b []byte
	for ; *(*byte)(unsafe.Pointer(p)) != 0; p++ {
		b = append(b, *(*byte)(unsafe.Pointer(p)))
	}
	return string(b)
}

func call(dll *syscall.LazyDLL, name string, args ...uintptr) uintptr {
	p := dll.NewProc(name)
	if err := p.Find(); err != nil {
		fmt.Printf("%s: %v\n", name, err)
		os.Exit(1)
	}
	r, _, _ := p.Call(args...)
	return r
}

func main() {
	dir := os.Getenv("DLL_DIR")
	icu := syscall.NewLazyDLL(dir + `\icuuc67.dll`)
	if err := icu.Load(); err != nil {
		fmt.Println("load icuuc67:", err)
		os.Exit(1)
	}
	var status int32
	call(icu, "u_init_67", uintptr(unsafe.Pointer(&status)))
	fmt.Println("u_init:", cstr(call(icu, "u_errorName_67", uintptr(status))))

	src := append(utf16.Encode([]rune("hello, wörld ß")), 0)
	dst := make([]uint16, 64)
	status = 0
	loc := []byte("en\x00")
	n := call(icu, "u_strToUpper_67", uintptr(unsafe.Pointer(&dst[0])), uintptr(len(dst)),
		uintptr(unsafe.Pointer(&src[0])), ^uintptr(0), uintptr(unsafe.Pointer(&loc[0])), uintptr(unsafe.Pointer(&status)))
	fmt.Printf("upper: %q %d %s\n", string(utf16.Decode(dst[:int32(n)])), int32(n), cstr(call(icu, "u_errorName_67", uintptr(status))))

	crypto := syscall.NewLazyDLL(dir + `\libcrypto-3-x64.dll`)
	if err := crypto.Load(); err != nil {
		fmt.Println("load libcrypto:", err)
		os.Exit(1)
	}
	fmt.Println("openssl:", cstr(call(crypto, "OpenSSL_version", 0)))
	buf := make([]byte, 32)
	r := call(crypto, "RAND_bytes", uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	zero := 0
	for _, b := range buf {
		if b == 0 {
			zero++
		}
	}
	fmt.Printf("RAND_bytes: %d random=%v\n", int32(r), zero < 8)
}
