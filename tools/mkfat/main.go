// Command mkfat combines Mach-O binaries into a universal ("fat") binary,
// like `lipo -create`, so a macOS universal build can be made on any OS.
//
//	go run ./tools/mkfat -o winemu winemu-arm64 winemu-amd64
package main

import (
	"debug/macho"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

func main() {
	out := flag.String("o", "", "output file")
	flag.Parse()
	if *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: mkfat -o out in1 [in2...]")
		os.Exit(2)
	}
	type slice struct {
		data          []byte
		cpu, sub      uint32
		align, offset uint32
	}
	var slices []slice
	for _, p := range flag.Args() {
		data, err := os.ReadFile(p)
		if err != nil {
			fail(err)
		}
		f, err := macho.Open(p)
		if err != nil {
			fail(fmt.Errorf("%s: %w", p, err))
		}
		align := uint32(12) // 4 KiB
		if f.Cpu == macho.CpuArm64 {
			align = 14 // 16 KiB pages
		}
		slices = append(slices, slice{data: data, cpu: uint32(f.Cpu), sub: f.SubCpu, align: align})
		f.Close()
	}
	hdr := 8 + 20*len(slices)
	off := uint32(hdr)
	for i := range slices {
		a := uint32(1) << slices[i].align
		off = (off + a - 1) &^ (a - 1)
		slices[i].offset = off
		off += uint32(len(slices[i].data))
	}
	buf := make([]byte, off)
	be := binary.BigEndian
	be.PutUint32(buf[0:], 0xCAFEBABE)
	be.PutUint32(buf[4:], uint32(len(slices)))
	for i, s := range slices {
		p := buf[8+20*i:]
		be.PutUint32(p[0:], s.cpu)
		be.PutUint32(p[4:], s.sub)
		be.PutUint32(p[8:], s.offset)
		be.PutUint32(p[12:], uint32(len(s.data)))
		be.PutUint32(p[16:], s.align)
		copy(buf[s.offset:], s.data)
	}
	if err := os.WriteFile(*out, buf, 0o755); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mkfat:", err)
	os.Exit(1)
}
