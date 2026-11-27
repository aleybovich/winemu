// Package pe parses 64-bit Portable Executable images.
package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	DirExport      = 0
	DirImport      = 1
	DirResource    = 2
	DirException   = 3
	DirBaseReloc   = 5
	DirTLS         = 9
	DirLoadConfig  = 10
	DirIAT         = 12
	DirDelayImport = 13

	MachineAMD64 = 0x8664
	MachineI386  = 0x14c
	MachineARM64 = 0xAA64

	CharDLL = 0x2000

	SubsystemGUI     = 2
	SubsystemConsole = 3
)

type DataDir struct {
	VA   uint32
	Size uint32
}

type Section struct {
	Name           string
	VirtualSize    uint32
	VirtualAddress uint32
	RawSize        uint32
	RawOffset      uint32
	Chars          uint32
}

type File struct {
	Data            []byte
	Machine         uint16
	Characteristics uint16
	ImageBase       uint64
	SizeOfImage     uint32
	SizeOfHeaders   uint32
	Entry           uint32
	Subsystem       uint16
	DllChars        uint16
	StackReserve    uint64
	StackCommit     uint64
	Dirs            [16]DataDir
	Sections        []Section
}

var le = binary.LittleEndian

func Parse(data []byte) (*File, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, errors.New("not an MZ executable")
	}
	off := int(le.Uint32(data[0x3C:]))
	if off+24 > len(data) || string(data[off:off+4]) != "PE\x00\x00" {
		return nil, errors.New("missing PE signature (16-bit DOS program?)")
	}
	f := &File{Data: data}
	fh := data[off+4:]
	f.Machine = le.Uint16(fh[0:])
	nsec := int(le.Uint16(fh[2:]))
	optSize := int(le.Uint16(fh[16:]))
	f.Characteristics = le.Uint16(fh[18:])
	switch f.Machine {
	case MachineAMD64:
	case MachineI386:
		return nil, errors.New("32-bit (x86) executables are not supported; only 64-bit x64 programs")
	case MachineARM64:
		return nil, errors.New("ARM64 Windows executables are not supported; only x64 programs")
	default:
		return nil, fmt.Errorf("unsupported machine type %#x", f.Machine)
	}
	oh := data[off+24:]
	if len(oh) < optSize || le.Uint16(oh) != 0x20B {
		return nil, errors.New("not a PE32+ image")
	}
	f.Entry = le.Uint32(oh[16:])
	f.ImageBase = le.Uint64(oh[24:])
	f.SizeOfImage = le.Uint32(oh[56:])
	f.SizeOfHeaders = le.Uint32(oh[60:])
	f.Subsystem = le.Uint16(oh[68:])
	f.DllChars = le.Uint16(oh[70:])
	f.StackReserve = le.Uint64(oh[72:])
	f.StackCommit = le.Uint64(oh[80:])
	ndirs := int(le.Uint32(oh[108:]))
	if ndirs > 16 {
		ndirs = 16
	}
	for i := 0; i < ndirs; i++ {
		f.Dirs[i] = DataDir{le.Uint32(oh[112+8*i:]), le.Uint32(oh[116+8*i:])}
	}
	sh := data[off+24+optSize:]
	for i := 0; i < nsec; i++ {
		s := sh[40*i:]
		if len(s) < 40 {
			return nil, errors.New("truncated section table")
		}
		name := s[:8]
		n := 0
		for n < 8 && name[n] != 0 {
			n++
		}
		f.Sections = append(f.Sections, Section{
			Name:           string(name[:n]),
			VirtualSize:    le.Uint32(s[8:]),
			VirtualAddress: le.Uint32(s[12:]),
			RawSize:        le.Uint32(s[16:]),
			RawOffset:      le.Uint32(s[20:]),
			Chars:          le.Uint32(s[36:]),
		})
	}
	return f, nil
}

func (f *File) IsDLL() bool { return f.Characteristics&CharDLL != 0 }
