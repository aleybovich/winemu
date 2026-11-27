package win

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	statusSuccess        = 0
	statusNoMoreFiles    = 0x80000006
	statusInvalidParam   = 0xC000000D
	statusNoSuchFile     = 0xC000000F
	statusAccessDenied   = 0xC0000022
	statusNameNotFound   = 0xC0000034
	statusPathNotFound   = 0xC000003A
	statusNameCollision  = 0xC0000035
	statusNotADirectory  = 0xC0000103
	statusFileIsADir     = 0xC00000BA
	statusInvalidHandle  = 0xC0000008
	statusBufferTooSmall = 0xC0000023
)

func winToNT(code uint32) uint64 {
	switch code {
	case errFileNotFound:
		return statusNameNotFound
	case errPathNotFound:
		return statusPathNotFound
	case errAccessDenied:
		return statusAccessDenied
	case errFileExists, errAlreadyExists:
		return statusNameCollision
	case errInvalidHandle:
		return statusInvalidHandle
	}
	return statusInvalidParam
}

// ntPath resolves OBJECT_ATTRIBUTES to a Windows path.
func (e *Emu) ntPath(oa uint64) string {
	root := e.Mem.R64(oa + 8)
	us := e.Mem.R64(oa + 16)
	name := ""
	if us != 0 {
		name = e.Mem.WStrN(e.Mem.R64(us+8), int(e.Mem.R16(us)/2))
	}
	if root != 0 {
		if fo := e.fileObj(root); fo != nil {
			base := fo.win
			if base == "" {
				base = e.fs.toWin(fo.host)
			}
			if name == "" {
				return base
			}
			return strings.TrimRight(base, `\`) + `\` + name
		}
	}
	name = strings.TrimPrefix(name, `\??\`)
	return name
}

// dirListing loads the entries of a directory handle for enumeration.
func (e *Emu) dirListing(fo *fileObj) []os.FileInfo {
	if fo.dirEnts != nil {
		return fo.dirEnts
	}
	ents, _ := os.ReadDir(fo.host)
	sort.Slice(ents, func(a, b int) bool { return strings.ToLower(ents[a].Name()) < strings.ToLower(ents[b].Name()) })
	list := []os.FileInfo{}
	if st, err := os.Stat(fo.host); err == nil {
		list = append(list, renamed{st, "."}, renamed{st, ".."})
	}
	for _, en := range ents {
		if st, err := en.Info(); err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				if st2, err := os.Stat(filepath.Join(fo.host, en.Name())); err == nil {
					st = renamed{st2, en.Name()}
				}
			}
			list = append(list, st)
		}
	}
	fo.dirEnts = list
	return list
}

type renamed struct {
	os.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }

// fillDirInfo writes FILE_ID_BOTH_DIR_INFO (both=true) or
// FILE_FULL_DIR_INFO records. Returns bytes written, or 0 if none fit.
func (e *Emu) fillDirInfo(fo *fileObj, buf uint64, size uint32, both bool, single bool) (uint32, bool) {
	list := e.dirListing(fo)
	m := e.Mem
	var off, prev uint32
	wrote := false
	for fo.dirPos < len(list) {
		st := list[fo.dirPos]
		name := utf16.Encode([]rune(st.Name()))
		hdr := uint32(68)
		if both {
			hdr = 104
		}
		rec := (hdr + uint32(2*len(name)) + 7) &^ 7
		if off+rec > size {
			break
		}
		a := buf + uint64(off)
		m.Fill(a, 0, uint64(rec))
		c, ac, w := fileTimes(st)
		m.W64(a+8, c)
		m.W64(a+16, ac)
		m.W64(a+24, w)
		m.W64(a+32, w)
		sz := uint64(st.Size())
		if st.IsDir() {
			sz = 0
		}
		m.W64(a+40, sz)
		m.W64(a+48, (sz+4095)&^4095)
		m.W32(a+56, fileAttrs(st, st.Name()))
		m.W32(a+60, uint32(2*len(name)))
		if both {
			ino, _, _ := fileID(st)
			m.W64(a+96, ino)
			m.WriteUnits(a+104, name)
		} else {
			m.WriteUnits(a+68, name)
		}
		if wrote {
			m.W32(buf+uint64(prev), off-prev)
		}
		prev = off
		off += rec
		wrote = true
		fo.dirPos++
		if single {
			break
		}
	}
	return off, wrote
}

func init() {
	n := dNt
	ntCreate := func(e *Emu, hp, access, oa, iosb uint64, disp, opts uint32) uint64 {
		path := e.ntPath(oa)
		host := e.fs.toHost(path)
		st, err := os.Stat(host)
		isDir := err == nil && st.IsDir()
		if opts&0x1 != 0 && err == nil && !isDir { // FILE_DIRECTORY_FILE
			return statusNotADirectory
		}
		if opts&0x40 != 0 && isDir { // FILE_NON_DIRECTORY_FILE
			return statusFileIsADir
		}
		if opts&0x1 != 0 && (disp == 2 || disp == 3) && err != nil {
			if mkErr := os.Mkdir(host, 0o755); mkErr != nil {
				return winToNT(winErr(mkErr))
			}
		}
		w32disp := map[uint32]uint32{0: 2, 1: 3, 2: 1, 3: 4, 4: 5, 5: 2}[disp]
		flags := uint32(0x02000000) // allow directories
		if opts&0x1000 != 0 {
			flags |= 0x04000000
		}
		acc := uint32(access)
		if acc&0x2 != 0 || acc&0x40000000 != 0 {
			acc |= genericWrite
		}
		if acc&0x1 != 0 || acc&0x80000000 != 0 {
			acc |= genericRead
		}
		h := e.createFile(path, acc, w32disp, flags)
		if h == invalidHandle {
			return winToNT(e.LastError())
		}
		if fo := e.fileObj(h); fo != nil && opts&0x1000 != 0 {
			fo.delClose = true
		}
		e.Mem.W64(hp, h)
		if iosb != 0 {
			e.Mem.W64(iosb, 0)
			e.Mem.W64(iosb+8, 1) // FILE_OPENED
		}
		return statusSuccess
	}
	reg(n, "NtCreateFile", func(e *Emu) uint64 {
		return ntCreate(e, e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), e.Arg32(7), e.Arg32(8))
	})
	reg(n, "NtOpenFile", func(e *Emu) uint64 {
		return ntCreate(e, e.Arg(0), e.Arg(1), e.Arg(2), e.Arg(3), 1, e.Arg32(5))
	})
	reg(n, "NtQueryDirectoryFile", func(e *Emu) uint64 {
		// (h, event, apc, apcctx, iosb, buf, len, class, single, mask, restart)
		fo := e.fileObj(e.Arg(0))
		if fo == nil || !fo.isDir {
			return statusInvalidHandle
		}
		class := e.Arg32(7)
		if e.Arg32(10) != 0 {
			fo.dirPos = 0
		}
		if class != 37 && class != 2 {
			return statusInvalidParam
		}
		nb, ok := e.fillDirInfo(fo, e.Arg(5), e.Arg32(6), class == 37, e.Arg32(8) != 0)
		if !ok {
			if fo.dirPos >= len(e.dirListing(fo)) {
				return statusNoMoreFiles
			}
			return statusBufferTooSmall
		}
		if iosb := e.Arg(4); iosb != 0 {
			e.Mem.W64(iosb, 0)
			e.Mem.W64(iosb+8, uint64(nb))
		}
		return statusSuccess
	})
	reg(n, "NtReadFile", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			return statusInvalidHandle
		}
		if e.blockOnEmptyPipe(fo) {
			return 0
		}
		buf := make([]byte, e.Arg32(6))
		if p := e.Arg(7); p != 0 && fo.f != nil && fo.console == 0 {
			fo.f.Seek(int64(e.Mem.R64(p)), 0)
		}
		got, err := e.fileRead(fo, buf)
		e.Mem.Write(e.Arg(5), buf[:got])
		e.Mem.W64(e.Arg(4), 0)
		e.Mem.W64(e.Arg(4)+8, uint64(got))
		if got == 0 && err != nil {
			return 0xC0000011 // STATUS_END_OF_FILE
		}
		return statusSuccess
	})
	reg(n, "NtWriteFile", func(e *Emu) uint64 {
		fo := e.fileObj(e.Arg(0))
		if fo == nil {
			return statusInvalidHandle
		}
		if p := e.Arg(7); p != 0 && fo.f != nil && fo.console == 0 {
			fo.f.Seek(int64(e.Mem.R64(p)), 0)
		}
		got, _ := e.fileWrite(fo, e.Mem.ReadBytes(e.Arg(5), int(e.Arg32(6))))
		e.Mem.W64(e.Arg(4), 0)
		e.Mem.W64(e.Arg(4)+8, uint64(got))
		return statusSuccess
	})
	reg(n, "NtQueryInformationFile", func(e *Emu) uint64 { return 0xC0000003 })
	reg(n, "NtSetInformationFile", func(e *Emu) uint64 { return 0xC0000003 })
	reg(n, "RtlDosPathNameToNtPathName_U", func(e *Emu) uint64 {
		full := `\??\` + e.fs.full(e.WStr(e.Arg(0)))
		u := utf16.Encode([]rune(full))
		buf := e.heapAlloc(uint64(2*len(u)+2), false)
		e.Mem.WriteUnits(buf, append(u, 0))
		us := e.Arg(1)
		e.Mem.W16(us, uint16(2*len(u)))
		e.Mem.W16(us+2, uint16(2*len(u)+2))
		e.Mem.W64(us+8, buf)
		return 1
	})
	reg(dUcrt+","+dMsvc, "_register_thread_local_exe_atexit_callback", retZero)
}
