package win

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"winemu/internal/mem"
	"winemu/internal/pe"
)

// Module is a loaded image, native (from a file) or builtin (emulated).
type Module struct {
	Name     string // base name as loaded, e.g. "KERNEL32.dll"
	WinPath  string
	HostPath string
	Base     uint64
	Size     uint64
	Entry    uint64
	Native   bool
	PE       *pe.File

	exports  map[string]uint64
	ordinals map[uint32]uint64
	forward  map[string]string // export name -> "DLL.Func"
	ordFwd   map[uint32]string

	// builtin
	table  *apiTable
	apiset bool

	// TLS
	tlsIndex    int
	tlsStart    uint64
	tlsEnd      uint64
	tlsZero     uint64
	tlsIndexPtr uint64
	tlsCallback uint64 // address of callback array

	pdata, pdataSize uint64

	initDone   bool
	noThreadCB bool
	refs       int
	loadOrder  int
	ldrEntry   uint64
}

// ---------------------------------------------------------------------------
// builtin API registry

type apiDef struct {
	fn       Fn
	dataSize int
	dataInit func(e *Emu, addr uint64)
}

type apiTable struct {
	name  string // canonical dll file name, e.g. "kernel32.dll"
	funcs map[string]*apiDef
	ords  map[uint32]string
}

var registry = map[string]*apiTable{}

func table(dll string) *apiTable {
	dll = lower(dll)
	t := registry[dll]
	if t == nil {
		t = &apiTable{name: dll, funcs: map[string]*apiDef{}, ords: map[uint32]string{}}
		registry[dll] = t
	}
	return t
}

// regDups records "dll!name" for every registration that replaced an
// earlier one (the later one wins, in init order); tests require it empty.
var regDups []string

func regDef(dlls, name string, def *apiDef) {
	for _, d := range strings.Split(dlls, ",") {
		t := table(d)
		if t.funcs[name] != nil {
			regDups = append(regDups, t.name+"!"+name)
		}
		t.funcs[name] = def
	}
}

// reg registers fn under each of the given dlls.
func reg(dlls string, name string, fn Fn) { regDef(dlls, name, &apiDef{fn: fn}) }

// regData registers a data export.
func regData(dlls, name string, size int, init func(e *Emu, addr uint64)) {
	regDef(dlls, name, &apiDef{dataSize: size, dataInit: init})
}

func regOrd(dll string, ord uint32, name string) { table(dll).ords[ord] = name }

const (
	dK32   = "kernel32.dll"
	dNt    = "ntdll.dll"
	dUcrt  = "ucrtbase.dll"
	dMsvc  = "msvcrt.dll"
	dVc    = "vcruntime140.dll"
	dAdv   = "advapi32.dll"
	dUser  = "user32.dll"
	dShell = "shell32.dll"
)

// builtinOnly lists DLLs that are always emulated even if a native copy exists.
var builtinOnly = map[string]bool{
	"kernel32.dll": true, "kernelbase.dll": true, "ntdll.dll": true, "ucrtbase.dll": true,
	"msvcrt.dll": true, "advapi32.dll": true, "user32.dll": true, "gdi32.dll": true,
	"shell32.dll": true, "bcrypt.dll": true, "bcryptprimitives.dll": true, "ws2_32.dll": true,
	"ole32.dll": true, "oleaut32.dll": true, "userenv.dll": true, "secur32.dll": true,
	"crypt32.dll": true, "shlwapi.dll": true, "psapi.dll": true, "version.dll": true,
	"dbghelp.dll": true, "winmm.dll": true, "powrprof.dll": true, "iphlpapi.dll": true,
	"ntoskrnl.exe": true, "rpcrt4.dll": true, "sechost.dll": true, "cfgmgr32.dll": true,
	"msvcrt40.dll": true, "crtdll.dll": true, "comctl32.dll": true, "comdlg32.dll": true,
	"imm32.dll": true, "netapi32.dll": true, "mswsock.dll": true, "dwmapi.dll": true,
	"uxtheme.dll": true, "setupapi.dll": true, "wtsapi32.dll": true, "winhttp.dll": true,
	"wininet.dll": true, "synchronization.dll": true, "pdh.dll": true, "ncrypt.dll": true,
	"wldap32.dll": true,
	// Microsoft C/C++ runtime (redistributable): never load a native copy
	"msvcp140.dll": true, "msvcp140_1.dll": true, "msvcp140_2.dll": true, "msvcp140_atomic_wait.dll": true,
	"msvcp140_codecvt_ids.dll": true, "vcruntime140.dll": true, "vcruntime140_1.dll": true, "concrt140.dll": true,
}

// aliases maps alternative names onto canonical builtin tables.
func canonicalBuiltin(name string) (string, bool) {
	n := lower(name)
	switch {
	case strings.HasPrefix(n, "api-ms-win-crt-"):
		return dUcrt, true
	case strings.HasPrefix(n, "api-ms-win-") || strings.HasPrefix(n, "ext-ms-win-"):
		return n, true // resolved through apiset lookup
	case n == "kernelbase.dll":
		return dK32, true
	case n == "msvcr100.dll" || n == "msvcr110.dll" || n == "msvcr120.dll" || n == "msvcr90.dll" || n == "msvcr80.dll" || n == "crtdll.dll" || n == "msvcrt40.dll":
		return dMsvc, true
	case n == "vcruntime140_1.dll":
		return "vcruntime140_1.dll", true
	}
	return n, true
}

// ---------------------------------------------------------------------------
// DLL resolution

func normDLL(name string) string {
	n := strings.TrimSpace(name)
	if i := strings.LastIndexAny(n, `\/`); i >= 0 {
		n = n[i+1:]
	}
	if !strings.Contains(n, ".") {
		n += ".dll"
	}
	return lower(n)
}

// findNativeDLL searches the application directory, the prefix's system32
// and the working directory (system32Only: system32 alone).
func (e *Emu) findNativeDLL(name string, system32Only bool) string {
	var dirs []string
	if !system32Only {
		dirs = append(dirs, filepath.Dir(e.exeHost))
	}
	if e.fs != nil {
		dirs = append(dirs, filepath.Join(e.fs.driveC, "windows", "system32"))
		if !system32Only {
			dirs = append(dirs, e.fs.hostCwd())
		}
	}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, en := range ents {
			if lower(en.Name()) == name && !en.IsDir() {
				return filepath.Join(d, en.Name())
			}
		}
	}
	return ""
}

// LoadDLL loads (or returns an already loaded) module by name.
func (e *Emu) LoadDLL(name string) (*Module, error) { return e.loadDLL(name, false) }

// loadDLL is LoadDLL; system32Only restricts the search for a native DLL
// given by name only to the system directory.
func (e *Emu) loadDLL(name string, system32Only bool) (*Module, error) {
	key := normDLL(name)
	if m := e.modByName[key]; m != nil {
		return m, nil
	}
	alwaysBuiltin := builtinOnly[key] || strings.HasPrefix(key, "api-ms-") || strings.HasPrefix(key, "ext-ms-")
	if strings.ContainsAny(name, `\/`) && !alwaysBuiltin {
		// explicit path
		host := e.fs.toHost(name)
		if st, err := os.Stat(host); err == nil && !st.IsDir() {
			return e.loadNativeFile(host)
		}
	}
	if !alwaysBuiltin {
		if p := e.findNativeDLL(key, system32Only); p != "" {
			return e.loadNativeFile(p)
		}
	}
	canon, _ := canonicalBuiltin(key)
	if strings.HasPrefix(canon, "api-ms-") || strings.HasPrefix(canon, "ext-ms-") {
		return e.makeBuiltin(key, nil, true), nil
	}
	if t := registry[canon]; t != nil {
		m := e.modByName[canon]
		if m == nil {
			m = e.makeBuiltin(canon, t, false)
		}
		e.modByName[key] = m
		return m, nil
	}
	if builtinOnly[key] {
		// known system DLL without a table: provide an empty builtin
		// (a fresh table: the registry is only written by init, other
		// processes read it concurrently)
		return e.makeBuiltin(key, &apiTable{name: key, funcs: map[string]*apiDef{}, ords: map[uint32]string{}}, false), nil
	}
	return nil, fmt.Errorf("%s not found (put the DLL next to the .exe or into %s)", name,
		filepath.Join(e.fs.driveC, "windows", "system32"))
}

// ---------------------------------------------------------------------------
// builtin images

func (e *Emu) makeBuiltin(name string, t *apiTable, apiset bool) *Module {
	m := &Module{Name: name, WinPath: `C:\windows\system32\` + name, exports: map[string]uint64{},
		ordinals: map[uint32]uint64{}, table: t, apiset: apiset}
	var names []string
	if t != nil {
		names = sortedKeys(t.funcs)
	}
	// layout: headers page, export dir, thunks, data
	exportSize := 40 + 4*len(names)*3 + 64
	for _, n := range names {
		exportSize += len(n) + 1
	}
	exportSize = (exportSize + 15) &^ 15
	thunkOff := uint64(0x1000 + exportSize)
	thunkOff = (thunkOff + 0xFFF) &^ 0xFFF
	nfuncs := 0
	dataSize := 0
	if t != nil {
		for _, d := range t.funcs {
			if d.fn != nil {
				nfuncs++
			} else {
				dataSize += (d.dataSize + 15) &^ 15
			}
		}
	}
	dataOff := thunkOff + uint64(nfuncs*thunkSize)
	dataOff = (dataOff + 0xFFF) &^ 0xFFF
	size := dataOff + uint64(dataSize) + 0x1000
	if e.builtinTop == 0 {
		e.builtinTop = 0x7FF800000000
	}
	r, err := e.Mem.AllocFrom(e.builtinTop, size, mem.PageExecuteRead, mem.MemImage, name)
	if err != nil {
		panic(err)
	}
	e.builtinTop = r.Base + r.Size
	m.Base, m.Size = r.Base, r.Size
	base := m.Base

	// headers
	hdr := make([]byte, 0x400)
	hdr[0], hdr[1] = 'M', 'Z'
	le.PutUint32(hdr[0x3C:], 0x80)
	copy(hdr[0x80:], "PE\x00\x00")
	fh := hdr[0x84:]
	le.PutUint16(fh[0:], pe.MachineAMD64)
	le.PutUint16(fh[2:], 1)
	le.PutUint16(fh[16:], 240)
	le.PutUint16(fh[18:], 0x2022)
	oh := hdr[0x98:]
	le.PutUint16(oh[0:], 0x20B)
	le.PutUint64(oh[24:], base)
	le.PutUint32(oh[32:], 0x1000)
	le.PutUint32(oh[36:], 0x200)
	le.PutUint16(oh[40:], 10)
	le.PutUint32(oh[56:], uint32(size))
	le.PutUint32(oh[60:], 0x400)
	le.PutUint16(oh[68:], 3)
	le.PutUint32(oh[108:], 16)
	le.PutUint32(oh[112:], 0x1000)
	le.PutUint32(oh[116:], uint32(exportSize))
	sec := hdr[0x98+240:]
	copy(sec, ".text")
	le.PutUint32(sec[8:], uint32(size-0x1000))
	le.PutUint32(sec[12:], 0x1000)
	le.PutUint32(sec[36:], 0x60000020)
	e.Mem.Write(base, hdr)

	// thunks and data
	ti := 0
	doff := dataOff
	funcAddr := map[string]uint64{}
	for _, n := range names {
		d := t.funcs[n]
		if d.fn != nil {
			a := base + thunkOff + uint64(ti*thunkSize)
			e.writeThunk(a, e.addHLE(strings.TrimSuffix(name, ".dll"), n, d.fn))
			funcAddr[n] = a
			ti++
		} else {
			a := base + doff
			doff += uint64((d.dataSize + 15) &^ 15)
			funcAddr[n] = a
		}
	}
	// export directory
	ed := base + 0x1000
	nn := uint32(len(names))
	aof := ed + 40
	aon := aof + uint64(4*nn)
	aoo := aon + uint64(4*nn)
	strs := aoo + uint64(2*nn)
	e.Mem.W32(ed+12, uint32(strs-base)) // name
	e.Mem.WriteCStr(strs, name)
	strs += uint64(len(name) + 1)
	e.Mem.W32(ed+16, 1)
	e.Mem.W32(ed+20, nn)
	e.Mem.W32(ed+24, nn)
	e.Mem.W32(ed+28, uint32(aof-base))
	e.Mem.W32(ed+32, uint32(aon-base))
	e.Mem.W32(ed+36, uint32(aoo-base))
	for i, n := range names {
		e.Mem.W32(aof+uint64(4*i), uint32(funcAddr[n]-base))
		e.Mem.W32(aon+uint64(4*i), uint32(strs-base))
		e.Mem.W16(aoo+uint64(2*i), uint16(i))
		e.Mem.WriteCStr(strs, n)
		strs += uint64(len(n) + 1)
		m.exports[n] = funcAddr[n]
	}
	if t != nil {
		for o, n := range t.ords {
			if a, ok := funcAddr[n]; ok {
				m.ordinals[o] = a
			}
		}
	}
	e.registerModule(m)
	// initialise data exports
	if t != nil {
		for _, n := range names {
			if d := t.funcs[n]; d.fn == nil && d.dataInit != nil {
				d.dataInit(e, funcAddr[n])
			}
		}
	}
	m.initDone = true
	return m
}

func (e *Emu) registerModule(m *Module) {
	m.loadOrder = len(e.modules)
	e.modules = append(e.modules, m)
	e.modByName[normDLL(m.Name)] = m
	if e.peb != 0 {
		e.addLdrEntry(m)
	}
}

// ---------------------------------------------------------------------------
// export lookup

var apisetOrder = []string{dK32, dNt, dAdv, dUcrt, "bcryptprimitives.dll", dUser, "synchronization.dll"}

// GetExport resolves name (or "#ord") in module m. ok=false if not found.
func (e *Emu) GetExport(m *Module, name string, ord uint32, byOrd bool) (uint64, bool) {
	if m.apiset {
		if byOrd {
			return 0, false
		}
		for _, d := range apisetOrder {
			if t := registry[d]; t != nil && t.funcs[name] != nil {
				mm, err := e.LoadDLL(d)
				if err == nil {
					return e.GetExport(mm, name, 0, false)
				}
			}
		}
		return 0, false
	}
	var a uint64
	var ok bool
	var fwd string
	if byOrd {
		a, ok = m.ordinals[ord]
		if !ok {
			fwd = m.ordFwd[ord]
		}
	} else {
		a, ok = m.exports[name]
		if !ok {
			fwd = m.forward[name]
		}
	}
	if ok {
		return a, true
	}
	if fwd != "" {
		i := strings.LastIndex(fwd, ".")
		if i > 0 {
			dm, err := e.LoadDLL(fwd[:i])
			if err == nil {
				fn := fwd[i+1:]
				if strings.HasPrefix(fn, "#") {
					var o uint32
					fmt.Sscanf(fn[1:], "%d", &o)
					return e.GetExport(dm, "", o, true)
				}
				return e.GetExport(dm, fn, 0, false)
			}
		}
	}
	return 0, false
}

// resolveImport returns an address for an import, creating an
// "unimplemented" stub for missing builtin functions.
func (e *Emu) resolveImport(m *Module, dllName, name string, ord uint32, byOrd bool) (uint64, error) {
	if a, ok := e.GetExport(m, name, ord, byOrd); ok {
		return a, nil
	}
	if m.Native {
		if byOrd {
			return 0, fmt.Errorf("ordinal %d not found in %s", ord, m.Name)
		}
		return 0, fmt.Errorf("%s not found in %s", name, m.Name)
	}
	fname := name
	if byOrd {
		fname = fmt.Sprintf("#%d", ord)
	}
	dll := strings.TrimSuffix(lower(dllName), ".dll")
	return e.stub(dll, fname, func(e *Emu) uint64 {
		return e.unimplemented(dll, fname)
	}), nil
}

func (e *Emu) unimplemented(dll, name string) uint64 {
	if e.Opt.Lenient {
		e.warnOnce(dll+name, "unimplemented API %s!%s called, returning 0", dll, name)
		return 0
	}
	c := e.Cur.CPU
	ret := e.Mem.R64(c.R[4])
	e.logf("unimplemented API called: %s!%s (from %s)", dll, name, e.symbolize(ret))
	e.logf("run with -lenient to make unimplemented APIs return 0 instead")
	e.exitProcess(0xC0000139) // STATUS_ENTRYPOINT_NOT_FOUND
	return 0
}

// ---------------------------------------------------------------------------
// native PE loading

var le = binary.LittleEndian

func (e *Emu) loadNativeFile(hostPath string) (*Module, error) {
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return nil, err
	}
	m, err := e.loadNative(filepath.Base(hostPath), data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(hostPath), err)
	}
	m.HostPath = hostPath
	m.WinPath = e.fs.toWin(hostPath)
	return m, nil
}

func (e *Emu) loadNative(name string, data []byte) (*Module, error) {
	f, err := pe.Parse(data)
	if err != nil {
		return nil, err
	}
	size := uint64(f.SizeOfImage)
	base := f.ImageBase
	var r *mem.Region
	if base != 0 && e.Mem.IsFree(base, (size+0xFFFF)&^0xFFFF) {
		r, err = e.Mem.Map(base, size, mem.PageExecuteReadWrite, mem.MemImage, name)
	}
	if r == nil {
		if f.Dirs[pe.DirBaseReloc].Size == 0 && !f.IsDLL() {
			return nil, fmt.Errorf("image base %#x unavailable and image has no relocations", base)
		}
		start := uint64(0x180000000)
		if !f.IsDLL() {
			start = 0x140000000
		}
		r, err = e.Mem.AllocFrom(start, size, mem.PageExecuteReadWrite, mem.MemImage, name)
		if err != nil {
			return nil, err
		}
	}
	m := &Module{Name: name, Base: r.Base, Size: r.Size, Native: true, PE: f,
		exports: map[string]uint64{}, ordinals: map[uint32]uint64{}, forward: map[string]string{}, ordFwd: map[uint32]string{}}
	// headers
	hs := uint64(f.SizeOfHeaders)
	if hs > uint64(len(data)) {
		hs = uint64(len(data))
	}
	e.Mem.Write(m.Base, data[:hs])
	for _, s := range f.Sections {
		n := s.RawSize
		if s.VirtualSize != 0 && n > s.VirtualSize {
			n = s.VirtualSize
		}
		if s.RawOffset == 0 || n == 0 {
			continue
		}
		end := uint64(s.RawOffset) + uint64(n)
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		if uint64(s.RawOffset) < end {
			e.Mem.Write(m.Base+uint64(s.VirtualAddress), data[s.RawOffset:end])
		}
	}
	if delta := m.Base - f.ImageBase; delta != 0 {
		e.relocate(m, delta)
		// patch ImageBase in the mapped header
		peOff := uint64(e.Mem.R32(m.Base + 0x3C))
		e.Mem.W64(m.Base+peOff+24+24, m.Base)
	}
	if f.Entry != 0 {
		m.Entry = m.Base + uint64(f.Entry)
	}
	if d := f.Dirs[pe.DirException]; d.Size != 0 {
		m.pdata, m.pdataSize = m.Base+uint64(d.VA), uint64(d.Size)
	}
	e.parseExports(m)
	e.registerModule(m)
	if err := e.resolveImports(m); err != nil {
		return nil, err
	}
	e.setupTLS(m)
	return m, nil
}

func (e *Emu) relocate(m *Module, delta uint64) {
	d := m.PE.Dirs[pe.DirBaseReloc]
	p := m.Base + uint64(d.VA)
	end := p + uint64(d.Size)
	for p+8 <= end {
		page := uint64(e.Mem.R32(p))
		bs := uint64(e.Mem.R32(p + 4))
		if bs < 8 {
			break
		}
		for q := p + 8; q < p+bs; q += 2 {
			v := e.Mem.R16(q)
			typ, off := v>>12, uint64(v&0xFFF)
			a := m.Base + page + off
			switch typ {
			case 10:
				e.Mem.W64(a, e.Mem.R64(a)+delta)
			case 3:
				e.Mem.W32(a, e.Mem.R32(a)+uint32(delta))
			}
		}
		p += bs
	}
}

func (e *Emu) parseExports(m *Module) {
	d := m.PE.Dirs[pe.DirExport]
	if d.Size == 0 {
		return
	}
	ed := m.Base + uint64(d.VA)
	edEnd := ed + uint64(d.Size)
	ordBase := e.Mem.R32(ed + 16)
	nf := e.Mem.R32(ed + 20)
	nn := e.Mem.R32(ed + 24)
	aof := m.Base + uint64(e.Mem.R32(ed+28))
	aon := m.Base + uint64(e.Mem.R32(ed+32))
	aoo := m.Base + uint64(e.Mem.R32(ed+36))
	addrOf := func(i uint32) (uint64, string) {
		rva := uint64(e.Mem.R32(aof + 4*uint64(i)))
		a := m.Base + rva
		if a >= ed && a < edEnd {
			return 0, e.Mem.CStr(a)
		}
		return a, ""
	}
	for i := uint32(0); i < nf; i++ {
		a, fwd := addrOf(i)
		if fwd != "" {
			m.ordFwd[ordBase+i] = fwd
		} else if a != m.Base {
			m.ordinals[ordBase+i] = a
		}
	}
	for i := uint32(0); i < nn; i++ {
		name := e.Mem.CStr(m.Base + uint64(e.Mem.R32(aon+4*uint64(i))))
		idx := uint32(e.Mem.R16(aoo + 2*uint64(i)))
		a, fwd := addrOf(idx)
		if fwd != "" {
			m.forward[name] = fwd
		} else {
			m.exports[name] = a
		}
	}
}

func (e *Emu) resolveImports(m *Module) error {
	d := m.PE.Dirs[pe.DirImport]
	if d.Size == 0 {
		return nil
	}
	for p := m.Base + uint64(d.VA); ; p += 20 {
		ilt := uint64(e.Mem.R32(p))
		nameRVA := e.Mem.R32(p + 12)
		iat := uint64(e.Mem.R32(p + 16))
		if nameRVA == 0 && iat == 0 {
			break
		}
		dll := e.Mem.CStr(m.Base + uint64(nameRVA))
		dm, err := e.LoadDLL(dll)
		if err != nil {
			return err
		}
		if ilt == 0 {
			ilt = iat
		}
		for i := uint64(0); ; i++ {
			v := e.Mem.R64(m.Base + ilt + 8*i)
			if v == 0 {
				break
			}
			var a uint64
			if v>>63 != 0 {
				a, err = e.resolveImport(dm, dll, "", uint32(v&0xFFFF), true)
			} else {
				name := e.Mem.CStr(m.Base + (v & 0x7FFFFFFF) + 2)
				a, err = e.resolveImport(dm, dll, name, 0, false)
			}
			if err != nil {
				return err
			}
			e.Mem.W64(m.Base+iat+8*i, a)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// static TLS

func (e *Emu) setupTLS(m *Module) {
	d := m.PE.Dirs[pe.DirTLS]
	if d.Size == 0 {
		return
	}
	td := m.Base + uint64(d.VA)
	m.tlsStart = e.Mem.R64(td)
	m.tlsEnd = e.Mem.R64(td + 8)
	m.tlsIndexPtr = e.Mem.R64(td + 16)
	m.tlsCallback = e.Mem.R64(td + 24)
	m.tlsZero = uint64(e.Mem.R32(td + 32))
	m.tlsIndex = len(e.tlsModules)
	e.tlsModules = append(e.tlsModules, m)
	if m.tlsIndexPtr != 0 {
		e.Mem.W32(m.tlsIndexPtr, uint32(m.tlsIndex))
	}
	// allocate for existing threads
	for _, t := range e.threads {
		e.allocThreadTLS(t)
	}
}

// allocThreadTLS (re)builds the ThreadLocalStoragePointer array for t.
func (e *Emu) allocThreadTLS(t *Thread) {
	if len(e.tlsModules) == 0 {
		return
	}
	arr := e.Mem.R64(t.TEB + 0x58)
	n := uint64(len(e.tlsModules))
	newArr := e.heapAlloc(8*(n+8), true)
	if arr != 0 {
		// copy existing pointers
		for i := uint64(0); i < n; i++ {
			// old array might be shorter; it is zero-filled by heap on growth
			v := uint64(0)
			if e.heapSize(arr) >= 8*(i+1) {
				v = e.Mem.R64(arr + 8*i)
			}
			e.Mem.W64(newArr+8*i, v)
		}
	}
	for i, m := range e.tlsModules {
		slot := newArr + 8*uint64(i)
		if e.Mem.R64(slot) != 0 {
			continue
		}
		tsize := m.tlsEnd - m.tlsStart
		blk := e.heapAlloc(tsize+m.tlsZero+16, true)
		if tsize > 0 {
			e.Mem.Move(blk, m.tlsStart, tsize)
		}
		e.Mem.W64(slot, blk)
	}
	e.Mem.W64(t.TEB+0x58, newArr)
}

// callTLSCallbacks invokes the module's TLS callbacks with reason.
func (e *Emu) callTLSCallbacks(m *Module, reason uint64) {
	if m.tlsCallback == 0 {
		return
	}
	for p := m.tlsCallback; ; p += 8 {
		cb := e.Mem.R64(p)
		if cb == 0 {
			break
		}
		e.CallGuest(cb, m.Base, reason, 0)
	}
}

const (
	dllProcessDetach = 0
	dllProcessAttach = 1
	dllThreadAttach  = 2
	dllThreadDetach  = 3
)

// initModule runs TLS callbacks and DllMain for a native DLL (deps first).
func (e *Emu) initModule(m *Module) error {
	if m.initDone || !m.Native {
		return nil
	}
	m.initDone = true
	// dependencies
	if d := m.PE.Dirs[pe.DirImport]; d.Size != 0 {
		for p := m.Base + uint64(d.VA); ; p += 20 {
			nameRVA := e.Mem.R32(p + 12)
			if nameRVA == 0 {
				break
			}
			if dm := e.modByName[normDLL(e.Mem.CStr(m.Base+uint64(nameRVA)))]; dm != nil {
				if err := e.initModule(dm); err != nil {
					return err
				}
			}
		}
	}
	if m == e.exe {
		return nil
	}
	e.callTLSCallbacks(m, dllProcessAttach)
	if m.Entry != 0 && m.PE.IsDLL() {
		r := e.CallGuest(m.Entry, m.Base, dllProcessAttach, 0)
		if uint32(r) == 0 {
			return fmt.Errorf("DllMain of %s failed", m.Name)
		}
	}
	return nil
}

func (e *Emu) threadAttach(t *Thread) {
	e.allocThreadTLS(t)
	for _, m := range e.modules {
		if !m.Native || !m.initDone || m.noThreadCB {
			continue
		}
		e.callTLSCallbacks(m, dllThreadAttach)
		if m.Entry != 0 && m.PE.IsDLL() {
			e.CallGuest(m.Entry, m.Base, dllThreadAttach, 0)
		}
	}
}

func (e *Emu) threadDetach(t *Thread) {
	// best effort, but a process exit requested meanwhile (by a callback, or
	// by another thread scheduled during it) must still end the process
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(processExit); ok {
				panic(r)
			}
		}
	}()
	for i := len(e.modules) - 1; i >= 0; i-- {
		m := e.modules[i]
		if !m.Native || !m.initDone || m.noThreadCB {
			continue
		}
		e.callTLSCallbacks(m, dllThreadDetach)
		if m.Entry != 0 && m.PE.IsDLL() {
			e.CallGuest(m.Entry, m.Base, dllThreadDetach, 0)
		}
	}
	e.flsThreadExit(t)
}
