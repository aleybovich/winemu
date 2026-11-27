package win

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"winemu/internal/cpu"
	"winemu/internal/mem"
	"winemu/internal/pe"
)

const kuserBase = 0x7FFE0000

// Run loads and executes a Windows program as the root process of a session.
// It returns the root process's exit code when the root exits; every other
// guest process of the session is terminated then (the host exits with the
// root).
func (e *Emu) Run(exeHost string, args []string) (code int, err error) {
	if err := e.load(exeHost, args); err != nil {
		e.proc.exit(1)
		return 1, err
	}
	code, err = e.runProcess()
	e.k.endSession(1, 2*time.Second)
	return code, err
}

// parseExe reads and validates a PE executable.
func parseExe(abs string) ([]byte, *pe.File, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, nil, err
	}
	f, err := pe.Parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", filepath.Base(abs), err)
	}
	if f.IsDLL() {
		return nil, nil, errors.New("cannot run a DLL")
	}
	if f.Dirs[14].Size != 0 {
		return nil, nil, errors.New(".NET (managed) executables are not supported; only native x64 programs")
	}
	return data, f, nil
}

// load prepares the process for exeHost up to (excluding) running it.
func (e *Emu) load(exeHost string, args []string) (err error) {
	abs, err := filepath.Abs(exeHost)
	if err != nil {
		return err
	}
	data, f, err := parseExe(abs)
	if err != nil {
		return err
	}
	if f.Subsystem != pe.SubsystemConsole && e.Opt.Verbose {
		e.logf("note: %s is a GUI-subsystem program; only console output is supported", filepath.Base(abs))
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("loading %s: %v", filepath.Base(abs), r)
		}
	}()
	stack := min(max(f.StackReserve, 1<<20), 64<<20)
	main, err := e.setupProcess(abs, args, stack)
	if err != nil {
		return err
	}
	m, err := e.loadNativeAsExe(abs, data)
	if err != nil {
		return err
	}
	e.exe = m
	e.Mem.W64(e.peb+0x10, m.Base)
	main.start = m.Entry
	main.CPU.RIP = e.stub("winemu", "__process_start", func(e *Emu) uint64 {
		e.processInit()
		return 0
	})
	return nil
}

// setupProcess builds the process environment for the image at exeHost
// (prefix, command line, environment, console, KUSER_SHARED_DATA, heap, CRT,
// PEB, main thread with a stack of stack bytes as e.Cur, core DLLs) without
// loading the image itself. Used by Run, child processes and the unit harness.
func (e *Emu) setupProcess(exeHost string, args []string, stack uint64) (*Thread, error) {
	var err error
	e.exeHost = exeHost
	e.fs, err = newFS(e, e.Opt.Prefix)
	if err != nil {
		return nil, err
	}
	e.exeWin = e.fs.toWin(exeHost)
	e.args = append([]string{e.exeWin}, args...)
	e.cmdLine = buildCmdLine(e.args)
	if e.Opt.CmdLine != "" {
		e.cmdLine = e.Opt.CmdLine
	}
	e.env = buildEnv(e)
	if e.Opt.Env != nil {
		e.env = e.Opt.Env
	}
	if e.Opt.Cwd != "" {
		if st, err := os.Stat(e.fs.toHost(e.Opt.Cwd)); err == nil && st.IsDir() {
			e.fs.cwd = strings.TrimSuffix(e.fs.full(e.Opt.Cwd), `\`)
			if len(e.fs.cwd) == 2 {
				e.fs.cwd += `\`
			}
		}
	}
	e.con = newConsole(e)
	if _, err := e.Mem.Map(kuserBase, 0x10000, mem.PageReadOnly, mem.MemPrivate, "kuser_shared_data"); err != nil {
		return nil, err
	}
	e.initKUSER()
	e.initSpecialThunks()
	e.heap = newHeap(e)
	e.crt = newCRT(e)
	if err := e.initPEB(); err != nil {
		return nil, err
	}
	main, err := e.newThread(0, 0, stack)
	if err != nil {
		return nil, err
	}
	e.Cur = main
	for _, core := range []string{"ntdll.dll", "kernel32.dll", "kernelbase.dll"} {
		if _, err := e.LoadDLL(core); err != nil {
			return nil, err
		}
	}
	return main, nil
}

// runProcess runs a loaded process on the calling goroutine until it exits,
// then releases its kernel resources.
func (e *Emu) runProcess() (code int, err error) {
	e.lockRun()
	defer e.unlockRun() // after endProcess: other processes may touch this one only once it is gone
	e.proc.markStarted()
	root := e.proc.parent == 0
	defer func() { e.endProcess(uint32(code)) }()
	defer func() {
		if r := recover(); r != nil {
			switch v := r.(type) {
			case processExit:
				code = int(v.code)
				err = nil
			default:
				e.crt.flushAll()
				err = fmt.Errorf("%v", r)
				if os.Getenv("WINEMU_DEBUG") != "" {
					err = fmt.Errorf("%v\n%s", r, debug.Stack())
				}
				code = 1
			}
		}
		e.crt.flushAll()
		e.con.restore()
		if os.Getenv("WINEMU_STATS") != "" {
			var n uint64
			for _, t := range e.threads {
				n += t.CPU.ICount
			}
			el := time.Since(e.started)
			e.logf("stats: %d instructions in %v (%.1f M/s), %d threads", n, el, float64(n)/el.Seconds()/1e6, len(e.threads))
		}
		if p := os.Getenv("WINEMU_CPUPROFILE"); p != "" && root {
			stopProfile()
		}
	}()
	if p := os.Getenv("WINEMU_CPUPROFILE"); p != "" && root {
		startProfile(p)
	}
	e.schedule(nil, 0)
	return int(e.exitCode), nil
}

// endProcess is the kernel side of process exit: every thread is marked
// exited, every handle closed (pipe peers see EOF, names are released) and
// the process object is signalled.
func (e *Emu) endProcess(code uint32) {
	for _, t := range e.threads {
		if !t.exited {
			t.exited, t.exitCode = true, code
			t.gone.Store(true)
		}
	}
	e.unmapAllViews()
	e.handles.closeAll()
	e.proc.exit(code)
}

func (e *Emu) loadNativeAsExe(abs string, data []byte) (*Module, error) {
	m, err := e.loadNative(filepath.Base(abs), data)
	if err != nil {
		return nil, err
	}
	m.HostPath = abs
	m.WinPath = e.exeWin
	return m, nil
}

// processInit runs in the main thread before the entry point.
func (e *Emu) processInit() {
	t := e.Cur
	e.allocThreadTLS(t)
	// initialise DLLs in dependency order
	mods := append([]*Module{}, e.modules...)
	sort.SliceStable(mods, func(i, j int) bool { return mods[i].loadOrder < mods[j].loadOrder })
	if err := e.initModule(e.exe); err != nil {
		e.logf("%v", err)
		e.exitProcess(0xC0000142)
	}
	e.callTLSCallbacks(e.exe, dllProcessAttach)
	c := t.CPU
	c.R[cpu.RCX] = e.peb
	c.RIP = e.exe.Entry
	e.skipRet = true
}

func buildCmdLine(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(quoteArg(a))
	}
	return b.String()
}

// quoteArg quotes an argument following the MSVC command-line rules.
func quoteArg(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\n\v\"") {
		return a
	}
	var b strings.Builder
	b.WriteByte('"')
	bs := 0
	for _, r := range a {
		switch r {
		case '\\':
			bs++
		case '"':
			b.WriteString(strings.Repeat(`\`, 2*bs+1))
			b.WriteByte('"')
			bs = 0
		default:
			b.WriteString(strings.Repeat(`\`, bs))
			bs = 0
			b.WriteRune(r)
		}
	}
	b.WriteString(strings.Repeat(`\`, 2*bs))
	b.WriteByte('"')
	return b.String()
}

// splitCmdLine parses a command line using MSVC rules (CommandLineToArgvW).
func splitCmdLine(s string) []string {
	var args []string
	var cur strings.Builder
	inq := false
	have := false
	rs := []rune(s)
	i := 0
	// program name: no backslash processing
	for i < len(rs) && (rs[i] == ' ' || rs[i] == '\t') {
		i++
	}
	if i < len(rs) {
		if rs[i] == '"' {
			i++
			for i < len(rs) && rs[i] != '"' {
				cur.WriteRune(rs[i])
				i++
			}
			i++
		} else {
			for i < len(rs) && rs[i] != ' ' && rs[i] != '\t' {
				cur.WriteRune(rs[i])
				i++
			}
		}
		args = append(args, cur.String())
		cur.Reset()
	}
	for i < len(rs) {
		r := rs[i]
		switch {
		case (r == ' ' || r == '\t') && !inq:
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
			i++
		case r == '\\':
			n := 0
			for i < len(rs) && rs[i] == '\\' {
				n++
				i++
			}
			if i < len(rs) && rs[i] == '"' {
				cur.WriteString(strings.Repeat(`\`, n/2))
				if n%2 == 1 {
					cur.WriteByte('"')
					i++
				}
			} else {
				cur.WriteString(strings.Repeat(`\`, n))
			}
			have = true
		case r == '"':
			if inq && i+1 < len(rs) && rs[i+1] == '"' {
				cur.WriteByte('"')
				i += 2
			} else {
				inq = !inq
				i++
			}
			have = true
		default:
			cur.WriteRune(r)
			have = true
			i++
		}
	}
	if have {
		args = append(args, cur.String())
	}
	return args
}

func buildEnv(e *Emu) []string {
	user := os.Getenv("USER")
	if user == "" {
		user = "user"
	}
	vars := map[string]string{
		"ALLUSERSPROFILE":        `C:\ProgramData`,
		"APPDATA":                `C:\Users\` + user + `\AppData\Roaming`,
		"LOCALAPPDATA":           `C:\Users\` + user + `\AppData\Local`,
		"COMPUTERNAME":           "WINEMU",
		"ComSpec":                `C:\windows\system32\cmd.exe`,
		"HOMEDRIVE":              "C:",
		"HOMEPATH":               `\Users\` + user,
		"NUMBER_OF_PROCESSORS":   "4",
		"OS":                     "Windows_NT",
		"PATH":                   `C:\windows\system32;C:\windows`,
		"PATHEXT":                ".COM;.EXE;.BAT;.CMD",
		"PROCESSOR_ARCHITECTURE": "AMD64",
		"PROGRAMDATA":            `C:\ProgramData`,
		"ProgramFiles":           `C:\Program Files`,
		"ProgramFiles(x86)":      `C:\Program Files (x86)`,
		"SystemDrive":            "C:",
		"SystemRoot":             `C:\windows`,
		"TEMP":                   `C:\Users\` + user + `\AppData\Local\Temp`,
		"TMP":                    `C:\Users\` + user + `\AppData\Local\Temp`,
		"USERNAME":               user,
		"USERPROFILE":            `C:\Users\` + user,
		"windir":                 `C:\windows`,
	}
	// pass through selected host variables
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		k, v := kv[:i], kv[i+1:]
		if strings.HasPrefix(k, "WINEMU_ENV_") {
			vars[strings.TrimPrefix(k, "WINEMU_ENV_")] = v
			continue
		}
		switch k {
		case "TERM", "LANG", "LC_ALL", "COLUMNS", "LINES", "NO_COLOR", "TZ":
			vars[k] = v
		}
	}
	var env []string
	for _, k := range sortedKeys(vars) {
		env = append(env, k+"="+vars[k])
	}
	return env
}

// ---------------------------------------------------------------------------
// PEB / TEB

func (e *Emu) initPEB() error {
	r, err := e.Mem.Alloc(0x10000, mem.PageReadWrite, mem.MemPrivate, "peb")
	if err != nil {
		return err
	}
	e.peb = r.Base
	p := e.peb
	m := e.Mem
	m.W8(p+2, 0)                      // BeingDebugged
	m.W64(p+0x30, e.heap.processHeap) // ProcessHeap
	m.W32(p+0xB8, 4)                  // NumberOfProcessors
	m.W32(p+0x118, 10)                // OSMajorVersion
	m.W32(p+0x11C, 0)                 // OSMinorVersion
	m.W16(p+0x120, 19045)             // OSBuildNumber
	m.W32(p+0x124, 2)                 // OSPlatformId
	m.W32(p+0x128, 3)                 // ImageSubsystem
	m.W32(p+0x12C, 6)

	// loader data
	ldr := p + 0x1000
	m.W32(ldr, 0x58)
	m.W8(ldr+4, 1)
	for _, off := range []uint64{0x10, 0x20, 0x30} {
		m.W64(ldr+off, ldr+off)
		m.W64(ldr+off+8, ldr+off)
	}
	m.W64(p+0x18, ldr)

	// process parameters
	pp := p + 0x2000
	e.params = pp
	m.W32(pp, 0x1000)
	m.W32(pp+4, 0x1000)
	m.W32(pp+8, 1) // normalized
	strs := pp + 0x400
	putUS := func(off uint64, s string) {
		u := utf16.Encode([]rune(s))
		m.W16(pp+off, uint16(2*len(u)))
		m.W16(pp+off+2, uint16(2*len(u)+2))
		m.W64(pp+off+8, strs)
		m.WriteUnits(strs, append(u, 0))
		strs += uint64(2*len(u)+2+7) &^ 7
	}
	putUS(0x38, e.fs.cwd+`\`)
	putUS(0x50, `C:\windows\system32`)
	putUS(0x60, e.exeWin)
	putUS(0x70, e.cmdLine)
	putUS(0xB0, `WinSta0\Default`)
	// environment block
	envBlk := e.heapAllocRaw(uint64(4096 + 4*len(strings.Join(e.env, "\x00"))))
	e.writeEnvBlock(envBlk)
	m.W64(pp+0x80, envBlk)
	m.W64(p+0x20, pp)
	// std handles
	m.W64(pp+0x20, stdInputHandle)
	m.W64(pp+0x28, stdOutputHandle)
	m.W64(pp+0x30, stdErrorHandle)
	return nil
}

func (e *Emu) writeEnvBlock(a uint64) uint64 {
	p := a
	for _, kv := range e.env {
		n := e.Mem.WriteWStr(p, kv)
		p += uint64(2*n + 2)
	}
	e.Mem.W16(p, 0)
	return p + 2
}

func (e *Emu) addLdrEntry(mod *Module) {
	m := e.Mem
	ent := e.heapAllocRaw(0x200)
	m.Fill(ent, 0, 0x200)
	mod.ldrEntry = ent
	m.W64(ent+0x30, mod.Base)
	m.W64(ent+0x38, mod.Entry)
	m.W32(ent+0x40, uint32(mod.Size))
	full := mod.WinPath
	if full == "" {
		full = `C:\windows\system32\` + mod.Name
	}
	strs := ent + 0x120
	put := func(off uint64, s string) {
		u := utf16.Encode([]rune(s))
		if len(u) > 100 {
			u = u[:100]
		}
		m.W16(ent+off, uint16(2*len(u)))
		m.W16(ent+off+2, uint16(2*len(u)+2))
		buf := e.heapAllocRaw(uint64(2*len(u) + 2))
		m.WriteUnits(buf, append(u, 0))
		m.W64(ent+off+8, buf)
	}
	_ = strs
	put(0x48, full)
	put(0x58, mod.Name)
	m.W16(ent+0x6C, 0xFFFF)
	ldr := m.R64(e.peb + 0x18)
	for i, off := range []uint64{0x10, 0x20, 0x30} {
		head := ldr + off
		link := ent + uint64(i)*0x10
		last := m.R64(head + 8)
		m.W64(link, head)
		m.W64(link+8, last)
		m.W64(last, link)
		m.W64(head+8, link)
	}
}

func (e *Emu) initTEB(t *Thread) {
	m := e.Mem
	b := t.TEB
	m.W64(b+0x08, t.StackBase)
	m.W64(b+0x10, t.StackLimit)
	m.W64(b+0x30, b)
	m.W64(b+0x40, uint64(e.proc.pid))
	m.W64(b+0x48, uint64(t.ID))
	m.W64(b+0x60, e.peb)
	m.W64(b+0x1478, t.StackAlloc)
	if e.peb != 0 {
		e.allocThreadTLS(t)
	}
}

// ---------------------------------------------------------------------------
// KUSER_SHARED_DATA

func (e *Emu) initKUSER() {
	m := e.Mem
	k := uint64(kuserBase)
	m.W32(k+0x4, 0x0FA00000)
	m.W16(k+0x2C, 0x8664)
	m.W16(k+0x2E, 0x8664)
	m.WriteWStr(k+0x30, `C:\windows`)
	m.W32(k+0x260, 19045)
	m.W32(k+0x264, 1) // product type: workstation
	m.W32(k+0x26C, 10)
	m.W32(k+0x270, 0)
	// processor features: SSE/SSE2/SSE3/RDTSC/CX16/NX...
	for _, f := range []int{1, 3, 6, 7, 8, 9, 10, 12, 13, 17, 20, 23, 36, 37, 38} {
		m.W8(k+0x274+uint64(f), 1)
	}
	m.W32(k+0x3C0, 4)
	e.updateKUSER()
}

func (e *Emu) updateKUSER() {
	m := e.Mem
	k := uint64(kuserBase)
	now := time.Now() // one clock read per call: this runs on every API call
	ft := unixToFiletime(now)
	el := now.Sub(e.started)
	it := uint64(el/100) + 10000000
	m.W32(k+0x0C, uint32(it>>32))
	m.W32(k+0x08, uint32(it))
	m.W32(k+0x10, uint32(it>>32))
	m.W32(k+0x18, uint32(ft>>32))
	m.W32(k+0x14, uint32(ft))
	m.W32(k+0x1C, uint32(ft>>32))
	tick := uint64(el/time.Millisecond) + 100000
	m.W32(k+0x0, uint32(tick))
	tc := tick * (1 << 24) / 0x0FA00000 * 1 // TickCount in ticks such that GetTickCount reproduces ms
	_ = tc
	m.W32(k+0x324, uint32(tick>>32))
	m.W32(k+0x320, uint32(tick))
	m.W32(k+0x328, uint32(tick>>32))
}

func unixToFiletime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}

func filetimeToUnix(ft uint64) time.Time {
	ns := (int64(ft) - 116444736000000000) * 100
	return time.Unix(0, ns)
}
