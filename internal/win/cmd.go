package win

// Builtin cmd.exe (%COMSPEC%): a guest process without an image whose main
// thread runs cmdMain. It supports what "cmd /C <command>" needs: switch
// and quote processing as documented by "cmd /?", %VAR% expansion, the
// redirections <, >, >>, n>, n>>, n>&m (NUL included), a few internal
// commands, and running one external program in-process (it inherits
// cmd's handles), whose exit code becomes cmd's. No interactive shell, no
// batch files, no pipes or command chaining. Its own output ends lines in
// CRLF, like cmd.exe.

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

const (
	builtinCmdPath = `C:\windows\system32\cmd.exe`
	// exit code of cmd /C for an unknown command (ERRORLEVEL is 9009
	// inside a batch, but the process exit code is 1)
	cmdNotFound = 1
)

// isBuiltinCmd reports whether a host image path is the builtin cmd.exe.
func (e *Emu) isBuiltinCmd(host string) bool {
	return host != "" && strings.EqualFold(e.fs.toWin(host), builtinCmdPath)
}

// cmdInit is the state handed to a builtin cmd's main thread.
type cmdInit struct{}

// loadBuiltinCmd prepares e (a new child process) as the builtin cmd.exe.
// It runs on the parent's goroutine.
func (e *Emu) loadBuiltinCmd(host string) error {
	main, err := e.setupProcess(host, nil, 1<<20)
	if err != nil {
		return err
	}
	main.xop = cmdInit{}
	main.CPU.RIP = e.stub("winemu", "__cmd_main", cmdMain)
	return nil
}

// cmdMain is the builtin cmd's main thread: it runs the command and waits
// (blocking only this thread) for the program it started.
func cmdMain(e *Emu) uint64 {
	t := e.Cur
	switch st := t.xop.(type) {
	case *Process:
		if !e.inWait() {
			break
		}
		e.endWait()
		code, _ := st.exitStatus()
		e.exitProcess(code)
	case cmdInit:
		t.xop = nil
		code, child := e.cmdRun(e.cmdLine)
		e.crt.flushAll()
		if child == nil {
			e.exitProcess(code)
		}
		t.xop = child
		e.block(func() bool { _, done := child.exitStatus(); return done }, infinite)
		return 0
	}
	e.exitProcess(0)
	return 0
}

// cmdSwitches skips argv[0] and the switches before /C or /K and returns
// the command text after it (ok false without /C or /K).
func cmdSwitches(cmdline string) (cmd string, s, ok bool) {
	rest := strings.TrimLeft(cmdline, " \t")
	if strings.HasPrefix(rest, `"`) {
		if i := strings.IndexByte(rest[1:], '"'); i >= 0 {
			rest = rest[i+2:]
		} else {
			rest = ""
		}
	} else if i := strings.IndexAny(rest, " \t/"); i >= 0 {
		rest = rest[i:]
	} else {
		rest = ""
	}
	for {
		rest = strings.TrimLeft(rest, " \t")
		if len(rest) < 2 || rest[0] != '/' {
			return "", s, false
		}
		switch sw := rest[1] | 0x20; sw {
		case 'c', 'k':
			return strings.TrimLeft(rest[2:], " \t"), s, true
		case 's':
			s = true
		}
		i := strings.IndexAny(rest[1:], " \t/")
		if i < 0 {
			return "", s, false
		}
		rest = rest[i+1:]
	}
}

// cmdStripQuotes applies cmd's quote rule to the command after /C.
func cmdStripQuotes(cmd string, s bool, isExe func(string) bool) string {
	if !s && strings.Count(cmd, `"`) == 2 {
		i := strings.IndexByte(cmd, '"')
		j := strings.LastIndexByte(cmd, '"')
		in := cmd[i+1 : j]
		if !strings.ContainsAny(in, "&<>()@^|") && strings.ContainsAny(in, " \t") && isExe(in) {
			return cmd
		}
	}
	if !strings.HasPrefix(cmd, `"`) {
		return cmd
	}
	cmd = cmd[1:]
	if j := strings.LastIndexByte(cmd, '"'); j >= 0 {
		cmd = cmd[:j] + cmd[j+1:]
	}
	return cmd
}

// cmdExpand replaces %NAME% by the variable's value; undefined names and
// lone percent signs stay as they are.
func cmdExpand(s string, get func(string) (string, bool)) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			break
		}
		if v, ok := get(s[i+1 : i+1+j]); ok && j > 0 {
			b.WriteString(s[:i])
			b.WriteString(v)
			s = s[i+j+2:]
			continue
		}
		b.WriteString(s[:i+1])
		s = s[i+1:]
	}
	b.WriteString(s)
	return b.String()
}

type cmdWord struct{ raw, val string } // raw keeps the quotes

type cmdRedir struct {
	fd     int
	op     string // "<", ">", ">>", ">&"
	target string
	dup    int
}

// cmdError is an error whose text is the message cmd prints.
type cmdError string

func (c cmdError) Error() string { return string(c) }

const errCmdSyntax = cmdError("The syntax of the command is incorrect.")

// cmdParse splits a command into words and redirections.
func cmdParse(s string) (words []cmdWord, redirs []cmdRedir, err error) {
	i := 0
	// word reads one word starting at i (quotes and ^ escapes); it stops
	// at whitespace and, outside quotes, at an operator character.
	word := func() (w cmdWord) {
		var raw, val strings.Builder
		quoted := false
		for ; i < len(s); i++ {
			c := s[i]
			switch {
			case c == '"':
				quoted = !quoted
				raw.WriteByte(c)
				continue
			case quoted:
			case c == ' ' || c == '\t' || c == '<' || c == '>' || c == '|' || c == '&':
				return cmdWord{raw.String(), val.String()}
			case c == '^' && i+1 < len(s):
				i++
				c = s[i]
			}
			raw.WriteByte(c)
			val.WriteByte(c)
		}
		return cmdWord{raw.String(), val.String()}
	}
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '|' || c == '&':
			return nil, nil, errors.New("winemu cmd: command chaining and pipes are not supported")
		case c == '<' || c == '>':
			fd := 0
			if c == '>' {
				fd = 1
			}
			if n := len(words); n > 0 && len(words[n-1].raw) == 1 && words[n-1].raw[0] >= '0' && words[n-1].raw[0] <= '9' &&
				i > 0 && s[i-1] == words[n-1].raw[0] && (i == 1 || s[i-2] == ' ' || s[i-2] == '\t') {
				fd = int(words[n-1].raw[0] - '0')
				words = words[:n-1]
			}
			r := cmdRedir{fd: fd, op: string(c)}
			i++
			if c == '>' && i < len(s) && s[i] == '>' {
				r.op = ">>"
				i++
			}
			if i < len(s) && s[i] == '&' {
				if i+1 >= len(s) || s[i+1] < '0' || s[i+1] > '9' {
					return nil, nil, errCmdSyntax
				}
				r.op, r.dup = ">&", int(s[i+1]-'0')
				i += 2
			} else {
				for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
					i++
				}
				w := word()
				if w.raw == "" {
					return nil, nil, errCmdSyntax
				}
				r.target = w.val
			}
			redirs = append(redirs, r)
		default:
			words = append(words, word())
		}
	}
	return words, redirs, nil
}

// cmdFindExe locates a program like cmd does: as given if it has a path,
// else in the current directory, then PATH; a name without extension gets
// the PATHEXT extensions in order.
func (e *Emu) cmdFindExe(name string) string {
	if strings.ContainsAny(name, `\/:`) {
		return e.findExe(name, nil, e.cmdPathExt())
	}
	dirs := []string{e.fs.cwd}
	if p, ok := e.getEnv("PATH"); ok {
		dirs = append(dirs, strings.Split(p, ";")...)
	}
	return e.findExe(name, dirs, e.cmdPathExt())
}

// cmdPathExt returns the PATHEXT extensions cmd can run (.COM and .EXE;
// batch files are not supported), in PATHEXT order.
func (e *Emu) cmdPathExt() []string {
	pe, ok := e.getEnv("PATHEXT")
	if !ok {
		pe = ".COM;.EXE;.BAT;.CMD"
	}
	var exts []string
	for _, x := range strings.Split(pe, ";") {
		if strings.EqualFold(x, ".com") || strings.EqualFold(x, ".exe") {
			exts = append(exts, strings.ToLower(x))
		}
	}
	return exts
}

// cmdRun runs a builtin cmd command line. It returns the exit code, or the
// started child process whose exit code cmd returns.
func (e *Emu) cmdRun(cmdline string) (uint32, *Process) {
	cmd, s, ok := cmdSwitches(cmdline)
	if !ok {
		return 0, nil
	}
	cmd = cmdStripQuotes(cmd, s, func(p string) bool { return e.cmdFindExe(p) != "" })
	cmd = cmdExpand(cmd, e.getEnv)
	var std [3]any
	for i := range std {
		std[i] = e.handles.get(e.stdHandle(i))
	}
	// cmd's own messages go to its stderr as redirected so far
	errOut := func(msg string) { e.cmdWrite(std[2], msg+"\r\n") }
	words, redirs, err := cmdParse(cmd)
	if err != nil {
		errOut(err.Error())
		return 1, nil
	}
	var opened []uint64
	defer func() {
		for _, h := range opened {
			e.handles.close(h)
		}
	}()
	for _, r := range redirs {
		if r.fd > 2 {
			continue
		}
		if r.op == ">&" {
			if r.dup <= 2 {
				std[r.fd] = std[r.dup]
			}
			continue
		}
		access, disp := uint32(genericWrite), uint32(2) // CREATE_ALWAYS
		switch r.op {
		case "<":
			access, disp = genericRead, 3 // OPEN_EXISTING
		case ">>":
			access, disp = fileAppendData, 4 // OPEN_ALWAYS
		}
		h := e.createFile(r.target, access, disp, 0)
		if h == invalidHandle {
			if r.op == "<" {
				errOut("The system cannot find the file specified.")
			} else {
				errOut("The system cannot find the path specified.")
			}
			return 1, nil
		}
		opened = append(opened, h)
		std[r.fd] = e.handles.get(h)
	}
	if len(words) == 0 {
		return 0, nil
	}
	if code, ok := e.cmdInternal(words, std); ok {
		return code, nil
	}
	name := words[0].val
	host := e.cmdFindExe(name)
	if host == "" {
		errOut("'" + name + "' is not recognized as an internal or external command,\r\noperable program or batch file.")
		return cmdNotFound, nil
	}
	raw := make([]string, len(words))
	for i, w := range words {
		raw[i] = w.raw
	}
	var c *Emu
	if data, rerr := os.ReadFile(host); e.isBuiltinCmd(host) || (rerr == nil && len(data) > 1 && data[0] == 'M' && data[1] == 'Z') {
		c, err = e.newChildProcess(childSpec{host: host, cmdline: strings.Join(raw, " "), cwd: e.fs.cwd, env: e.env, inherit: true, std: std})
	}
	if c == nil || err != nil {
		errOut("The system cannot execute the specified program.")
		return 1, nil
	}
	e.inheritJob(c.proc)
	c.startProcess()
	return 0, c.proc
}

func (e *Emu) cmdWrite(o any, s string) {
	if fo, ok := o.(*fileObj); ok {
		e.fileWrite(fo, []byte(s))
	}
}

// cmdInternal runs the internal commands cmd /C is used for.
func (e *Emu) cmdInternal(words []cmdWord, std [3]any) (uint32, bool) {
	word := strings.ToLower(words[0].val)
	var args []string
	for _, w := range words[1:] {
		args = append(args, w.raw)
	}
	rest := strings.Join(args, " ")
	out := func(s string) { e.cmdWrite(std[1], s) }
	switch {
	case strings.HasPrefix(word, "echo."):
		out(words[0].val[5:] + rest + "\r\n")
	case word == "echo":
		if rest == "" {
			out("ECHO is on.\r\n")
		} else {
			out(rest + "\r\n")
		}
	case word == "rem":
	case word == "exit":
		if len(args) > 0 && strings.EqualFold(args[0], "/b") {
			args = args[1:]
		}
		n := 0
		if len(args) > 0 {
			n, _ = strconv.Atoi(args[0])
		}
		return uint32(n), true
	case word == "ver":
		out("\r\nMicrosoft Windows [Version 10.0.19045.0] (winemu)\r\n")
	case word == "cd" || word == "chdir":
		if rest == "" {
			out(e.fs.cwd + "\r\n")
		}
	case word == "cls":
		if fo := e.conOut(stdOutputHandle); fo != nil && fo.kind == fileChar {
			e.con.write(fo, []byte("\x1b[2J\x1b[3J\x1b[H"))
			e.con.vx, e.con.vy = 0, 0
		}
	case word == "pause":
		out("Press any key to continue . . . ")
		e.con.getch()
		out("\r\n")
	case word == "title":
		e.con.title = rest
	case word == "color":
		if v, err := strconv.ParseUint(rest, 16, 8); err == nil {
			e.con.setAttr(e.conOut(stdOutputHandle), uint16(v))
		}
	default:
		return 0, false
	}
	return 0, true
}

// spawnShell starts "%COMSPEC% /c cmd" with the given std objects
// (system, _popen).
func (e *Emu) spawnShell(cmd string, std [3]any) (*Process, error) {
	comspec, ok := e.getEnv("COMSPEC")
	if !ok || comspec == "" {
		comspec = builtinCmdPath
	}
	host := e.searchExe(comspec)
	if host == "" {
		return nil, os.ErrNotExist
	}
	return e.runChild(host, comspec+" /c "+cmd, std)
}

// waitChild blocks the calling thread until p exits; the CRT call is
// re-executed then and waitChild returns (code, true).
func (e *Emu) waitChild(p *Process) {
	e.Cur.xop = p
	e.block(func() bool { _, done := p.exitStatus(); return done }, infinite)
}

// resumedChild returns the exit code of the child a re-executed CRT call
// waited for.
func (e *Emu) resumedChild() (uint32, bool) {
	p, ok := e.Cur.xop.(*Process)
	if !ok || !e.inWait() {
		return 0, false
	}
	e.Cur.xop = nil
	e.endWait()
	code, _ := p.exitStatus()
	return code, true
}

func init() {
	reg(dK32, "GenerateConsoleCtrlEvent", func(e *Emu) uint64 {
		// CTRL_C_EVENT / CTRL_BREAK_EVENT; no handler is invoked (console
		// control events are not delivered between guest processes)
		if ev := e.Arg32(0); ev > 1 {
			return e.fail(errInvalidParameter)
		}
		return 1
	})
}
