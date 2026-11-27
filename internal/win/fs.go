package win

import (
	"os"
	"path/filepath"
	"strings"
)

// FS maps Windows paths onto the host file system.
//
//	C:\  -> <prefix>/drive_c
//	Z:\  -> host root "/"
//
// Paths without a drive are resolved against the current directory, which
// starts as the host working directory (seen as Z:\...).
type FS struct {
	e      *Emu
	prefix string
	driveC string
	cwd    string // Windows path, no trailing backslash except for roots
	user   string
}

func newFS(e *Emu, prefix string) (*FS, error) {
	if prefix == "" {
		home, _ := os.UserHomeDir()
		prefix = filepath.Join(home, ".winemu")
	}
	prefix, _ = filepath.Abs(prefix)
	user := os.Getenv("USER")
	if user == "" {
		user = "user"
	}
	fs := &FS{e: e, prefix: prefix, driveC: filepath.Join(prefix, "drive_c"), user: user}
	for _, d := range []string{
		"windows/system32", "windows/temp", "ProgramData", "Program Files", "Program Files (x86)",
		"users/" + user + "/AppData/Local/Temp", "users/" + user + "/AppData/Roaming",
		"users/" + user + "/Documents", "users/" + user + "/Desktop", "users/Public",
	} {
		if err := os.MkdirAll(filepath.Join(fs.driveC, filepath.FromSlash(d)), 0o755); err != nil {
			return nil, err
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = "/"
	}
	fs.cwd = fs.toWin(wd)
	return fs, nil
}

func (fs *FS) hostCwd() string { return fs.toHost(fs.cwd) }

// isDevice reports special DOS device names.
func deviceName(p string) string {
	b := strings.ToUpper(p)
	b = strings.TrimPrefix(b, `\\.\`)
	if i := strings.LastIndexAny(b, `\/`); i >= 0 {
		b = b[i+1:]
	}
	if i := strings.IndexByte(b, '.'); i >= 0 && (strings.HasPrefix(b, "NUL") || strings.HasPrefix(b, "CON")) {
		b = b[:i]
	}
	b = strings.TrimSuffix(b, ":")
	switch b {
	case "NUL", "CON", "CONIN$", "CONOUT$", "AUX", "PRN":
		return b
	}
	return ""
}

// full normalises a Windows path to an absolute form like C:\a\b.
func (fs *FS) full(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	for _, pre := range []string{`\\?\`, `\??\`} {
		if strings.HasPrefix(p, pre) {
			p = p[len(pre):]
			if strings.HasPrefix(strings.ToUpper(p), `UNC\`) {
				p = `\\` + p[4:]
			}
			break
		}
	}
	var drive string
	var rest string
	switch {
	case len(p) >= 2 && p[1] == ':' && isLetter(p[0]):
		drive = strings.ToUpper(p[:1])
		rest = p[2:]
		if !strings.HasPrefix(rest, `\`) {
			// drive-relative
			if strings.EqualFold(fs.cwd[:1], drive) {
				rest = fs.cwd[2:] + `\` + rest
			} else {
				rest = `\` + rest
			}
		}
	case strings.HasPrefix(p, `\\`):
		// UNC: map \\server\share\x to Z:\server\share\x (rarely useful)
		drive = "Z"
		rest = p[1:]
	case strings.HasPrefix(p, `\`):
		drive = fs.cwd[:1]
		rest = p
	default:
		drive = fs.cwd[:1]
		rest = fs.cwd[2:] + `\` + p
	}
	parts := strings.Split(rest, `\`)
	var out []string
	for _, s := range parts {
		switch s {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			// Windows strips trailing dots and spaces from components
			t := strings.TrimRight(s, ". ")
			if t == "" {
				t = s
			}
			out = append(out, t)
		}
	}
	return drive + `:\` + strings.Join(out, `\`)
}

func isLetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

// toHost converts a Windows path to a host path.
func (fs *FS) toHost(p string) string {
	f := fs.full(p)
	drive := f[:1]
	rest := strings.ReplaceAll(f[3:], `\`, "/")
	var root string
	switch drive {
	case "C":
		root = fs.driveC
	case "Z":
		root = "/"
	default:
		root = filepath.Join(fs.prefix, "drive_"+strings.ToLower(drive))
	}
	h := filepath.Join(root, rest)
	return resolveCase(h)
}

// toWin converts a host path to a Windows path.
func (fs *FS) toWin(h string) string {
	h, _ = filepath.Abs(h)
	if rel, err := filepath.Rel(fs.driveC, h); err == nil && !strings.HasPrefix(rel, "..") {
		if rel == "." {
			return `C:\`
		}
		return `C:\` + strings.ReplaceAll(rel, "/", `\`)
	}
	return `Z:` + strings.ReplaceAll(h, "/", `\`)
}

// winDir etc.
func (fs *FS) userProfile() string { return `C:\users\` + fs.user }
func (fs *FS) tempDir() string     { return fs.userProfile() + `\AppData\Local\Temp\` }
