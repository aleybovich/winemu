// Command peimports lists the imports of a set of PE files that winemu
// cannot resolve: imports from a DLL in the set must be exported by that
// file, all others must be implemented by winemu's builtin DLLs.
//
//	go run ./tools/peimports [-all] file.dll file.exe ...
//
// Output: one line per missing import, "dll!name  [importing files]",
// sorted by DLL and name. -all also lists imports that are resolved.
package main

import (
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"winemu/internal/win"
)

type peFile struct {
	name    string // lower-case base name
	imports []string
	exports map[string]bool
}

func main() {
	all := flag.Bool("all", false, "also list resolved imports")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: peimports [-all] file.dll|file.exe ...")
		os.Exit(2)
	}
	files := map[string]*peFile{}
	var order []*peFile
	for _, path := range flag.Args() {
		f, err := load(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		files[f.name] = f
		order = append(order, f)
	}
	users := map[string][]string{}
	resolved := map[string]bool{}
	for _, f := range order {
		for _, imp := range f.imports {
			fn, dll, _ := strings.Cut(imp, ":")
			dll = strings.ToLower(dll)
			key := dll + "!" + fn
			if _, seen := resolved[key]; !seen {
				if nf := files[dll]; nf != nil {
					resolved[key] = nf.exports[fn]
				} else {
					resolved[key] = win.BuiltinHas(dll, fn)
				}
			}
			users[key] = append(users[key], f.name)
		}
	}
	keys := make([]string, 0, len(users))
	for k := range users {
		if *all || !resolved[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		mark := ""
		if *all && resolved[k] {
			mark = "ok "
		}
		fmt.Printf("%s%s  %v\n", mark, k, users[k])
	}
}

func load(path string) (*peFile, error) {
	p, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	f := &peFile{name: strings.ToLower(filepath.Base(path)), exports: map[string]bool{}}
	syms, err := p.ImportedSymbols()
	if err != nil {
		return nil, fmt.Errorf("imports: %w", err)
	}
	ords, err := ordinalImports(p)
	if err != nil {
		return nil, fmt.Errorf("ordinal imports: %w", err)
	}
	f.imports = append(syms, ords...)
	if err := readExports(p, f.exports); err != nil {
		return nil, fmt.Errorf("exports: %w", err)
	}
	return f, nil
}

// ordinalImports returns the imports by ordinal as "#n:dll" (debug/pe's
// ImportedSymbols skips them).
func ordinalImports(p *pe.File) ([]string, error) {
	oh, ok := p.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || len(oh.DataDirectory) < 2 || oh.DataDirectory[1].Size == 0 {
		return nil, nil
	}
	le := binary.LittleEndian
	var out []string
	for d := oh.DataDirectory[1].VirtualAddress; ; d += 20 {
		desc, err := readRVA(p, d, 20)
		if err != nil {
			return nil, err
		}
		nameRVA, thunk := le.Uint32(desc[12:]), le.Uint32(desc[0:])
		if nameRVA == 0 {
			return out, nil
		}
		if thunk == 0 {
			thunk = le.Uint32(desc[16:])
		}
		dll, err := readCStr(p, nameRVA)
		if err != nil {
			return nil, err
		}
		for ; ; thunk += 8 {
			b, err := readRVA(p, thunk, 8)
			if err != nil {
				return nil, err
			}
			v := le.Uint64(b)
			if v == 0 {
				break
			}
			if v&(1<<63) != 0 {
				out = append(out, fmt.Sprintf("#%d:%s", uint16(v), dll))
			}
		}
	}
}

func readRVA(p *pe.File, rva, n uint32) ([]byte, error) {
	for _, s := range p.Sections {
		if rva >= s.VirtualAddress && rva+n <= s.VirtualAddress+max(s.VirtualSize, s.Size) {
			b := make([]byte, n)
			if _, err := s.ReadAt(b, int64(rva-s.VirtualAddress)); err != nil {
				return nil, err
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("rva %#x not in any section", rva)
}

func readCStr(p *pe.File, rva uint32) (string, error) {
	var sb strings.Builder
	for ; ; rva++ {
		b, err := readRVA(p, rva, 1)
		if err != nil {
			return "", err
		}
		if b[0] == 0 {
			return sb.String(), nil
		}
		sb.WriteByte(b[0])
	}
}

// readExports adds the names (and "#ordinal"s) exported by p to out.
func readExports(p *pe.File, out map[string]bool) error {
	oh, ok := p.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || len(oh.DataDirectory) == 0 || oh.DataDirectory[0].Size == 0 {
		return nil
	}
	rva := oh.DataDirectory[0].VirtualAddress
	read := func(rva, n uint32) ([]byte, error) { return readRVA(p, rva, n) }
	dir, err := read(rva, 40)
	if err != nil {
		return err
	}
	le := binary.LittleEndian
	ordBase, nFuncs, nNames := le.Uint32(dir[16:]), le.Uint32(dir[20:]), le.Uint32(dir[24:])
	for i := range nFuncs {
		out[fmt.Sprintf("#%d", ordBase+i)] = true
	}
	if nNames == 0 {
		return nil
	}
	names, err := read(le.Uint32(dir[32:]), 4*nNames)
	if err != nil {
		return err
	}
	for i := range nNames {
		name, err := readCStr(p, le.Uint32(names[4*i:]))
		if err != nil {
			return err
		}
		out[name] = true
	}
	return nil
}
