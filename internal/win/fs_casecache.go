package win

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Case-insensitive host path resolution with a directory-listing cache.
//
// resolveCase maps a host path to an existing path that matches it
// case-insensitively (the first match in directory order wins, an exact
// match always wins). Paths that exist exactly cost one lstat, as before.
// For other paths the parent directory is resolved recursively and its
// listing is taken from dirCache instead of walking every component from
// the root and re-reading the parent directory.
//
// Staleness: the cache is shared by all processes (goroutines) and never
// told about changes, whether made by winemu or by anyone else. Instead each
// use re-stats the directory and trusts the cached listing only if the
// directory's change time (st_ctime, which unlike the mtime cannot be set
// back by tools that restore timestamps) is unchanged and the listing was
// taken clearly after that time (more than the timestamp granularity later), so a
// change in the same timestamp tick as the listing cannot go unnoticed. A
// case-corrected match is lstat-ed before it is returned. The cache only
// avoids syscalls; it never yields a path the old full walk would not.

type dirListing struct {
	mtime  time.Time
	listed time.Time
	names  []string // directory order (sorted), as os.ReadDir returns them
}

var dirCache = struct {
	sync.Mutex
	m map[string]*dirListing
}{m: map[string]*dirListing{}}

// dirCacheMax bounds the cache; it is simply dropped when full.
const dirCacheMax = 4096

// mtimeSlack is how long after a directory's modification time a listing
// must have been taken to be trusted: generous for filesystems with whole-
// second (or 2 s) timestamps, small for sub-second ones (coarse kernel clock).
func mtimeSlack(mtime time.Time) time.Duration {
	if mtime.Nanosecond() == 0 {
		return 2 * time.Second
	}
	return 100 * time.Millisecond
}

// changeTime is st's inode change time, or its mtime where there is none.
func changeTime(st os.FileInfo) time.Time {
	if s, ok := st.Sys().(*syscall.Stat_t); ok && s != nil {
		return statusChangeTime(s)
	}
	return st.ModTime()
}

// listDir returns the names in directory d, whose stat result is st.
func listDir(d string, st os.FileInfo) ([]string, bool) {
	mt := changeTime(st)
	dirCache.Lock()
	l := dirCache.m[d]
	dirCache.Unlock()
	if l != nil && l.mtime.Equal(mt) && l.listed.Sub(mt) > mtimeSlack(mt) {
		return l.names, true
	}
	listed := time.Now()
	ents, err := os.ReadDir(d)
	if err != nil {
		return nil, false
	}
	names := make([]string, len(ents))
	for i, en := range ents {
		names[i] = en.Name()
	}
	dirCache.Lock()
	if len(dirCache.m) >= dirCacheMax {
		clear(dirCache.m)
	}
	dirCache.m[d] = &dirListing{mtime: mt, listed: listed, names: names}
	dirCache.Unlock()
	return names, true
}

// forgetDir drops d's cached listing (after a case-corrected match vanished).
func forgetDir(d string) {
	dirCache.Lock()
	delete(dirCache.m, d)
	dirCache.Unlock()
}

// resolveCase finds an existing path matching h case-insensitively; if there
// is none it returns the longest resolvable prefix with the rest of h
// appended unchanged.
func resolveCase(h string) string {
	if _, err := os.Lstat(h); err == nil {
		return h
	}
	return resolveMissing(filepath.Clean(h))
}

func lstatOK(p string) bool { _, err := os.Lstat(p); return err == nil }

// resolveMissing resolves h, which does not exist with exactly this case.
func resolveMissing(h string) string {
	dir, base := filepath.Dir(h), filepath.Base(h)
	if dir == h || base == "" {
		return h
	}
	st, err := os.Stat(dir)
	if err != nil {
		if _, lerr := os.Lstat(dir); lerr == nil {
			return h // exists (e.g. a dangling link) but cannot be listed
		}
		dir = resolveMissing(dir)
		if st, err = os.Stat(dir); err != nil {
			return filepath.Join(dir, base)
		}
		if p := filepath.Join(dir, base); lstatOK(p) { // exact case wins under the corrected parent too
			return p
		}
	}
	for range 2 {
		names, ok := listDir(dir, st)
		if !ok {
			break
		}
		match := ""
		for _, n := range names {
			if strings.EqualFold(n, base) {
				match = n
				break
			}
		}
		if match == "" {
			break
		}
		if match != base { // base itself is missing, so match == base means stale
			if p := filepath.Join(dir, match); lstatOK(p) {
				return p
			}
		}
		forgetDir(dir) // stale listing: re-read once
		if st, err = os.Stat(dir); err != nil {
			break
		}
	}
	return filepath.Join(dir, base)
}
