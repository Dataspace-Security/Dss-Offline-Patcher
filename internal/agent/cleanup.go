package agent

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// cacheMaxAge: payloads left in the cache (a failed install keeps its
	// file for the retry, an abandoned .part a resumable download) are
	// removed once untouched for this long.
	cacheMaxAge = 7 * 24 * time.Hour
	// maxInstallerLogs caps msiexec verbose logs (several MB each).
	maxInstallerLogs = 50
	// cleanupEvery: how often the agent sweeps its cache.
	cleanupEvery = 24 * time.Hour
)

// cleanCache removes regular files in dir not modified within maxAge.
func cleanCache(dir string, maxAge time.Duration, now time.Time) (removed int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil || now.Sub(fi.ModTime()) < maxAge {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			removed++
		}
	}
	return removed
}

// pruneOldest keeps the newest keep files with suffix ext in dir, leaving
// room for one more (call it before creating a new file).
func pruneOldest(dir, ext string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type f struct {
		name string
		mod  time.Time
	}
	var fs []f
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.HasSuffix(strings.ToLower(e.Name()), ext) {
			continue
		}
		if fi, err := e.Info(); err == nil {
			fs = append(fs, f{e.Name(), fi.ModTime()})
		}
	}
	if len(fs) < keep {
		return
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].mod.After(fs[j].mod) })
	for _, x := range fs[keep-1:] {
		os.Remove(filepath.Join(dir, x.name))
	}
}

// RotatingFile is an append-only log file that is renamed to <path>.1 (one
// generation kept) once it exceeds max bytes, so agent.log cannot fill the
// system volume over years of service.
type RotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

// OpenRotatingFile opens (or creates) path for appending.
func OpenRotatingFile(path string, max int64) (*RotatingFile, error) {
	r := &RotatingFile{path: path, max: max}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.max && r.size > 0 {
		r.f.Close()
		os.Remove(r.path + ".1")
		os.Rename(r.path, r.path+".1")
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
