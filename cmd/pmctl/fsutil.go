package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// writeFileAtomic replaces path with data: temp file in the same directory,
// fsync, rename, then a best-effort fsync of the directory, so a crash
// leaves either the old or the new content, never a torn file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		d.Sync() // not supported on every platform (Windows); the rename is what matters
		d.Close()
	}
	return nil
}

// lockFile takes a short-lived exclusive lock (<path> created with O_EXCL)
// and returns its release func. It waits up to wait for another holder; a
// lock older than staleAfter is from a crashed process and is removed.
func lockFile(path string, wait, staleAfter time.Duration) (func(), error) {
	deadline := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if fi, serr := os.Stat(path); serr == nil && time.Since(fi.ModTime()) > staleAfter {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s is held by another pmctl process (remove it if none is running)", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// splitArgs splits a command line into arguments. Whitespace separates
// arguments; "double" or 'single' quotes group text containing spaces (e.g.
// "C:\Program Files\HSM\sign.exe"). Backslashes are literal, so Windows
// paths need no escaping.
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inArg := false
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, inArg = r, true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inArg {
				out = append(out, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote in %q", quote, s)
	}
	if inArg {
		out = append(out, cur.String())
	}
	return out, nil
}
