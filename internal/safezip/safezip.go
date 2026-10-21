// Package safezip reads vendor zip archives without trusting them: the
// entry rules shared by pmctl (acquisition zone, internal/acquire) and the
// agent (endpoints, archive and portable packages). Every entry is checked
// before anything is written: no absolute paths, drive letters, "." or ".."
// elements, symbolic links or other special files, encrypted entries, names
// that differ only in case (Windows would merge them), or a file that is
// also a directory of another entry. The total size, the number of entries
// and the compression ratio are capped (zip bombs). Files are written only
// below a directory the caller created, with O_EXCL, and their size and
// CRC-32 are checked while they are written.
//
// The package depends on the standard library only.
package safezip

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// Limits caps what an archive may contain. Zero values use the defaults.
type Limits struct {
	// MaxUncompressed caps the sum of the declared uncompressed sizes.
	MaxUncompressed int64
	// MaxEntries caps the number of entries (files and directories).
	MaxEntries int
	// MaxRatio caps one entry's uncompressed / compressed size once it is
	// larger than RatioFloor (deflate rarely exceeds 100:1 on installers;
	// zip bombs reach 1000:1 and more).
	MaxRatio int64
}

// Defaults: 4 GB uncompressed, 20,000 entries, 200:1 above 1 MiB.
const (
	DefaultMaxUncompressed int64 = 4 << 30
	DefaultMaxEntries            = 20000
	DefaultMaxRatio        int64 = 200
	RatioFloor                   = 1 << 20
)

func (l Limits) withDefaults() Limits {
	if l.MaxUncompressed <= 0 {
		l.MaxUncompressed = DefaultMaxUncompressed
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxEntries
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = DefaultMaxRatio
	}
	return l
}

// ErrUnsafe wraps every problem with the archive itself (as opposed to the
// local file system): retrying the same archive cannot help.
var ErrUnsafe = errors.New("unsafe archive")

func unsafeErr(f string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsafe, fmt.Sprintf(f, a...))
}

// CleanPath normalises a zip entry name (or a winget RelativeFilePath) to
// forward slashes and refuses anything that could leave the extraction
// directory or mean something special on Windows: an empty name, an
// absolute path, a drive letter or other colon, a "." or ".." element,
// control characters, or an element ending in a dot or space.
func CleanPath(p string) (string, error) {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimSuffix(p, "/")
	switch {
	case p == "":
		return "", errors.New("empty path")
	case strings.HasPrefix(p, "/"):
		return "", fmt.Errorf("absolute path %q", p)
	case strings.ContainsRune(p, ':'):
		return "", fmt.Errorf("path %q has a drive letter or colon", p)
	case strings.ContainsFunc(p, unicode.IsControl):
		return "", fmt.Errorf("path %q has control characters", p)
	}
	for _, el := range strings.Split(p, "/") {
		switch {
		case el == "" || el == "." || el == "..":
			return "", fmt.Errorf("path %q has an empty, . or .. element", p)
		case strings.HasSuffix(el, ".") || strings.HasSuffix(el, " "):
			return "", fmt.Errorf("path %q has an element ending in a dot or space", p)
		}
	}
	return p, nil
}

// Entry is one checked file of an archive (directories are not listed).
type Entry struct {
	Path string // cleaned, forward slashes, as named in the zip
	Size int64  // declared uncompressed size
	File *zip.File
}

// Check applies the entry rules to every entry and returns the files (in
// archive order).
func Check(files []*zip.File, lim Limits) ([]Entry, error) {
	lim = lim.withDefaults()
	if len(files) > lim.MaxEntries {
		return nil, unsafeErr("the zip has %d entries, more than %d", len(files), lim.MaxEntries)
	}
	seen := map[string]bool{}   // lower-case names of every entry
	isFile := map[string]bool{} // lower-case names of files
	var out []Entry
	var total int64
	for _, f := range files {
		p, err := CleanPath(f.Name)
		if err != nil {
			return nil, unsafeErr("the zip has an unsafe entry: %v", err)
		}
		mode := f.Mode()
		dir := mode.IsDir() || strings.HasSuffix(f.Name, "/")
		switch {
		case mode&fs.ModeSymlink != 0:
			return nil, unsafeErr("the zip has a symbolic link (%s)", p)
		case !dir && !mode.IsRegular():
			return nil, unsafeErr("the zip has a special file (%s)", p)
		case f.Flags&0x1 != 0:
			return nil, unsafeErr("the zip has an encrypted entry (%s)", p)
		}
		key := strings.ToLower(p)
		if seen[key] {
			return nil, unsafeErr("the zip has two entries named %s (names differ only in case, or repeated)", p)
		}
		seen[key] = true
		if dir {
			continue
		}
		isFile[key] = true
		u, c := f.UncompressedSize64, f.CompressedSize64
		if u > uint64(lim.MaxUncompressed) || total+int64(u) > lim.MaxUncompressed {
			return nil, unsafeErr("the zip unpacks to more than %d MB", lim.MaxUncompressed>>20)
		}
		total += int64(u)
		if u > RatioFloor && (c == 0 || u/c > uint64(lim.MaxRatio)) {
			return nil, unsafeErr("the zip entry %s is compressed more than %d:1 (zip bomb?)", p, lim.MaxRatio)
		}
		out = append(out, Entry{Path: p, Size: int64(u), File: f})
	}
	// A file may not also be the parent directory of another entry.
	for key := range seen {
		for d := path.Dir(key); d != "."; d = path.Dir(d) {
			if isFile[d] {
				return nil, unsafeErr("the zip has %s both as a file and as a directory", d)
			}
		}
	}
	return out, nil
}

// WriteEntry writes e to out (which must not exist) and returns its
// SHA-256. More or fewer bytes than declared, or a bad CRC-32, fail with
// ErrUnsafe.
func WriteEntry(e Entry, out string) (string, error) {
	rc, err := e.File.Open()
	if err != nil {
		return "", unsafeErr("the zip entry %s cannot be read: %v", e.Path, err)
	}
	defer rc.Close()
	w, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(rc, e.Size+1))
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	switch {
	case errors.Is(err, zip.ErrChecksum) || errors.Is(err, zip.ErrFormat) || errors.Is(err, zip.ErrAlgorithm):
		os.Remove(out)
		return "", unsafeErr("the zip entry %s is damaged: %v", e.Path, err)
	case err != nil:
		os.Remove(out)
		return "", err
	case n != e.Size:
		os.Remove(out)
		return "", unsafeErr("the zip entry %s is not the size the zip declares", e.Path)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// File is a file of an extracted archive: its path in the archive and the
// size and SHA-256 of its content.
type File struct {
	Path   string
	Size   int64
	SHA256 string
}

// ExtractAll checks every entry of the zip at zipPath and writes all files
// below destDir (which must exist and be private to the caller). It returns
// the files with their SHA-256, sorted by path.
func ExtractAll(zipPath, destDir string, lim Limits) ([]File, error) {
	return extract(zipPath, destDir, lim, nil)
}

// ExtractVerified is ExtractAll for an archive described by a signed
// manifest: the zip must hold exactly the files in want (paths compared
// case-insensitively, as Windows does; sizes equal), and every extracted
// file must have want's SHA-256. The listing is compared before anything
// is written. On error the caller removes destDir.
func ExtractVerified(zipPath, destDir string, want []File, lim Limits) error {
	if want == nil {
		want = []File{}
	}
	_, err := extract(zipPath, destDir, lim, want)
	return err
}

func extract(zipPath, destDir string, lim Limits, want []File) ([]File, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, unsafeErr("the zip cannot be read: %v", err)
	}
	defer zr.Close()
	ents, err := Check(zr.File, lim)
	if err != nil {
		return nil, err
	}
	var byPath map[string]File
	if want != nil {
		byPath = make(map[string]File, len(want))
		for _, w := range want {
			byPath[strings.ToLower(w.Path)] = w
		}
		if len(ents) != len(want) {
			return nil, unsafeErr("the zip holds %d files, the signed manifest lists %d", len(ents), len(want))
		}
		for _, e := range ents {
			w, ok := byPath[strings.ToLower(e.Path)]
			if !ok {
				return nil, unsafeErr("the zip holds %s, which the signed manifest does not list", e.Path)
			}
			if w.Size != e.Size {
				return nil, unsafeErr("the zip entry %s is %d bytes, the signed manifest says %d", e.Path, e.Size, w.Size)
			}
		}
	}
	root, err := filepath.Abs(destDir)
	if err != nil {
		return nil, err
	}
	out := make([]File, 0, len(ents))
	for _, e := range ents {
		dst := filepath.Join(root, filepath.FromSlash(e.Path))
		if rel, err := filepath.Rel(root, dst); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, unsafeErr("the zip entry %s leaves the extraction directory", e.Path)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		sum, err := WriteEntry(e, dst)
		if err != nil {
			return nil, err
		}
		if byPath != nil && byPath[strings.ToLower(e.Path)].SHA256 != sum {
			return nil, unsafeErr("the zip entry %s does not match the signed manifest (sha256)", e.Path)
		}
		out = append(out, File{Path: e.Path, Size: e.Size, SHA256: sum})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
