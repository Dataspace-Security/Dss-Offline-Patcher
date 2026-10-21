package acquire

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
	"strings"
	"unicode"
)

// Installers inside a zip (winget InstallerType zip with an MSI or EXE
// NestedInstallerType): pmctl downloads the zip and checks it against the
// manifest's SHA-256 like any installer, then extracts only the named file
// (NestedInstallerFiles) with ExtractNested. That file becomes the package:
// its own SHA-256, Authenticode signature and MSI ProductCode are what the
// bundle and the agent check. The bundle format carries one file per
// package, so an installer that needs other files of the zip (a setup.exe
// next to its .msi and .cab files) is refused (ZipSiblings).
//
// The zip is vendor content checked only by its hash: every entry is
// validated before anything is written (no absolute paths, no "..", no
// symlinks or other special files, no names that differ only in case, no
// encryption), the total uncompressed size, the number of entries and the
// compression ratio are capped, and the one file is written into a
// directory the caller created for it, under a name the caller chose.

// Zip limits (variables so tests can lower them).
var (
	// MaxZipUncompressed caps the sum of the declared uncompressed sizes.
	MaxZipUncompressed int64 = 4 << 30
	// MaxZipEntries caps the number of entries (files and directories).
	MaxZipEntries = 20000
	// MaxZipRatio caps one entry's uncompressed / compressed size once it
	// is larger than zipRatioFloor (deflate rarely exceeds 100:1 on
	// installers; zip bombs reach 1000:1 and more).
	MaxZipRatio int64 = 200
)

const zipRatioFloor = 1 << 20

// ReasonZipSiblings is the console text for a zip whose installer needs
// other files from the zip.
const ReasonZipSiblings = "installer needs other files from the zip"

// NestedFile is the installer ExtractNested wrote.
type NestedFile struct {
	Path   string // the extracted file (destDir/name)
	Size   int64
	SHA256 string // lower-case hex of the extracted file
	// Others are the zip's other files (not directories), as named in the zip.
	Others []string
}

// CleanZipPath normalises a winget RelativeFilePath or a zip entry name to
// forward slashes and refuses anything that could leave the extraction
// directory or mean something special on Windows: an empty name, an
// absolute path, a drive letter or other colon, a "." or ".." element,
// control characters, or an element ending in a dot or space.
func CleanZipPath(p string) (string, error) {
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

// ExtractNested validates every entry of the zip at zipPath and writes the
// entry rel (compared case-insensitively, as Windows does) to
// destDir/name. destDir must exist and be private to the caller; name is a
// plain file name. Problems with the archive are UnsupportedErrors: the
// zip matched the manifest's SHA-256, so fetching it again cannot help.
func ExtractNested(zipPath, rel, destDir, name string) (*NestedFile, error) {
	want, err := CleanZipPath(rel)
	if err != nil {
		return nil, unsupported("the winget manifest's installer path in the zip is unsafe: %v", err)
	}
	if !safeNameRe.MatchString(name) || name == "." || name == ".." {
		return nil, fmt.Errorf("unsafe file name %q", name)
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, unsupported("the zip cannot be read: %v", err)
	}
	defer zr.Close()
	target, others, err := checkZipEntries(zr.File, want)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, unsupported("the zip has no %s (named by the winget manifest)", want)
	}
	size := int64(target.UncompressedSize64)
	if err := CheckDiskSpace(destDir, size); err != nil {
		return nil, err
	}
	out := filepath.Join(destDir, name)
	sum, err := writeZipEntry(target, out, size)
	if err != nil {
		os.Remove(out)
		return nil, err
	}
	return &NestedFile{Path: out, Size: size, SHA256: sum, Others: others}, nil
}

// checkZipEntries applies the archive rules to every entry and returns the
// entry named want (nil if absent) and the other files' names.
func checkZipEntries(files []*zip.File, want string) (*zip.File, []string, error) {
	if len(files) > MaxZipEntries {
		return nil, nil, unsupported("the zip has %d entries, more than %d", len(files), MaxZipEntries)
	}
	seen := map[string]bool{}   // lower-case names of every entry
	isFile := map[string]bool{} // lower-case names of files
	var target *zip.File
	var others []string
	var total int64
	for _, f := range files {
		p, err := CleanZipPath(f.Name)
		if err != nil {
			return nil, nil, unsupported("the zip has an unsafe entry: %v", err)
		}
		mode := f.Mode()
		dir := mode.IsDir() || strings.HasSuffix(f.Name, "/")
		switch {
		case mode&fs.ModeSymlink != 0:
			return nil, nil, unsupported("the zip has a symbolic link (%s)", p)
		case !dir && !mode.IsRegular():
			return nil, nil, unsupported("the zip has a special file (%s)", p)
		case f.Flags&0x1 != 0:
			return nil, nil, unsupported("the zip has an encrypted entry (%s)", p)
		}
		key := strings.ToLower(p)
		if seen[key] {
			return nil, nil, unsupported("the zip has two entries named %s (names differ only in case, or repeated)", p)
		}
		seen[key] = true
		if dir {
			continue
		}
		isFile[key] = true
		u, c := f.UncompressedSize64, f.CompressedSize64
		if u > uint64(MaxZipUncompressed) || total+int64(u) > MaxZipUncompressed {
			return nil, nil, unsupported("the zip unpacks to more than %d GB", MaxZipUncompressed>>30)
		}
		total += int64(u)
		if u > zipRatioFloor && (c == 0 || u/c > uint64(MaxZipRatio)) {
			return nil, nil, unsupported("the zip entry %s is compressed more than %d:1 (zip bomb?)", p, MaxZipRatio)
		}
		if key == strings.ToLower(want) {
			target = f
		} else {
			others = append(others, p)
		}
	}
	// A file may not also be the parent directory of another entry.
	for key := range seen {
		for d := path.Dir(key); d != "."; d = path.Dir(d) {
			if isFile[d] {
				return nil, nil, unsupported("the zip has %s both as a file and as a directory", d)
			}
		}
	}
	return target, others, nil
}

// writeZipEntry writes f to out (which must not exist) and returns its
// SHA-256. More or fewer bytes than declared, or a bad CRC-32, fail.
func writeZipEntry(f *zip.File, out string, size int64) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", unsupported("the zip entry %s cannot be read: %v", f.Name, err)
	}
	defer rc.Close()
	w, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(rc, size+1))
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	switch {
	case errors.Is(err, zip.ErrChecksum) || errors.Is(err, zip.ErrFormat) || errors.Is(err, zip.ErrAlgorithm):
		return "", unsupported("the zip entry %s is damaged: %v", f.Name, err)
	case err != nil:
		return "", err
	case n != size:
		return "", unsupported("the zip entry %s is not the size the zip declares", f.Name)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// zipDocExts: files an installer never needs (release notes, licences).
var zipDocExts = map[string]bool{".txt": true, ".md": true, ".pdf": true, ".rtf": true, ".htm": true, ".html": true, ".url": true}

// ZipSiblings returns the files of others the installer might need: every
// file except documentation (.txt, .md, .pdf, .rtf, .htm, .html, .url) and
// macOS metadata. A non-empty result means the installer cannot be
// packaged on its own (ReasonZipSiblings).
func ZipSiblings(others []string) []string {
	var out []string
	for _, p := range others {
		base := path.Base(p)
		switch {
		case zipDocExts[strings.ToLower(path.Ext(p))]:
		case strings.HasPrefix(p, "__MACOSX/") || base == ".DS_Store":
		default:
			out = append(out, p)
		}
	}
	return out
}
