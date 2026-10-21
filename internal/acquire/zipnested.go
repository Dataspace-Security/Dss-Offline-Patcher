package acquire

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"offpatch/internal/safezip"
)

// Installers inside a zip (winget InstallerType zip with an MSI or EXE
// NestedInstallerType): pmctl downloads the zip and checks it against the
// manifest's SHA-256 like any installer, then extracts only the named file
// (NestedInstallerFiles) with ExtractNested. That file becomes the package:
// its own SHA-256, Authenticode signature and MSI ProductCode are what the
// bundle and the agent check. An installer that needs other files of the
// zip (a setup.exe next to its .msi and .cab files, ZipSiblings) becomes an
// archive package instead: the zip is the payload, ExtractArchive lists
// every file with its SHA-256, and agents 0.10.0+ extract and verify it.
//
// The zip is vendor content checked only by its hash: every entry is
// validated before anything is written (internal/safezip: no absolute
// paths, no "..", no symlinks or other special files, no names that differ
// only in case, no encryption), the total uncompressed size, the number of
// entries and the compression ratio are capped, and files are written only
// into a directory the caller created for them.

// Zip limits (variables so tests can lower them).
var (
	// MaxZipUncompressed caps the sum of the declared uncompressed sizes.
	MaxZipUncompressed int64 = safezip.DefaultMaxUncompressed
	// MaxZipEntries caps the number of entries (files and directories).
	MaxZipEntries = safezip.DefaultMaxEntries
	// MaxZipRatio caps one entry's uncompressed / compressed size once it
	// is larger than safezip.RatioFloor (deflate rarely exceeds 100:1 on
	// installers; zip bombs reach 1000:1 and more).
	MaxZipRatio int64 = safezip.DefaultMaxRatio
)

// NestedFile is the installer ExtractNested wrote.
type NestedFile struct {
	Path   string // the extracted file (destDir/name)
	Size   int64
	SHA256 string // lower-case hex of the extracted file
	// Others are the zip's other files (not directories), as named in the zip.
	Others []string
	// Entry is the installer's path as the zip names it.
	Entry string
}

// CleanZipPath normalises a winget RelativeFilePath or a zip entry name to
// forward slashes and refuses anything that could leave the extraction
// directory or mean something special on Windows (safezip.CleanPath).
func CleanZipPath(p string) (string, error) { return safezip.CleanPath(p) }

// zipLimits are the archive limits in force (safezip.Limits).
func zipLimits() safezip.Limits {
	return safezip.Limits{MaxUncompressed: MaxZipUncompressed, MaxEntries: MaxZipEntries, MaxRatio: MaxZipRatio}
}

// zipErr turns a problem with the archive itself into an UnsupportedError:
// the zip matched the manifest's SHA-256, so fetching it again cannot help.
func zipErr(err error) error {
	if err != nil && errors.Is(err, safezip.ErrUnsafe) {
		return unsupported("%s", strings.TrimPrefix(err.Error(), safezip.ErrUnsafe.Error()+": "))
	}
	return err
}

// ExtractNested validates every entry of the zip at zipPath and writes the
// entry rel (compared case-insensitively, as Windows does) to
// destDir/name. destDir must exist and be private to the caller; name is a
// plain file name. Problems with the archive are UnsupportedErrors.
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
	ents, err := safezip.Check(zr.File, zipLimits())
	if err != nil {
		return nil, zipErr(err)
	}
	var target *safezip.Entry
	var others []string
	for i, e := range ents {
		if strings.EqualFold(e.Path, want) {
			target = &ents[i]
		} else {
			others = append(others, e.Path)
		}
	}
	if target == nil {
		return nil, unsupported("the zip has no %s (named by the winget manifest)", want)
	}
	if err := CheckDiskSpace(destDir, target.Size); err != nil {
		return nil, err
	}
	out := filepath.Join(destDir, name)
	sum, err := safezip.WriteEntry(*target, out)
	if err != nil {
		os.Remove(out)
		return nil, zipErr(err)
	}
	return &NestedFile{Path: out, Size: target.Size, SHA256: sum, Others: others, Entry: target.Path}, nil
}

// ExtractArchive validates every entry of the zip at zipPath and writes
// all its files below destDir (private to the caller), for an installer
// that needs the zip's other files (an archive package). It returns the
// files with their SHA-256; problems with the archive are UnsupportedErrors.
func ExtractArchive(zipPath, destDir string) ([]safezip.File, error) {
	var total int64
	if zr, err := zip.OpenReader(zipPath); err == nil {
		for _, f := range zr.File {
			total += int64(f.UncompressedSize64 & (1<<62 - 1))
		}
		zr.Close()
	}
	if err := CheckDiskSpace(destDir, total); err != nil {
		return nil, err
	}
	files, err := safezip.ExtractAll(zipPath, destDir, zipLimits())
	return files, zipErr(err)
}

// zipDocExts: files an installer never needs (release notes, licences).
var zipDocExts = map[string]bool{".txt": true, ".md": true, ".pdf": true, ".rtf": true, ".htm": true, ".html": true, ".url": true}

// ZipSiblings returns the files of others the installer might need: every
// file except documentation (.txt, .md, .pdf, .rtf, .htm, .html, .url) and
// macOS metadata. A non-empty result means the installer cannot be
// packaged on its own: it becomes an archive package.
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
