package main

// Installers inside a zip (winget InstallerType zip, NestedInstallerType
// msi/wix, an EXE type or portable): the zip is downloaded over HTTPS and
// checked against the manifest's InstallerSha256 like any installer, then
// every entry is validated (acquire.ExtractNested / ExtractArchive: no
// absolute paths, "..", symlinks or case-insensitive duplicates; size,
// entry count and compression ratio capped).
//
//   - An installer that needs nothing else from the zip (documentation
//     aside) is extracted on its own and moved to downloads/<package
//     id>.msi|.exe. From there it is handled exactly like a downloaded MSI
//     or EXE (ProductCode, Authenticode, signer pin); the package is the
//     extracted file, and the spec's provenance records the zip
//     (source_url, zip_sha256, zip_path). Every agent installs it.
//   - An installer that needs the zip's other files (Adobe Acrobat:
//     setup.exe with its .msi, .cab and setup.ini), and every portable app
//     in a zip, becomes an archive package: the payload is the verified zip
//     itself (downloads/<package id>.zip), and the manifest's archive block
//     names the installer inside and lists every file with its SHA-256. The
//     whole tree is extracted into a private directory here to verify the
//     installer (ProductCode, Authenticode, signer pin) and every signed
//     program next to it; agents 0.10.0 and later extract and verify it the
//     same way before they run anything.

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire"
	peauth "offpatch/internal/acquire/authenticode"
	"offpatch/internal/manifest"
	"offpatch/internal/safezip"
)

// installerOnDisk is a verified installer in the downloads directory.
type installerOnDisk struct {
	path   string
	sha256 string             // the file's (for a zip: the extracted file's, or the zip's for an archive)
	zip    *acquire.ZipOrigin // nil unless extracted from a zip
	// Archive packages: path is the zip, entry the installer extracted
	// below tree (removed by cleanup), archive the manifest block.
	entry   string
	tree    string
	archive *manifest.Archive
}

// installer is the file to verify: the extracted entry of an archive, else
// the payload itself.
func (o installerOnDisk) installer() string {
	if o.entry != "" {
		return o.entry
	}
	return o.path
}

// cleanup removes an archive's extracted tree (the payload stays).
func (o installerOnDisk) cleanup() {
	if o.tree != "" {
		os.RemoveAll(o.tree)
	}
}

// discard removes the payload too (it must not be picked up later).
func (o installerOnDisk) discard() {
	o.cleanup()
	os.Remove(o.path)
}

// installerFile puts the installer in into r.downloads/file: a plain
// download, or (in.ZipPath set) the file extracted from the downloaded zip,
// or an archive package (the zip, when the installer needs its other files
// or whole is set). The caller calls cleanup.
func (r *requestRun) installerFile(a acqrequest.App, m *acquire.WingetManifest, in acquire.WingetInstaller, file string, whole bool) (installerOnDisk, error) {
	if in.ZipPath == "" {
		dl, err := acquire.Download(r.ctx, r.hc, acquire.DownloadRequest{URL: in.URL, DestDir: r.downloads, FileName: file, SHA256: in.SHA256})
		if err != nil {
			return installerOnDisk{}, err
		}
		return installerOnDisk{path: dl.Path, sha256: dl.SHA256}, nil
	}
	zipName := strings.TrimSuffix(file, filepath.Ext(file)) + ".zip"
	dl, err := acquire.Download(r.ctx, r.hc, acquire.DownloadRequest{URL: in.URL, DestDir: r.downloads, FileName: zipName, SHA256: in.SHA256})
	if err != nil {
		return installerOnDisk{}, err
	}
	tmp, err := os.MkdirTemp(r.downloads, ".unzip-")
	if err != nil {
		return installerOnDisk{}, err
	}
	defer os.RemoveAll(tmp)
	nf, err := acquire.ExtractNested(dl.Path, in.ZipPath, tmp, file)
	var un *acquire.UnsupportedError
	if errors.As(err, &un) {
		os.Remove(dl.Path)
		return installerOnDisk{}, unsupportedItem(shortReason("the zip cannot be used: "+un.Reason),
			fmt.Sprintf("%s %s (%s): %s", a.WingetID, m.Version, in.URL, un.Reason))
	}
	if err != nil {
		return installerOnDisk{}, err
	}
	origin := &acquire.ZipOrigin{SHA256: dl.SHA256, Size: dl.Size, Path: nf.Entry}
	if sib := acquire.ZipSiblings(nf.Others); len(sib) > 0 || whole {
		got, err := r.archiveFile(a, m, in, dl, nf.Entry)
		if err != nil {
			os.Remove(dl.Path)
			return installerOnDisk{}, err
		}
		got.zip = origin
		return got, nil
	}
	dest := filepath.Join(r.downloads, file)
	if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return installerOnDisk{}, err
	}
	if err := os.Rename(nf.Path, dest); err != nil {
		return installerOnDisk{}, err
	}
	os.Remove(dl.Path) // the extracted file is what gets packaged
	origin.Path = in.ZipPath
	return installerOnDisk{path: dest, sha256: nf.SHA256, zip: origin}, nil
}

// archiveFile makes the verified zip dl an archive package whose installer
// is entry: the whole tree is extracted (to verify it) and listed.
func (r *requestRun) archiveFile(a acqrequest.App, m *acquire.WingetManifest, in acquire.WingetInstaller, dl *acquire.DownloadResult, entry string) (installerOnDisk, error) {
	tree, err := os.MkdirTemp(r.downloads, ".tree-")
	if err != nil {
		return installerOnDisk{}, err
	}
	files, err := acquire.ExtractArchive(dl.Path, tree)
	var un *acquire.UnsupportedError
	if errors.As(err, &un) {
		os.RemoveAll(tree)
		return installerOnDisk{}, unsupportedItem(shortReason("the zip cannot be used: "+un.Reason),
			fmt.Sprintf("%s %s (%s): %s", a.WingetID, m.Version, in.URL, un.Reason))
	}
	if err != nil {
		os.RemoveAll(tree)
		return installerOnDisk{}, err
	}
	if len(files) > manifest.MaxArchiveFiles {
		os.RemoveAll(tree)
		return installerOnDisk{}, unsupportedItem(fmt.Sprintf("the zip holds more than %d files", manifest.MaxArchiveFiles),
			fmt.Sprintf("%s %s (%s): %d files in the zip, at most %d per package", a.WingetID, m.Version, in.URL, len(files), manifest.MaxArchiveFiles))
	}
	arc := &manifest.Archive{Format: manifest.ArchiveFormatZip, Entry: entry}
	for _, f := range files {
		if len(f.Path) > manifest.MaxArchivePathLen {
			os.RemoveAll(tree)
			return installerOnDisk{}, unsupportedItem("a path in the zip is too long", fmt.Sprintf("%s %s: %s is longer than %d characters", a.WingetID, m.Version, f.Path, manifest.MaxArchivePathLen))
		}
		arc.Files = append(arc.Files, manifest.ArchiveFile{Path: f.Path, Size: f.Size, SHA256: f.SHA256})
	}
	return installerOnDisk{path: dl.Path, sha256: dl.SHA256, entry: filepath.Join(tree, filepath.FromSlash(entry)), tree: tree, archive: arc}, nil
}

// verifyArchivePrograms checks the signed programs next to an archive's
// installer: every .exe that carries an Authenticode signature must verify
// (an unsigned helper is accepted: its SHA-256 is in the signed manifest),
// and on Windows acquisition hosts every signed .msi must be Valid. The
// entry itself is verified by the caller (signer and pin).
func verifyArchivePrograms(tree string, arc *manifest.Archive) error {
	for _, f := range arc.Files {
		if strings.EqualFold(f.Path, arc.Entry) {
			continue
		}
		p := filepath.Join(tree, filepath.FromSlash(f.Path))
		switch strings.ToLower(path.Ext(f.Path)) {
		case ".exe":
			if _, err := exeVerify(p); err != nil && !errors.Is(err, peauth.ErrNotSigned) {
				return fmt.Errorf("%w: %s in the zip: %w", errExeSignature, f.Path, err)
			}
		case ".msi":
			if !authenticodeHere() {
				continue
			}
			sig, err := authenticode(p)
			if err == nil && !strings.EqualFold(sig.Status, "Valid") && !strings.EqualFold(sig.Status, "NotSigned") {
				return fmt.Errorf("%w: %s in the zip: signature status %s", errExeSignature, f.Path, sig.Status)
			}
		}
	}
	return nil
}

// withArchiveEntry extracts the archive package at zipPath into a temporary
// directory, verifying every file against the manifest's list (as the
// agent does), and calls fn with the tree and the installer's path.
func withArchiveEntry(p manifest.Package, zipPath string, fn func(tree, entry string) error) error {
	if p.Archive == nil {
		return fn("", zipPath)
	}
	tree, err := os.MkdirTemp("", "pmctl-archive-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tree)
	if err := safezip.ExtractVerified(zipPath, tree, p.Archive.Want(), safezip.Limits{}); err != nil {
		return fmt.Errorf("archive does not match the manifest: %w", err)
	}
	return fn(tree, filepath.Join(tree, filepath.FromSlash(p.Archive.Entry)))
}

// zipVerified is the provenance text for the checks made on the zip.
func zipVerified(zo *acquire.ZipOrigin, arc *manifest.Archive) string {
	switch {
	case zo == nil:
		return ""
	case arc != nil:
		return fmt.Sprintf("+archive(%s, %d files)", zo.Path, len(arc.Files))
	}
	return "+unzipped(" + zo.Path + ")"
}

// listSome names the first n of s, and how many more there are.
func listSome(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(s[:n], ", "), len(s)-n)
}
