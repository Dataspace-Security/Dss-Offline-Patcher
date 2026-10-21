package main

// Installers inside a zip (winget InstallerType zip, NestedInstallerType
// msi/wix or an EXE type): the zip is downloaded over HTTPS and checked
// against the manifest's InstallerSha256 like any installer, then only the
// file NestedInstallerFiles names is extracted (acquire.ExtractNested: no
// absolute paths, "..", symlinks or case-insensitive duplicates; size,
// entry count and compression ratio capped) into a private directory and
// moved to downloads/<package id>.msi|.exe. From there it is handled
// exactly like a downloaded MSI or EXE (ProductCode, Authenticode, signer
// pin); the package is the extracted file, and the spec's provenance
// records the zip (source_url, zip_sha256, zip_path).
//
// A bundle package is one file, so an installer that needs other files of
// the zip (a setup.exe with its .msi and .cab files) is refused with
// acquire.ReasonZipSiblings; documentation files do not count.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire"
)

// installerOnDisk is a verified installer in the downloads directory.
type installerOnDisk struct {
	path   string
	sha256 string             // the file's (for a zip: the extracted file's)
	zip    *acquire.ZipOrigin // nil unless extracted from a zip
}

// installerFile puts the installer in into r.downloads/file: a plain
// download, or (in.ZipPath set) the file extracted from the downloaded zip.
func (r *requestRun) installerFile(a acqrequest.App, m *acquire.WingetManifest, in acquire.WingetInstaller, file string) (installerOnDisk, error) {
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
	if sib := acquire.ZipSiblings(nf.Others); len(sib) > 0 {
		os.Remove(dl.Path)
		return installerOnDisk{}, unsupportedItem(acquire.ReasonZipSiblings,
			fmt.Sprintf("%s %s: %s in the zip %s needs other files from it (%s); offpatch packages one file per installer",
				a.WingetID, m.Version, in.ZipPath, in.URL, listSome(sib, 3)))
	}
	dest := filepath.Join(r.downloads, file)
	if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return installerOnDisk{}, err
	}
	if err := os.Rename(nf.Path, dest); err != nil {
		return installerOnDisk{}, err
	}
	os.Remove(dl.Path) // the extracted file is what gets packaged
	return installerOnDisk{path: dest, sha256: nf.SHA256, zip: &acquire.ZipOrigin{SHA256: dl.SHA256, Size: dl.Size, Path: in.ZipPath}}, nil
}

// zipVerified is the provenance text for the checks made on the zip.
func zipVerified(zo *acquire.ZipOrigin) string {
	if zo == nil {
		return ""
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
