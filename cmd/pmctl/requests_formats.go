package main

// Portable apps and MSIX packages in acquisition requests (agents 0.10.0
// and later; docs/08-acquisition.md "Portable apps" and "MSIX packages").
//
//   - Portable (winget InstallerType portable, or a zip whose
//     NestedInstallerType is portable): the exe, or the whole zip as an
//     archive package, checked against the manifest's SHA-256. The main
//     program must carry a valid Authenticode signature (pure Go, any
//     host), pinned like an EXE installer; every other signed program in a
//     zip must verify too. The agent copies the files to
//     %ProgramFiles%\DSS Patcher Apps\<winget id> and registers them in
//     Apps & features under DSSPatcher.<winget id>.
//   - MSIX (InstallerType msix or appx): the package or bundle, checked
//     against the manifest's SHA-256; its identity (Name, Publisher,
//     Version, and the package family name computed from them) is read
//     from the package itself and must match the manifest's
//     PackageFamilyName when winget states one. On Windows acquisition
//     hosts the package signature is verified (Get-AuthenticodeSignature)
//     and pinned; elsewhere the winget SHA-256 is the check
//     (vendor_signature not_checked) and the agent requires a valid
//     signature before Windows provisions it.

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire"
	"offpatch/internal/manifest"
)

// authenticodeHere: Windows Authenticode (Get-AuthenticodeSignature) is
// available on this acquisition host.
func authenticodeHere() bool { return runtime.GOOS == "windows" || authenticodeAnywhere }

var nonFolderChars = regexp.MustCompile(`[^A-Za-z0-9._+()-]+`)

// portableFolder is the folder (and ARP key suffix) for a winget id.
func portableFolder(id string) string {
	f := strings.Trim(nonFolderChars.ReplaceAllString(id, "-"), ".- ")
	if len(f) > 100 {
		f = f[:100]
	}
	if !manifest.ValidFolderName(f) {
		f = "app-" + f
	}
	return f
}

var nonShortcutChars = regexp.MustCompile(`[^A-Za-z0-9._ +()-]+`)

// portableShortcut is a Start-menu shortcut name for display name n ("" if
// none can be made).
func portableShortcut(n string) string {
	s := strings.TrimSpace(nonShortcutChars.ReplaceAllString(n, " "))
	s = strings.TrimRight(s, ". ")
	if len(s) > 80 {
		s = strings.TrimRight(s[:80], ". ")
	}
	if s == "" || !manifest.ValidFolderName(s) {
		return ""
	}
	return s
}

// formatNames: the title and the Apps & features name of a portable or
// MSIX package (the product name users see: the locale manifest's first).
func (r *requestRun) formatNames(a acqrequest.App, m *acquire.WingetManifest) (title, name string, loc *acquire.WingetLocale) {
	loc, _ = acquire.FetchWingetLocale(r.ctx, r.c.sourceClient(r.hc, acqpolicy.UpstreamWingetManifests), r.c.WingetManifestsURL, m.ID, m.Version)
	locName := ""
	if loc != nil {
		locName = loc.PackageName
	}
	first := func(cands ...string) string {
		for _, c := range cands {
			if c = strings.TrimSpace(c); exeTextOK(c) {
				return c
			}
		}
		return ""
	}
	return first(a.Name, locName, m.PackageName, a.WingetID), first(locName, m.PackageName, a.Name, a.WingetID), loc
}

func releaseDate(in acquire.WingetInstaller) string {
	if _, err := time.Parse("2006-01-02", in.ReleaseDate); err != nil {
		return ""
	}
	return in.ReleaseDate
}

func (r *requestRun) fetchWingetPortable(a acqrequest.App, arch string, m *acquire.WingetManifest, murl string, in acquire.WingetInstaller) error {
	ver := m.Version
	id := wingetPackageID(a.WingetID, m.Version, arch)
	got, err := r.installerFile(a, m, in, id+".exe", true)
	if err != nil {
		return err
	}
	defer got.cleanup()
	res, err := verifyExeResult(got.installer())
	if err == nil && got.archive != nil {
		err = verifyArchivePrograms(got.tree, got.archive)
	}
	if err != nil {
		got.discard()
		return unsupportedItem(shortReason("the portable app's program is not validly signed: "+strings.TrimPrefix(err.Error(), "Authenticode: ")),
			fmt.Sprintf("%s %s (%s): %v", a.WingetID, m.Version, in.URL, err))
	}
	signer := res.Signer
	title, name, loc := r.formatNames(a, m)
	if name == "" {
		got.discard()
		return unsupportedItem("no usable name for the portable app", a.WingetID+" "+m.Version+": no product name in the winget manifests")
	}
	pub := wingetPublisher(in, m)
	if loc != nil && loc.Publisher != "" && m.Publisher == "" {
		pub = loc.Publisher
	}
	vs, err := pinInstaller(r.ctx, r.c, r.pins, pinKeyWinget(a.WingetID), m.Version, pub, infoFromResult(res))
	if err != nil {
		got.discard()
		return err
	}
	folder := portableFolder(a.WingetID)
	cmd := in.PortableCommandName(path.Base(folder))
	if got.archive != nil {
		cmd = got.archive.Entry
	}
	po := &manifest.Portable{Folder: folder, Command: cmd, Signer: signer, ARPKey: "DSSPatcher." + folder,
		DisplayName: name, DisplayVersion: ver, Publisher: arpPublisher(in, pub), Shortcut: portableShortcut(name)}
	if !exeTextOK(po.Publisher) {
		po.Publisher = ""
	}
	_, err = acquire.FetchURL(r.ctx, acquire.FetchURLOptions{URL: in.URL, SHA256: got.sha256, FileName: filepath.Base(got.path), PackageID: wingetPackageID(a.WingetID, a.Version, arch),
		Title: title + " " + ver, Vendor: pub, Kind: manifest.KindPortable, PackageName: name, OS: "windows",
		Version: ver, Severity: "important", ReleaseDate: releaseDate(in), Arch: arch, OutDir: r.downloads, SpecPath: r.spec, HTTP: r.hc,
		Portable: po, Archive: got.archive, FromZip: got.zip,
		Verified: "sha256(winget manifest " + murl + ")" + zipVerified(got.zip, got.archive) + "+authenticode(" + signer + ")", VendorSignature: &vs,
		VerifyPayload: func(string) error {
			now, err := verifyExeSigner(got.installer())
			if err == nil && now != signer {
				err = fmt.Errorf("signer changed from %q to %q", signer, now)
			}
			return err
		}})
	return err
}

// msixExt is the payload extension for an MSIX installer URL ("" when the
// URL does not say).
func msixExt(u string) string {
	switch e := strings.ToLower(path.Ext(portableURLName(u))); e {
	case ".msix", ".appx", ".msixbundle", ".appxbundle":
		return e
	}
	return ""
}

func portableURLName(u string) string {
	u, _, _ = strings.Cut(u, "?")
	u, _, _ = strings.Cut(u, "#")
	return path.Base(u)
}

func (r *requestRun) fetchWingetMsix(a acqrequest.App, arch string, m *acquire.WingetManifest, murl string, in acquire.WingetInstaller) error {
	id := wingetPackageID(a.WingetID, m.Version, arch)
	ext := msixExt(in.URL)
	if ext == "" {
		ext = ".msix"
	}
	got, err := r.installerFile(a, m, in, id+ext, false)
	if err != nil {
		return err
	}
	ident, err := acquire.ReadMsixIdentity(got.path)
	var un *acquire.UnsupportedError
	if errors.As(err, &un) {
		os.Remove(got.path)
		return unsupportedItem(shortReason("the MSIX package cannot be read: "+un.Reason), fmt.Sprintf("%s %s (%s): %s", a.WingetID, m.Version, in.URL, un.Reason))
	}
	if err != nil {
		return err
	}
	if in.PackageFamilyName != "" && !strings.EqualFold(in.PackageFamilyName, ident.PackageFamilyName) {
		os.Remove(got.path)
		return unsupportedItem("the MSIX package is not the one the winget manifest names",
			fmt.Sprintf("%s %s: the package's family name is %s, the winget manifest says %s", a.WingetID, m.Version, ident.PackageFamilyName, in.PackageFamilyName))
	}
	if want := ".msix"; ident.Bundle != (ext == ".msixbundle" || ext == ".appxbundle") {
		// The URL did not say (or said wrong): name the file by its content.
		if ident.Bundle {
			want = ".msixbundle"
		}
		np := strings.TrimSuffix(got.path, filepath.Ext(got.path)) + want
		if err := os.Rename(got.path, np); err != nil {
			return err
		}
		got.path = np
	}
	if !manifest.ValidPackageFamilyName(ident.PackageFamilyName) || !acqrequest.ValidVersion(ident.Version) {
		os.Remove(got.path)
		return unsupportedItem("the MSIX package identity is not usable", fmt.Sprintf("%s %s: identity %s %s", a.WingetID, m.Version, ident.PackageFamilyName, ident.Version))
	}
	title, name, loc := r.formatNames(a, m)
	pub := wingetPublisher(in, m)
	if loc != nil && loc.Publisher != "" && m.Publisher == "" {
		pub = loc.Publisher
	}
	mx := &manifest.Msix{PackageFamilyName: ident.PackageFamilyName, Name: ident.Name, Publisher: ident.Publisher, Version: ident.Version, Bundle: ident.Bundle}
	var vs *manifest.VendorSignature
	verified := "sha256(winget manifest " + murl + ")+identity(" + ident.PackageFamilyName + " " + ident.Version + ")"
	if authenticodeHere() {
		info, err := signerOfFile(got.path)
		if err != nil {
			os.Remove(got.path)
			return unsupportedItem(shortReason("the MSIX package signature is not valid: "+strings.TrimPrefix(err.Error(), "Authenticode: ")),
				fmt.Sprintf("%s %s (%s): %v", a.WingetID, m.Version, in.URL, err))
		}
		v, err := pinInstaller(r.ctx, r.c, r.pins, pinKeyWinget(a.WingetID), m.Version, pub, info)
		if err != nil {
			os.Remove(got.path)
			return err
		}
		vs, mx.Signer = &v, info.CN
		verified += "+authenticode(" + info.CN + ")"
	} else {
		autoWarn(fmt.Sprintf("%s %s: MSIX signature not checked on this acquisition host (needs Windows); the SHA-256 from winget is the check, and agents require a valid signature before installing", a.WingetID, m.Version))
	}
	_, err = acquire.FetchURL(r.ctx, acquire.FetchURLOptions{URL: in.URL, SHA256: got.sha256, FileName: filepath.Base(got.path), PackageID: wingetPackageID(a.WingetID, a.Version, arch),
		Title: title + " " + ident.Version, Vendor: pub, Kind: manifest.KindMsix, PackageName: name, OS: "windows",
		Version: ident.Version, Severity: "important", ReleaseDate: releaseDate(in), Arch: arch, OutDir: r.downloads, SpecPath: r.spec, HTTP: r.hc,
		Msix: mx, Verified: verified, VendorSignature: vs})
	return err
}

// checkPayload verifies a package's payload at build time for the kinds
// whose signature pmctl checks itself, and returns its vendor_signature.
// handled is false for the kinds signatureFor covers (msu, plain msi, ...).
func checkPayload(p manifest.Package, path string) (vs manifest.VendorSignature, handled bool, err error) {
	switch {
	case p.Kind == manifest.KindExe:
		err = withArchiveEntry(p, path, func(tree, entry string) error {
			if p.Archive != nil {
				if err := verifyArchivePrograms(tree, p.Archive); err != nil {
					return err
				}
			}
			vs, err = checkExeSignature(p, entry)
			return err
		})
		return vs, true, err
	case p.Kind == manifest.KindPortable:
		err = withArchiveEntry(p, path, func(tree, entry string) error {
			if p.Archive != nil {
				if err := verifyArchivePrograms(tree, p.Archive); err != nil {
					return err
				}
			}
			vs, err = checkSignerOf(p, entry, p.Portable.Signer)
			return err
		})
		return vs, true, err
	case p.Kind == manifest.KindMsix:
		vs, err = checkMsixPayload(p, path)
		return vs, true, err
	case p.Archive != nil: // msi
		err = withArchiveEntry(p, path, func(tree, entry string) error {
			if err := verifyArchivePrograms(tree, p.Archive); err != nil {
				return err
			}
			vs = p.VendorSignature
			if vs.Status == "" {
				vs = signatureFor(p.Kind, entry)
			}
			return nil
		})
		return vs, true, err
	}
	return manifest.VendorSignature{}, false, nil
}

// checkSignerOf: the program at path carries a valid signature by exactly
// signer (portable apps; checkExeSignature does the same for kind exe).
func checkSignerOf(p manifest.Package, path, signer string) (manifest.VendorSignature, error) {
	got, err := verifyExeSigner(path)
	if err != nil {
		return manifest.VendorSignature{}, err
	}
	if !strings.EqualFold(got, signer) {
		return manifest.VendorSignature{}, fmt.Errorf("%w: program signed by %q, manifest names %q", errExeSignature, got, signer)
	}
	detail := got
	if d := p.VendorSignature.Signer; strings.HasPrefix(d, got+" (") {
		detail = d
	}
	return manifest.VendorSignature{Status: "valid", Signer: detail, CheckedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

// checkMsixPayload: the package's identity is the manifest's, and (where
// this host can check it) its signature is valid and by msix.signer.
func checkMsixPayload(p manifest.Package, path string) (manifest.VendorSignature, error) {
	if p.Msix == nil {
		return manifest.VendorSignature{}, errors.New("kind msix without the msix block")
	}
	ident, err := acquire.ReadMsixIdentity(path)
	if err != nil {
		return manifest.VendorSignature{}, err
	}
	if !strings.EqualFold(ident.PackageFamilyName, p.Msix.PackageFamilyName) || ident.Version != p.Msix.Version || ident.Bundle != p.Msix.Bundle {
		return manifest.VendorSignature{}, fmt.Errorf("MSIX identity %s %s does not match the manifest (%s %s)", ident.PackageFamilyName, ident.Version, p.Msix.PackageFamilyName, p.Msix.Version)
	}
	vs := p.VendorSignature
	if vs.Status == "" {
		vs = manifest.VendorSignature{Status: "not_checked", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	if p.Msix.Signer == "" || !authenticodeHere() {
		return vs, nil
	}
	info, err := signerOfFile(path)
	if err != nil {
		return manifest.VendorSignature{}, err
	}
	if !strings.EqualFold(info.CN, p.Msix.Signer) {
		return manifest.VendorSignature{}, fmt.Errorf("%w: package signed by %q, manifest names %q", errExeSignature, info.CN, p.Msix.Signer)
	}
	if !strings.HasPrefix(vs.Signer, info.CN) {
		vs.Signer = info.CN
	}
	vs.Status, vs.CheckedAt = "valid", time.Now().UTC().Format(time.RFC3339)
	return vs, nil
}
