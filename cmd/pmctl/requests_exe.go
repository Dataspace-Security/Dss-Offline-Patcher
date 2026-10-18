package main

// EXE installers in acquisition requests: an app whose winget manifest has
// no MSI for the architecture, but an EXE installer offpatch can run
// silently (acquire.PickEXE: exe with a documented silent switch, inno,
// nullsoft, burn; machine scope; https; SHA-256). The download is checked
// against the manifest's SHA-256, then its Authenticode signature is
// verified in pure Go (any acquisition host); the verified signer goes into
// the manifest. EXE packages travel in bundles of their own (bundles.go).

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire"
	"offpatch/internal/intel"
	"offpatch/internal/manifest"
)

func (r *requestRun) fetchWingetExe(a acqrequest.App, arch string, m *acquire.WingetManifest, murl string, in acquire.WingetInstaller) error {
	ver := m.Version
	if v := in.ARPVersion(); acqrequest.ValidVersion(v) {
		ver = v
	}
	file := wingetPackageID(a.WingetID, m.Version, arch) + ".exe"
	dl, err := acquire.Download(r.ctx, r.hc, acquire.DownloadRequest{URL: in.URL, DestDir: r.downloads, FileName: file, SHA256: in.SHA256})
	if err != nil {
		return err
	}
	signer, err := verifyExeSigner(dl.Path)
	if err != nil {
		os.Remove(dl.Path) // never left where a later run could pick it up
		return unsupportedItem(shortReason("the installer's Authenticode signature is not valid: "+strings.TrimPrefix(err.Error(), "Authenticode: ")),
			fmt.Sprintf("%s %s (%s): %v", a.WingetID, m.Version, in.URL, err))
	}
	// Best effort: the locale manifest's product name and publisher.
	loc, _ := acquire.FetchWingetLocale(r.ctx, r.hc, r.c.WingetManifestsURL, m.ID, m.Version)
	name := exeDisplayName(in, a, m, loc)
	if name == "" {
		return unsupportedItem("no Apps & features name to detect the installed app",
			fmt.Sprintf("%s %s: neither the winget manifest nor the inventory gives a usable Apps & features name", a.WingetID, m.Version))
	}
	pub := wingetPublisher(in, m)
	if loc != nil && loc.Publisher != "" && m.Publisher == "" {
		pub = loc.Publisher
	}
	ex, err := in.ExeInstall(acquire.ExeInstallOptions{Signer: signer, DisplayName: name, Publisher: arpPublisher(in, pub)})
	if err != nil {
		var un *acquire.UnsupportedError
		if errors.As(err, &un) {
			return unsupportedItem(un.Reason, a.WingetID+" "+m.Version+": "+un.Reason)
		}
		return err
	}
	if !ex.Uninstall.QuietUninstall {
		autoWarn(fmt.Sprintf("%s %s: %s installer registers no known silent uninstall; rollback will not be offered", a.WingetID, m.Version, in.InstallerType))
	}
	rel := in.ReleaseDate
	if _, err := time.Parse("2006-01-02", rel); err != nil {
		rel = ""
	}
	title := a.Name
	if title == "" && loc != nil {
		title = loc.PackageName
	}
	if title == "" {
		title = a.WingetID
	}
	_, err = acquire.FetchURL(r.ctx, acquire.FetchURLOptions{URL: in.URL, SHA256: in.SHA256, FileName: file, PackageID: wingetPackageID(a.WingetID, a.Version, arch),
		Title: title + " " + ver, Vendor: pub, Kind: manifest.KindExe, PackageName: name, OS: "windows",
		Version: ver, Severity: "important", ReleaseDate: rel, Arch: arch, OutDir: r.downloads, SpecPath: r.spec, HTTP: r.hc, Exe: ex,
		Verified: "sha256(winget manifest " + murl + ")+authenticode(" + signer + ")",
		VerifyPayload: func(p string) error {
			got, err := verifyExeSigner(p)
			if err == nil && got != signer {
				err = fmt.Errorf("signer changed from %q to %q", signer, got)
			}
			return err
		}})
	return err
}

// exeDisplayName picks detect.display_name (= package_name): the manifest's
// Apps & features name, else the name the endpoints report (when they all
// name the same app; a version in it is fine, matching ignores versions),
// else the winget product name.
func exeDisplayName(in acquire.WingetInstaller, a acqrequest.App, m *acquire.WingetManifest, loc *acquire.WingetLocale) string {
	cands := []string{in.ARPName()}
	var inv string
	agree := true
	for _, i := range a.Installed {
		if i.Name == "" {
			continue
		}
		if inv == "" {
			inv = i.Name
		} else if !strings.EqualFold(i.Name, inv) && intel.Normalize(i.Name) != intel.Normalize(inv) {
			agree = false
		}
	}
	if agree {
		cands = append(cands, inv)
	}
	if loc != nil {
		cands = append(cands, loc.PackageName)
	}
	cands = append(cands, m.PackageName, a.Name)
	for _, c := range cands {
		if c = strings.TrimSpace(c); exeTextOK(c) {
			return c
		}
	}
	return ""
}

// arpPublisher: the Apps & features publisher when the manifest states it.
func arpPublisher(in acquire.WingetInstaller, fallback string) string {
	for _, e := range in.ARP {
		if exeTextOK(e.Publisher) {
			return e.Publisher
		}
	}
	if exeTextOK(fallback) {
		return fallback
	}
	return ""
}

// exeTextOK: the manifest's rule for exe display names (single line, no
// quotes or control characters, at most 200 characters).
func exeTextOK(s string) bool {
	if s == "" || strings.TrimSpace(s) != s || len([]rune(s)) > 200 {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == '"' })
}
