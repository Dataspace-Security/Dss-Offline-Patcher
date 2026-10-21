package acquire

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf16"

	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/safezip"
)

// MSIX packages and portable apps from winget manifests (agents 0.10.0 and
// later; see docs/08-acquisition.md "MSIX packages" and "Portable apps").

// msixTypes are imported as kind msix.
var msixTypes = map[string]bool{"msix": true, "appx": true}

// IsMSIX reports whether the installer is an MSIX/APPX package.
func (in WingetInstaller) IsMSIX() bool { return msixTypes[in.InstallerType] }

// IsPortable reports whether the installer is a portable app (a plain exe,
// or a zip of files with ZipPath its program).
func (in WingetInstaller) IsPortable() bool { return in.InstallerType == "portable" }

// pickSimple chooses, for arch, an installer for which ok holds and that
// has an https URL and a SHA-256; reason says why one does not qualify.
func (m *WingetManifest) pickSimple(arch, label string, ok func(WingetInstaller) bool, reason func(WingetInstaller) string) (WingetInstaller, error) {
	var cands []WingetInstaller
	var reasons []string
	for pass, a := range []string{arch, "x86"} {
		if pass == 1 && (arch != "x64" || len(cands)+len(reasons) > 0) {
			break // x86 builds run on x64 Windows, if there is nothing native
		}
		for _, in := range m.zipped() {
			if !ok(in) || !exeArchFits(in, a) || pass == 1 && in.Architecture != "x86" {
				continue
			}
			if r := reason(in); r != "" {
				reasons = append(reasons, r)
				continue
			}
			cands = append(cands, in)
		}
	}
	if len(cands) == 0 {
		if len(reasons) > 0 {
			return WingetInstaller{}, unsupported("%s %s: %s for %s is not importable: %s", m.ID, m.Version, label, arch, reasons[0])
		}
		return WingetInstaller{}, unsupported("%s %s has no %s for %s", m.ID, m.Version, label, arch)
	}
	rank := func(in WingetInstaller) int {
		r := 0
		switch strings.ToLower(in.Locale) {
		case "", "en-us":
		case "en-gb", "en":
			r += 2
		default:
			r += 4
		}
		if in.Architecture == "neutral" {
			r++
		}
		if in.Scope == "user" {
			r += 8 // machine-scope first
		}
		return r
	}
	sort.SliceStable(cands, func(i, j int) bool { return rank(cands[i]) < rank(cands[j]) })
	return cands[0], nil
}

// msixReason is the importable rule for an MSIX installer.
func (in WingetInstaller) msixReason() string {
	return intel.MsixReason(in.resolved())
}

// PickMSIX chooses the MSIX/APPX package for arch (https, SHA-256).
func (m *WingetManifest) PickMSIX(arch string) (WingetInstaller, error) {
	return m.pickSimple(arch, "MSIX package", WingetInstaller.IsMSIX, WingetInstaller.msixReason)
}

// portableReason is the importable rule for a portable app.
func (in WingetInstaller) portableReason() string {
	if r := intel.PortableReason(in.resolved()); r != "" {
		return r
	}
	if in.ZipPath == "" && !strings.EqualFold(path.Ext(portableURLName(in.URL)), ".exe") && !strings.HasSuffix(strings.ToLower(in.URL), ".exe") {
		// A plain portable app is one program; winget allows other files
		// (a script, a .com) that offpatch does not install.
		if len(in.Commands) == 0 {
			return "portable app that is not an .exe"
		}
	}
	if in.ZipPath != "" && !strings.EqualFold(path.Ext(in.ZipPath), ".exe") {
		return "portable app whose program is not an .exe"
	}
	return ""
}

// PickPortable chooses the portable app for arch (a plain exe, or a zip of
// files; https, SHA-256).
func (m *WingetManifest) PickPortable(arch string) (WingetInstaller, error) {
	return m.pickSimple(arch, "portable app", WingetInstaller.IsPortable, WingetInstaller.portableReason)
}

// portableURLName is the last path element of an installer URL.
func portableURLName(u string) string {
	u, _, _ = strings.Cut(u, "?")
	u, _, _ = strings.Cut(u, "#")
	return path.Base(u)
}

// PortableCommandName is the file name a single-exe portable app gets in
// its folder: the URL's file name when it is a safe .exe name, else the
// first command (or PortableCommandAlias, or fallback) + ".exe".
func (in WingetInstaller) PortableCommandName(fallback string) string {
	if n := portableURLName(in.URL); strings.EqualFold(path.Ext(n), ".exe") && safeNameRe.MatchString(n) && manifestBase(n) {
		return n
	}
	for _, c := range append(append([]string{}, in.Commands...), fallback) {
		n := c + ".exe"
		if safeNameRe.MatchString(n) && manifestBase(n) {
			return n
		}
	}
	return "app.exe"
}

// manifestBase: the manifest's rule for payload / command file names.
func manifestBase(n string) bool {
	return n != "." && n != ".." && !strings.HasSuffix(n, ".") && manifest.ValidFolderName(n)
}

// ---- MSIX identity ----

// MsixIdentity is the identity of an MSIX/APPX package or bundle, read
// from its AppxManifest.xml (or AppxMetadata/AppxBundleManifest.xml).
type MsixIdentity struct {
	Name, Publisher, Version string
	Bundle                   bool
	// PackageFamilyName is Name_PublisherId.
	PackageFamilyName string
}

type appxIdentity struct {
	Name      string `xml:"Name,attr"`
	Publisher string `xml:"Publisher,attr"`
	Version   string `xml:"Version,attr"`
}

type appxManifestXML struct {
	Identity appxIdentity `xml:"Identity"`
}

type appxBundleXML struct {
	Identity appxIdentity `xml:"Identity"`
	Packages []struct {
		Type    string `xml:"Type,attr"`
		Version string `xml:"Version,attr"`
		Arch    string `xml:"Architecture,attr"`
	} `xml:"Packages>Package"`
}

const maxAppxManifest = 4 << 20

// ReadMsixIdentity reads the package identity of the MSIX/APPX file at
// p. For a bundle, Version is the highest version of its application
// packages (what Get-AppxPackage reports once installed), else the
// bundle's own.
func ReadMsixIdentity(p string) (*MsixIdentity, error) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, unsupported("the MSIX package cannot be read as a zip: %v", err)
	}
	defer zr.Close()
	if _, err := checkZip(zr.File); err != nil {
		return nil, err
	}
	read := func(name string) ([]byte, bool, error) {
		for _, f := range zr.File {
			if strings.EqualFold(f.Name, name) {
				if f.UncompressedSize64 > maxAppxManifest {
					return nil, true, unsupported("%s is larger than %d bytes", name, maxAppxManifest)
				}
				rc, err := f.Open()
				if err != nil {
					return nil, true, unsupported("%s cannot be read: %v", name, err)
				}
				defer rc.Close()
				b, err := io.ReadAll(io.LimitReader(rc, maxAppxManifest+1))
				if err != nil {
					return nil, true, unsupported("%s cannot be read: %v", name, err)
				}
				return b, true, nil
			}
		}
		return nil, false, nil
	}
	id := &MsixIdentity{}
	if b, ok, err := read("AppxMetadata/AppxBundleManifest.xml"); err != nil {
		return nil, err
	} else if ok {
		var x appxBundleXML
		if err := xml.Unmarshal(b, &x); err != nil {
			return nil, unsupported("AppxBundleManifest.xml: %v", err)
		}
		id.Name, id.Publisher, id.Version, id.Bundle = x.Identity.Name, x.Identity.Publisher, x.Identity.Version, true
		best := ""
		for _, p := range x.Packages {
			if strings.EqualFold(p.Type, "application") && (best == "" || versionLess(best, p.Version)) {
				best = p.Version
			}
		}
		if best != "" {
			id.Version = best
		}
	} else if b, ok, err := read("AppxManifest.xml"); err != nil {
		return nil, err
	} else if ok {
		var x appxManifestXML
		if err := xml.Unmarshal(b, &x); err != nil {
			return nil, unsupported("AppxManifest.xml: %v", err)
		}
		id.Name, id.Publisher, id.Version = x.Identity.Name, x.Identity.Publisher, x.Identity.Version
	} else {
		return nil, unsupported("the file is not an MSIX/APPX package (no AppxManifest.xml or AppxBundleManifest.xml)")
	}
	if id.Name == "" || id.Publisher == "" || id.Version == "" {
		return nil, unsupported("the MSIX package identity is incomplete (Name, Publisher, Version)")
	}
	id.PackageFamilyName = id.Name + "_" + PublisherID(id.Publisher)
	return id, nil
}

// checkZip applies the archive rules (safezip) to an MSIX container.
func checkZip(files []*zip.File) (int, error) {
	ents, err := safezip.Check(files, zipLimits())
	return len(ents), zipErr(err)
}

// PublisherID computes the 13-character publisher id of a package family
// name: the first 8 bytes of SHA-256 over the UTF-16LE publisher string,
// in Crockford's base32 (lower case), 5 bits at a time over 65 bits (the
// last group padded with a zero bit).
func PublisherID(publisher string) string {
	u := utf16.Encode([]rune(publisher))
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	h := sha256.Sum256(b)
	const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	var bits uint64
	for _, c := range h[:8] {
		bits = bits<<8 | uint64(c)
	}
	out := make([]byte, 13)
	for i := 0; i < 13; i++ {
		shift := 64 - 5*(i+1) // 65 bits: the last group takes 4 bits and a zero
		var v uint64
		if shift >= 0 {
			v = bits >> uint(shift) & 31
		} else {
			v = bits << uint(-shift) & 31
		}
		out[i] = alphabet[v]
	}
	return string(out)
}

func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			fmt.Sscan(as[i], &x)
		}
		if i < len(bs) {
			fmt.Sscan(bs[i], &y)
		}
		if x != y {
			return x < y
		}
	}
	return false
}
