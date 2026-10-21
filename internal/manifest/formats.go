package manifest

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"offpatch/internal/safezip"
)

// App formats added in agent 0.10.0 (see docs/04-bundle-format.md):
//
//   - archive packages: an msi, exe or portable package whose payload is
//     the vendor's verified zip, because the installer needs the zip's other
//     files (Adobe Acrobat: setup.exe with its .msi, .cab and setup.ini).
//     The "archive" block names the installer inside and lists every file
//     with its size and SHA-256; the agent extracts into a private folder
//     and verifies each file before it runs the installer.
//   - kind "portable": an app without an installer (one exe, or a zip of
//     files) that the agent copies to %ProgramFiles%\DSS Patcher Apps and
//     registers in Apps & features ("portable" block).
//   - kind "msix": an MSIX/APPX package (or bundle) the agent provisions
//     machine-wide ("msix" block).
//   - kind "exe" with exe.scope "user": a per-user installer the agent runs
//     in each signed-in user's session.
//
// All four are unknown to older agents, which parse manifests strictly:
// pmctl puts them in bundles of their own and the server never offers them
// to an agent before MinAgentVersionFormats (target not_applicable).

// Kinds added with the app formats.
const (
	KindPortable = "portable"
	KindMsix     = "msix"
)

// ExeScopeUser: a per-user EXE installer, run as each signed-in user.
const ExeScopeUser = "user"

// MinAgentVersionFormats is the first agent release that installs archive,
// portable, MSIX and per-user packages.
const MinAgentVersionFormats = "0.10.0"

// not_applicable details for agents older than MinAgentVersionFormats.
const (
	AgentTooOldForArchive  = "agent too old for archive packages: upgrade the agent to 0.10.0 or later"
	AgentTooOldForPortable = "agent too old for portable apps: upgrade the agent to 0.10.0 or later"
	AgentTooOldForMsix     = "agent too old for MSIX packages: upgrade the agent to 0.10.0 or later"
	AgentTooOldForPerUser  = "agent too old for per-user installers: upgrade the agent to 0.10.0 or later"
)

// AgentTooOldDetails are every "agent too old" not_applicable detail; such a
// target comes back in scope once the agent is new enough.
var AgentTooOldDetails = []string{AgentTooOldForExe, AgentTooOldForArchive, AgentTooOldForPortable, AgentTooOldForMsix, AgentTooOldForPerUser}

// RequiredAgent is the oldest agent version that can install a package of
// kind with the given exe and archive blocks ("" = any agent), and the
// not_applicable detail for older agents.
func RequiredAgent(kind string, e *ExeInstall, a *Archive) (version, tooOld string) {
	switch {
	case kind == KindPortable:
		return MinAgentVersionFormats, AgentTooOldForPortable
	case kind == KindMsix:
		return MinAgentVersionFormats, AgentTooOldForMsix
	case a != nil:
		return MinAgentVersionFormats, AgentTooOldForArchive
	case kind == KindExe && e != nil && e.Scope == ExeScopeUser:
		return MinAgentVersionFormats, AgentTooOldForPerUser
	case kind == KindExe:
		return MinAgentVersionExe, AgentTooOldForExe
	}
	return "", ""
}

// FormatGeneration groups packages by the oldest agent that parses their
// manifest entry: 0 = every agent, 1 = kind exe (0.9.0), 2 = the app
// formats (0.10.0). pmctl never mixes generations in one bundle.
func (p *Package) FormatGeneration() int {
	switch v, _ := RequiredAgent(p.Kind, p.Exe, p.Archive); v {
	case "":
		return 0
	case MinAgentVersionExe:
		return 1
	}
	return 2
}

// ---- archive ----

// ArchiveFormatZip is the only archive format.
const ArchiveFormatZip = "zip"

// Archive limits (per package; the manifest as a whole is capped at 16 MiB).
const (
	MaxArchiveFiles   = 5000
	MaxArchivePathLen = 240
	MaxArchiveBytes   = safezip.DefaultMaxUncompressed
)

// Archive describes a package whose payload is a zip.
type Archive struct {
	// Format is "zip".
	Format string `json:"format"`
	// Entry is the installer (msi, exe) or the main program (portable) in
	// the zip: a path from Files.
	Entry string `json:"entry"`
	// Files are every file in the zip (directories are implied), with their
	// uncompressed size and SHA-256. The agent refuses a zip with any other
	// file, or any file whose hash differs.
	Files []ArchiveFile `json:"files"`
}

// ArchiveFile is one file of an archive.
type ArchiveFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// TotalSize is the sum of the files' sizes (disk space needed to extract).
func (a *Archive) TotalSize() int64 {
	if a == nil {
		return 0
	}
	var n int64
	for _, f := range a.Files {
		n += f.Size
	}
	return n
}

// Want converts the file list for safezip.ExtractVerified.
func (a *Archive) Want() []safezip.File {
	out := make([]safezip.File, 0, len(a.Files))
	for _, f := range a.Files {
		out = append(out, safezip.File{Path: f.Path, Size: f.Size, SHA256: f.SHA256})
	}
	return out
}

// EntryFile returns the Files entry for Entry (matched case-insensitively).
func (a *Archive) EntryFile() (ArchiveFile, bool) {
	for _, f := range a.Files {
		if strings.EqualFold(f.Path, a.Entry) {
			return f, true
		}
	}
	return ArchiveFile{}, false
}

func validateArchive(p *Package, pfx string, add func(string, ...any)) {
	a := p.Archive
	if a.Format != ArchiveFormatZip {
		add("%s.archive.format must be zip", pfx)
	}
	if !strings.HasSuffix(strings.ToLower(p.File.Name), ".zip") {
		add("%s.file.name must end in .zip for an archive package", pfx)
	}
	if n := len(a.Files); n == 0 || n > MaxArchiveFiles {
		add("%s.archive.files: 1..%d files", pfx, MaxArchiveFiles)
		return
	}
	seen := map[string]bool{}
	var total int64
	bad := 0
	for _, f := range a.Files {
		c, err := safezip.CleanPath(f.Path)
		switch {
		case err != nil || c != f.Path || len(f.Path) > MaxArchivePathLen:
			add("%s.archive.files path %q invalid", pfx, f.Path)
			bad++
		case seen[strings.ToLower(f.Path)]:
			add("%s.archive.files path %q duplicated (names compare without case)", pfx, f.Path)
			bad++
		case f.Size < 0 || !hexRe.MatchString(f.SHA256):
			add("%s.archive.files %q: size >= 0 and a lower-case sha256 required", pfx, f.Path)
			bad++
		default:
			seen[strings.ToLower(f.Path)] = true // only clean relative paths
		}
		total += max(f.Size, 0)
		if bad >= 5 {
			return // the rest is noise
		}
	}
	if bad > 0 {
		return
	}
	for k := range seen {
		for d := path.Dir(k); d != "." && d != "/"; d = path.Dir(d) {
			if seen[d] {
				add("%s.archive.files: %s is both a file and a directory", pfx, d)
				return
			}
		}
	}
	if total > MaxArchiveBytes {
		add("%s.archive.files: more than %d bytes in total", pfx, MaxArchiveBytes)
	}
	ef, ok := a.EntryFile()
	if !ok {
		add("%s.archive.entry %q is not one of archive.files", pfx, a.Entry)
		return
	}
	if ef.Path != a.Entry {
		add("%s.archive.entry must be written as in archive.files (%q)", pfx, ef.Path)
	}
	want := map[string]string{"msi": ".msi", KindExe: ".exe", KindPortable: ".exe"}[p.Kind]
	if want != "" && !strings.EqualFold(path.Ext(a.Entry), want) {
		add("%s.archive.entry must be a %s file for kind %s", pfx, want, p.Kind)
	}
}

// ---- portable ----

// PortableParent is the folder under %ProgramFiles% that holds portable apps.
const PortableParent = "DSS Patcher Apps"

// Portable describes how the agent installs a portable app.
type Portable struct {
	// Folder is the app's folder under %ProgramFiles%\DSS Patcher Apps
	// (the winget PackageIdentifier). The whole folder is replaced on update.
	Folder string `json:"folder"`
	// Command is the main program: a path in archive.files, or for a
	// single-exe payload the file name it gets in the folder.
	Command string `json:"command"`
	// Signer is the Authenticode signer CommonName of Command that pmctl
	// verified; the agent checks it again before it copies anything.
	Signer string `json:"signer"`
	// ARPKey is the Apps & features (Uninstall) key the agent writes:
	// DisplayName, DisplayVersion, Publisher, InstallLocation.
	ARPKey         string `json:"arp_key"`
	DisplayName    string `json:"display_name"`
	DisplayVersion string `json:"display_version"`
	Publisher      string `json:"publisher,omitempty"`
	// Shortcut, if set, is the name of the Start-menu shortcut (all users)
	// to Command.
	Shortcut string `json:"shortcut,omitempty"`
}

var (
	folderRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ +()-]{0,99}$`)
	shortcutR = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ +()-]{0,79}$`)
)

// ValidFolderName: one path element Windows treats as a plain name.
func ValidFolderName(s string) bool {
	if !folderRe.MatchString(s) || strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
		return false
	}
	return !reservedDeviceName(s)
}

func validatePortable(p *Package, pfx string, add func(string, ...any)) {
	po := p.Portable
	if po == nil {
		add("%s: kind portable requires the portable block", pfx)
		return
	}
	if !ValidFolderName(po.Folder) {
		add("%s.portable.folder must be one folder name like Vendor.App", pfx)
	}
	if !arpKeyRe.MatchString(po.ARPKey) {
		add("%s.portable.arp_key must be an Apps & features key name", pfx)
	}
	if !safeText(po.DisplayName, maxExeText) {
		add("%s.portable.display_name required", pfx)
	} else if p.PackageName != po.DisplayName {
		add("%s.package_name must equal portable.display_name", pfx)
	}
	if !safeText(po.DisplayVersion, 64) {
		add("%s.portable.display_version required", pfx)
	}
	if po.Publisher != "" && !safeText(po.Publisher, maxExeText) {
		add("%s.portable.publisher invalid", pfx)
	}
	if !safeText(po.Signer, maxExeText) {
		add("%s.portable.signer (verified Authenticode subject of the main program) required", pfx)
	}
	if po.Shortcut != "" && (!shortcutR.MatchString(po.Shortcut) || strings.HasSuffix(po.Shortcut, ".") || strings.HasSuffix(po.Shortcut, " ")) {
		add("%s.portable.shortcut must be a plain name", pfx)
	}
	if strings.TrimSpace(p.Version) == "" {
		add("%s: portable packages need a version", pfx)
	}
	if p.ProductCode != "" || p.KB != "" {
		add("%s: portable packages have no product_code or kb", pfx)
	}
	if !strings.EqualFold(path.Ext(po.Command), ".exe") {
		add("%s.portable.command must be an .exe", pfx)
	}
	if p.Archive != nil {
		if po.Command != p.Archive.Entry {
			add("%s.portable.command must equal archive.entry", pfx)
		}
		return
	}
	if !validBase(po.Command) {
		add("%s.portable.command must be a plain file name for a single-file app", pfx)
	}
	if !strings.HasSuffix(strings.ToLower(p.File.Name), ".exe") {
		add("%s.file.name must end in .exe (or .zip with an archive block) for kind portable", pfx)
	}
}

// ---- msix ----

// Msix identifies an MSIX/APPX package (or bundle) by its identity.
type Msix struct {
	// PackageFamilyName is <Name>_<PublisherId>, as Get-AppxPackage reports
	// it; the inventory lists the app under it (kind appx).
	PackageFamilyName string `json:"package_family_name"`
	// Name and Publisher are the package identity (AppxManifest.xml).
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	// Version is the identity version (four numbers) the endpoint reports.
	Version string `json:"version"`
	// Bundle: the payload is an .msixbundle / .appxbundle.
	Bundle bool `json:"bundle,omitempty"`
	// Signer is the signer CommonName pmctl verified (Windows acquisition
	// hosts only; "" = verified only by the winget SHA-256). The agent
	// always requires a valid signature, and this signer when set.
	Signer string `json:"signer,omitempty"`
}

var (
	pfnRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{2,49}_[a-hj-km-np-tv-z0-9]{13}$`)
	appxNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{2,49}$`)
	appxVerRe    = regexp.MustCompile(`^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$`)
	msixExts     = map[string]bool{".msix": false, ".appx": false, ".msixbundle": true, ".appxbundle": true}
	maxPublisher = 8192
)

// ValidPackageFamilyName reports whether s looks like Name_PublisherId.
func ValidPackageFamilyName(s string) bool { return pfnRe.MatchString(s) }

func validateMsix(p *Package, pfx string, add func(string, ...any)) {
	m := p.Msix
	if m == nil {
		add("%s: kind msix requires the msix block", pfx)
		return
	}
	if !pfnRe.MatchString(m.PackageFamilyName) {
		add("%s.msix.package_family_name must look like Name_publisherid", pfx)
	}
	if !appxNameRe.MatchString(m.Name) || !strings.HasPrefix(m.PackageFamilyName, m.Name+"_") {
		add("%s.msix.name must be the identity name the family name starts with", pfx)
	}
	if strings.TrimSpace(m.Publisher) == "" || len(m.Publisher) > maxPublisher || strings.ContainsFunc(m.Publisher, func(r rune) bool { return r < 0x20 }) {
		add("%s.msix.publisher (the identity publisher) required", pfx)
	}
	if !appxVerRe.MatchString(m.Version) {
		add("%s.msix.version must be four numbers like 1.2.3.0", pfx)
	}
	if m.Signer != "" && !safeText(m.Signer, maxExeText) {
		add("%s.msix.signer invalid", pfx)
	}
	ext := strings.ToLower(path.Ext(p.File.Name))
	if bundle, ok := msixExts[ext]; !ok {
		add("%s.file.name must end in .msix, .appx, .msixbundle or .appxbundle for kind msix", pfx)
	} else if bundle != m.Bundle {
		add("%s.msix.bundle must match the file type", pfx)
	}
	if strings.TrimSpace(p.Version) == "" {
		add("%s: msix packages need a version", pfx)
	}
	if p.ProductCode != "" || p.KB != "" || p.Archive != nil {
		add("%s: msix packages have no product_code, kb or archive", pfx)
	}
	if p.PackageName != "" && !safeText(p.PackageName, maxExeText) {
		add("%s.package_name invalid", pfx)
	}
}

// formatBlockMisuse reports app-format blocks on kinds they are not for.
func formatBlockMisuse(p *Package) error {
	switch {
	case p.Portable != nil && p.Kind != KindPortable:
		return fmt.Errorf("portable block is only for kind portable")
	case p.Msix != nil && p.Kind != KindMsix:
		return fmt.Errorf("msix block is only for kind msix")
	case p.Archive != nil && p.Kind != "msi" && p.Kind != KindExe && p.Kind != KindPortable:
		return fmt.Errorf("archive block is only for kinds msi, exe and portable")
	case p.Archive != nil && p.Kind == KindExe && p.Exe != nil && p.Exe.Scope == ExeScopeUser:
		return fmt.Errorf("per-user installers in an archive are not supported")
	}
	return nil
}
