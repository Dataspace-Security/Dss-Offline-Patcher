package manifest

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// KindExe is a signed vendor EXE installer (plain exe, Inno Setup, NSIS or
// WiX Burn bootstrapper) run silently with an argv from the manifest. Only
// packages of this kind carry an ExeInstall block; msu/msi/agent manifests
// are byte-identical to the pre-EXE format (the field is omitempty).
const KindExe = "exe"

// MinAgentVersionExe is the first agent release that understands kind "exe".
// Older agents parse manifests strictly, so the server never offers them an
// EXE package and reports the target not_applicable with AgentTooOldForExe.
const MinAgentVersionExe = "0.9.0"

// AgentTooOldForExe is the not_applicable detail for such targets.
const AgentTooOldForExe = "agent too old for EXE packages: upgrade the agent to 0.9.0 or later"

// EXE installer technologies (winget InstallerType values).
const (
	ExeTypeExe      = "exe"
	ExeTypeInno     = "inno"
	ExeTypeNullsoft = "nullsoft"
	ExeTypeBurn     = "burn"
)

// ExeScopeMachine is the only supported install scope: per-user installers
// would install into the SYSTEM profile when the agent runs them.
const ExeScopeMachine = "machine"

// ExeInstall describes how the agent runs, detects and (optionally) rolls
// back an EXE-kind package.
type ExeInstall struct {
	// InstallerType: exe | inno | nullsoft | burn.
	InstallerType string `json:"installer_type"`
	// SilentArgs is the argv passed to the installer (no shell).
	SilentArgs []string `json:"silent_args"`
	// SuccessCodes always include 0; 3010 and 1641 mean installed + restart.
	SuccessCodes []int `json:"success_codes"`
	// BusyCodes mean "another install in progress / package in use": retry later.
	BusyCodes []int `json:"busy_codes,omitempty"`
	// Signer is the Authenticode signer subject CN that pmctl verified.
	Signer    string       `json:"signer"`
	Detect    ExeDetect    `json:"detect"`
	Uninstall ExeUninstall `json:"uninstall"`
	// Scope is always "machine".
	Scope string `json:"scope"`
}

// ExeDetect identifies the installed app in Apps & features (ARP).
type ExeDetect struct {
	DisplayName    string `json:"display_name"`
	DisplayVersion string `json:"display_version,omitempty"`
	ProductCode    string `json:"product_code,omitempty"`
	Publisher      string `json:"publisher,omitempty"`
}

// ExeUninstall: QuietUninstall is true only when the app is known to register
// a QuietUninstallString; otherwise rollback is unsupported.
type ExeUninstall struct {
	QuietUninstall bool `json:"quiet_uninstall"`
}

// DefaultSilentArgs returns the well-known silent switches of an installer
// technology, or nil for a plain "exe" (no documented default).
func DefaultSilentArgs(installerType string) []string {
	switch installerType {
	case ExeTypeInno:
		return []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"}
	case ExeTypeNullsoft:
		return []string{"/S"}
	case ExeTypeBurn:
		return []string{"/quiet", "/norestart"}
	}
	return nil
}

// IsExeInstallerType reports whether t is one of the supported EXE types.
func IsExeInstallerType(t string) bool {
	switch t {
	case ExeTypeExe, ExeTypeInno, ExeTypeNullsoft, ExeTypeBurn:
		return true
	}
	return false
}

// RollbackSupported reports whether the package can be rolled back
// (uninstalled) by the agent. Non-EXE kinds keep their existing rules.
func (p *Package) RollbackSupported() bool {
	if p.Kind != KindExe {
		return true
	}
	return p.Exe != nil && p.Exe.Uninstall.QuietUninstall
}

const (
	maxSilentArgs   = 32
	maxSilentArgLen = 256
	maxExeText      = 200
	maxExitCodes    = 64
)

var arpKeyRe = regexp.MustCompile(`^[A-Za-z0-9{}][A-Za-z0-9{}._ +()-]{0,127}$`)

// safeText: non-empty after trimming, bounded, single-line, no quotes or
// control characters (the agent compares it against registry values and
// logs it; it is never interpreted).
func safeText(s string, max int) bool {
	if strings.TrimSpace(s) != s || s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '"' {
			return false
		}
	}
	return true
}

func validExitCode(c int) bool { v := int64(c); return v >= -(1<<31) && v <= 1<<32-1 }

// validateExe checks kind "exe" packages. add appends an error message.
func validateExe(p *Package, pfx string, add func(string, ...any)) {
	e := p.Exe
	if e == nil {
		add("%s: kind exe requires the exe block", pfx)
		return
	}
	if !IsExeInstallerType(e.InstallerType) {
		add("%s.exe.installer_type must be exe, inno, nullsoft or burn", pfx)
	}
	if len(e.SilentArgs) == 0 {
		add("%s.exe.silent_args required (EXE installer without a documented silent switch)", pfx)
	}
	if len(e.SilentArgs) > maxSilentArgs {
		add("%s.exe.silent_args: at most %d arguments", pfx, maxSilentArgs)
	}
	for _, a := range e.SilentArgs {
		if !safeText(a, maxSilentArgLen) {
			add("%s.exe.silent_args entry %q invalid", pfx, a)
		}
	}
	if len(e.SuccessCodes) > maxExitCodes || len(e.BusyCodes) > maxExitCodes {
		add("%s.exe: at most %d success/busy codes", pfx, maxExitCodes)
	}
	hasZero := false
	success := map[int]bool{}
	for _, c := range e.SuccessCodes {
		if !validExitCode(c) {
			add("%s.exe.success_codes entry %d out of range", pfx, c)
		}
		hasZero = hasZero || c == 0
		success[c] = true
	}
	if !hasZero {
		add("%s.exe.success_codes must include 0", pfx)
	}
	for _, c := range e.BusyCodes {
		if !validExitCode(c) || c == 0 || success[c] {
			add("%s.exe.busy_codes entry %d invalid", pfx, c)
		}
	}
	if !safeText(e.Signer, maxExeText) {
		add("%s.exe.signer (verified Authenticode subject) required", pfx)
	}
	if !safeText(e.Detect.DisplayName, maxExeText) {
		add("%s.exe.detect.display_name required", pfx)
	} else if p.PackageName != e.Detect.DisplayName {
		add("%s.package_name must equal exe.detect.display_name", pfx)
	}
	if e.Detect.DisplayVersion != "" && !safeText(e.Detect.DisplayVersion, 64) {
		add("%s.exe.detect.display_version invalid", pfx)
	}
	if e.Detect.Publisher != "" && !safeText(e.Detect.Publisher, maxExeText) {
		add("%s.exe.detect.publisher invalid", pfx)
	}
	if e.Detect.ProductCode != "" && !arpKeyRe.MatchString(e.Detect.ProductCode) {
		add("%s.exe.detect.product_code must be an ARP key name or {GUID}", pfx)
	}
	if e.Scope != ExeScopeMachine {
		add("%s.exe.scope must be machine", pfx)
	}
	if strings.TrimSpace(p.Version) == "" {
		add("%s: exe packages need a version", pfx)
	}
	if p.ProductCode != "" {
		add("%s.product_code is for msi; use exe.detect.product_code", pfx)
	}
	if !strings.HasSuffix(strings.ToLower(p.File.Name), ".exe") {
		add("%s.file.name must end in .exe for kind exe", pfx)
	}
}

// exeBlockMisuse reports an Exe block on a non-exe kind.
func exeBlockMisuse(p *Package) error {
	if p.Exe != nil && p.Kind != KindExe {
		return fmt.Errorf("exe block is only for kind exe")
	}
	return nil
}
