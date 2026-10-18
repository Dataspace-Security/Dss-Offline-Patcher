package acquire

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"offpatch/internal/intel"
	"offpatch/internal/manifest"
)

// EXE installers from winget manifests (exe, inno, nullsoft, burn): which
// installer to take for an architecture, and the manifest.ExeInstall that
// tells the agent how to run it. The rule matches intel.Importable (see
// docs/08-acquisition.md "EXE installers").

// exeARPKeyRe: the manifest's rule for exe.detect.product_code.
var exeARPKeyRe = regexp.MustCompile(`^[A-Za-z0-9{}][A-Za-z0-9{}._ +()-]{0,127}$`)

// WingetSwitches is a manifest's InstallerSwitches.
type WingetSwitches struct {
	Silent             string
	SilentWithProgress string
	Custom             string
}

// WingetReturnCode is one ExpectedReturnCodes entry.
type WingetReturnCode struct {
	Code     int
	Response string // winget ReturnResponse, e.g. installInProgress
}

// exe-type installer field parsing: called by ParseWingetManifest.
func exeFields(m map[string]any) (sw WingetSwitches, success []int, codes []WingetReturnCode, unsupported []string, err error) {
	if s, ok := m["InstallerSwitches"].(map[string]any); ok {
		sw = WingetSwitches{Silent: str(s, "Silent"), SilentWithProgress: str(s, "SilentWithProgress"), Custom: str(s, "Custom")}
	}
	if list, ok := m["InstallerSuccessCodes"].([]any); ok {
		for _, v := range list {
			s, _ := v.(string)
			c, perr := parseExitCode(s)
			if perr != nil {
				return sw, nil, nil, nil, fmt.Errorf("InstallerSuccessCodes: %w", perr)
			}
			success = append(success, c)
		}
	}
	if list, ok := m["ExpectedReturnCodes"].([]any); ok {
		for _, v := range list {
			e, ok := v.(map[string]any)
			if !ok {
				return sw, nil, nil, nil, errors.New("ExpectedReturnCodes entry is not a mapping")
			}
			c, perr := parseExitCode(str(e, "InstallerReturnCode"))
			if perr != nil {
				return sw, nil, nil, nil, fmt.Errorf("ExpectedReturnCodes: %w", perr)
			}
			codes = append(codes, WingetReturnCode{Code: c, Response: str(e, "ReturnResponse")})
		}
	}
	if list, ok := m["UnsupportedOSArchitectures"].([]any); ok {
		for _, v := range list {
			if s, ok := v.(string); ok {
				unsupported = append(unsupported, strings.ToLower(strings.TrimSpace(s)))
			}
		}
	}
	return sw, success, codes, unsupported, nil
}

// parseExitCode reads a winget return code (int32 range, or a DWORD).
func parseExitCode(s string) (int, error) {
	s = strings.TrimSpace(s)
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil || v < -(1<<31) || v > 1<<32-1 {
		return 0, fmt.Errorf("return code %q invalid", s)
	}
	return int(v), nil
}

// IsEXE reports whether the installer is one of the EXE flavours.
func (in WingetInstaller) IsEXE() bool { return manifest.IsExeInstallerType(in.InstallerType) }

// SilentArgs returns the argv the agent runs the installer with: the
// manifest's Silent switch, else the installer type's documented default,
// plus the manifest's Custom switches (winget always passes those). nil
// when there is none (a plain "exe" without a Silent switch).
func (in WingetInstaller) SilentArgs() ([]string, error) {
	var args []string
	switch {
	case in.Switches.Silent != "":
		a, err := SplitSwitches(in.Switches.Silent)
		if err != nil {
			return nil, fmt.Errorf("InstallerSwitches.Silent: %w", err)
		}
		args = a
	default:
		args = manifest.DefaultSilentArgs(in.InstallerType)
	}
	if len(args) == 0 {
		return nil, nil
	}
	if in.Switches.Custom != "" {
		c, err := SplitSwitches(in.Switches.Custom)
		if err != nil {
			return nil, fmt.Errorf("InstallerSwitches.Custom: %w", err)
		}
		args = append(args, c...)
	}
	return args, nil
}

// SplitSwitches splits a winget switch string into argv the way the
// Windows command line does for simple cases: whitespace separates,
// double quotes group (and are removed). Control characters, a lone quote
// or shell metacharacters that only make sense to cmd.exe are refused.
func SplitSwitches(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQ, have := false, false
	for _, r := range s {
		switch {
		case unicode.IsControl(r):
			return nil, errors.New("control character in switches")
		case r == '"':
			inQ, have = !inQ, true
		case (r == ' ' || r == '\t') && !inQ:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		case !inQ && strings.ContainsRune("&|<>^", r):
			return nil, fmt.Errorf("shell metacharacter %q in switches", r)
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if inQ {
		return nil, errors.New("unbalanced quote in switches")
	}
	if have {
		out = append(out, cur.String())
	}
	return out, nil
}

// winget ReturnResponse values that mean "installed" / "busy, retry later".
var (
	installedResponses = map[string]bool{"alreadyInstalled": true, "rebootRequiredToFinish": true, "rebootRequiredForInstall": true}
	busyResponses      = map[string]bool{"installInProgress": true, "packageInUse": true, "packageInUseByApplication": true}
)

// ExitCodes returns the success and busy codes for the agent: 0, 3010 and
// 1641 always succeed; InstallerSuccessCodes and ExpectedReturnCodes whose
// response means installed are added; installInProgress / packageInUse
// codes are busy (retry later). Burn's 1618 (another install running) is
// busy by default.
func (in WingetInstaller) ExitCodes() (success, busy []int) {
	seen := map[int]bool{}
	add := func(dst *[]int, c int) {
		if !seen[c] {
			seen[c] = true
			*dst = append(*dst, c)
		}
	}
	for _, c := range []int{0, 3010, 1641} {
		add(&success, c)
	}
	for _, c := range in.SuccessCodes {
		add(&success, c)
	}
	for _, rc := range in.ReturnCodes {
		if installedResponses[rc.Response] {
			add(&success, rc.Code)
		}
	}
	for _, rc := range in.ReturnCodes {
		if busyResponses[rc.Response] {
			add(&busy, rc.Code)
		}
	}
	if in.InstallerType == manifest.ExeTypeBurn {
		add(&busy, 1618)
	}
	return success, busy
}

// exeArchFits: an EXE installer runs on its own architecture; a neutral
// one on x64 and x86. UnsupportedOSArchitectures excludes an entry.
func exeArchFits(in WingetInstaller, arch string) bool {
	for _, u := range in.UnsupportedArch {
		if u == arch {
			return false
		}
	}
	return in.Architecture == arch || (in.Architecture == "neutral" && arch != "arm64")
}

// ExeUnsupportedReason is the console text for an EXE installer offpatch
// cannot deploy, or "" if it can.
func (in WingetInstaller) ExeUnsupportedReason() string {
	if r := intel.ExeReason(in.resolved()); r != "" {
		return r
	}
	if args, err := in.SilentArgs(); err != nil || len(args) == 0 {
		return intel.ReasonExeNoSilent
	}
	return ""
}

// resolved is the installer as the Library describes it (intel rule input).
func (in WingetInstaller) resolved() intel.ResolvedInstaller {
	ri := intel.ResolvedInstaller{Arch: in.Architecture, Type: in.InstallerType, Scope: in.Scope, URL: in.URL,
		Silent: in.Switches.Silent != ""}
	if httpsURL(in.URL) {
		ri.URL = in.URL
	} else {
		ri.URL = ""
	}
	if hex64Re.MatchString(in.SHA256) {
		ri.SHA256 = in.SHA256
	}
	return ri
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// PickEXE chooses the EXE installer for arch that offpatch can deploy:
// machine scope (or unspecified), https, SHA-256 and a silent switch; then
// a neutral or en-US locale over others. Otherwise an UnsupportedError
// whose reason names why (e.g. "installs per user only").
func (m *WingetManifest) PickEXE(arch string) (WingetInstaller, error) {
	var ok []WingetInstaller
	var reasons, types []string
	for _, in := range m.Installers {
		if !in.IsEXE() || !exeArchFits(in, arch) {
			continue
		}
		types = append(types, in.InstallerType)
		if r := in.ExeUnsupportedReason(); r != "" {
			reasons = append(reasons, r)
			continue
		}
		ok = append(ok, in)
	}
	if len(ok) == 0 {
		if len(reasons) == 0 {
			return WingetInstaller{}, unsupported("%s %s has no EXE installer for %s", m.ID, m.Version, arch)
		}
		sort.Strings(types)
		return WingetInstaller{}, unsupported("%s %s: EXE installer (%s) for %s %s", m.ID, m.Version, strings.Join(dedupe(types), ", "), arch, firstReason(reasons))
	}
	rank := func(in WingetInstaller) int {
		r := 0
		if in.Scope == "" {
			r++ // machine preferred over unspecified
		}
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
		return r
	}
	sort.SliceStable(ok, func(i, j int) bool { return rank(ok[i]) < rank(ok[j]) })
	return ok[0], nil
}

// firstReason orders reasons by how specific they are.
func firstReason(rs []string) string {
	for _, want := range []string{intel.ReasonExeNoSilent, intel.ReasonPerUser} {
		for _, r := range rs {
			if r == want {
				return "is not importable: " + r
			}
		}
	}
	return "is not importable: " + rs[0]
}

// PickInstaller picks what pmctl imports for arch: an MSI when there is one
// (PickMSI), else an EXE installer (PickEXE). The error explains both.
func (m *WingetManifest) PickInstaller(arch string) (WingetInstaller, error) {
	in, err := m.PickMSI(arch)
	if err == nil {
		return in, nil
	}
	var msiErr *UnsupportedError
	if !errors.As(err, &msiErr) {
		return in, err
	}
	ex, exErr := m.PickEXE(arch)
	if exErr == nil {
		return ex, nil
	}
	var un *UnsupportedError
	if errors.As(exErr, &un) && strings.Contains(un.Reason, "is not importable") {
		return WingetInstaller{}, exErr // the EXE reason is the useful one
	}
	return WingetInstaller{}, &UnsupportedError{Reason: strings.Replace(msiErr.Reason, "has no MSI installer", "has no MSI or EXE installer", 1)}
}

// ExeInstallOptions are the parts of an ExeInstall pmctl knows only after
// download (the verified signer) or from elsewhere (the display name).
type ExeInstallOptions struct {
	Signer      string // verified Authenticode signer CN
	DisplayName string // Apps & features name (detect.display_name)
	Publisher   string
}

// ExeInstall builds the manifest block for an EXE installer.
func (in WingetInstaller) ExeInstall(o ExeInstallOptions) (*manifest.ExeInstall, error) {
	if !in.IsEXE() {
		return nil, fmt.Errorf("installer type %q is not an EXE installer", in.InstallerType)
	}
	if r := in.ExeUnsupportedReason(); r != "" {
		return nil, &UnsupportedError{Reason: r}
	}
	args, _ := in.SilentArgs()
	success, busy := in.ExitCodes()
	e := &manifest.ExeInstall{InstallerType: in.InstallerType, SilentArgs: args, SuccessCodes: success, BusyCodes: busy,
		Signer: o.Signer, Scope: manifest.ExeScopeMachine,
		Detect:    manifest.ExeDetect{DisplayName: o.DisplayName, DisplayVersion: in.ARPVersion(), ProductCode: in.ARPKey(), Publisher: o.Publisher},
		Uninstall: manifest.ExeUninstall{QuietUninstall: quietUninstallKnown(in)}}
	return e, nil
}

// ARPKey is the Apps & features registry key name the installer creates
// (winget ProductCode for EXE installers, e.g. "Microsoft EdgeWebView" or a
// Burn bundle's {GUID}), when the manifest states one in a usable form.
func (in WingetInstaller) ARPKey() string {
	cands := []string{in.ProductCode}
	for _, a := range in.ARP {
		cands = append(cands, a.ProductCode)
	}
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if c != "" && exeARPKeyRe.MatchString(c) {
			if productRe.MatchString(c) {
				return strings.ToUpper(c)
			}
			return c
		}
	}
	return ""
}

// quietUninstallKnown: Burn bundles always register a QuietUninstallString
// ("<cache>\bundle.exe /uninstall /quiet"); Inno Setup registers one
// (unins000.exe /SILENT) for every machine install. NSIS and plain EXE
// installers may not, so rollback is unsupported for them.
func quietUninstallKnown(in WingetInstaller) bool {
	switch in.InstallerType {
	case manifest.ExeTypeBurn, manifest.ExeTypeInno:
		return true
	}
	return false
}
