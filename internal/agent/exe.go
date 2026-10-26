package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// EXE-kind packages (plain exe, Inno Setup, NSIS, WiX Burn) are vendor
// installers run silently with an argv taken from the signed manifest. The
// pure helpers here (exit codes, argv quoting, QuietUninstallString parsing,
// signer and inventory matching) are shared by the Windows platform and the
// simulator, and are tested on every OS.

const (
	// exeRollbackUnsupported: the manifest does not promise a quiet uninstall.
	exeRollbackUnsupported = "rollback not supported for this EXE package"
	// sigCheckFailed prefixes Authenticode failures. "possible tampering"
	// makes the server treat it as critical, like a hash mismatch.
	sigCheckFailed  = "signature check failed: "
	sigTampering    = " — possible tampering"
	burnLogHeader   = "\nburn log (last lines):\n"
	maxExeArgs      = 32
	maxExeArgLen    = 256
	maxCmdLineChars = 2048
)

// classifyExe maps an EXE installer (or QuietUninstallString) exit code.
// 3010/1641 always mean "done, restart needed" (also when the manifest lists
// them as success codes: winget's rebootRequired responses are folded into
// success_codes). busy_codes, and for Burn bundles the Windows Installer
// "another install is running" code, take the retry-later path.
func classifyExe(e *manifest.ExeInstall, code int, uninstall bool) Result {
	u := uint32(code)
	verb, noun := "installed", "installer"
	if uninstall {
		verb, noun = "uninstalled", "uninstaller"
	}
	switch {
	case u == exitRebootRequired || u == exitRebootInitiated || u == exitHRRebootRequired:
		return Result{State: "pending_reboot", ExitCode: code, Detail: verb + "; reboot required"}
	case u == exitOK || codeIn(u, e.SuccessCodes):
		return Result{State: "installed", ExitCode: code, Detail: fmt.Sprintf("exe %s (exit code %d)", verb, code)}
	case codeIn(u, e.BusyCodes) || (e.InstallerType == manifest.ExeTypeBurn && installerBusy(u)):
		return Result{State: "failed", ExitCode: code, Detail: fmt.Sprintf("%s (the installer reported another installation in progress or the app in use, 0x%08X)", retryLater, u)}
	}
	return Result{State: "failed", ExitCode: code, Detail: fmt.Sprintf("%s exit code %d (0x%08X)", noun, code, u)}
}

func codeIn(u uint32, codes []int) bool {
	for _, c := range codes {
		if uint32(c) == u {
			return true
		}
	}
	return false
}

// exeArgs returns the installer arguments from the signed manifest after
// re-checking them (the manifest validator already does; the agent runs
// them as SYSTEM, so it does not rely on that alone).
func exeArgs(e *manifest.ExeInstall) ([]string, error) {
	if e == nil {
		return nil, errors.New("exe package without an exe block")
	}
	if len(e.SilentArgs) == 0 {
		return nil, errors.New("no silent arguments: refusing to run an interactive installer")
	}
	if len(e.SilentArgs) > maxExeArgs {
		return nil, fmt.Errorf("too many installer arguments (%d)", len(e.SilentArgs))
	}
	out := make([]string, 0, len(e.SilentArgs))
	for _, a := range e.SilentArgs {
		if a == "" || len(a) > maxExeArgLen || strings.ContainsRune(a, '"') || strings.ContainsFunc(a, unicode.IsControl) {
			return nil, fmt.Errorf("invalid installer argument %q", a)
		}
		out = append(out, a)
	}
	return out, nil
}

// quoteArg quotes one argument so that CommandLineToArgvW (and the C
// runtime) reads it back unchanged; the same rules as syscall.EscapeArg.
func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes+1))
			slashes = 0
		default:
			slashes = 0
		}
		b.WriteByte(c)
	}
	b.WriteString(strings.Repeat(`\`, slashes)) // before the closing quote
	b.WriteByte('"')
	return b.String()
}

// buildCmdLine is the exact command line the installer receives. The
// program is always quoted (CreateProcess must not guess where a path with
// spaces ends); there is no shell, so nothing else is interpreted.
func buildCmdLine(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, `"`+exe+`"`)
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

// splitCommandLine parses a Windows command line with CommandLineToArgvW
// semantics: the program name ends at the first space/tab outside quotes
// (no backslash escapes in it); later arguments follow the 2n / 2n+1
// backslash rules and "" inside quotes yields a literal quote and closes
// the quoted part.
func splitCommandLine(s string) []string {
	var args []string
	i := 0
	// argv[0]
	var b strings.Builder
	inQ := false
	for ; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQ = !inQ
			continue
		}
		if !inQ && (c == ' ' || c == '\t') {
			break
		}
		b.WriteByte(c)
	}
	args = append(args, b.String())
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			return args
		}
		b.Reset()
		inQ = false
		for i < len(s) {
			c := s[i]
			if !inQ && (c == ' ' || c == '\t') {
				break
			}
			if c == '\\' {
				n := 0
				for i < len(s) && s[i] == '\\' {
					n++
					i++
				}
				if i < len(s) && s[i] == '"' {
					b.WriteString(strings.Repeat(`\`, n/2))
					if n%2 == 1 {
						b.WriteByte('"')
						i++
					}
					continue
				}
				b.WriteString(strings.Repeat(`\`, n))
				continue
			}
			if c == '"' {
				if inQ && i+1 < len(s) && s[i+1] == '"' {
					// "" inside quotes: a literal quote, and (as in
					// CommandLineToArgvW) the quoted part ends.
					b.WriteByte('"')
					inQ = false
					i += 2
					continue
				}
				inQ = !inQ
				i++
				continue
			}
			b.WriteByte(c)
			i++
		}
		args = append(args, b.String())
	}
}

// shellHosts would interpret their arguments as script or code; a
// QuietUninstallString that needs one is refused.
var shellHosts = map[string]bool{
	"cmd.exe": true, "command.com": true, "powershell.exe": true, "pwsh.exe": true,
	"wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "rundll32.exe": true,
	"bash.exe": true, "wsl.exe": true, "conhost.exe": true, "start.exe": true,
}

var drivePathRe = regexp.MustCompile(`^[A-Za-z]:\\`)

// quietUninstall validates an ARP QuietUninstallString and returns the
// executable to run (bound as the application name, so CreateProcess never
// searches for it) and the parsed argv. The original string is passed as
// the command line unchanged. Refused: anything that would need cmd.exe
// (shell operators, %VAR%, a shell or script host), relative or network
// executables other than msiexec, and unquoted paths with spaces.
func quietUninstall(cmdline, system32 string) (exe string, argv []string, err error) {
	s := strings.TrimSpace(cmdline)
	switch {
	case s == "":
		return "", nil, errors.New("empty QuietUninstallString")
	case len(s) > maxCmdLineChars:
		return "", nil, errors.New("QuietUninstallString too long")
	case strings.ContainsFunc(s, unicode.IsControl):
		return "", nil, errors.New("QuietUninstallString contains control characters")
	case strings.Contains(s, "%"):
		return "", nil, errors.New("QuietUninstallString uses environment variables, which only cmd.exe expands")
	}
	if op := shellOperator(s); op != 0 {
		return "", nil, fmt.Errorf("QuietUninstallString uses the shell operator %q, which needs cmd.exe", op)
	}
	argv = splitCommandLine(s)
	prog := argv[0]
	base := strings.ToLower(winBase(prog))
	if shellHosts[base] || shellHosts[base+".exe"] {
		return "", nil, fmt.Errorf("QuietUninstallString runs %s; refusing to run a shell or script host", base)
	}
	if !strings.HasSuffix(base, ".exe") {
		if base == "msiexec" {
			return filepath.Join(system32, "msiexec.exe"), argv, nil
		}
		if !strings.HasPrefix(s, `"`) && strings.Contains(strings.ToLower(s), ".exe") {
			return "", nil, errors.New("QuietUninstallString has an unquoted program path with spaces (ambiguous)")
		}
		return "", nil, fmt.Errorf("QuietUninstallString program %q is not an .exe", prog)
	}
	if base == "msiexec.exe" && !strings.ContainsAny(prog, `\/:`) {
		return filepath.Join(system32, "msiexec.exe"), argv, nil
	}
	if !drivePathRe.MatchString(prog) {
		return "", nil, fmt.Errorf("QuietUninstallString program %q is not an absolute local path", prog)
	}
	return prog, argv, nil
}

// shellOperator returns the first cmd.exe operator outside double quotes.
func shellOperator(s string) byte {
	inQ := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			inQ = !inQ
		case !inQ && strings.IndexByte("&|<>^", c) >= 0:
			return c
		}
	}
	return 0
}

// isMsiexec reports whether exe is Windows Installer (its exit codes follow
// the msiexec rules: 1605 = not installed).
func isMsiexec(exe string) bool {
	return strings.EqualFold(winBase(exe), "msiexec.exe")
}

// winBase is the last element of a Windows path on any OS.
func winBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

var spaceRun = regexp.MustCompile(`\s+`)

func normSigner(s string) string {
	return strings.ToLower(spaceRun.ReplaceAllString(strings.TrimSpace(s), " "))
}

// signerMatches compares the manifest signer (the Authenticode subject CN
// pmctl verified) with the file's signer certificate subject: CN, or O when
// the certificate has no CN. Case and repeated spaces are ignored; nothing
// else (no substring match: "Microsoft" must not accept "Microsoft Fake Ltd").
func signerMatches(want, cn, org string) bool {
	w := normSigner(want)
	if w == "" {
		return false
	}
	if c := normSigner(cn); c != "" {
		return c == w
	}
	return normSigner(org) != "" && normSigner(org) == w
}

// archTag extracts the architecture an app name mentions, so that name
// matching never confuses the x86 and x64 builds of one product (the VC++
// redistributables differ only by that).
var archTagRe = regexp.MustCompile(`(?i)\b(x64|x86|amd64|arm64|64-bit|32-bit|ia64)\b`)

func archTag(name string) string {
	m := archTagRe.FindString(name)
	switch strings.ToLower(m) {
	case "x64", "amd64", "64-bit":
		return "x64"
	case "x86", "32-bit":
		return "x86"
	}
	return strings.ToLower(m)
}

// exeDetect is the package's detection block, via the one shared fallback
// rule (manifest.DetectFor) internal/store and internal/server/updates.go
// also use, so none of the three can drift out of sync with the others.
func exeDetect(p manifest.Package) manifest.ExeDetect {
	return manifest.DetectFor(p.Exe, p.PackageName)
}

// exeAppMatch reports whether an inventory item is the app an EXE package
// installs, with the server's rule (internal/store/exe.go): by ARP key
// (detect.product_code) when known, as long as the architectures the names
// (or the item's registry view) mention agree (both Notepad++ builds use
// the key "Notepad++"); else by display name (store.SameAppName) with a
// compatible architecture: a name without one ("7-Zip") matches either.
// A machine-wide package counts per-machine entries only, a per-user
// installer (exe.scope user) per-user entries only.
func exeAppMatch(p manifest.Package, it store.InventoryItem) bool {
	if p.Kind != manifest.KindExe || it.Kind != "product" || (it.Scope == "user") != perUserExe(p) {
		return false
	}
	d := exeDetect(p)
	if d.ProductCode != "" && strings.EqualFold(it.ID, d.ProductCode) {
		return strings.TrimSpace(it.Name) == "" || strings.TrimSpace(d.DisplayName) == "" || itemArchOK(it.Name, it.View, d.DisplayName)
	}
	return arpNameMatch(d.DisplayName, it.Name, it.View)
}

// arpNameMatch: an Apps & features name (from registry view, "" if
// unknown) is the app named want.
func arpNameMatch(want, name, view string) bool {
	if strings.TrimSpace(want) == "" || strings.TrimSpace(name) == "" {
		return false
	}
	return store.SameAppName(name, want) && itemArchOK(name, view, want)
}

// itemArchOK: the architecture an installed entry's name (or registry
// view: "32" is a 32-bit app, "64" is not) mentions is compatible with the
// package name's; a name without one matches either (the server's
// archCompatible / itemArchCompatible).
func itemArchOK(name, view, want string) bool {
	tn, tw := archTag(name), archTag(want)
	if tn != "" && tw != "" {
		return tn == tw
	}
	if tw == "" || tn != "" {
		return true
	}
	switch view {
	case "32":
		return tw == "x86"
	case "64":
		return tw != "x86"
	}
	return true
}

// exeWantVersion is the version the app reports once the package is
// installed: detect.display_version when known, else the package version.
func exeWantVersion(p manifest.Package) string {
	if p.Exe != nil && p.Exe.Detect.DisplayVersion != "" {
		return p.Exe.Detect.DisplayVersion
	}
	return p.Version
}

// exeUpToDate: the app is installed at (at least) the package's version. An
// entry without a DisplayVersion cannot prove that, so the installer runs.
// Mirrors the server's exePresent (internal/store/exe.go) exactly: if this
// diverged, the agent could skip installing (and so never attempt it) for a
// package the server can never independently verify as present, leaving the
// target stuck "installed · confirming by inventory" forever.
func exeUpToDate(p manifest.Package, it store.InventoryItem) bool {
	if !exeAppMatch(p, it) {
		return false
	}
	want := exeWantVersion(p)
	return want != "" && it.Version != "" && store.VersionAtLeast(it.Version, want)
}

// newestLog returns the most recently written *.log directly in dir ("" if
// none). Burn writes its bundle log to %TEMP%, which the agent points at a
// private folder per run.
func newestLog(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best, bestT := "", int64(0)
	for _, e := range ents {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".log") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if t := fi.ModTime().UnixNano(); best == "" || t > bestT {
			best, bestT = filepath.Join(dir, e.Name()), t
		}
	}
	return best
}

// withLogTail appends the meaningful end of a log to a failed result (not
// to retry-later results, whose detail the server compares across retries).
func withLogTail(r Result, logPath, header string) Result {
	if r.State != "failed" || logPath == "" || strings.HasPrefix(r.Detail, retryLater) {
		return r
	}
	if tail := logTailWith(logPath, header); tail != "" {
		r.Detail += header + tail
	}
	return r
}

// withBurnLog: for a failed Burn bundle, the tail of its newest log in dir.
func withBurnLog(r Result, e *manifest.ExeInstall, dir string) Result {
	if e == nil || e.InstallerType != manifest.ExeTypeBurn {
		return r
	}
	return withLogTail(r, newestLog(dir), burnLogHeader)
}

// signatureCheck verifies the Authenticode signature (verify: WinVerifyTrust
// on Windows) and that the manifest's signer signed it: the primary signer
// or a nested signature's (pmctl records whichever signature it verified;
// dual-signed installers carry the publisher in both).
func signatureCheck(path, want string, verify func(string) error) error {
	if strings.TrimSpace(want) == "" {
		return errors.New("the manifest names no signer")
	}
	if err := verify(path); err != nil {
		return err
	}
	signers, err := peSigners(path)
	if err != nil {
		return err
	}
	for _, s := range signers {
		if signerMatches(want, s[0], s[1]) {
			return nil
		}
	}
	got := signers[0][0]
	if got == "" {
		got = signers[0][1]
	}
	return fmt.Errorf("signed by %q, expected %q", got, want)
}

// sigFailure is the failed result for a signature problem.
func sigFailure(err error) Result {
	return Result{State: "failed", ExitCode: -1, Detail: sigCheckFailed + err.Error() + sigTampering}
}

// arpEntry is one Apps & features (Uninstall key) entry.
type arpEntry struct {
	View           string // registry view: "64" or "32"
	Key            string
	DisplayName    string
	DisplayVersion string
	QuietUninstall string
}

// chooseARPEntry picks the entry an EXE package installed: the ARP key
// (detect.product_code) first; else the display name, preferring the
// package's version, then an entry that registers a quiet uninstall.
func chooseARPEntry(p manifest.Package, entries []arpEntry) (arpEntry, bool) {
	if p.Exe == nil {
		return arpEntry{}, false
	}
	d := exeDetect(p)
	if d.ProductCode != "" {
		for _, e := range entries {
			if strings.EqualFold(e.Key, d.ProductCode) {
				return e, true
			}
		}
	}
	var named []arpEntry
	for _, e := range entries {
		if arpNameMatch(d.DisplayName, e.DisplayName, e.View) {
			named = append(named, e)
		}
	}
	if len(named) == 0 {
		return arpEntry{}, false
	}
	want := exeWantVersion(p)
	for _, e := range named {
		if want != "" && e.DisplayVersion == want {
			return e, true
		}
	}
	for _, e := range named {
		if e.QuietUninstall != "" {
			return e, true
		}
	}
	return named[0], true
}
