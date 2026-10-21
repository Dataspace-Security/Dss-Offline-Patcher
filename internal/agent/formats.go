package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"offpatch/internal/manifest"
	"offpatch/internal/safezip"
	"offpatch/internal/store"
)

// App formats (agent 0.10.0; internal/manifest/formats.go). The pure parts
// shared by the Windows platform and the simulator, tested on every OS:
// inventory matching (the same rules as internal/store/formats.go), the
// verified extraction of archive packages, the folder swap of portable
// apps, and the aggregation of per-user installs.

const (
	// waitingForUser is the deferred detail of a per-user installer when
	// nobody is signed in; the server keeps the target and the agent tries
	// again at later check-ins.
	waitingForUser = "waiting for the user to sign in (per-user installer)"
	// appRunning: a portable app is not replaced while it runs.
	appRunning = retryLater + " (the app is running"
	// archiveTampered prefixes extraction failures of archive packages.
	archiveTampered = "archive does not match signed manifest: "
)

// perUserExe: a per-user EXE installer (exe.scope user).
func perUserExe(p manifest.Package) bool {
	return p.Kind == manifest.KindExe && p.Exe != nil && p.Exe.Scope == manifest.ExeScopeUser
}

// portableMatch: it is the portable app p installs (per machine: the
// Uninstall key the agent writes, or a machine entry with the same name).
func portableMatch(p manifest.Package, it store.InventoryItem) bool {
	if p.Kind != manifest.KindPortable || p.Portable == nil || it.Kind != "product" || it.Scope == "user" {
		return false
	}
	return strings.EqualFold(it.ID, p.Portable.ARPKey) || arpNameMatch(p.Portable.DisplayName, it.Name, it.View)
}

// msixMatch: it is the appx package family of p (a machine-wide package:
// never a per-user entry).
func msixMatch(p manifest.Package, it store.InventoryItem) bool {
	return p.Kind == manifest.KindMsix && p.Msix != nil && it.Kind == "appx" && it.Scope != "user" && strings.EqualFold(it.ID, p.Msix.PackageFamilyName)
}

// formatWantVersion is the version a portable or MSIX package installs.
func formatWantVersion(p manifest.Package) string {
	switch {
	case p.Kind == manifest.KindMsix && p.Msix != nil:
		return p.Msix.Version
	case p.Kind == manifest.KindPortable && p.Portable != nil && p.Portable.DisplayVersion != "":
		return p.Portable.DisplayVersion
	}
	return p.Version
}

// formatAppMatch: it is the app of a portable or MSIX package.
func formatAppMatch(p manifest.Package, it store.InventoryItem) bool {
	return portableMatch(p, it) || msixMatch(p, it)
}

// formatUpToDate: a portable or MSIX app is installed at (at least) the
// package's version.
func formatUpToDate(p manifest.Package, it store.InventoryItem) bool {
	want := formatWantVersion(p)
	return formatAppMatch(p, it) && want != "" && it.Version != "" && store.VersionAtLeast(it.Version, want)
}

// msiCopy: it is the machine-wide entry of MSI package p's product code.
// A per-user entry never proves a per-machine MSI.
func msiCopy(p manifest.Package, it store.InventoryItem) bool {
	return p.ProductCode != "" && it.Kind == "product" && it.Scope != "user" && strings.EqualFold(it.ID, p.ProductCode)
}

// appCopies are the inventory entries of the app Windows package p (MSI by
// product code, EXE, portable, MSIX) installs or updates: machine-wide
// entries for a machine-wide package, per-user entries for a per-user
// installer. An app can have several (both registry views, a copy left by
// another installer, several user profiles).
func appCopies(p manifest.Package, inv []store.InventoryItem) []store.InventoryItem {
	var out []store.InventoryItem
	for _, it := range inv {
		if msiCopy(p, it) || (p.Kind == manifest.KindExe && exeAppMatch(p, it)) || formatAppMatch(p, it) {
			out = append(out, it)
		}
	}
	return out
}

// copyUpToDate: one copy of p's app is at (at least) p's version.
func copyUpToDate(p manifest.Package, it store.InventoryItem) bool {
	switch {
	case msiCopy(p, it):
		// Some MSIs keep their product code across versions (Chrome's): an
		// older version under the same code is an update.
		return p.Version == "" || it.Version == "" || store.VersionAtLeast(it.Version, p.Version)
	case p.Kind == manifest.KindExe:
		return exeUpToDate(p, it)
	}
	return formatUpToDate(p, it)
}

// appUpToDate: inventory proves Windows app package p installed: some copy
// of its app is at p's version or later and no copy with a known version
// is older (a copy without a version proves nothing either way). One
// up-to-date copy (say, the one the portable path wrote) must not hide an
// older, vulnerable MSI/EXE copy of the same app; the server decides the
// same way (internal/store appPresentOn).
func appUpToDate(p manifest.Package, inv []store.InventoryItem) bool {
	proved := false
	for _, it := range appCopies(p, inv) {
		switch {
		case copyUpToDate(p, it):
			proved = true
		case it.Version != "":
			return false
		}
	}
	return proved
}

// msixProvisionedOnly: the MSIX package is provisioned at (at least) its
// version, but users still run an older one until their next sign-in. The
// detail says so ("" when that is not the case).
func msixProvisionedOnly(p manifest.Package, inv []store.InventoryItem) string {
	want := formatWantVersion(p)
	if p.Kind != manifest.KindMsix || want == "" {
		return ""
	}
	for _, it := range inv {
		if msixMatch(p, it) && it.Provisioned != "" && store.VersionAtLeast(it.Provisioned, want) && !formatUpToDate(p, it) {
			have := it.Version
			if have == "" {
				have = "unknown version"
			}
			return fmt.Sprintf("MSIX %s already provisioned; users get it at their next sign-in (installed for users: %s)", it.Provisioned, have)
		}
	}
	return ""
}

// installSize is the disk space an install needs besides the cached
// payload: the extracted archive.
func installSize(p manifest.Package) int64 {
	return p.File.Size + p.Archive.TotalSize()
}

// extractArchive extracts the archive package at zipPath into dir (which
// the caller created, private to SYSTEM and Administrators), refusing a zip
// whose files differ in any way from the signed manifest's list.
func extractArchive(p manifest.Package, zipPath, dir string) error {
	if p.Archive == nil {
		return errors.New("package has no archive block")
	}
	if p.Archive.Format != manifest.ArchiveFormatZip {
		return fmt.Errorf("archive format %q not supported", p.Archive.Format)
	}
	if err := safezip.ExtractVerified(zipPath, dir, p.Archive.Want(), safezip.Limits{}); err != nil {
		return err
	}
	return nil
}

// archiveFailure is the failed result of an archive that does not verify:
// treated like a payload hash mismatch (possible tampering).
func archiveFailure(err error) Result {
	if errors.Is(err, safezip.ErrUnsafe) {
		return Result{State: "failed", ExitCode: -1, Detail: archiveTampered + err.Error() + sigTampering}
	}
	return Result{State: "failed", ExitCode: -1, Detail: "could not extract the archive: " + err.Error()}
}

// archiveEntry is the extracted installer's path below dir.
func archiveEntry(p manifest.Package, dir string) string {
	return filepath.Join(dir, filepath.FromSlash(p.Archive.Entry))
}

// ---- portable apps ----

// portableEnv is what installing a portable app needs from the platform.
type portableEnv struct {
	// parent is %ProgramFiles%\DSS Patcher Apps.
	parent string
	// verify checks the main program's Authenticode signature and signer.
	verify func(path, signer string) error
	// running returns a program running from below dir ("" if none).
	running func(dir string) string
}

// portableDir is the app's folder.
func portableDir(p manifest.Package, parent string) string {
	return filepath.Join(parent, p.Portable.Folder)
}

// installPortableFiles stages the verified files of portable package p
// (payload: the zip of an archive package, else the single program) next
// to the app's folder, checks the main program's signature, and swaps the
// folder in. A program running from the folder is checked first (nothing
// is extracted or verified then: retry later) and again just before the
// swap. It returns the folder.
func installPortableFiles(p manifest.Package, payload string, env portableEnv) (string, *Result) {
	fail := func(f string, a ...any) (string, *Result) {
		return "", &Result{State: "failed", ExitCode: -1, Detail: fmt.Sprintf(f, a...)}
	}
	po := p.Portable
	if po == nil || !manifest.ValidFolderName(po.Folder) {
		return fail("portable package refused: invalid folder")
	}
	if err := os.MkdirAll(env.parent, 0o755); err != nil {
		return fail("could not create %s: %v", env.parent, err)
	}
	dir := portableDir(p, env.parent)
	// A running app is not replaced: say so before any work is done.
	if prog := env.running(dir); prog != "" {
		return "", &Result{State: "failed", ExitCode: -1, Detail: appRunning + ": " + prog + ")"}
	}
	// Leftovers of an install of this app the agent did not finish (killed
	// mid-swap): only names the agent itself makes (portableLeftover), never
	// another app's folder.
	if ents, err := os.ReadDir(env.parent); err == nil {
		for _, e := range ents {
			if portableLeftover(e.Name(), po.Folder) {
				os.RemoveAll(filepath.Join(env.parent, e.Name()))
			}
		}
	}
	sfx, err := portableSuffix()
	if err != nil {
		return fail("could not stage the app: %v", err)
	}
	stage := filepath.Join(env.parent, "."+po.Folder+".new-"+sfx)
	if err := os.Mkdir(stage, 0o755); err != nil {
		return fail("could not stage the app: %v", err)
	}
	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(stage)
		}
	}()
	if p.Archive != nil {
		if err := extractArchive(p, payload, stage); err != nil {
			r := archiveFailure(err)
			return "", &r
		}
	} else {
		dst := filepath.Join(stage, po.Command)
		if filepath.Base(po.Command) != po.Command {
			return fail("portable package refused: command %q is not a file name", po.Command)
		}
		if err := copyPlain(payload, dst); err != nil {
			return fail("could not stage the app: %v", err)
		}
		if n, h, err := manifest.HashFile(dst); err != nil || n != p.File.Size || h != p.File.SHA256 {
			return fail("staged program does not match signed manifest (sha256)" + sigTampering)
		}
	}
	main := filepath.Join(stage, filepath.FromSlash(po.Command))
	if err := env.verify(main, po.Signer); err != nil {
		r := sigFailure(err)
		return "", &r
	}
	if prog := env.running(dir); prog != "" {
		return "", &Result{State: "failed", ExitCode: -1, Detail: appRunning + ": " + prog + ")"}
	}
	var old string
	if _, err := os.Stat(dir); err == nil {
		old = dir + ".old-" + sfx
		if err := os.Rename(dir, old); err != nil {
			// A file in use (an open document, a service): try again later.
			return "", &Result{State: "failed", ExitCode: -1, Detail: appRunning + ": files in " + dir + " are in use: " + err.Error() + ")"}
		}
	}
	if err := os.Rename(stage, dir); err != nil {
		if old != "" {
			os.Rename(old, dir)
		}
		return fail("could not move the app into %s: %v", dir, err)
	}
	keep = true
	if old != "" {
		os.RemoveAll(old)
	}
	return dir, nil
}

// portableSuffixLen is the length of the random suffix of the staging
// (".<folder>.new-<suffix>") and old ("<folder>.old-<suffix>") folders.
const portableSuffixLen = 16

// portableSuffix is a random lower-case hex suffix of portableSuffixLen.
func portableSuffix() (string, error) {
	b := make([]byte, portableSuffixLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// portableLeftover reports whether name (in the portable parent folder) is
// a staging or old folder of the app in folder: exactly
// ".<folder>.new-<suffix>" or "<folder>.old-<suffix>" with a suffix as
// portableSuffix makes. Another app's folder ("<folder>.old-tools", or a
// folder whose name merely starts the same) never matches.
func portableLeftover(name, folder string) bool {
	for _, pre := range []string{"." + folder + ".new-", folder + ".old-"} {
		if len(name) != len(pre)+portableSuffixLen || !strings.EqualFold(name[:len(pre)], pre) {
			continue
		}
		if strings.Trim(name[len(pre):], "0123456789abcdef") == "" {
			return true
		}
	}
	return false
}

// copyPlain copies src to a new file dst.
func copyPlain(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// dirSize is the total size of the files below dir (Apps & features'
// EstimatedSize).
func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// underDir reports whether path is dir or below it (Windows paths compare
// without case).
func underDir(path, dir string) bool {
	p, d := strings.ToLower(filepath.Clean(path)), strings.ToLower(filepath.Clean(dir))
	return p == d || strings.HasPrefix(p, d+string(filepath.Separator))
}

// arpKeyRe is the manifest's rule for Apps & features key names.
var arpKeyRe = regexp.MustCompile(`^[A-Za-z0-9{}][A-Za-z0-9{}._ +()-]{0,127}$`)

// validARPKey: a single Uninstall key name (no path separators).
func validARPKey(k string) bool { return arpKeyRe.MatchString(k) }

// portableRemoveCommand is the UninstallString of a portable app's Apps &
// features entry: the agent's own program with portable-remove and the
// key, both quoted (a key may contain spaces: "Rufus Portable").
func portableRemoveCommand(self, key string) string {
	return `"` + self + `" portable-remove "` + key + `"`
}

// PortableRemoveKey is the Apps & features key named by the arguments of
// pmagent portable-remove: one (quoted) argument, or, for an entry an
// older agent wrote without quotes, a key with spaces split into several
// arguments (joined again with single spaces). The key must be valid.
func PortableRemoveKey(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("portable-remove needs the Apps & features key")
	}
	k := strings.Join(args, " ")
	if !validARPKey(k) {
		return "", fmt.Errorf("invalid Apps & features key %q", k)
	}
	return k, nil
}

// ---- per-user installers ----

// userRun is the outcome of a per-user installer in one user's session.
type userRun struct {
	User   string // DOMAIN\user (for the detail)
	Result Result
	// Skipped: the user already has the version (nothing was run).
	Skipped bool
}

// aggregateUserRuns turns the per-user outcomes into the target's result:
// no session → deferred (waiting for the user to sign in); any failure →
// failed (a busy one: retry later); a restart needed by any → pending
// reboot; else installed.
func aggregateUserRuns(runs []userRun) Result {
	if len(runs) == 0 {
		return Result{State: "deferred", Detail: waitingForUser}
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].User < runs[j].User })
	var done, skipped, failed, busy []string
	reboot := false
	code := 0
	for _, r := range runs {
		switch {
		case r.Skipped:
			skipped = append(skipped, r.User)
		case r.Result.State == "failed" && strings.HasPrefix(r.Result.Detail, retryLater):
			busy = append(busy, r.User+": "+r.Result.Detail)
			code = r.Result.ExitCode
		case r.Result.State == "failed":
			failed = append(failed, r.User+": "+r.Result.Detail)
			code = r.Result.ExitCode
		case r.Result.State == "pending_reboot":
			reboot = true
			done = append(done, r.User)
		default:
			done = append(done, r.User)
		}
	}
	switch {
	case len(failed) > 0:
		return Result{State: "failed", ExitCode: code, Detail: "per-user install failed for " + strings.Join(failed, "; ")}
	case len(busy) > 0:
		return Result{State: "failed", ExitCode: code, Detail: retryLater + " (per-user install: " + strings.Join(busy, "; ") + ")"}
	}
	detail := "installed for " + listOrNone(done)
	if len(skipped) > 0 {
		detail += "; already current for " + strings.Join(skipped, ", ")
	}
	if reboot {
		return Result{State: "pending_reboot", ExitCode: exitRebootRequired, Detail: detail + "; reboot required"}
	}
	return Result{State: "installed", Detail: detail}
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "nobody (every signed-in user already had it)"
	}
	return strings.Join(s, ", ")
}

// userHasVersion: the user's own inventory (their HKU Uninstall entries)
// shows the per-user app, and every entry of it is at the package's
// version or later (an old second copy still needs the installer).
func userHasVersion(p manifest.Package, items []store.InventoryItem) bool {
	found := false
	for _, it := range items {
		it.Scope = "user"
		if !exeAppMatch(p, it) {
			continue
		}
		if !exeUpToDate(p, it) {
			return false
		}
		found = true
	}
	return found
}

// ---- MSIX ----

// msixSigScript reads the package signature (Get-AuthenticodeSignature
// understands MSIX/APPX); the path comes from the environment, never from
// the script text.
const msixSigScript = `$s = Get-AuthenticodeSignature -LiteralPath $env:PM_PKG; ` +
	`[pscustomobject]@{status=[string]$s.Status; subject=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress`

// msixProvisionScript provisions the package for every user of the machine
// (existing users get it at their next sign-in).
const msixProvisionScript = `$ErrorActionPreference = 'Stop'; ` +
	`Add-AppxProvisionedPackage -Online -PackagePath $env:PM_PKG -SkipLicense | Out-Null; 'ok'`

// msixSignature checks the PowerShell signature result: Valid, and by the
// manifest's signer when it names one. Without a signer (a package pmctl
// acquired on Linux, where it cannot verify signatures) the signature
// subject must be the package's own publisher (msix.publisher, the
// AppxManifest Publisher DN): the same DN, or the same CN (the same O when
// the publisher DN has no CN). With neither, the package is refused.
func msixSignature(out []byte, signer, publisher string) error {
	var r struct{ Status, Subject string }
	if err := json.Unmarshal(out, &r); err != nil {
		return fmt.Errorf("signature status unreadable: %v", err)
	}
	if !strings.EqualFold(r.Status, "Valid") {
		return fmt.Errorf("package signature status %s", r.Status)
	}
	if signer != "" {
		if cn := subjectCN(r.Subject); !signerMatches(signer, cn, subjectField(r.Subject, "O")) {
			return fmt.Errorf("signed by %q, expected %q", cn, signer)
		}
		return nil
	}
	if strings.TrimSpace(publisher) == "" {
		return errors.New("the manifest names neither a signer nor a publisher for this MSIX package")
	}
	if !publisherMatches(publisher, r.Subject) {
		return fmt.Errorf("signed by %q, expected the package publisher %q", r.Subject, publisher)
	}
	return nil
}

// publisherMatches: certificate subject is the MSIX publisher DN: the
// same RDNs (any order, case and repeated spaces ignored), or the same CN,
// or, when the publisher has no CN, the same O. No substring matches.
func publisherMatches(publisher, subject string) bool {
	if normDN(publisher) != "" && normDN(publisher) == normDN(subject) {
		return true
	}
	if cn := subjectCN(publisher); normSigner(cn) != "" {
		return normSigner(cn) == normSigner(subjectCN(subject))
	}
	o := subjectField(publisher, "O")
	return normSigner(o) != "" && normSigner(o) == normSigner(subjectField(subject, "O"))
}

// normDN is a DN in a comparable form: its RDNs as key=value with the key
// upper-case, the value without quotes and in normSigner form, sorted.
func normDN(dn string) string {
	var parts []string
	for _, rdn := range splitRDN(dn) {
		k, v, ok := strings.Cut(rdn, "=")
		if !ok {
			if strings.TrimSpace(rdn) != "" {
				return "" // not a DN
			}
			continue
		}
		parts = append(parts, strings.ToUpper(strings.TrimSpace(k))+"="+normSigner(strings.Trim(strings.TrimSpace(v), `"`)))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// subjectCN and subjectField read an RDN of an X.500 subject string.
func subjectCN(s string) string { return subjectField(s, "CN") }

func subjectField(s, key string) string {
	for _, part := range splitRDN(s) {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// splitRDN splits "CN=a, O=\"b, c\"" at commas outside quotes.
func splitRDN(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case r == ',' && !inQ:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

// MSIX deployment errors (HRESULTs as Add-AppxProvisionedPackage reports
// them in its message).
var (
	msixBusy      = []string{"0x80073D02", "0x80073D05", "0x80073CF6"} // in use / still removing / another operation
	msixInstalled = []string{"0x80073CFB"}                             // the same package is already installed
)

// classifyMsix maps the outcome of the provisioning script.
func classifyMsix(out []byte, err error) Result {
	if err == nil && strings.TrimSpace(string(out)) == "ok" {
		return Result{State: "installed", Detail: "MSIX package provisioned for all users (existing users get it at their next sign-in)"}
	}
	msg := strings.TrimSpace(string(out))
	if err != nil {
		msg = err.Error()
	}
	up := strings.ToUpper(msg)
	for _, c := range msixInstalled {
		if strings.Contains(up, strings.ToUpper(c)) {
			return Result{State: "installed", Detail: "MSIX package already provisioned (" + c + ")"}
		}
	}
	for _, c := range msixBusy {
		if strings.Contains(up, strings.ToUpper(c)) {
			return Result{State: "failed", ExitCode: -1, Detail: retryLater + " (the app is in use or another app deployment is running, " + c + ")"}
		}
	}
	if len(msg) > 600 {
		msg = msg[:600]
	}
	return Result{State: "failed", ExitCode: -1, Detail: "Add-AppxProvisionedPackage failed: " + msg}
}

// parseProvisioned turns Get-AppxProvisionedPackage output (JSON array of
// {name, version, publisher_id}) into appx inventory items: the package
// family name is <DisplayName>_<PublisherId>. Provisioned packages reach
// existing users at their next sign-in, so the provisioned version is the
// version the machine is at.
func parseProvisioned(out []byte) []store.InventoryItem {
	var raw []struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		PublisherID string `json:"publisher_id"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil
	}
	var items []store.InventoryItem
	for _, r := range raw {
		if r.Name == "" || r.PublisherID == "" {
			continue
		}
		items = append(items, store.InventoryItem{Kind: "appx", ID: r.Name + "_" + r.PublisherID, Name: r.Name, Version: r.Version, Source: "provisioned"})
	}
	return items
}

// mergeAppx merges installed (per user) and provisioned appx items: one
// item per package family. Its Version is the LOWER of the two: a
// provisioned package reaches existing users only at their next sign-in,
// and until then they run the old build, so only the lower version is
// proven. A provisioned version above the users' is kept in Provisioned,
// so the console can say "provisioned 1.22, users get it at next sign-in".
func mergeAppx(installed, provisioned []store.InventoryItem) []store.InventoryItem {
	out := append([]store.InventoryItem{}, installed...)
	idx := map[string]int{}
	for i, it := range out {
		idx[strings.ToLower(it.ID)] = i
	}
	for _, it := range provisioned {
		k := strings.ToLower(it.ID)
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, it)
			continue
		}
		cur := out[i]
		switch {
		case it.Version == "" || it.Version == cur.Version:
		case cur.Version == "":
			cur.Version = it.Version
		case store.VersionAtLeast(it.Version, cur.Version):
			cur.Provisioned = it.Version // users get it at their next sign-in
		default:
			cur.Version = it.Version // new users would get the older provisioned build
		}
		out[i] = cur
	}
	return out
}
