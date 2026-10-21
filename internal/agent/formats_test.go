package agent

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func writeZip(t *testing.T, dir string, files [][2]string) (string, []manifest.ArchiveFile) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var list []manifest.ArchiveFile
	for _, f := range files {
		w, err := zw.Create(f[0])
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(f[1]))
		h := sha256.Sum256([]byte(f[1]))
		list = append(list, manifest.ArchiveFile{Path: f[0], Size: int64(len(f[1])), SHA256: hex.EncodeToString(h[:])})
	}
	zw.Close()
	p := filepath.Join(dir, "payload.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, list
}

// The agent extracts an archive package only if the zip holds exactly the
// signed list, file for file and hash for hash; unsafe names never reach
// the disk.
func TestExtractArchiveVerifies(t *testing.T) {
	files := [][2]string{{"Adobe Acrobat/setup.exe", "MZ setup"}, {"Adobe Acrobat/AcroPro.msi", "msi"}, {"Adobe Acrobat/setup.ini", "[Startup]"}}
	zp, list := writeZip(t, t.TempDir(), files)
	pkg := func(l []manifest.ArchiveFile) manifest.Package {
		return manifest.Package{Kind: manifest.KindExe, Archive: &manifest.Archive{Format: "zip", Entry: "Adobe Acrobat/setup.exe", Files: l}}
	}
	dir := t.TempDir()
	if err := extractArchive(pkg(list), zp, dir); err != nil {
		t.Fatalf("good archive: %v", err)
	}
	if b, err := os.ReadFile(archiveEntry(pkg(list), dir)); err != nil || string(b) != "MZ setup" {
		t.Fatalf("entry not extracted: %v %q", err, b)
	}
	tampered := append([]manifest.ArchiveFile{}, list...)
	tampered[1].SHA256 = strings.Repeat("0", 64)
	missing := list[:2]
	extra := append(append([]manifest.ArchiveFile{}, list...), manifest.ArchiveFile{Path: "Adobe Acrobat/other.dll", Size: 1, SHA256: strings.Repeat("1", 64)})
	resized := append([]manifest.ArchiveFile{}, list...)
	resized[2].Size++
	for name, l := range map[string][]manifest.ArchiveFile{"tampered": tampered, "unlisted file": missing, "missing file": extra, "size": resized} {
		r := func() Result {
			if err := extractArchive(pkg(l), zp, t.TempDir()); err != nil {
				return archiveFailure(err)
			}
			return Result{State: "installed"}
		}()
		if r.State != "failed" || !strings.HasPrefix(r.Detail, archiveTampered) || !strings.Contains(r.Detail, "possible tampering") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// Unsafe names: refused before anything is written.
	for _, bad := range []string{"../evil.exe", "/abs.exe", "C:/x.exe", "a/../../x.exe"} {
		d := t.TempDir()
		zp, l := writeZip(t, d, [][2]string{{"ok.txt", "x"}, {bad, "evil"}})
		out := t.TempDir()
		if err := extractArchive(pkg(l), zp, out); err == nil {
			t.Errorf("%s: extracted", bad)
		}
		if _, err := os.Stat(filepath.Join(out, "ok.txt")); err == nil {
			t.Errorf("%s: wrote files before refusing", bad)
		}
	}
}

func portablePkg(t *testing.T, dir string, zipped bool) (manifest.Package, string) {
	t.Helper()
	p := manifest.Package{PackageID: "Akeo.Rufus-4.6", Kind: manifest.KindPortable, Version: "4.6",
		Portable: &manifest.Portable{Folder: "Akeo.Rufus", Command: "rufus.exe", Signer: "Akeo", ARPKey: "DSSPatcher.Akeo.Rufus", DisplayName: "Rufus", DisplayVersion: "4.6"}}
	if zipped {
		zp, list := writeZip(t, dir, [][2]string{{"rufus/rufus.exe", "MZ rufus 4.6"}, {"rufus/lang/de.txt", "de"}})
		p.Portable.Command = "rufus/rufus.exe"
		p.Archive = &manifest.Archive{Format: "zip", Entry: "rufus/rufus.exe", Files: list}
		return p, zp
	}
	exe := filepath.Join(dir, "payload.exe")
	os.WriteFile(exe, []byte("MZ rufus 4.6"), 0o600)
	n, h, _ := manifest.HashFile(exe)
	p.File = manifest.FileRef{Name: "payload/Akeo.Rufus-4.6.exe", Size: n, SHA256: h}
	return p, exe
}

// Portable apps: the folder is staged, the program's signature checked,
// then swapped in; an update replaces the folder unless a program runs from
// it (retry later), and a bad signature or hash changes nothing.
func TestInstallPortableFiles(t *testing.T) {
	for _, zipped := range []bool{false, true} {
		parent := filepath.Join(t.TempDir(), manifest.PortableParent)
		running := ""
		var verified []string
		env := portableEnv{parent: parent, running: func(string) string { return running },
			verify: func(path, signer string) error {
				verified = append(verified, filepath.Base(path)+"/"+signer)
				return nil
			}}
		p, payload := portablePkg(t, t.TempDir(), zipped)
		dir, res := installPortableFiles(p, payload, env)
		if res != nil {
			t.Fatalf("zipped=%v: %+v", zipped, res)
		}
		main := filepath.Join(dir, filepath.FromSlash(p.Portable.Command))
		if b, err := os.ReadFile(main); err != nil || string(b) != "MZ rufus 4.6" || len(verified) != 1 || verified[0] != "rufus.exe/Akeo" {
			t.Fatalf("zipped=%v: installed %v %q, verified %v", zipped, err, b, verified)
		}
		// A stale file of the old version disappears with the old folder.
		os.WriteFile(filepath.Join(dir, "old.dll"), []byte("old"), 0o600)
		running = filepath.Join(dir, "rufus.exe")
		if _, res := installPortableFiles(p, payload, env); res == nil || !strings.HasPrefix(res.Detail, retryLater) || !strings.Contains(res.Detail, "running") {
			t.Fatalf("zipped=%v: running app replaced: %+v", zipped, res)
		}
		if _, err := os.Stat(filepath.Join(dir, "old.dll")); err != nil {
			t.Fatal("running app's folder touched")
		}
		running = ""
		if _, res := installPortableFiles(p, payload, env); res != nil {
			t.Fatalf("zipped=%v: update: %+v", zipped, res)
		}
		if _, err := os.Stat(filepath.Join(dir, "old.dll")); err == nil {
			t.Error("old folder kept")
		}
		ents, _ := os.ReadDir(parent)
		if len(ents) != 1 {
			t.Errorf("zipped=%v: leftovers in %s: %v", zipped, parent, ents)
		}
		// A signature failure leaves the installed app alone.
		env.verify = func(string, string) error { return errors.New("signed by \"Evil\"") }
		if _, res := installPortableFiles(p, payload, env); res == nil || !strings.HasPrefix(res.Detail, sigCheckFailed) {
			t.Fatalf("zipped=%v: bad signature: %+v", zipped, res)
		}
		if _, err := os.Stat(main); err != nil {
			t.Fatal("installed app removed by a failed update")
		}
	}
	// A single-exe payload that does not match the manifest is refused.
	p, payload := portablePkg(t, t.TempDir(), false)
	p.File.SHA256 = strings.Repeat("0", 64)
	env := portableEnv{parent: t.TempDir(), running: func(string) string { return "" }, verify: func(string, string) error { return nil }}
	if _, res := installPortableFiles(p, payload, env); res == nil || !strings.Contains(res.Detail, "possible tampering") {
		t.Fatalf("tampered program: %+v", res)
	}
}

func TestAggregateUserRuns(t *testing.T) {
	ok := Result{State: "installed"}
	cases := []struct {
		runs  []userRun
		state string
		has   string
	}{
		{nil, "deferred", waitingForUser},
		{[]userRun{{User: `PC\ann`, Result: ok}, {User: `PC\bob`, Skipped: true}}, "installed", `installed for PC\ann; already current for PC\bob`},
		{[]userRun{{User: `PC\ann`, Result: ok}, {User: `PC\bob`, Result: Result{State: "failed", ExitCode: 2, Detail: "installer exit code 2"}}}, "failed", `PC\bob: installer exit code 2`},
		{[]userRun{{User: `PC\ann`, Result: Result{State: "failed", Detail: retryLater + " (in use)"}}}, "failed", retryLater},
		{[]userRun{{User: `PC\ann`, Result: Result{State: "pending_reboot"}}}, "pending_reboot", "reboot required"},
	}
	for i, c := range cases {
		r := aggregateUserRuns(c.runs)
		if r.State != c.state || !strings.Contains(r.Detail, c.has) {
			t.Errorf("%d: %+v", i, r)
		}
	}
}

// Matching as the server does it (internal/store/formats.go).
func TestFormatMatching(t *testing.T) {
	p, _ := portablePkg(t, t.TempDir(), false)
	if !formatUpToDate(p, store.InventoryItem{Kind: "product", ID: "DSSPatcher.Akeo.Rufus", Name: "Rufus", Version: "4.6"}) ||
		formatUpToDate(p, store.InventoryItem{Kind: "product", ID: "DSSPatcher.Akeo.Rufus", Name: "Rufus", Version: "4.5"}) ||
		formatAppMatch(p, store.InventoryItem{Kind: "product", ID: "DSSPatcher.Akeo.Rufus", Name: "Rufus", Version: "4.6", Scope: "user"}) {
		t.Error("portable matching")
	}
	m := manifest.Package{Kind: manifest.KindMsix, Msix: &manifest.Msix{PackageFamilyName: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Version: "1.21.2361.0"}}
	if !formatUpToDate(m, store.InventoryItem{Kind: "appx", ID: "microsoft.windowsterminal_8wekyb3d8bbwe", Version: "1.21.2361.0"}) ||
		formatUpToDate(m, store.InventoryItem{Kind: "product", ID: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Version: "1.21.2361.0"}) {
		t.Error("msix matching")
	}
	u := manifest.Package{Kind: manifest.KindExe, Version: "2.1.0", Exe: &manifest.ExeInstall{Scope: manifest.ExeScopeUser, Detect: manifest.ExeDetect{DisplayName: "balenaEtcher", DisplayVersion: "2.1.0"}}}
	user := store.InventoryItem{Kind: "product", ID: "x", Name: "balenaEtcher 2.1.0", Version: "2.1.0", Scope: "user"}
	machine := user
	machine.Scope = ""
	if !exeUpToDate(u, user) || exeAppMatch(u, machine) || !userHasVersion(u, []store.InventoryItem{machine}) {
		t.Error("per-user matching")
	}
	if installSize(manifest.Package{File: manifest.FileRef{Size: 10}, Archive: &manifest.Archive{Files: []manifest.ArchiveFile{{Size: 5}, {Size: 7}}}}) != 22 {
		t.Error("installSize")
	}
}

func TestMsixHelpers(t *testing.T) {
	sig := []byte(`{"status":"Valid","subject":"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"}`)
	const msPub = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
	if err := msixSignature(sig, "Microsoft Corporation", msPub); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := msixSignature(sig, "Microsoft", msPub); err == nil {
		t.Error("substring signer accepted")
	}
	if err := msixSignature([]byte(`{"status":"NotSigned","subject":""}`), "", msPub); err == nil {
		t.Error("unsigned package accepted")
	}
	// Without a signer (acquired on Linux) the subject must be the
	// manifest's publisher: the same DN (any RDN order/case/spacing) or CN.
	for _, pub := range []string{msPub, "c=US, s=Washington, l=Redmond, o=Microsoft  Corporation, cn=microsoft corporation", "CN=Microsoft Corporation"} {
		if err := msixSignature(sig, "", pub); err != nil {
			t.Errorf("publisher %q: %v", pub, err)
		}
	}
	for _, pub := range []string{"", "  ", "CN=Contoso Ltd, O=Contoso Ltd, C=US", "CN=Microsoft", "O=Contoso"} {
		if err := msixSignature(sig, "", pub); err == nil {
			t.Errorf("publisher %q: other signer accepted", pub)
		}
	}
	if err := msixSignature([]byte(`{"status":"Valid","subject":"O=Microsoft Corporation, C=US"}`), "", "O=Microsoft Corporation"); err != nil {
		t.Errorf("O-only publisher: %v", err)
	}
	if r := classifyMsix([]byte("ok\r\n"), nil); r.State != "installed" {
		t.Errorf("ok: %+v", r)
	}
	if r := classifyMsix(nil, errors.New("powershell: exit status 1: Add-AppxProvisionedPackage : ... 0x80073D02 ...")); r.State != "failed" || !strings.HasPrefix(r.Detail, retryLater) {
		t.Errorf("in use: %+v", r)
	}
	if r := classifyMsix(nil, errors.New("error 0x80073CF3: dependency missing")); r.State != "failed" || strings.HasPrefix(r.Detail, retryLater) {
		t.Errorf("failure: %+v", r)
	}
	prov := parseProvisioned([]byte(`[{"name":"Microsoft.WindowsTerminal","version":"1.21.2361.0","publisher_id":"8wekyb3d8bbwe"},{"name":"","version":"1"}]`))
	if len(prov) != 1 || prov[0].ID != "Microsoft.WindowsTerminal_8wekyb3d8bbwe" || prov[0].Kind != "appx" {
		t.Fatalf("provisioned: %+v", prov)
	}
	installed := []store.InventoryItem{{Kind: "appx", ID: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Version: "1.20.11781.0"}, {Kind: "appx", ID: "Other_x", Version: "1.0"}}
	merged := mergeAppx(installed, prov)
	// Users keep the old build until their next sign-in: the lower version
	// is the proof, the provisioned one is reported beside it.
	if len(merged) != 2 || merged[0].Version != "1.20.11781.0" || merged[0].Provisioned != "1.21.2361.0" || installed[0].Version != "1.20.11781.0" {
		t.Fatalf("merged: %+v (installed %+v)", merged, installed)
	}
	// A provisioned build older than the users' is what new users get.
	older := mergeAppx([]store.InventoryItem{{Kind: "appx", ID: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Version: "1.22.0.0"}}, prov)
	if older[0].Version != "1.21.2361.0" || older[0].Provisioned != "" {
		t.Fatalf("older provisioned: %+v", older)
	}
	m := manifest.Package{Kind: manifest.KindMsix, Msix: &manifest.Msix{PackageFamilyName: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Version: "1.21.2361.0"}}
	if appUpToDate(m, merged) {
		t.Error("provisioned-only MSIX verified")
	}
	if d := msixProvisionedOnly(m, merged); !strings.Contains(d, "provisioned") || !strings.Contains(d, "next sign-in") || !strings.Contains(d, "1.20.11781.0") {
		t.Errorf("provisioned detail: %q", d)
	}
	if msixProvisionedOnly(m, []store.InventoryItem{{Kind: "appx", ID: m.Msix.PackageFamilyName, Version: "1.21.2361.0"}}) != "" {
		t.Error("installed MSIX reported as provisioned only")
	}
}

// Only results that change what is installed bring the next check-in
// forward: a busy ("retry later") or deferred result must not, or the
// server's installer-busy grace is spent in a few minutes.
func TestRefreshesInventory(t *testing.T) {
	busy := []Result{
		classifyMsix(nil, errors.New("0x80073D02")),
		aggregateUserRuns([]userRun{{User: `PC\ann`, Result: Result{State: "failed", Detail: retryLater + " (in use)"}}}),
		{State: "failed", ExitCode: -1, Detail: appRunning + ": C:\\x\\a.exe)"},
		{State: "deferred", Detail: waitingForUser},
	}
	for _, r := range busy {
		a := &Agent{}
		a.recheckSoon = a.recheckSoon || refreshesInventory(r)
		if a.recheckSoon || a.afterInstallWait(5*time.Minute) != 5*time.Minute {
			t.Errorf("%+v: recheck soon", r)
		}
	}
	for _, r := range []Result{{State: "installed"}, {State: "pending_reboot"}, {State: "failed", ExitCode: 1603, Detail: "fatal error"}} {
		if !refreshesInventory(r) {
			t.Errorf("%+v: no recheck", r)
		}
	}
}

// Machine-wide packages are never proven by a per-user entry, and every
// copy of the app must be current: an up-to-date second copy does not
// hide an older one.
func TestAppUpToDateAllCopies(t *testing.T) {
	msi := manifest.Package{Kind: "msi", ProductCode: "{11111111-2222-3333-4444-555555555555}", Version: "2.0"}
	cur := store.InventoryItem{Kind: "product", ID: msi.ProductCode, Name: "App", Version: "2.0"}
	user := cur
	user.Scope = "user"
	if appUpToDate(msi, []store.InventoryItem{user}) || !appUpToDate(msi, []store.InventoryItem{cur}) {
		t.Error("msi scope")
	}
	p, _ := portablePkg(t, t.TempDir(), false)
	newCopy := store.InventoryItem{Kind: "product", ID: p.Portable.ARPKey, Name: "Rufus", Version: "4.6"}
	oldCopy := store.InventoryItem{Kind: "product", ID: "Rufus", Name: "Rufus", Version: "4.1", View: "64"}
	if !appUpToDate(p, []store.InventoryItem{newCopy}) || appUpToDate(p, []store.InventoryItem{newCopy, oldCopy}) {
		t.Error("portable: old copy hidden by the new one")
	}
	exe := manifest.Package{Kind: manifest.KindExe, Version: "24.08", Exe: &manifest.ExeInstall{Detect: manifest.ExeDetect{DisplayName: "7-Zip", DisplayVersion: "24.08"}}}
	a := store.InventoryItem{Kind: "product", ID: "7-Zip", Name: "7-Zip 24.08 (x64)", Version: "24.08", View: "64"}
	b := store.InventoryItem{Kind: "product", ID: "{23170F69-40C1-2701-1900-000001000000}", Name: "7-Zip 19.00 (x64 edition)", Version: "19.00.00.0", View: "64"}
	if !appUpToDate(exe, []store.InventoryItem{a}) || appUpToDate(exe, []store.InventoryItem{a, b}) {
		t.Error("exe: old MSI copy hidden by the new EXE copy")
	}
	noVer := store.InventoryItem{Kind: "product", ID: "7-Zip-old", Name: "7-Zip", View: "64"}
	if !appUpToDate(exe, []store.InventoryItem{a, noVer}) || appUpToDate(exe, []store.InventoryItem{noVer}) {
		t.Error("exe: a copy without a version proves nothing either way")
	}
	ua := a
	ua.Scope = "user"
	if appUpToDate(exe, []store.InventoryItem{ua}) {
		t.Error("exe: per-user entry proved a machine-wide package")
	}
	m := manifest.Package{Kind: manifest.KindMsix, Msix: &manifest.Msix{PackageFamilyName: "A_x", Version: "1.0"}}
	if appUpToDate(m, []store.InventoryItem{{Kind: "appx", ID: "A_x", Version: "1.0", Scope: "user"}}) {
		t.Error("msix: per-user entry proved the package")
	}
}

// A per-user app counts as current for a user only when every entry of it
// in their hive is.
func TestUserHasVersionAllEntries(t *testing.T) {
	u := manifest.Package{Kind: manifest.KindExe, Version: "2.1.0", Exe: &manifest.ExeInstall{Scope: manifest.ExeScopeUser, Detect: manifest.ExeDetect{DisplayName: "balenaEtcher", DisplayVersion: "2.1.0"}}}
	cur := store.InventoryItem{Kind: "product", ID: "a", Name: "balenaEtcher", Version: "2.1.0"}
	old := store.InventoryItem{Kind: "product", ID: "b", Name: "balenaEtcher", Version: "1.18.0"}
	if !userHasVersion(u, []store.InventoryItem{cur}) || userHasVersion(u, []store.InventoryItem{cur, old}) || userHasVersion(u, nil) {
		t.Error("userHasVersion")
	}
	// Merged inventory: two users with the same key report the lowest; two
	// keys are both listed, and the old one keeps the package needed.
	merged := mergeUserInventory(nil, []store.InventoryItem{cur, {Kind: "product", ID: "a", Name: "balenaEtcher", Version: "1.0"}})
	if len(merged) != 1 || merged[0].Version != "1.0" || merged[0].Scope != "user" {
		t.Fatalf("merged: %+v", merged)
	}
	if appUpToDate(u, mergeUserInventory(nil, []store.InventoryItem{cur, old})) {
		t.Error("one user's current copy hid another user's old one")
	}
}

// The portable app's Apps & features UninstallString quotes the key, and
// pmagent portable-remove reads it back (also from an older unquoted entry
// whose key has spaces).
func TestPortableRemoveCommand(t *testing.T) {
	cmd := portableRemoveCommand(`C:\Program Files\DSS Patcher\pmagent.exe`, "Rufus Portable (x64)")
	args := splitCommandLine(cmd)
	if len(args) != 3 || args[0] != `C:\Program Files\DSS Patcher\pmagent.exe` || args[1] != "portable-remove" {
		t.Fatalf("split %q: %q", cmd, args)
	}
	if k, err := PortableRemoveKey(args[2:]); err != nil || k != "Rufus Portable (x64)" {
		t.Fatalf("key %q %v", k, err)
	}
	if k, err := PortableRemoveKey([]string{"Rufus", "Portable"}); err != nil || k != "Rufus Portable" {
		t.Fatalf("legacy key %q %v", k, err)
	}
	for _, bad := range [][]string{nil, {`..\Other`}, {""}, {"a\\b"}} {
		if _, err := PortableRemoveKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Leftover cleanup removes only the staging/old folders the agent makes
// for this app, never another app's folder.
func TestPortableLeftover(t *testing.T) {
	for name, want := range map[string]bool{
		".Rufus.new-0123456789abcdef": true, "Rufus.old-0123456789abcdef": true, "rufus.OLD-0123456789abcdef": true,
		"Rufus.old-tools": false, "Rufus.old-0123456789abcdeg": false, "Rufus.old-0123456789abcdef0": false,
		".Rufus.new-": false, "Rufus": false, "Rufus.Tools.old-0123456789abcdef": false, "Other.old-0123456789abcdef": false,
	} {
		if portableLeftover(name, "Rufus") != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
	parent := filepath.Join(t.TempDir(), manifest.PortableParent)
	for _, d := range []string{"Akeo.Rufus.old-tools", "Akeo.Rufus.old-0123456789abcdef", ".Akeo.Rufus.new-fedcba9876543210", "Akeo.RufusX"} {
		os.MkdirAll(filepath.Join(parent, d), 0o755)
	}
	p, payload := portablePkg(t, t.TempDir(), false)
	env := portableEnv{parent: parent, running: func(string) string { return "" }, verify: func(string, string) error { return nil }}
	if _, res := installPortableFiles(p, payload, env); res != nil {
		t.Fatal(res)
	}
	for d, want := range map[string]bool{"Akeo.Rufus.old-tools": true, "Akeo.Rufus.old-0123456789abcdef": false, ".Akeo.Rufus.new-fedcba9876543210": false, "Akeo.RufusX": true} {
		if _, err := os.Stat(filepath.Join(parent, d)); (err == nil) != want {
			t.Errorf("%s: exists=%v", d, err == nil)
		}
	}
}

// A running app is reported before anything is extracted or verified.
func TestPortableRunningCheckedFirst(t *testing.T) {
	p, payload := portablePkg(t, t.TempDir(), true)
	parent := filepath.Join(t.TempDir(), manifest.PortableParent)
	verified := false
	env := portableEnv{parent: parent, running: func(dir string) string { return filepath.Join(dir, "rufus.exe") },
		verify: func(string, string) error { verified = true; return nil }}
	if _, res := installPortableFiles(p, payload, env); res == nil || !strings.HasPrefix(res.Detail, appRunning) {
		t.Fatalf("running: %+v", res)
	}
	ents, _ := os.ReadDir(parent)
	if verified || len(ents) != 0 {
		t.Errorf("work done for a running app: verified=%v, %v", verified, ents)
	}
}

// After a cycle that ran an installer the agent checks in again soon, with
// a fresh inventory, so the server verifies the target promptly.
func TestAfterInstallWait(t *testing.T) {
	a := &Agent{}
	if w := a.afterInstallWait(5 * time.Minute); w != 5*time.Minute {
		t.Fatalf("no install: %s", w)
	}
	a.recheckSoon = true
	if w := a.afterInstallWait(5 * time.Minute); w != postInstallRecheck || a.recheckSoon {
		t.Fatalf("after install: %s %v", w, a.recheckSoon)
	}
	a.recheckSoon = true
	if w := a.afterInstallWait(5 * time.Second); w != 5*time.Second {
		t.Fatalf("shorter wait kept: %s", w)
	}
}

func TestUninstallViewAndServicingKBs(t *testing.T) {
	if uninstallView(0, "x64") != "64" || uninstallView(1, "x64") != "32" || uninstallView(0, "arm64") != "64" || uninstallView(0, "x86") != "32" {
		t.Error("uninstallView")
	}
	out := []byte(`["Package_for_KB5043080~31bf3856ad364e35~amd64~~26100.1742.1.10","Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9711.1.7",` +
		`"Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9294.1","Package_for_KB5043080~31bf3856ad364e35~amd64~~26100.1742.1.10",` +
		`"Microsoft-Windows-Foo-Package~31bf3856ad364e35~amd64~~10.0.1","Package_for_ServicingStack_9711~31bf3856ad364e35~amd64~~26100.9711.1.2",` +
		`"Package_for_KB5066128~31bf3856ad364e35~amd64~~10.0.1.0"]`)
	if got := parseServicingKBs(out); strings.Join(got, ",") != "KB5043080,KB5066128" {
		t.Errorf("servicing KBs: %v", got)
	}
	if parseServicingKBs([]byte("not json")) != nil {
		t.Error("bad output not ignored")
	}
	if got := mergeKBs([]string{"kb5031358", "KB5043080"}, []string{"KB5043080", "KB5066128"}); strings.Join(got, ",") != "KB5031358,KB5043080,KB5066128" {
		t.Errorf("merge: %v", got)
	}
}

// The agent's own matching follows the server's (internal/store/exe.go):
// an untagged detection name matches a tagged entry, an ARP key match
// still needs compatible architectures, and the registry view tells a
// 32-bit untagged entry from a 64-bit package.
func TestAgentArchMatching(t *testing.T) {
	p := func(name, key string) manifest.Package {
		return manifest.Package{Kind: manifest.KindExe, Exe: &manifest.ExeInstall{Scope: manifest.ExeScopeMachine, Detect: manifest.ExeDetect{DisplayName: name, ProductCode: key}}}
	}
	it := func(id, name, view string) store.InventoryItem {
		return store.InventoryItem{Kind: "product", ID: id, Name: name, Version: "1", View: view}
	}
	cases := []struct {
		pkg  manifest.Package
		item store.InventoryItem
		want bool
	}{
		{p("7-Zip", ""), it("7-Zip", "7-Zip 24.08 (x64)", "64"), true},
		{p("7-Zip", ""), it("7-Zip", "7-Zip 24.08", "32"), true},
		{p("7-Zip (x64)", ""), it("7-Zip", "7-Zip 24.08", "32"), false},
		{p("7-Zip (x64)", ""), it("7-Zip", "7-Zip 24.08", "64"), true},
		{p("7-Zip (x64)", ""), it("7-Zip", "7-Zip 24.08", ""), true},
		{p("7-Zip (32-bit)", ""), it("7-Zip", "7-Zip 24.08", "64"), false},
		{p("Notepad++ (64-bit x64)", "Notepad++"), it("Notepad++", "Notepad++ (32-bit x86)", "32"), false},
		{p("Notepad++ (64-bit x64)", "Notepad++"), it("Notepad++", "Notepad++ (64-bit x64)", "64"), true},
		{p("Notepad++ (64-bit x64)", "Notepad++"), it("Notepad++", "Notepad++", "32"), false},
		{p("Microsoft Visual C++ 2015-2022 Redistributable (x64)", ""), it("{X}", "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.40", ""), false},
	}
	for i, c := range cases {
		if got := exeAppMatch(c.pkg, c.item); got != c.want {
			t.Errorf("%d: %q vs %q (view %q): %v", i, c.pkg.Exe.Detect.DisplayName, c.item.Name, c.item.View, got)
		}
	}
}
