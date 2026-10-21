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
	if err := msixSignature(sig, "Microsoft Corporation"); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := msixSignature(sig, ""); err != nil {
		t.Errorf("valid without pin: %v", err)
	}
	if err := msixSignature(sig, "Microsoft"); err == nil {
		t.Error("substring signer accepted")
	}
	if err := msixSignature([]byte(`{"status":"NotSigned","subject":""}`), ""); err == nil {
		t.Error("unsigned package accepted")
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
	if len(merged) != 2 || merged[0].Version != "1.21.2361.0" || installed[0].Version != "1.20.11781.0" {
		t.Fatalf("merged: %+v (installed %+v)", merged, installed)
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
