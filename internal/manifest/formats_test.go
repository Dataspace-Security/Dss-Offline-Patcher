package manifest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func archiveManifest(t *testing.T) *Manifest {
	t.Helper()
	m := exeManifest(t)
	p := &m.Packages[0]
	p.PackageID, p.Title, p.PackageName = "Adobe.Acrobat.Pro-25.001", "Adobe Acrobat", "Adobe Acrobat (64-bit)"
	p.File = FileRef{Name: "payload/Adobe.Acrobat.Pro-25.001.zip", Size: 100, SHA256: strings.Repeat("c", 64)}
	p.Exe.InstallerType, p.Exe.SilentArgs, p.Exe.Signer = ExeTypeExe, []string{"/sAll", "/rs", "/msi", "EULA_ACCEPT=YES"}, "Adobe Inc."
	p.Exe.Detect = ExeDetect{DisplayName: "Adobe Acrobat (64-bit)", DisplayVersion: "25.001.20531"}
	p.Archive = &Archive{Format: ArchiveFormatZip, Entry: "Adobe Acrobat/setup.exe", Files: []ArchiveFile{
		{Path: "Adobe Acrobat/setup.exe", Size: 10, SHA256: strings.Repeat("1", 64)},
		{Path: "Adobe Acrobat/AcroPro.msi", Size: 20, SHA256: strings.Repeat("2", 64)},
		{Path: "Adobe Acrobat/Data1.cab", Size: 30, SHA256: strings.Repeat("3", 64)},
		{Path: "Adobe Acrobat/setup.ini", Size: 1, SHA256: strings.Repeat("4", 64)},
	}}
	return m
}

func portableManifest(t *testing.T, zipped bool) *Manifest {
	t.Helper()
	m := validManifest(t)
	m.Packages[0] = Package{
		PackageID: "Rufus.Rufus-4.6", Title: "Rufus 4.6", Vendor: "Akeo", Kind: KindPortable, Version: "4.6", Severity: "important",
		PackageName: "Rufus", Applicability: Applicability{OS: "windows", Arch: "x64"},
		File:            FileRef{Name: "payload/Rufus.Rufus-4.6.exe", Size: 10, SHA256: strings.Repeat("b", 64)},
		SourceURL:       "https://github.com/pbatard/rufus/releases/download/v4.6/rufus-4.6.exe",
		VendorSignature: VendorSignature{Status: "valid", Signer: "Akeo Consulting"},
		Portable: &Portable{Folder: "Rufus.Rufus", Command: "rufus.exe", Signer: "Akeo Consulting", ARPKey: "DSSPatcher.Rufus.Rufus",
			DisplayName: "Rufus", DisplayVersion: "4.6", Publisher: "Akeo", Shortcut: "Rufus"},
	}
	if zipped {
		p := &m.Packages[0]
		p.File.Name = "payload/Rufus.Rufus-4.6.zip"
		p.Portable.Command = "rufus/rufus.exe"
		p.Archive = &Archive{Format: ArchiveFormatZip, Entry: "rufus/rufus.exe", Files: []ArchiveFile{
			{Path: "rufus/rufus.exe", Size: 10, SHA256: strings.Repeat("1", 64)},
			{Path: "rufus/README.txt", Size: 0, SHA256: strings.Repeat("e", 64)},
		}}
	}
	return m
}

func msixManifest(t *testing.T) *Manifest {
	t.Helper()
	m := validManifest(t)
	m.Packages[0] = Package{
		PackageID: "Microsoft.WindowsTerminal-1.21", Title: "Windows Terminal 1.21", Vendor: "Microsoft", Kind: KindMsix, Version: "1.21.2361.0",
		Severity: "important", PackageName: "Windows Terminal", Applicability: Applicability{OS: "windows", Arch: "any"},
		File:            FileRef{Name: "payload/Microsoft.WindowsTerminal-1.21.msixbundle", Size: 10, SHA256: strings.Repeat("b", 64)},
		SourceURL:       "https://github.com/microsoft/terminal/releases/download/v1.21.2361.0/x.msixbundle",
		VendorSignature: VendorSignature{Status: "not_checked"},
		Msix: &Msix{PackageFamilyName: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Name: "Microsoft.WindowsTerminal",
			Publisher: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", Version: "1.21.2361.0", Bundle: true},
	}
	return m
}

func TestFormatManifestsValidAndRoundTrip(t *testing.T) {
	for name, m := range map[string]*Manifest{"archive": archiveManifest(t), "portable": portableManifest(t, false),
		"portable zip": portableManifest(t, true), "msix": msixManifest(t)} {
		if err := m.ValidateSchema(time.Now()); err != nil {
			t.Fatalf("%s: valid manifest rejected: %v", name, err)
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: strict parse: %v", name, err)
		}
		if !reflect.DeepEqual(back.Packages[0], m.Packages[0]) {
			t.Fatalf("%s: round trip mismatch", name)
		}
		if g := back.Packages[0].FormatGeneration(); g != 2 {
			t.Fatalf("%s: generation %d, want 2", name, g)
		}
	}
}

func TestFormatManifestRejections(t *testing.T) {
	cases := map[string]struct {
		mk  func(*testing.T) *Manifest
		mut func(p *Package)
	}{
		"archive on msu":              {archiveManifest, func(p *Package) { p.Kind = "msu"; p.Exe = nil }},
		"archive not zip":             {archiveManifest, func(p *Package) { p.Archive.Format = "7z" }},
		"archive payload not .zip":    {archiveManifest, func(p *Package) { p.File.Name = "payload/a.exe" }},
		"archive entry missing":       {archiveManifest, func(p *Package) { p.Archive.Entry = "Adobe Acrobat/other.exe" }},
		"archive entry wrong case":    {archiveManifest, func(p *Package) { p.Archive.Entry = "adobe acrobat/setup.exe" }},
		"archive entry not exe":       {archiveManifest, func(p *Package) { p.Archive.Entry = "Adobe Acrobat/AcroPro.msi" }},
		"archive dotdot":              {archiveManifest, func(p *Package) { p.Archive.Files[1].Path = "../evil.dll" }},
		"archive absolute":            {archiveManifest, func(p *Package) { p.Archive.Files[1].Path = "/evil.dll" }},
		"archive backslash":           {archiveManifest, func(p *Package) { p.Archive.Files[1].Path = `Adobe Acrobat\x.dll` }},
		"archive drive":               {archiveManifest, func(p *Package) { p.Archive.Files[1].Path = "C:evil.dll" }},
		"archive case duplicate":      {archiveManifest, func(p *Package) { p.Archive.Files[1].Path = "adobe acrobat/SETUP.exe" }},
		"archive file as dir":         {archiveManifest, func(p *Package) { p.Archive.Files[1].Path = "Adobe Acrobat/setup.ini/x" }},
		"archive bad hash":            {archiveManifest, func(p *Package) { p.Archive.Files[2].SHA256 = "abc" }},
		"archive empty":               {archiveManifest, func(p *Package) { p.Archive.Files = nil }},
		"archive per-user":            {archiveManifest, func(p *Package) { p.Exe.Scope = ExeScopeUser }},
		"portable no block":           {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable = nil }},
		"portable folder path":        {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable.Folder = `a\b` }},
		"portable folder dotdot":      {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable.Folder = ".." }},
		"portable folder device":      {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable.Folder = "NUL" }},
		"portable no signer":          {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable.Signer = "" }},
		"portable command not exe":    {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable.Command = "rufus.bat" }},
		"portable command path":       {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable.Command = "x/rufus.exe" }},
		"portable name mismatch":      {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.PackageName = "Other" }},
		"portable zip command":        {func(t *testing.T) *Manifest { return portableManifest(t, true) }, func(p *Package) { p.Portable.Command = "rufus.exe" }},
		"portable bad arp key":        {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable.ARPKey = `a\b` }},
		"portable shortcut path":      {func(t *testing.T) *Manifest { return portableManifest(t, false) }, func(p *Package) { p.Portable.Shortcut = `..\x` }},
		"msix no block":               {msixManifest, func(p *Package) { p.Msix = nil }},
		"msix bad pfn":                {msixManifest, func(p *Package) { p.Msix.PackageFamilyName = "Microsoft.WindowsTerminal_8wekyb3d8bbwi" }},
		"msix name not pfn":           {msixManifest, func(p *Package) { p.Msix.Name = "Other.App" }},
		"msix version":                {msixManifest, func(p *Package) { p.Msix.Version = "1.21" }},
		"msix extension":              {msixManifest, func(p *Package) { p.File.Name = "payload/x.exe" }},
		"msix bundle flag":            {msixManifest, func(p *Package) { p.Msix.Bundle = false }},
		"portable block on exe":       {exeManifest, func(p *Package) { p.Portable = &Portable{} }},
		"msix block on msi":           {exeManifest, func(p *Package) { p.Msix = &Msix{} }},
		"exe single file needs .exe ": {exeManifest, func(p *Package) { p.File.Name = "payload/x.zip" }},
	}
	for name, c := range cases {
		m := c.mk(t)
		c.mut(&m.Packages[0])
		if err := m.ValidateSchema(time.Now()); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestRequiredAgentAndRollback(t *testing.T) {
	machine := &ExeInstall{Scope: ExeScopeMachine, Uninstall: ExeUninstall{QuietUninstall: true}}
	user := &ExeInstall{Scope: ExeScopeUser, Uninstall: ExeUninstall{QuietUninstall: true}}
	for _, c := range []struct {
		kind      string
		e         *ExeInstall
		a         *Archive
		ver, why  string
		rollback  bool
		generaton int
	}{
		{"msu", nil, nil, "", "", true, 0},
		{"msi", nil, nil, "", "", true, 0},
		{KindExe, machine, nil, MinAgentVersionExe, AgentTooOldForExe, true, 1},
		{KindExe, user, nil, MinAgentVersionFormats, AgentTooOldForPerUser, false, 2},
		{KindExe, machine, &Archive{}, MinAgentVersionFormats, AgentTooOldForArchive, true, 2},
		{"msi", nil, &Archive{}, MinAgentVersionFormats, AgentTooOldForArchive, true, 2},
		{KindPortable, nil, nil, MinAgentVersionFormats, AgentTooOldForPortable, true, 2},
		{KindPortable, nil, &Archive{}, MinAgentVersionFormats, AgentTooOldForPortable, true, 2},
		{KindMsix, nil, nil, MinAgentVersionFormats, AgentTooOldForMsix, false, 2},
	} {
		v, why := RequiredAgent(c.kind, c.e, c.a)
		p := Package{Kind: c.kind, Exe: c.e, Archive: c.a}
		if v != c.ver || why != c.why || p.RollbackSupported() != c.rollback || p.FormatGeneration() != c.generaton {
			t.Errorf("%s %+v: got %q %q rollback=%v gen=%d", c.kind, c.e, v, why, p.RollbackSupported(), p.FormatGeneration())
		}
	}
}
