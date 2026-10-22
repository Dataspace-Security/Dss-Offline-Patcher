package agent

import (
	"context"
	"testing"

	"offpatch/internal/manifest"
)

func TestInstallDirFrom(t *testing.T) {
	for _, c := range []struct{ loc, icon, un, want string }{
		{`C:\Program Files\Acme\`, "", "", `C:\Program Files\Acme`},
		{`"D:\Apps\Acme"`, "", "", `D:\Apps\Acme`},
		{"", `"C:\Program Files (x86)\Foo\foo.exe",0`, "", `C:\Program Files (x86)\Foo`},
		{"", `C:\Tools\Bar\bar.ico`, "", `C:\Tools\Bar`},
		{"", "", `"C:\Program Files\Baz\uninst.exe" /S`, `C:\Program Files\Baz`},
		{"", "", `MsiExec.exe /X{11111111-2222-3333-4444-555555555555}`, ""},
		{`relative\dir`, "", "", ""},
		{"", "", "", ""},
	} {
		if got := installDirFrom(c.loc, c.icon, c.un); got != c.want {
			t.Errorf("installDirFrom(%q,%q,%q) = %q, want %q", c.loc, c.icon, c.un, got, c.want)
		}
	}
}

func TestServiceExe(t *testing.T) {
	for in, want := range map[string]string{
		`"C:\Program Files\Acme\svc.exe" -k run`: `C:\Program Files\Acme\svc.exe`,
		`C:\Acme\svc.exe /service`:               `C:\Acme\svc.exe`,
		`C:\WINDOWS\system32\svchost.exe -k netsvcs`: `C:\WINDOWS\system32\svchost.exe`,
		`\SystemRoot\System32\drivers\x.sys`:     "",
	} {
		if got := serviceExe(in); got != want {
			t.Errorf("serviceExe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeAppDir(t *testing.T) {
	trees := []string{`C:\Windows`, `C:\offpatch`, `C:\ProgramData\offpatch`}
	exact := []string{`C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`, `C:\Users`}
	for dir, want := range map[string]bool{
		`C:\Program Files\Acme`:          true,
		`D:\Apps\Acme`:                   true,
		`C:\`:                            false,
		`C:\Program Files`:               false,
		`C:\Windows\System32`:            false,
		`C:\Windows`:                     false,
		`C:\offpatch`:                    false, // the agent's own folder
		`C:\ProgramData\offpatch\x`:      false,
		`C:\Users`:                       false,
		`C:\Users\aadesh`:                false, // a profile
		`C:\Users\aadesh\AppData\Local\X`: true,
		`C:\ProgramData`:                 false,
	} {
		if got := safeAppDir(dir, trees, exact); got != want {
			t.Errorf("safeAppDir(%q) = %v, want %v", dir, got, want)
		}
	}
}

func TestUnderAnyDir(t *testing.T) {
	dirs := []string{`C:\Program Files\Acme`}
	if !underAnyDir(`c:\program files\acme\bin\a.exe`, dirs) || underAnyDir(`C:\Program Files\AcmeTools\a.exe`, dirs) {
		t.Fatal("underAnyDir")
	}
}

func TestQuiesceKindAndFlag(t *testing.T) {
	if !quiesceKind(manifest.Package{Kind: "msi"}) || quiesceKind(manifest.Package{Kind: "msu"}) ||
		quiesceKind(manifest.Package{Kind: manifest.KindExe, Exe: &manifest.ExeInstall{Scope: manifest.ExeScopeUser}}) {
		t.Fatal("quiesceKind")
	}
	if closeAppsAllowed(context.Background()) || !closeAppsAllowed(withCloseApps(context.Background(), true)) {
		t.Fatal("close apps flag")
	}
	if n := quiesceNote([]string{"AcmeSvc"}, []string{"AcmeSvc"}, nil, []string{"acme.exe"}); n !=
		"stopped service(s) AcmeSvc during the update; started again: AcmeSvc; closed open app(s): acme.exe" {
		t.Fatal(n)
	}
}
