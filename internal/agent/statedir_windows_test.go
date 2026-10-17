//go:build windows

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestTrustedOwner(t *testing.T) {
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	users, _ := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	self, err := processUserSID()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		owner, self *windows.SID
		want        bool
	}{
		{"SYSTEM", system, system, true},
		{"Administrators", admins, system, true},
		{"standard user while agent is SYSTEM", self, system, self.Equals(system)},
		{"Users group", users, system, false},
		{"own account", self, self, true},
		{"nil owner", nil, self, false},
	}
	for _, c := range cases {
		if got := trustedOwner(c.owner, c.self); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestSecureStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "offpatch")
	if err := SecureStateDir(dir); err != nil {
		t.Fatal(err)
	}
	// The DACL is protected: no inherited entries (e.g. Users) remain.
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if ctl, _, _ := sd.Control(); ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL not protected")
	}
	if s := sd.String(); strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;WD)") || strings.Contains(s, ";;;AU)") {
		t.Fatalf("users still have access: %s", s)
	}
	// Still usable by the account running the agent; idempotent.
	if err := os.WriteFile(filepath.Join(dir, "agent.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SecureStateDir(dir); err != nil {
		t.Fatal(err)
	}
}

func TestSecureStateDirRefusesJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	os.Mkdir(target, 0o700)
	link := filepath.Join(base, "offpatch")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	err := SecureStateDir(link)
	if err == nil || !strings.Contains(err.Error(), "junction") {
		t.Fatalf("junction must be refused: %v", err)
	}
}

// The registry-based collection must work on a real Windows host.
func TestWindowsNativeCollection(t *testing.T) {
	w := &Windows{LogDir: t.TempDir()}
	f, err := w.Facts()
	if err != nil || f.Build < 10000 || f.Edition == "" || f.Arch == "" {
		t.Fatalf("facts: %+v %v", f, err)
	}
	prods, err := msiProducts()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range prods {
		// MSI products by upper-case product code; EXE-installed apps by key
		// name, and only those with a display name.
		if productKeyRe.MatchString(p.ID) && p.ID != strings.ToUpper(p.ID) {
			t.Fatalf("product code not upper-case: %q", p.ID)
		}
		if !productKeyRe.MatchString(p.ID) && strings.TrimSpace(p.Name) == "" {
			t.Fatalf("EXE app %q without a display name", p.ID)
		}
	}
	if testing.Short() {
		return // the WMI query below takes seconds to minutes
	}
	inv, reboot, err := w.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	kbs := 0
	for _, it := range inv {
		if it.Kind == "kb" {
			kbs++
		}
	}
	t.Logf("facts %+v, %d MSI products, %d KBs, reboot pending %v", f, len(prods), kbs, reboot)
}
