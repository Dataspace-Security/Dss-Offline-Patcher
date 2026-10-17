package acquire

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Builds real component and product .pkg files with Apple's tools (macOS
// only) and checks the version read back matches.
func TestPkgVersion(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("pkgbuild/productbuild only on macOS")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root", "Fake.app", "Contents")
	os.MkdirAll(root, 0o755)
	os.WriteFile(filepath.Join(root, "Info.plist"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.fake</string>
<key>CFBundleShortVersionString</key><string>155.0.8059.85</string><key>CFBundleVersion</key><string>8059.85</string></dict></plist>`), 0o644)
	comp := filepath.Join(dir, "comp.pkg")
	if out, err := exec.Command("pkgbuild", "--root", filepath.Join(dir, "root"), "--identifier", "com.example.fake.pkg", "--version", "7.7.7",
		"--install-location", "/Applications", comp).CombinedOutput(); err != nil {
		t.Fatalf("pkgbuild: %v %s", err, out)
	}
	if v, err := PkgVersion(comp, ""); err != nil || v != "7.7.7" {
		t.Fatalf("component pkg version: %q %v", v, err)
	}
	prod := filepath.Join(dir, "product.pkg")
	if out, err := exec.Command("productbuild", "--package", comp, prod).CombinedOutput(); err != nil {
		t.Fatalf("productbuild: %v %s", err, out)
	}
	if v, err := PkgVersion(prod, "com.example.fake"); err != nil || v != "155.0.8059.85" {
		t.Fatalf("product pkg app version: %q %v", v, err)
	}
	if v, err := PkgVersion(prod, ""); err != nil || v != "7.7.7" {
		t.Fatalf("product pkg component version: %q %v", v, err)
	}
	if _, err := PkgVersion(filepath.Join(dir, "root", "Fake.app", "Contents", "Info.plist"), ""); err == nil {
		t.Fatal("non-pkg accepted")
	}
}

// Real vendor installers downloaded by the demo, if present: Edge (bzip2
// metadata), Node.js (leading "v").
func TestPkgVersionRealInstallers(t *testing.T) {
	dl := "../../demo/acq/auto/downloads/"
	for _, c := range []struct{ file, id, want string }{
		{"MicrosoftEdge-155.0.4283.62.pkg", "com.microsoft.edgemac", "155.0.4283.62"},
		{"node-v24.22.0.pkg", "org.nodejs.node.pkg", "24.22.0"},
	} {
		if _, err := os.Stat(dl + c.file); err != nil {
			continue
		}
		if v, err := PkgVersion(dl+c.file, c.id); err != nil || v != c.want {
			t.Errorf("%s: got %q %v, want %s", c.file, v, err, c.want)
		}
	}
}
