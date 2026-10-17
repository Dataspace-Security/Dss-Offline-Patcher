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

// The real Chrome installer downloaded by the demo, if present.
func TestPkgVersionRealChrome(t *testing.T) {
	p := "../../demo/acq/auto/downloads/GoogleChrome-156.0.8078.36.pkg"
	if _, err := os.Stat(p); err != nil {
		t.Skip("demo Chrome pkg not present")
	}
	v, err := PkgVersion(p, "com.google.Chrome")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GoogleChrome.pkg labelled 156 really contains Chrome %s", v)
	if v == "156.0.8078.36" {
		t.Fatal("expected the mislabelled pkg to contain an older build")
	}
}
