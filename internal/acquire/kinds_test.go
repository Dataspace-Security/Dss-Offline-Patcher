package acquire

import "testing"

func TestValidateEntryLinuxKinds(t *testing.T) {
	sha := "0000000000000000000000000000000000000000000000000000000000000001"
	deb := SpecEntry{PackageID: "openssl-3.0.13", Title: "openssl", Vendor: "Debian", Kind: "deb", Version: "3.0.13-1", PackageName: "openssl",
		Severity: "important", ReleaseDate: "2026-10-01", Path: "d/openssl.deb"}
	deb.Applicability.OS, deb.Applicability.Arch = osForKind("deb", ""), "any"
	if err := ValidateEntry(deb, 10, sha); err != nil {
		t.Fatalf("deb entry: %v", err)
	}
	deb.PackageName = ""
	if err := ValidateEntry(deb, 10, sha); err == nil {
		t.Fatal("deb without package_name accepted")
	}
	if osForKind("pkg", "") != "macos" || osForKind("agent", "linux") != "linux" || osForKind("msi", "") != "windows" {
		t.Fatal("osForKind")
	}
}
