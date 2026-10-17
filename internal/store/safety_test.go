package store

import (
	"strings"
	"testing"
)

func TestRollbackSupport(t *testing.T) {
	for _, c := range []struct {
		p  Package
		ok bool
	}{
		{Package{Kind: "msu", KB: "KB5001"}, true},
		{Package{Kind: "msu"}, false},
		{Package{Kind: "msi", ProductCode: "{X}"}, true},
		{Package{Kind: "deb", PackageName: "openssl"}, true},
		{Package{Kind: "rpm"}, false},
		{Package{Kind: "pkg", PackageName: "com.acme.app"}, false},
		{Package{Kind: "agent"}, false},
	} {
		if got := RollbackUnsupported(c.p) == ""; got != c.ok {
			t.Errorf("%+v: supported=%v want %v (%q)", c.p, got, c.ok, RollbackUnsupported(c.p))
		}
	}
	if !strings.Contains(RollbackUnsupported(Package{Kind: "pkg"}), "no uninstall") {
		t.Error("pkg reason should say there is no uninstall")
	}
}

func TestRollbackPresent(t *testing.T) {
	inv := []InventoryItem{{Kind: "kb", ID: "KB5001"}, {Kind: "pkg", ID: "openssl", Version: "3.0.13-1"}, {Kind: "product", ID: "{AAA}"}}
	cases := []struct {
		p    Package
		want bool
	}{
		{Package{Kind: "msu", KB: "kb5001"}, true},
		{Package{Kind: "msu", KB: "KB5002"}, false},
		{Package{Kind: "msi", ProductCode: "{aaa}"}, true},
		{Package{Kind: "deb", PackageName: "openssl", Version: "3.0.13-1"}, true},
		{Package{Kind: "deb", PackageName: "openssl", Version: "3.0.12-1"}, false}, // a newer version is installed
		{Package{Kind: "deb", PackageName: "curl", Version: "8.0"}, false},
	}
	for _, c := range cases {
		if got, why := rollbackPresent(inv, c.p); got != c.want {
			t.Errorf("%+v: got %v (%s)", c.p, got, why)
		}
	}
}
