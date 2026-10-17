package store

import "testing"

func TestSameAppName(t *testing.T) {
	cases := []struct {
		installed, pkg string
		want           bool
	}{
		{"Google Chrome", "Google Chrome", true},
		{"google chrome ", "Google Chrome", true},
		{"7-Zip 26.03 (x64 edition)", "7-Zip", true},
		{"Mozilla Firefox (x64 en-US)", "Mozilla Firefox (x64 en-US)", true},
		{"Mozilla Firefox ESR (x64 en-US)", "Mozilla Firefox", false},
		{"Notepad++ (64-bit x64)", "Notepad++", true},
		{"Zoom Workplace", "Zoom", false},
		{"R", "R 4.4", false}, // too short to match loosely
	}
	for _, c := range cases {
		if got := SameAppName(c.installed, c.pkg); got != c.want {
			t.Errorf("SameAppName(%q, %q) = %v", c.installed, c.pkg, got)
		}
	}
}

// An MSI that keeps its product code across versions (Chrome) is present
// only at the same or a newer version.
func TestPresentInMSIVersion(t *testing.T) {
	p := Package{Kind: "msi", ProductCode: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", PackageName: "Google Chrome", Version: "155.0.8059.85"}
	p.Applicability.OS, p.Applicability.Arch = "windows", "x64"
	old := []InventoryItem{{Kind: "product", ID: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.82"}}
	if ok, _ := presentIn(old, p, nil); ok {
		t.Fatal("older version under the same product code counted as installed")
	}
	cur := []InventoryItem{{Kind: "product", ID: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.85"}}
	if ok, _ := presentIn(cur, p, nil); !ok {
		t.Fatal("same version not counted as installed")
	}
	if need, from, _ := needs(p, Endpoint{OS: "windows", Arch: "x64"}, old, nil); !need || from != "155.0.8059.82" {
		t.Fatalf("needs: %v %q", need, from)
	}
}
