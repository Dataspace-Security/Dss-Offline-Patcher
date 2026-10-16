package acquire

import (
	"context"
	"reflect"
	"testing"

	"offpatch/internal/acquire/acquiretest"
)

func TestParseCVRF(t *testing.T) {
	list, err := ParseCVRF(fixture(t, "cvrf-2026-Oct.json"))
	if err != nil {
		t.Fatal(err)
	}
	// "Release Notes" (Edge) is not a KB and must be ignored.
	if len(list) != 1 {
		t.Fatalf("got %d updates: %+v", len(list), list)
	}
	u := list[0]
	if u.KB != "KB5126657" || u.Severity != "critical" {
		t.Fatalf("u = %+v", u)
	}
	if want := []string{"CVE-2026-100201", "CVE-2026-100202"}; !reflect.DeepEqual(u.CVEs, want) {
		t.Fatalf("cves = %v", u.CVEs)
	}
	wantProducts := []string{
		"Windows 10 Version 21H2 for 32-bit Systems",
		"Windows 10 Version 22H2 for 32-bit Systems",
		"Windows 10 Version 22H2 for ARM64-based Systems",
		"Windows 10 Version 22H2 for x64-based Systems",
	}
	if !reflect.DeepEqual(u.Products, wantProducts) {
		t.Fatalf("products = %v", u.Products)
	}
	if !reflect.DeepEqual(u.Supersedes, []string{"KB5122878"}) {
		t.Fatalf("supersedes = %v", u.Supersedes)
	}
	s, ok := u.ForProduct("Windows 10 Version 22H2", "x64")
	if !ok || !reflect.DeepEqual(s.Products, []string{"Windows 10 Version 22H2 for x64-based Systems"}) || s.Severity != "critical" || len(s.CVEs) != 2 {
		t.Fatalf("ForProduct x64 = %+v", s)
	}
	s, ok = u.ForProduct("Windows 10 Version 22H2", "x86")
	if !ok || len(s.Products) != 1 || s.Products[0] != "Windows 10 Version 22H2 for 32-bit Systems" {
		t.Fatalf("ForProduct x86 = %+v", s)
	}
	if _, ok := u.ForProduct("Windows Server 2022", ""); ok {
		t.Fatal("unexpected product match")
	}
}

// Severity is per product: a CVE rated Critical only for another product
// must not raise this product's severity.
func TestParseCVRFPerProductSeverity(t *testing.T) {
	doc := `{"ProductTree":{"FullProductName":[{"ProductID":"1","Value":"Prod A x64"},{"ProductID":"2","Value":"Prod B x64"}]},
	 "Vulnerability":[
	  {"CVE":"CVE-1","Threats":[{"Type":3,"Description":{"Value":"Critical"},"ProductID":["2"]},{"Type":3,"Description":{"Value":"Moderate"},"ProductID":["1"]}],
	   "Remediations":[{"Type":2,"Description":{"Value":"5000001"},"ProductID":["1","2"]}]},
	  {"CVE":"CVE-2","Threats":[{"Type":3,"Description":{"Value":"Low"},"ProductID":["1"]}],
	   "Remediations":[{"Type":2,"Description":{"Value":"5000001"},"ProductID":["1"]},{"Type":2,"Description":{"Value":null},"ProductID":["1"]}]}]}`
	list, err := ParseCVRF([]byte(doc))
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %+v", err, list)
	}
	if list[0].Severity != "critical" {
		t.Fatalf("overall = %s", list[0].Severity)
	}
	a, _ := list[0].ForProduct("Prod A", "")
	if a.Severity != "moderate" || !reflect.DeepEqual(a.CVEs, []string{"CVE-1", "CVE-2"}) {
		t.Fatalf("Prod A = %+v", a)
	}
}

func TestMSRCClient(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(1))
	m := &MSRC{BaseURL: srv.URL, HTTP: srv.Client()}
	list, err := m.Month(context.Background(), "2026-Oct")
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	if srv.MSRCAccept != "application/json" {
		t.Fatalf("Accept = %q", srv.MSRCAccept)
	}
	for _, bad := range []string{"2026-10", "Oct-2026", "2026-oct", "../x"} {
		if _, err := m.Month(context.Background(), bad); err == nil {
			t.Errorf("month %q accepted", bad)
		}
	}
}
