package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/intel"
	"offpatch/internal/store"
)

type importableRow struct {
	Kind             string `json:"kind"`
	Key              string `json:"key"`
	AppID            string `json:"app_id"`
	Importable       string `json:"importable"`
	ImportableReason string `json:"importable_reason"`
}

// GET /api/updates, /api/fleet/status and /api/endpoints/{id}/updates carry
// the Library's importable verdict per row (intel.Importable with the
// fleet's architectures), and a request for a "no" row is refused with the
// reason (400, nothing exported).
func TestImportableOnFleetRows(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("pc-imp-01", []string{"pilot"}, agent.SimConfig{})
	if _, err := e.st.Checkin(context.Background(), a.id, store.CheckinRequest{Hostname: "pc-imp-01", OSVersion: "Windows 11 Pro 21H2 (22000.2538)", Build: 22000, Arch: "x64",
		AgentVersion: "0.9.0", Inventory: []store.InventoryItem{
			{Kind: "kb", ID: "KB5031358"},
			{Kind: "product", ID: "Microsoft EdgeWebView", Name: "Microsoft Edge WebView2 Runtime", Version: "154.0.4258.62"},
			{Kind: "product", ID: "Microsoft Visual Studio Code", Name: "Microsoft Visual Studio Code (User)", Version: "1.141.0"},
			{Kind: "product", ID: "{C0FFEE00-0000-0000-0000-000000000001}", Name: "Contoso Unresolved", Version: "1.0"},
		}}); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 64)
	gen := time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	e.dropIntel(intel.Doc{Source: "acq-zone-1", GeneratedAt: gen,
		Windows: []intel.WindowsRelease{{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", KB: "KB5044280", Title: "2024-10 Cumulative Update (KB5044280)"}},
		Apps: []intel.App{
			{ID: "Microsoft.EdgeWebView2Runtime", Name: "Microsoft Edge WebView2 Runtime", Version: "155.0.4283.62", Codes: []string{"microsoft edgewebview"}, Names: []string{"microsoftedgewebview2runtime"}},
			{ID: "Microsoft.VisualStudioCode", Name: "Microsoft Visual Studio Code", Version: "1.142.0", Codes: []string{"microsoft visual studio code"}},
			{ID: "Contoso.Unresolved", Name: "Contoso Unresolved", Version: "2.0", Codes: []string{"{c0ffee00-0000-0000-0000-000000000001}"}},
		},
		Resolved: []intel.Resolved{
			{ID: "Microsoft.EdgeWebView2Runtime", Version: "155.0.4283.62", ResolvedAt: gen, Installers: []intel.ResolvedInstaller{
				{Arch: "x64", Type: "exe", Scope: "user", URL: "https://x/wv2.exe", SHA256: sha, Silent: true},
				{Arch: "x64", Type: "exe", Scope: "machine", URL: "https://x/wv2.exe", SHA256: sha, Silent: true}}},
			{ID: "Microsoft.VisualStudioCode", Version: "1.142.0", ResolvedAt: gen, Installers: []intel.ResolvedInstaller{
				{Arch: "x64", Type: "inno", Scope: "user", URL: "https://x/code-user.exe", SHA256: sha}}},
		}}, e.priv, "intel-imp")

	want := map[string][2]string{
		"KB5044280":                     {"yes", "Windows cumulative update (Microsoft Update Catalog)"},
		"Microsoft.EdgeWebView2Runtime": {"yes", "EXE installer (exe)"},
		"Microsoft.VisualStudioCode":    {"no", "installs per user only"},
		"Contoso.Unresolved":            {"unknown", "installer details not resolved yet"},
	}
	check := func(what string, rows []importableRow) {
		t.Helper()
		got := map[string]importableRow{}
		for _, r := range rows {
			k := r.Key
			if k == "" {
				k = r.AppID
			}
			got[k] = r
		}
		for k, w := range want {
			r, ok := got[k]
			if !ok {
				if what == "endpoint" && k == "KB5044280" {
					continue // OS rows of the endpoint view carry no verdict
				}
				t.Errorf("%s: no row for %s in %+v", what, k, rows)
				continue
			}
			if r.Importable != w[0] || !strings.HasPrefix(r.ImportableReason, w[1]) {
				t.Errorf("%s %s: %s %q, want %s %q", what, k, r.Importable, r.ImportableReason, w[0], w[1])
			}
		}
	}
	var up struct {
		Updates []importableRow `json:"updates"`
	}
	if c := e.api("GET", "/api/updates", tokViewer, nil, &up); c != 200 {
		t.Fatalf("updates: %d", c)
	}
	check("updates", up.Updates)
	var fs struct {
		Rows []importableRow `json:"rows"`
	}
	if c := e.api("GET", "/api/fleet/status", tokViewer, nil, &fs); c != 200 {
		t.Fatalf("fleet status: %d", c)
	}
	check("fleet status", fs.Rows)
	var ep struct {
		Apps []importableRow `json:"apps"`
	}
	if c := e.api("GET", "/api/endpoints/"+a.id+"/updates", tokViewer, nil, &ep); c != 200 {
		t.Fatalf("endpoint updates: %d", c)
	}
	check("endpoint", ep.Apps)

	// Requests: the "no" row is refused with its reason; the others export.
	if c, msg := e.apiErr("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"Microsoft.VisualStudioCode", "Microsoft.EdgeWebView2Runtime"}}); c != 400 ||
		msg != "can't import: Microsoft.VisualStudioCode: installs per user only" {
		t.Errorf("refusal: %d %q", c, msg)
	}
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"Microsoft.EdgeWebView2Runtime", "Contoso.Unresolved"}, "kbs": []string{"KB5044280"}}, nil); c != 200 {
		t.Errorf("importable and unknown rows: %d", c)
	}
}
