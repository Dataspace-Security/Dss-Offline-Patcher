package e2e

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

type updatesResp struct {
	Intel *struct {
		GeneratedAt string `json:"generated_at"`
		Apps        int    `json:"apps"`
		Windows     int    `json:"windows"`
	} `json:"intel"`
	OS []struct {
		KB           string `json:"kb"`
		InstalledUBR int    `json:"installed_ubr"`
		Catalog      *struct {
			PackageID string `json:"package_id"`
		} `json:"catalog"`
	} `json:"os"`
	Apps []struct {
		AppID            string `json:"app_id"`
		InstalledVersion string `json:"installed_version"`
		LatestVersion    string `json:"latest_version"`
		MatchedBy        string `json:"matched_by"`
	} `json:"apps"`
	Current   int `json:"current"`
	Unmatched int `json:"unmatched"`
}

func (e *env) dropIntel(d intel.Doc, priv ed25519.PrivateKey, name string) {
	e.t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	f, err := os.Create(filepath.Join(e.inbox, name+intel.FileSuffix))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := intel.Write(f, d, manifest.KeyID(pub), func(b []byte) (string, error) { return manifest.Sign(priv, b), nil }); err != nil {
		e.t.Fatal(err)
	}
	f.Close()
	e.intake.ScanOnce(context.Background())
}

// Update intelligence: signed by a trusted bundle key, newest wins, matched
// against endpoint inventory, shown per endpoint and fleet-wide.
func TestUpdateIntelligence(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("pc-intel-01", []string{"pilot"}, agent.SimConfig{})
	if _, err := e.st.Checkin(context.Background(), a.id, store.CheckinRequest{
		Hostname: "pc-intel-01", OSVersion: "Windows 11 Pro 21H2 (22000.2538)", Build: 22000, Arch: "x64",
		Inventory: []store.InventoryItem{
			{Kind: "kb", ID: "KB5031358"},
			{Kind: "product", ID: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.82"},
			{Kind: "product", ID: "VLC media player", Name: "VLC media player", Version: "3.0.24"},
			{Kind: "product", ID: "custom", Name: "In-house Tool", Version: "1.0"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	path := "/api/endpoints/" + a.id + "/updates"

	var r updatesResp
	if c := e.api("GET", path, tokViewer, nil, &r); c != 200 || r.Intel != nil || len(r.OS)+len(r.Apps) != 0 {
		t.Fatalf("before any intel: %d %+v", c, r)
	}

	gen := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	doc := intel.Doc{Source: "acq-zone-1", GeneratedAt: gen.Format(time.RFC3339),
		Windows: []intel.WindowsRelease{{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", KB: "KB5044280", Title: "2024-10 Cumulative Update for Windows 11 for x64-based Systems (KB5044280)"}},
		Apps: []intel.App{
			{ID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Codes: []string{"{0228b730-26aa-39e9-b2e1-0fc0e3ea58c8}"}, Names: []string{"googlechrome"}},
			{ID: "VideoLAN.VLC", Name: "VLC media player", Version: "3.0.24", Codes: []string{"vlc media player"}, Names: []string{"vlcmediaplayer"}},
		}}

	// Signed by a key the server does not trust: rejected, nothing shown.
	_, rogue, _ := manifest.GenerateKey()
	e.dropIntel(doc, rogue, "intel-rogue")
	if c := e.api("GET", path, tokViewer, nil, &r); c != 200 || r.Intel != nil {
		t.Fatalf("untrusted intel accepted: %+v", r)
	}
	alerts, _ := e.st.ListAlerts(context.Background(), true)
	if !hasAlert(alerts, "intel_rejected") {
		t.Fatal("no intel_rejected alert")
	}

	e.dropIntel(doc, e.priv, "intel-1")
	r = updatesResp{}
	if c := e.api("GET", path, tokViewer, nil, &r); c != 200 || r.Intel == nil || r.Intel.Apps != 2 || r.Intel.Windows != 1 {
		t.Fatalf("after intel: %d %+v", c, r)
	}
	if len(r.OS) != 1 || r.OS[0].KB != "KB5044280" || r.OS[0].InstalledUBR != 2538 || r.OS[0].Catalog != nil {
		t.Errorf("os: %+v", r.OS)
	}
	if len(r.Apps) != 1 || r.Apps[0].AppID != "Google.Chrome" || r.Apps[0].InstalledVersion != "155.0.8059.82" || r.Apps[0].MatchedBy != "product_code" {
		t.Errorf("apps: %+v", r.Apps)
	}
	if r.Current != 1 || r.Unmatched != 1 { // VLC current, in-house tool unknown
		t.Errorf("current=%d unmatched=%d", r.Current, r.Unmatched)
	}

	var fleet struct {
		Updates []struct {
			Kind      string `json:"kind"`
			Key       string `json:"key"`
			Endpoints []struct {
				Hostname string `json:"hostname"`
			} `json:"endpoints"`
		} `json:"updates"`
	}
	if c := e.api("GET", "/api/updates", tokViewer, nil, &fleet); c != 200 || len(fleet.Updates) != 2 || fleet.Updates[0].Kind != "os" ||
		fleet.Updates[1].Key != "Google.Chrome" || fleet.Updates[1].Endpoints[0].Hostname != "pc-intel-01" {
		t.Fatalf("fleet: %d %+v", c, fleet)
	}

	// Replays (not newer) and documents dated in the future are refused; a
	// newer document replaces the index.
	e.dropIntel(doc, e.priv, "intel-2-replay")
	future := doc
	future.GeneratedAt = time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	e.dropIntel(future, e.priv, "intel-2b-future")
	doc.GeneratedAt = gen.Add(24 * time.Hour).Format(time.RFC3339)
	doc.Apps[0].Version = "155.0.8059.82"
	e.dropIntel(doc, e.priv, "intel-3")
	r = updatesResp{}
	e.api("GET", path, tokViewer, nil, &r)
	if r.Intel == nil || r.Intel.GeneratedAt != doc.GeneratedAt || len(r.Apps) != 0 || r.Current != 2 {
		t.Fatalf("newer intel not applied: %+v", r)
	}
	var audit []store.AuditEvent
	e.api("GET", "/api/audit", tokViewer, nil, &audit)
	accepted, rejected := 0, 0
	for _, ev := range audit {
		switch ev.Action {
		case "intel.accepted":
			accepted++
		case "intel.rejected":
			rejected++
		}
	}
	if accepted != 2 || rejected != 3 {
		t.Errorf("audit: accepted=%d rejected=%d, want 2 and 3", accepted, rejected)
	}

	// Installing the KB clears the Windows update.
	e.st.Checkin(context.Background(), a.id, store.CheckinRequest{Hostname: "pc-intel-01", OSVersion: "Windows 11 Pro 21H2 (22000.3260)", Build: 22000, Arch: "x64",
		Inventory: []store.InventoryItem{{Kind: "kb", ID: "KB5044280"}}})
	r = updatesResp{}
	if e.api("GET", path, tokViewer, nil, &r); len(r.OS) != 0 {
		t.Errorf("installed KB still listed: %+v", r.OS)
	}
}

func hasAlert(as []store.Alert, kind string) bool {
	for _, a := range as {
		if a.Kind == kind {
			return true
		}
	}
	return false
}
