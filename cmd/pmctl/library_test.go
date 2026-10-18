package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire/acquiretest"
	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/msi/msitest"
)

const edgeCode = "{6E669770-C655-388E-835E-C146C8EC6A2E}"

// serveEdge serves the recorded Microsoft.Edge manifests (which state no
// ProductCode) and, as the x64 installer, a synthetic MSI carrying Edge's
// real ProductCode, with the manifest's SHA-256 updated to match.
func serveEdge(t *testing.T, srv *acquiretest.Server) {
	t.Helper()
	const dir = "m/Microsoft/Edge/155.0.4283.62/"
	wingetFixtures(t, srv, dir+"Microsoft.Edge.installer.yaml", dir+"Microsoft.Edge.locale.en-US.yaml")
	const name = "dl/MicrosoftEdgeEnterpriseX64.msi"
	old := sha256.Sum256(srv.Vendor[name])
	body := msitest.MSI([][2]string{{"ProductCode", edgeCode}, {"ProductName", "Microsoft Edge"}, {"ProductVersion", "155.0.4283.62"}},
		msitest.Options{SectorSize: 4096})
	sum := sha256.Sum256(body)
	srv.Vendor[name] = body
	m := "manifests/" + dir + "Microsoft.Edge.installer.yaml"
	srv.Vendor[m] = []byte(strings.Replace(string(srv.Vendor[m]), strings.ToUpper(hex.EncodeToString(old[:])), strings.ToUpper(hex.EncodeToString(sum[:])), 1))
}

// Microsoft.Edge's winget manifest has no ProductCode: pmctl reads it from
// the downloaded MSI on any OS (no Windows Installer API), so a request for
// Edge with no endpoint having it installed (a Library import, arch from
// the console) becomes an MSI package.
func TestRequestReadsProductCodeFromMSI(t *testing.T) {
	e, reqDir := requestEnv(t)
	serveEdge(t, e.srv)
	writeRequest(t, reqDir, "acq-request-edge.json", acqrequest.Request{
		Apps: []acqrequest.App{{WingetID: "Microsoft.Edge", Version: "155.0.4283.62", Architectures: []string{"x64"}, Endpoints: 0}},
	})
	rep := runRequests(t, e)
	checkItems(t, rep.Items, "acq-request-edge", map[string][2]string{"Microsoft.Edge": {"fetched", ""}})
	if !rep.Sent || !slices.Contains(rep.New, "Microsoft.Edge-155.0.4283.62") {
		t.Fatalf("run: %+v", rep)
	}
	var pkg *manifest.Package
	for _, m := range e.bundles() {
		for i := range m.Packages {
			if m.Packages[i].PackageID == "Microsoft.Edge-155.0.4283.62" {
				pkg = &m.Packages[i]
			}
		}
	}
	if pkg == nil || pkg.Kind != "msi" || pkg.ProductCode != edgeCode || pkg.Applicability.Arch != "x64" || pkg.Vendor != "Microsoft Corporation" && pkg.Vendor != "Microsoft" {
		t.Fatalf("Edge package: %+v", pkg)
	}
	if st := e.state(); st.Requested["Microsoft.Edge"] != "2026-10-17T08:00:00Z" {
		t.Errorf("requested id not recorded: %v", st.Requested)
	}
}

func TestResolveLibrary(t *testing.T) {
	srv := acquiretest.New(t, "../../internal/acquire/testdata", acquiretest.Payload(1000))
	serveEdge(t, srv)
	wingetFixtures(t, srv, "g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml",
		"m/Microsoft/VisualStudioCode/1.142.0/Microsoft.VisualStudioCode.installer.yaml")
	apps := []intel.App{
		{ID: "Microsoft.Edge", Version: "155.0.4283.62"},
		{ID: "Google.Chrome", Version: "155.0.8059.85"},
		{ID: "Microsoft.VisualStudioCode", Version: "1.142.0"},
		{ID: "Contoso.NoManifest", Version: "1.0"},
	}
	ids := libraryIDs([]string{"Google.Chrome", "not an id"}, map[string]string{"Microsoft.Edge": "2026-10-01T00:00:00Z", "Contoso.Unknown": "2026-10-02T00:00:00Z"},
		[]string{"Microsoft.VisualStudioCode", "google.chrome", "Contoso.NoManifest", "Contoso.NotInIndex"})
	var got []string
	for _, li := range ids {
		got = append(got, li.id+"/"+li.why)
	}
	want := []string{"Google.Chrome/configured", "Contoso.Unknown/requested", "Microsoft.Edge/requested",
		"Microsoft.VisualStudioCode/common", "Contoso.NoManifest/common", "Contoso.NotInIndex/common"}
	if !slices.Equal(got, want) {
		t.Fatalf("ids: %v", got)
	}
	now := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	base := srv.URL + "/vendor/manifests"
	// A stale cache entry (older version) is dropped; budget 2 leaves 2 for later.
	cache := map[string]intel.Resolved{"Google.Chrome@150.0": {ID: "Google.Chrome", Version: "150.0"}}
	res := resolveLibrary(context.Background(), srv.Client(), base, apps, ids, cache, 2, now)
	if res.lookedUp != 2 || res.deferred != 2 || len(res.resolved) != 2 || res.importable != 2 {
		t.Fatalf("run 1: looked %d deferred %d resolved %+v", res.lookedUp, res.deferred, res.resolved)
	}
	if _, stale := res.cache["Google.Chrome@150.0"]; stale {
		t.Error("stale cache entry kept")
	}
	if w := strings.Join(res.warnings, "\n"); !strings.Contains(w, "Contoso.Unknown (requested): not in the winget index") || strings.Contains(w, "NotInIndex") {
		t.Errorf("warnings: %v", res.warnings)
	}
	// Next run: cached entries are reused, the rest looked up; a missing
	// manifest is a warning and stays unresolved (retried later).
	res = resolveLibrary(context.Background(), srv.Client(), base, apps, ids, res.cache, 300, now)
	// VS Code's machine-wide Inno installer is importable (kind exe).
	if res.lookedUp != 2 || res.deferred != 0 || len(res.resolved) != 3 || res.importable != 3 {
		t.Fatalf("run 2: looked %d deferred %d resolved %+v", res.lookedUp, res.deferred, res.resolved)
	}
	if !strings.Contains(strings.Join(res.warnings, "\n"), "Contoso.NoManifest 1.0 (common): no winget manifest yet") {
		t.Errorf("warnings: %v", res.warnings)
	}
	var edge intel.Resolved
	for _, r := range res.resolved {
		if r.ID == "Microsoft.Edge" {
			edge = r
		}
	}
	if edge.Publisher != "Microsoft Corporation" || edge.Homepage != "https://www.microsoft.com/en-us/edge" || len(edge.Installers) != 3 || edge.ResolvedAt != "2026-10-18T07:00:00Z" {
		t.Errorf("edge: %+v", edge)
	}
	if s := res.summary(); !strings.Contains(s, "3 packages (3 importable)") {
		t.Errorf("summary: %s", s)
	}
}

func TestBackfillRequested(t *testing.T) {
	dir := t.TempDir()
	writeRequest(t, filepath.Join(dir, "done"), "acq-request-old.json", acqrequest.Request{
		Apps: []acqrequest.App{{WingetID: "7zip.7zip", Version: "26.04", Architectures: []string{"x64"}, Endpoints: 1}}})
	os.WriteFile(filepath.Join(dir, "done", "junk.json"), []byte("{"), 0o640)
	st, _ := loadState(filepath.Join(dir, "nostate.json"))
	backfillRequested(st, dir)
	if st.Requested["7zip.7zip"] == "" || len(st.Requested) != 1 {
		t.Fatalf("backfill: %v", st.Requested)
	}
	// Only once: later runs rely on recordRequested.
	writeRequest(t, filepath.Join(dir, "done"), "acq-request-new.json", acqrequest.Request{
		Apps: []acqrequest.App{{WingetID: "Google.Chrome", Version: "1.0", Architectures: []string{"x64"}, Endpoints: 1}}})
	backfillRequested(st, dir)
	if len(st.Requested) != 1 {
		t.Fatalf("backfill ran twice: %v", st.Requested)
	}
}

func TestCommonLibraryIDsValid(t *testing.T) {
	if n := len(commonLibrary); n < 150 || n > 300 {
		t.Errorf("common library lists %d ids, want 150-300", n)
	}
	seen := map[string]bool{}
	for _, id := range commonLibrary {
		k := strings.ToLower(id)
		if !acqrequest.ValidWingetID(id) || seen[k] {
			t.Errorf("common library id %q invalid or duplicated", id)
		}
		seen[k] = true
	}
}

func TestLoadConfigWingetID(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "acquire.json")
	cfg := func(id string) string {
		return fmt.Sprintf(`{"work_dir": "w", "key": "k", "apps": [{"name": "acme", "title": "Acme", "vendor": "Acme", "kind": "msi",
		  "product_code": "{11111111-2222-3333-4444-555555555555}", "version": {"url": "https://x/v", "regex": "v"},
		  "download_url": "https://x/d", "sha256": {"url": "https://x/s"}, "winget_id": %q}], "intel": {"library": ["Google.Chrome"]}}`, id)
	}
	os.WriteFile(p, []byte(cfg("Acme.Agent")), 0o600)
	c, err := loadAutoConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := configuredLibraryIDs(c); !slices.Equal(got, []string{"Google.Chrome", "Acme.Agent"}) {
		t.Errorf("configured ids: %v", got)
	}
	os.WriteFile(p, []byte(cfg("../evil")), 0o600)
	if _, err := loadAutoConfig(p); err == nil {
		t.Error("bad winget_id accepted")
	}
}
