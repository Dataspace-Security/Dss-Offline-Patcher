package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqstatus"
	"offpatch/internal/agent"
	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

type uxRef struct {
	RequestID string `json:"request_id"`
	At        string `json:"at"`
	Status    string `json:"status"`
}

type uxFleetStatus struct {
	Intel *struct {
		GeneratedAt string `json:"generated_at"`
	} `json:"intel"`
	Rows []uxFleetRow `json:"rows"`
}

type uxFleetRow struct {
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	Catalog *struct {
		PackageID string `json:"package_id"`
	} `json:"catalog"`
	Requested    *uxRef `json:"requested"`
	UpToDate     int    `json:"up_to_date"`
	Outdated     int    `json:"outdated"`
	BeingPatched int    `json:"being_patched"`
	Verified     int    `json:"verified"`
	Failed       int    `json:"failed"`
	Exception    int    `json:"exception"`
	Endpoints    []struct {
		EndpointID string `json:"endpoint_id"`
		Status     string `json:"status"`
		Installed  string `json:"installed"`
	} `json:"endpoints"`
}

type uxTarget struct {
	EndpointID string `json:"endpoint_id"`
	State      string `json:"state"`
	Attempts   int    `json:"attempts"`
	Live       *struct {
		Stage      string `json:"stage"`
		Pct        int    `json:"pct"`
		BytesDone  int64  `json:"bytes_done"`
		BytesTotal int64  `json:"bytes_total"`
		At         string `json:"at"`
	} `json:"live"`
}

func (e *env) uxTargets(id string) map[string]uxTarget {
	e.t.Helper()
	var d struct {
		Targets []uxTarget `json:"targets"`
	}
	if c := e.api("GET", "/api/deployments/"+id, tokViewer, nil, &d); c != 200 {
		e.t.Fatalf("get deployment: %d", c)
	}
	m := map[string]uxTarget{}
	for _, t := range d.Targets {
		m[t.EndpointID] = t
	}
	return m
}

// The UX iteration's server side end to end: policy, fleet counts per
// package, missing counts per endpoint, the fleet status matrix with
// up-to-date rows, tracked acquisition requests, retry of exhausted
// targets, live progress from heartbeats and fast check-ins.
func TestUXIteration(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const chromeCode = "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}"
	checkin := func(a *simAgent, ubr int, inv ...store.InventoryItem) {
		t.Helper()
		if _, err := e.st.Checkin(ctx, a.id, store.CheckinRequest{Hostname: "h", OSVersion: "Windows 10 Pro 22H2 (19045." + itoa(int64(ubr)) + ")",
			Build: 19045, Arch: "x64", Inventory: inv}); err != nil {
			t.Fatal(err)
		}
	}
	// A: old Chrome and 7-Zip, missing the CU. B: current, has the CU. C: no Chrome, missing the CU.
	a := e.enroll("pc-ux-a", []string{"pilot"}, agent.SimConfig{})
	b := e.enroll("pc-ux-b", []string{"pilot"}, agent.SimConfig{})
	c := e.enroll("pc-ux-c", []string{"pilot"}, agent.SimConfig{})
	invA := []store.InventoryItem{{Kind: "product", ID: chromeCode, Name: "Google Chrome", Version: "155.0.8059.82"},
		{Kind: "product", ID: "{23170F69-40C1-2702-2603-000001000000}", Name: "7-Zip 26.03 (x64 edition)", Version: "26.03.00.0"}}
	checkin(a, 4000, invA...)
	checkin(b, 5000, store.InventoryItem{Kind: "kb", ID: "KB5000901"}, store.InventoryItem{Kind: "product", ID: chromeCode, Name: "Google Chrome", Version: "155.0.8059.85"})
	checkin(c, 4000)

	cu := msuPkg("KB5000901-x64", "KB5000901")
	chrome := manifest.Package{PackageID: "Google.Chrome-155.0.8059.85", Title: "Google Chrome 155.0.8059.85", Vendor: "Google", Kind: "msi",
		Version: "155.0.8059.85", ProductCode: chromeCode, PackageName: "Google Chrome", Severity: "important", ReleaseDate: "2026-10-15",
		Supersedes: []string{}, Applicability: manifest.Applicability{OS: "windows", Arch: "x64"}, VendorSignature: manifest.VendorSignature{Status: "not_checked"}}
	gen := time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	e.dropIntel(intel.Doc{Source: "acq-zone-1", GeneratedAt: gen,
		Windows: []intel.WindowsRelease{{Product: "Windows 10 Version 22H2", Build: 19045, Arch: "x64", KB: "KB5000901", UBR: 5000, Title: "2026-10 Cumulative Update (KB5000901)"}},
		Apps: []intel.App{
			{ID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Codes: []string{strings.ToLower(chromeCode)}, Names: []string{"googlechrome"}},
			{ID: "7zip.7zip", Name: "7-Zip", Version: "26.04", ARPMax: "26.04.00.0", Codes: []string{"{23170f69-40c1-2702-2603-000001000000}"}, Names: []string{"7zip"}},
		}}, e.priv, "intel-ux")

	// The operator requests the missing updates before they arrive (a package
	// that was already imported does not fulfil a later request).
	var req struct {
		RequestID string `json:"request_id"`
	}
	if code := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"Google.Chrome", "7zip.7zip"}, "kbs": []string{"KB5000901"}}, &req); code != 200 {
		t.Fatalf("export: %d", code)
	}
	if bd := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, map[string]manifest.Package{cu.PackageID: cu, chrome.PackageID: chrome},
		map[string]string{cu.PackageID: e.payload("cu.msu", "cu"), chrome.PackageID: e.payload("chrome.msi", "chrome")})); bd.State != "validated" {
		t.Fatalf("bundle %s: %v", bd.State, checksFailed(bd))
	}
	e.approve(cu.PackageID) // Chrome stays quarantined

	// ---- policy ----
	var pol struct {
		ApprovalsRequired  map[string]int    `json:"approvals_required"`
		SeparationOfDuties bool              `json:"separation_of_duties"`
		Deadlines          map[string]string `json:"deadlines"`
	}
	if code := e.api("GET", "/api/policy", tokViewer, nil, &pol); code != 200 || pol.ApprovalsRequired["critical"] != 1 || pol.SeparationOfDuties ||
		pol.Deadlines["critical"] != "168h0m0s" || pol.Deadlines["low"] != "2160h0m0s" {
		t.Fatalf("policy: %d %+v", code, pol)
	}
	if code := e.api("GET", "/api/policy", "", nil, nil); code != 401 {
		t.Fatalf("policy without auth: %d", code)
	}

	// ---- packages-needs (approved and quarantined) ----
	needs := func() map[string]store.PackageNeed {
		t.Helper()
		var n map[string]store.PackageNeed
		if code := e.api("GET", "/api/packages-needs", tokViewer, nil, &n); code != 200 {
			t.Fatalf("packages-needs: %d", code)
		}
		return n
	}
	n := needs()
	if k := n[cu.PackageID]; k.Needed != 2 || k.UpToDate != 1 || k.NotInstalled != 0 || len(k.Endpoints) != 2 {
		t.Errorf("CU needs: %+v", k)
	}
	if k := n[chrome.PackageID]; k.Needed != 1 || k.Endpoints[0] != a.id || k.UpToDate != 1 || k.NotInstalled != 1 {
		t.Errorf("Chrome needs (quarantined): %+v", k)
	}

	// ---- endpoints: missing {os, apps, ready} ----
	var eps []store.Endpoint
	if code := e.api("GET", "/api/endpoints", tokViewer, nil, &eps); code != 200 {
		t.Fatalf("endpoints: %d", code)
	}
	miss := map[string]*store.EndpointMissing{}
	for _, ep := range eps {
		miss[ep.EndpointID] = ep.Missing
	}
	if m := miss[a.id]; m == nil || *m != (store.EndpointMissing{OS: 1, Apps: 2, Ready: 1, Catalog: 2}) {
		t.Errorf("A missing: %+v", m)
	}
	if m := miss[b.id]; m == nil || *m != (store.EndpointMissing{}) {
		t.Errorf("B missing: %+v", m)
	}
	if m := miss[c.id]; m == nil || *m != (store.EndpointMissing{OS: 1, Ready: 1, Catalog: 1}) {
		t.Errorf("C missing: %+v", m)
	}
	var one store.EndpointDetail
	if code := e.api("GET", "/api/endpoints/"+a.id, tokViewer, nil, &one); code != 200 || one.Missing == nil || *one.Missing != *miss[a.id] {
		t.Errorf("endpoint detail missing: %d %+v", code, one.Missing)
	}
	// The views are cached, but an approval invalidates them at once.
	e.approve(chrome.PackageID)
	eps = nil
	e.api("GET", "/api/endpoints", tokViewer, nil, &eps)
	for _, ep := range eps {
		if ep.EndpointID == a.id && (ep.Missing == nil || ep.Missing.Ready != 2) {
			t.Errorf("A ready after approving Chrome: %+v", ep.Missing)
		}
	}

	// ---- acquisition requests: requested → seen → fulfilled ----
	reqs := func() []store.AcqRequestRecord {
		t.Helper()
		var v []store.AcqRequestRecord
		if code := e.api("GET", "/api/acquisition-requests", tokViewer, nil, &v); code != 200 {
			t.Fatalf("acquisition-requests: %d", code)
		}
		return v
	}
	items := func(r store.AcqRequestRecord) map[string]store.AcqRequestItem {
		m := map[string]store.AcqRequestItem{}
		for _, it := range r.Items {
			m[it.Key] = it
		}
		return m
	}
	rs := reqs()
	if len(rs) != 1 || rs[0].RequestID != req.RequestID || rs[0].CreatedBy != "user:otto@bank.test" || rs[0].IntelGeneratedAt != gen || rs[0].SeenAt != "" || len(rs[0].Items) != 3 {
		t.Fatalf("requests: %+v", rs)
	}
	it := items(rs[0])
	if it["Google.Chrome"].Status != "fulfilled" || it["Google.Chrome"].PackageID != chrome.PackageID || it["KB5000901"].Status != "fulfilled" ||
		it["KB5000901"].Version != "x64" || it["7zip.7zip"].Status != "requested" {
		t.Errorf("items before the acquisition zone saw it: %+v", it)
	}
	now := time.Now().UTC()
	e.dropStatus(acqstatus.Report{Source: "acq-zone-1", Host: "acq01", StartedAt: now.Add(-time.Minute).Format(time.RFC3339), FinishedAt: now.Format(time.RFC3339),
		Outcome: "ok", Failures: map[string]string{}, Feeds: []acqstatus.Feed{{Type: "request", Name: req.RequestID, Status: "new"}}}, nil)
	rs = reqs()
	if rs[0].SeenAt == "" || items(rs[0])["7zip.7zip"].Status != "seen" {
		t.Errorf("after the status report: %+v", rs[0])
	}
	var upd struct {
		Updates []struct {
			Key       string `json:"key"`
			Requested *uxRef `json:"requested"`
		} `json:"updates"`
	}
	e.api("GET", "/api/updates", tokViewer, nil, &upd)
	refs := map[string]*uxRef{}
	for _, u := range upd.Updates {
		refs[u.Key] = u.Requested
	}
	if r := refs["7zip.7zip"]; r == nil || r.Status != "seen" || r.RequestID != req.RequestID {
		t.Errorf("/api/updates requested: %+v", refs)
	}

	// ---- a deployment: A downloading, B already verified, C fails ----
	d := e.deploy(store.NewDeployment{PackageID: cu.PackageID, Name: "CU", Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}, MaxRetries: 0})
	if r := e.rawCheckinFull(c); r.NextCheckinSeconds != store.FastCheckinSeconds || len(r.Assignments) != 1 {
		t.Errorf("C check-in with work: %+v", r)
	}
	rep := func(ag *simAgent, state string) {
		t.Helper()
		if code := e.api("POST", "/api/agent/report", ag.secret, store.Report{DeploymentID: d.DeploymentID, PackageID: cu.PackageID, State: state, Detail: "x", ExitCode: 1}, nil); code != 200 {
			t.Fatalf("report %s: %d", state, code)
		}
	}
	rep(a, "downloading")
	rep(c, "failed") // max_retries 0: exhausted

	// ---- live progress ----
	hb := func(ag *simAgent, body any) int {
		t.Helper()
		return e.api("POST", "/api/agent/heartbeat", ag.secret, body, nil)
	}
	if code := hb(a, nil); code != 204 {
		t.Fatalf("heartbeat without a body (old agents): %d", code)
	}
	if code := hb(a, map[string]any{}); code != 204 {
		t.Fatalf("heartbeat {}: %d", code)
	}
	prog := map[string]any{"deployment_id": d.DeploymentID, "package_id": cu.PackageID, "stage": "downloading", "pct": 50, "bytes_done": 512, "bytes_total": 1024}
	if code := hb(a, map[string]any{"progress": prog, "future_field": true}); code != 204 {
		t.Fatalf("heartbeat with progress: %d", code)
	}
	bad := map[string]any{"deployment_id": d.DeploymentID, "package_id": cu.PackageID, "stage": "rebooting", "pct": 50}
	if code := hb(a, map[string]any{"progress": bad}); code != 400 {
		t.Fatalf("invalid stage: %d", code)
	}
	if code := hb(b, map[string]any{"progress": map[string]any{"deployment_id": "d-unknown", "package_id": cu.PackageID, "stage": "installing", "pct": -1}}); code != 204 {
		t.Fatalf("progress for another deployment: %d", code)
	}
	ts := e.uxTargets(d.DeploymentID)
	if l := ts[a.id].Live; l == nil || l.Stage != "downloading" || l.Pct != 50 || l.BytesDone != 512 || l.BytesTotal != 1024 || l.At == "" {
		t.Errorf("A live: %+v", ts[a.id])
	}
	if ts[b.id].Live != nil || ts[c.id].Live != nil || ts[b.id].State != "verified" || ts[c.id].State != "failed" {
		t.Errorf("B/C: %+v %+v", ts[b.id], ts[c.id])
	}
	if r := e.rawCheckinFull(a, invA...); r.NextCheckinSeconds != store.FastCheckinSeconds {
		t.Errorf("A downloading: next_checkin_seconds %d", r.NextCheckinSeconds)
	}

	// ---- packages-needs with targets ----
	if k := needs()[cu.PackageID]; k.Deploying != 1 || k.Verified != 1 || k.Failed != 1 || k.Exception != 0 || k.ActiveDeploymentID != d.DeploymentID {
		t.Errorf("CU fleet counts: %+v", k)
	}

	// ---- fleet status (up-to-date rows included) ----
	var fs uxFleetStatus
	if code := e.api("GET", "/api/fleet/status", tokViewer, nil, &fs); code != 200 || fs.Intel == nil || fs.Intel.GeneratedAt != gen {
		t.Fatalf("fleet status: %d %+v", code, fs)
	}
	rows := map[string]int{}
	for i, r := range fs.Rows {
		rows[r.Key] = i
	}
	for _, r := range fs.Rows {
		if r.Endpoints == nil || len(r.Endpoints) != 0 {
			t.Errorf("without ?key rows carry counts only: %+v", r)
		}
	}
	// ?key=&kind=: that one row with its endpoints.
	oneRow := func(q string, want int) uxFleetRow {
		t.Helper()
		var v uxFleetStatus
		if code := e.api("GET", "/api/fleet/status?"+q, tokViewer, nil, &v); code != want {
			t.Fatalf("fleet status ?%s: %d", q, code)
		}
		if want != 200 {
			return uxFleetRow{}
		}
		if len(v.Rows) != 1 || v.Intel == nil {
			t.Fatalf("fleet status ?%s: %+v", q, v)
		}
		return v.Rows[0]
	}
	kb := oneRow("key=KB5000901&kind=os", 200)
	if kb.Kind != "os" || kb.Catalog == nil || kb.Catalog.PackageID != cu.PackageID || kb.BeingPatched != 1 || kb.Verified != 1 || kb.Failed != 1 ||
		kb.Outdated != 0 || kb.UpToDate != 0 || kb.Requested == nil || kb.Requested.Status != "fulfilled" || len(kb.Endpoints) != 3 {
		t.Errorf("KB row: %+v", kb)
	}
	if s := fs.Rows[rows["KB5000901"]]; s.BeingPatched != kb.BeingPatched || s.Verified != kb.Verified || s.Failed != kb.Failed {
		t.Errorf("summary and detail counts differ: %+v %+v", s, kb)
	}
	ch := oneRow("key=google.chrome", 200) // case-insensitive, kind optional
	if ch.Key != "Google.Chrome" || ch.Outdated != 1 || ch.UpToDate != 1 || ch.Catalog == nil || ch.Requested == nil || ch.Requested.Status != "fulfilled" || len(ch.Endpoints) != 2 {
		t.Errorf("Chrome row: %+v", ch)
	}
	oneRow("key=Google.Chrome&kind=os", 404)
	oneRow("key=KB0&kind=os", 404)
	oneRow("key=KB5000901&kind=driver", 400)
	oneRow("kind=os", 400)
	for _, ep := range ch.Endpoints {
		if want := map[string]string{a.id: "outdated", b.id: "up_to_date"}[ep.EndpointID]; ep.Status != want {
			t.Errorf("Chrome %s: %s want %s", ep.EndpointID, ep.Status, want)
		}
	}
	if z := fs.Rows[rows["7zip.7zip"]]; z.Outdated != 1 || z.Catalog != nil || z.Requested == nil || z.Requested.Status != "seen" {
		t.Errorf("7-Zip row: %+v", z)
	}

	// ---- retry_failed ----
	if code := e.api("POST", "/api/deployments/"+d.DeploymentID+"/retry_failed", tokViewer, map[string]string{"reason": "x"}, nil); code != 403 {
		t.Fatalf("viewer retry: %d", code)
	}
	if code := e.api("POST", "/api/deployments/"+d.DeploymentID+"/retry_failed", tokOperator, map[string]string{"reason": ""}, nil); code != 400 {
		t.Fatalf("retry without reason: %d", code)
	}
	var dep store.Deployment
	if code := e.api("POST", "/api/deployments/"+d.DeploymentID+"/retry_failed", tokOperator, map[string]string{"reason": "disk cleaned"}, &dep); code != 200 ||
		dep.State != "active" || dep.Counts["pending"] != 1 || dep.Counts["failed"] != 0 {
		t.Fatalf("retry: %d %+v", code, dep)
	}
	if tc := e.uxTargets(d.DeploymentID)[c.id]; tc.State != "pending" || tc.Attempts != 0 {
		t.Errorf("C after retry: %+v", tc)
	}
	if code := e.api("POST", "/api/deployments/"+d.DeploymentID+"/retry_failed", tokOperator, map[string]string{"reason": "again"}, nil); code != 409 {
		t.Errorf("nothing left to retry: %d", code)
	}
	var audit []store.AuditEvent
	e.api("GET", "/api/audit?action=deployment.retry_failed", tokViewer, nil, &audit)
	if len(audit) != 1 || audit[0].Actor != "user:otto@bank.test" || !strings.Contains(string(audit[0].Details), c.id) || !strings.Contains(string(audit[0].Details), "disk cleaned") {
		t.Errorf("retry audit: %+v", audit)
	}

	// Leaving the live states drops the progress.
	rep(a, "installing")
	rep(a, "failed")
	if l := e.uxTargets(d.DeploymentID)[a.id].Live; l != nil {
		t.Errorf("live progress kept after failure: %+v", l)
	}
}

type checkinFull struct {
	Assignments        []store.Assignment `json:"assignments"`
	NextCheckinSeconds int                `json:"next_checkin_seconds"`
}

// rawCheckinFull checks in over the API keeping the Windows identity and
// the given inventory.
func (e *env) rawCheckinFull(a *simAgent, inv ...store.InventoryItem) checkinFull {
	e.t.Helper()
	var r checkinFull
	if inv == nil {
		inv = []store.InventoryItem{}
	}
	if c := e.api("POST", "/api/agent/checkin", a.secret, store.CheckinRequest{Hostname: "h", OSVersion: "Windows 10 Pro 22H2 (19045.4000)", Build: 19045, Arch: "x64",
		Inventory: inv}, &r); c != 200 {
		e.t.Fatalf("checkin: %d", c)
	}
	return r
}
