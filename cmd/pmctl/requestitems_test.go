package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acqstatus"
	"offpatch/internal/acquire"
	"offpatch/internal/acquire/acquiretest"
)

// requestEnv is newAutoEnv with acquisition requests and the recorded
// winget manifests served by the fake vendor.
func requestEnv(t *testing.T) (*autoEnv, string) {
	t.Helper()
	e := newAutoEnv(t, `"requests": "requests",`)
	wingetFixtures(t, e.srv, "g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml")
	b, _ := os.ReadFile(e.cfgPath)
	cfg := strings.Replace(string(b), `"work_dir"`, fmt.Sprintf(`"winget_manifests_url": %q, "work_dir"`, e.srv.URL+"/vendor/manifests"), 1)
	os.WriteFile(e.cfgPath, []byte(cfg), 0o600)
	return e, filepath.Join(e.dir, "requests")
}

func runRequests(t *testing.T, e *autoEnv) autoReport {
	t.Helper()
	rep, err := runAutoRequests(context.Background(), e.cfgPath, false, "", true)
	if err != nil {
		t.Fatalf("run: %v %+v", err, rep)
	}
	return rep
}

// Every requested item gets a result: KBs the catalog does not have for the
// build/arch are unsupported, a hash mismatch is failed; on the retry of
// that request the item already sent for it is already_sent (not sent
// twice), and once nothing failed the request is done and forgotten.
func TestRequestItemResults(t *testing.T) {
	e, reqDir := requestEnv(t)
	good := e.srv.Vendor["dl/googlechromestandaloneenterprise.msi"]
	e.srv.Vendor["dl/googlechromestandaloneenterprise.msi"] = []byte("tampered")
	writeRequest(t, reqDir, "acq-request-5.json", acqrequest.Request{
		Apps: []acqrequest.App{{WingetID: "Google.Chrome", Version: "155.0.8059.85", Architectures: []string{"x86"}, Endpoints: 1}},
		KBs: []acqrequest.KB{
			{KB: acquiretest.KB, Product: "Windows 10 Version 22H2", Title: acquiretest.Title, Build: 19045, Arch: "x64", Endpoints: 1},
			{KB: "KB5999999", Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", Endpoints: 1},
		},
	})
	writeRequest(t, reqDir, "acq-request-6.json", acqrequest.Request{
		KBs: []acqrequest.KB{{KB: acquiretest.KB, Product: "Windows 10 Version 1607", Build: 14393, Arch: "x86", Endpoints: 1}},
	})

	rep, _ := runAutoRequests(context.Background(), e.cfgPath, false, "", true)
	checkItems(t, rep.Items, "acq-request-5", map[string][2]string{
		"Google.Chrome": {"failed", "SHA-256 mismatch"},
		acquiretest.KB:  {"fetched", ""},
		"KB5999999":     {"unsupported", "KB5999999 not in the Microsoft Update Catalog for build 22000 x64"},
	})
	checkItems(t, rep.Items, "acq-request-6", map[string][2]string{
		acquiretest.KB: {"unsupported", acquiretest.KB + " not in the Microsoft Update Catalog for build 14393 x86"},
	})
	if !rep.Sent || !slices.Contains(rep.New, acquiretest.KB+"-x64") {
		t.Fatalf("run 1: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "acq-request-5.json")); err != nil {
		t.Fatal("request with a failed item was archived")
	}
	if _, err := os.Stat(filepath.Join(reqDir, "done", "acq-request-6.json")); err != nil {
		t.Errorf("request with only unsupported items not archived: %v", err)
	}
	st := e.state()
	if st.RequestSent["acq-request-5"][acquiretest.KB+"-x64"] == "" || st.RequestSent["acq-request-6"] != nil {
		t.Errorf("request_sent: %v", st.RequestSent)
	}

	// The retry: the KB sent for this request is not sent again; Chrome now
	// verifies and is fetched.
	e.srv.Vendor["dl/googlechromestandaloneenterprise.msi"] = good
	rep = runRequests(t, e)
	checkItems(t, rep.Items, "acq-request-5", map[string][2]string{
		"Google.Chrome": {"fetched", ""},
		acquiretest.KB:  {"already_sent", "sent for this request in bundle b-"},
		"KB5999999":     {"unsupported", "KB5999999 not in"},
	})
	if len(rep.New) != 1 || rep.New[0] != "Google.Chrome-155.0.8059.85-x86" || rep.Skipped != 1 || len(rep.Failures) != 0 {
		t.Fatalf("retry: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "done", "acq-request-5.json")); err != nil {
		t.Errorf("request not archived: %v", err)
	}
	if st := e.state(); len(st.RequestSent) != 0 {
		t.Errorf("request_sent not cleared once the request is done: %v", st.RequestSent)
	}
}

// A requested item is sent again although state.json says the regular
// Microsoft feed sent it in an earlier run, and is fetched only once when
// the feed brings it in the same run.
func TestRequestResendsAlreadySent(t *testing.T) {
	e, reqDir := requestEnv(t)
	rep := e.run() // Microsoft feed + configured app
	id := acquiretest.KB + "-x64"
	if !slices.Contains(rep.New, id) || !rep.Sent {
		t.Fatalf("run 1: %+v", rep)
	}
	first := e.state().Done[id].BundleID

	req := acqrequest.Request{KBs: []acqrequest.KB{{KB: acquiretest.KB, Product: "Windows 10 Version 22H2", Title: acquiretest.Title, Build: 19045, Arch: "x64", Endpoints: 1}}}
	writeRequest(t, reqDir, "acq-request-7.json", req)
	rep = runRequests(t, e)
	if !rep.Sent || len(rep.New) != 1 || rep.New[0] != id || rep.Skipped != 0 {
		t.Fatalf("explicit request not re-sent: %+v", rep)
	}
	checkItems(t, rep.Items, "acq-request-7", map[string][2]string{acquiretest.KB: {"fetched", ""}})
	if again := e.state().Done[id].BundleID; again == first || !slices.Contains(rep.Bundles, again) {
		t.Errorf("state.json still points at the first bundle: %s (bundles %v)", again, rep.Bundles)
	}

	// Full run with the request present: the feed (already sent, skipped)
	// and the request (sent again) share one download of the KB.
	writeRequest(t, reqDir, "acq-request-8.json", req)
	rep = e.run()
	if n := strings.Count(strings.Join(rep.New, ","), id); n != 1 || !rep.Sent {
		t.Fatalf("full run: %+v", rep)
	}
	checkItems(t, rep.Items, "acq-request-8", map[string][2]string{acquiretest.KB: {"fetched", ""}})
}

func TestClassifyItemErrors(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		result string
		reason string
	}{
		{"unsupported with short reason", unsupportedItem("winget no longer lists version 1.2.3", "Foo.Bar 1.2.3 is not in the winget repository"), "unsupported", "winget no longer lists version 1.2.3"},
		{"plain unsupported", &acquire.UnsupportedError{Reason: "no installer\nsecond line"}, "unsupported", "no installer"},
		{"wrapped sha-256", fmt.Errorf("download: %w", fmt.Errorf("%w: SHA-256 aa, expected bb", acquire.ErrHashMismatch)), "failed", "SHA-256 mismatch"},
		{"sha-1", fmt.Errorf("%w: SHA-1 aa, expected bb", acquire.ErrHashMismatch), "failed", "SHA-1 mismatch"},
		{"timeout", fmt.Errorf("catalog search: %w", context.DeadlineExceeded), "failed", "the run reached its time limit"},
		{"stopped", context.Canceled, "failed", "the run was stopped"},
		{"network", errors.New("GET https://x/y: HTTP 503\nbody"), "failed", "GET https://x/y: HTTP 503"},
	} {
		o := classify(c.err)
		if o.result != c.result || !strings.HasPrefix(o.reason, c.reason) || strings.Contains(o.reason, "\n") {
			t.Errorf("%s: %s %q, want %s %q", c.name, o.result, o.reason, c.result, c.reason)
		}
	}
	if r := shortReason(strings.Repeat("x", 500)); len(r) != maxReasonLen || !strings.HasSuffix(r, "...") {
		t.Errorf("long reason %d %q", len(r), r)
	}
}

func TestKBCatalogError(t *testing.T) {
	k := acqrequest.KB{KB: "KB5044273", Build: 22000, Arch: "x64"}
	for msg, want := range map[string]string{
		"catalog has no results for KB5044273":                       "unsupported:KB5044273 not in the Microsoft Update Catalog for build 22000 x64",
		"no catalog row matches kb=KB5044273 product=\"x\" arch=x64": "unsupported:KB5044273 not in the Microsoft Update Catalog for build 22000 x64",
		"2 catalog rows match; narrow with -product or -match:\n  a": "unsupported:several Microsoft Update Catalog entries match KB5044273",
		"catalog search: GET https://catalog: HTTP 503":              "failed:catalog search: GET https://catalog: HTTP 503",
	} {
		o := classify(kbCatalogError(k, errors.New(msg)))
		if got := o.result + ":" + o.reason; !strings.HasPrefix(got, want) {
			t.Errorf("%q: %q, want %q", msg, got, want)
		}
	}
	if o := classify(kbCatalogError(acqrequest.KB{KB: "KB1", Arch: "arm64"}, errors.New("catalog has no results for KB1"))); o.reason != "KB1 not in the Microsoft Update Catalog for arm64" {
		t.Errorf("no build: %q", o.reason)
	}
}

func TestPickMSIReason(t *testing.T) {
	for full, want := range map[string]string{
		"Foo 1.0 has no MSI installer for x86 (only exe, msix); offpatch deploys MSI packages only": "no MSI installer for x86 in winget (only exe, msix)",
		"Foo 1.0 has no installer for x86":                                                                         "no installer for x86 in winget",
		"Foo 1.0: installer URL \"http://x\" is not https":                                                         "the winget installer URL is not HTTPS",
		"Foo 1.0: manifest has no valid InstallerSha256":                                                           "the winget manifest has no valid SHA-256 for the installer",
		"Foo 1.0 has no MSI or EXE installer for x86 (only msix, zip)":                                             "no MSI or EXE installer for x86 in winget (only msix, zip)",
		"Foo 1.0 has no supported installer for x86 (only pwa)":                                                    "no supported installer for x86 in winget (only pwa)",
		"Foo 1.0: EXE installer (inno) for x86 is not importable: installs per user only":                          "installs per user only (winget EXE installer (inno) for x86)",
		"Foo 1.0: EXE installer (exe) for x86 is not importable: EXE installer without a documented silent switch": "EXE installer without a documented silent switch (winget EXE installer (exe) for x86)",
	} {
		if got := pickMSIReason(full, "x86"); got != want {
			t.Errorf("%q: %q, want %q", full, got, want)
		}
	}
}

// A package fetched this run but not carried by any sent bundle (send
// failed, or left out at build time) is failed, not fetched; an app's
// architectures fold into one result.
func TestFinishItems(t *testing.T) {
	st := autoState{Done: map[string]autoDone{"A-1": {BundleID: "b-old"}, "B-1": {BundleID: "b-new"}}, RequestSent: map[string]map[string]string{"gone": {"X": "b"}}}
	rep := &autoReport{Bundles: []string{"b-new"}, Failures: map[string]string{"C-1": "left out of the bundle: bad schema"}}
	fetched := itemOutcome{result: acqstatus.ItemFetched}
	lr := &loadedRequest{req: &acqrequest.Request{RequestID: "r1"}, items: []requestItem{
		{kind: "kb", key: "A", version: "x64", parts: []itemPart{{arch: "x64", id: "A-1", out: fetched}}},
		{kind: "kb", key: "C", version: "x64", parts: []itemPart{{arch: "x64", id: "C-1", out: fetched}}},
		{kind: "app", key: "B", version: "1", parts: []itemPart{
			{arch: "x64", id: "B-1", out: fetched},
			{arch: "arm64", id: "B-1-arm64", out: itemOutcome{result: acqstatus.ItemUnsupported, reason: "no MSI installer for arm64 in winget"}},
		}},
	}}
	got := finishItems([]*loadedRequest{lr}, st, rep, false, errors.New("send b-2: drop full"), false)
	want := []string{
		"A failed downloaded but not sent: send b-2: drop full",
		"C failed left out of the bundle: bad schema",
		"B fetched arm64: no MSI installer for arm64 in winget",
	}
	for i, it := range got {
		if s := it.Key + " " + it.Result + " " + it.Reason; i >= len(want) || s != want[i] {
			t.Errorf("item %d: %q", i, s)
		}
	}
	if st.RequestSent["r1"]["B-1"] != "b-new" || st.RequestSent["r1"]["A-1"] != "" || st.RequestSent["gone"] != nil {
		t.Errorf("request_sent: %v", st.RequestSent)
	}
}
