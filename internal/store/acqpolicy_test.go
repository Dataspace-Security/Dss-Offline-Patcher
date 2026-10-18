package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"offpatch/internal/acqpolicy"
)

func TestAcqPolicyVersioning(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, ok, err := s.GetAcqPolicy(ctx); ok || err != nil {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	defaults := acqpolicy.Policy{Windows: []acqpolicy.Windows{{Product: "Windows 11 Version 24H2", Build: 26100, Arch: "x64", Enabled: true}}}
	defaults.Normalize()

	p := defaults
	p.Apps = []acqpolicy.App{{ID: "Google.Chrome", Arch: []string{"x64"}, Enabled: true}}
	rec, err := s.SaveAcqPolicy(ctx, "user:sam", p, 0, defaults)
	if err != nil || rec.Version != 1 || rec.SHA256 != acqpolicy.Hash(rec.Policy) {
		t.Fatalf("save 1: %+v %v", rec, err)
	}
	if strings.Join(rec.Summary, ";") != "added app Google.Chrome" {
		t.Errorf("summary relative to the defaults: %v", rec.Summary)
	}

	// Stale base version: conflict, nothing stored.
	if _, err := s.SaveAcqPolicy(ctx, "user:other", p, 0, defaults); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save: %v", err)
	}
	// Invalid content: ErrInvalid.
	bad := p
	bad.Sources = []acqpolicy.Source{{ID: "x", Type: "vendor-url", Enabled: true, URL: "http://example.com/a.msi"}}
	if _, err := s.SaveAcqPolicy(ctx, "user:sam", bad, 1, defaults); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "https") {
		t.Fatalf("invalid save: %v", err)
	}

	p2 := p
	p2.Apps = []acqpolicy.App{{ID: "Google.Chrome", Arch: []string{"x64"}, Enabled: false}}
	rec2, err := s.SaveAcqPolicy(ctx, "user:sam", p2, 1, defaults)
	if err != nil || rec2.Version != 2 {
		t.Fatalf("save 2: %+v %v", rec2, err)
	}
	cur, ok, err := s.GetAcqPolicy(ctx)
	if err != nil || !ok || cur.Version != 2 || cur.Policy.Apps[0].Enabled {
		t.Fatalf("latest: %+v %v", cur, err)
	}
	v1, err := s.GetAcqPolicyVersion(ctx, 1)
	if err != nil || !v1.Policy.Apps[0].Enabled {
		t.Fatalf("version 1: %+v %v", v1, err)
	}
	if _, err := s.GetAcqPolicyVersion(ctx, 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	h, err := s.AcqPolicyHistory(ctx)
	if err != nil || len(h) != 2 || h[0].Version != 2 || h[0].EditedBy != "user:sam" || !strings.Contains(h[0].Summary[0], "Google.Chrome (off)") {
		t.Fatalf("history: %+v %v", h, err)
	}

	// Every save audited with the change summary.
	evs, err := s.ListAudit(ctx, AuditQuery{Action: "acquisition.policy_updated"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("audit events: %d", len(evs))
	}
	var d map[string]any
	json.Unmarshal(evs[0].Details, &d)
	if d["sha256"] == "" || d["changes"] == nil {
		t.Errorf("audit details: %v", d)
	}
}
