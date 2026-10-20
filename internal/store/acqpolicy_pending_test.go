package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"offpatch/internal/acqpolicy"
)

// S-4: adding or changing a download source needs a second super admin;
// toggling or removing applies directly.
func TestAcqPolicyTwoPersonSourceChange(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	defaults := acqpolicy.Empty()
	p := acqpolicy.Empty()
	p.Sources = []acqpolicy.Source{{ID: "tool", Type: "vendor-url", Enabled: true, Name: "Tool", URL: "https://vendor.example/tool.msi",
		ExpectedSHA256: strings.Repeat("a", 64), Kind: "msi", Version: "1.0.0", AddedBy: "user:sam"}}

	if _, err := s.SaveAcqPolicy(ctx, "user:sam", p, 0, defaults); !errors.Is(err, ErrNeedsSecondApprover) || !errors.Is(err, ErrForbidden) {
		t.Fatalf("direct save of a new source: %v", err)
	}
	pend, err := s.ProposeAcqPolicy(ctx, "user:sam", p, 0, defaults)
	if err != nil || len(pend.Changes) != 1 || pend.BaseVersion != 0 {
		t.Fatalf("propose: %+v %v", pend, err)
	}
	if got, err := s.GetAcqPolicyPending(ctx); err != nil || got == nil || got.SHA256 != pend.SHA256 || got.ProposedBy != "user:sam" {
		t.Fatalf("pending: %+v %v", got, err)
	}
	if _, err := s.ApproveAcqPolicy(ctx, "USER:SAM", pend.SHA256); !errors.Is(err, ErrForbidden) {
		t.Fatalf("proposer approved own change: %v", err)
	}
	if _, err := s.ApproveAcqPolicy(ctx, "user:sue", strings.Repeat("0", 64)); !errors.Is(err, ErrConflict) {
		t.Fatalf("approve with another hash: %v", err)
	}
	rec, err := s.ApproveAcqPolicy(ctx, "user:sue", pend.SHA256)
	if err != nil || rec.Version != 1 || rec.EditedBy != "user:sam" || len(rec.Policy.Sources) != 1 {
		t.Fatalf("approve: %+v %v", rec, err)
	}
	if got, _ := s.GetAcqPolicyPending(ctx); got != nil {
		t.Fatalf("pending left after approval: %+v", got)
	}

	// Toggling off (and back on) and editing the note apply directly.
	p2 := rec.Policy
	p2.Sources = append([]acqpolicy.Source{}, p2.Sources...)
	p2.Sources[0].Enabled, p2.Sources[0].Note = false, "paused"
	if r, err := s.SaveAcqPolicy(ctx, "user:sam", p2, 1, defaults); err != nil || r.Version != 2 {
		t.Fatalf("toggle: %+v %v", r, err)
	}
	// Changing the URL needs approval; a stale proposal cannot be approved.
	p3 := p2
	p3.Sources = append([]acqpolicy.Source{}, p2.Sources...)
	p3.Sources[0].URL = "https://vendor.example/other.msi"
	if _, err := s.SaveAcqPolicy(ctx, "user:sam", p3, 2, defaults); !errors.Is(err, ErrNeedsSecondApprover) {
		t.Fatalf("URL change saved directly: %v", err)
	}
	pend3, err := s.ProposeAcqPolicy(ctx, "user:sam", p3, 2, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveAcqPolicy(ctx, "user:sam", acqpolicy.Empty(), 2, defaults); err != nil { // removal: direct
		t.Fatalf("remove: %v", err)
	}
	if _, err := s.ApproveAcqPolicy(ctx, "user:sue", pend3.SHA256); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale proposal approved: %v", err)
	}
	if err := s.RejectAcqPolicy(ctx, "user:sam", "stale"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if err := s.RejectAcqPolicy(ctx, "user:sam", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reject with nothing pending: %v", err)
	}
	// A proposal without source changes is refused (save it directly).
	if _, err := s.ProposeAcqPolicy(ctx, "user:sam", acqpolicy.Empty(), 3, defaults); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty proposal: %v", err)
	}

	for _, a := range []string{"acquisition.policy_change_proposed", "acquisition.policy_change_approved", "acquisition.policy_change_rejected"} {
		evs, err := s.ListAudit(ctx, AuditQuery{Action: a})
		if err != nil || len(evs) == 0 {
			t.Errorf("%s not audited: %v", a, err)
		}
	}
	evs, _ := s.ListAudit(ctx, AuditQuery{Action: "acquisition.policy_change_approved"})
	if len(evs) != 1 || evs[0].Actor != "user:sue" {
		t.Errorf("approval audited as %+v", evs)
	}
}
