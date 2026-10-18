package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReportProfileDefaultsFromPolicy(t *testing.T) {
	s := openTest(t)
	s.Policy.Deadlines = map[string]time.Duration{"critical": 72 * time.Hour, "important": 14 * 24 * time.Hour}
	rec, err := s.GetReportProfile(context.Background())
	if err != nil || !rec.IsDefault || rec.Version != 0 || rec.SHA256 == "" {
		t.Fatalf("defaults: %+v %v", rec, err)
	}
	p := rec.Profile
	want := map[string]int{"emergency": 3, "critical": 3, "high": 14, "moderate": 60, "low": 90}
	if len(p.Deadlines) != 5 {
		t.Fatalf("deadlines: %+v", p.Deadlines)
	}
	for _, d := range p.Deadlines {
		if d.MaxDays != want[d.Priority] || d.ClockStart != "release" || d.Source == "" || d.ExceptionProcess == "" {
			t.Errorf("deadline %+v", d)
		}
	}
	if len(p.RegulatoryMappings) != len(TemplateMappings) || len(p.RegulatoryMappings) != 7 {
		t.Fatalf("mappings: %d", len(p.RegulatoryMappings))
	}
	for _, m := range p.RegulatoryMappings {
		if m.Applicable != "unknown" || m.Result != "" || m.Expectation == "" {
			t.Errorf("candidate mapping not neutral: %+v", m)
		}
	}
	if len(p.Signoff) != 4 || p.Signoff[3].Role != "Independent auditor" || p.ManualControls == nil {
		t.Fatalf("signoff / manual: %+v", p)
	}
}

func TestReportProfileVersionsAndValidation(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	p := s.Policy.DefaultReportProfile()
	p.LegalEntity, p.Regulators = "Example Co-operative Bank Ltd", []string{"rbi", "CERT-In", "RBI"}
	p.ManualControls = map[string]ManualControl{"pm-08": {Status: "compliant", EvidenceRef: "UAT-42"}}
	p.Deadlines = []DeadlineRule{{Priority: "Critical", MaxDays: 3, Source: "Board policy POL-7 §5", ClockStart: "acquired"}}
	r1, err := s.SaveReportProfile(ctx, "user:adam@bank.test", p, 0)
	if err != nil || r1.Version != 1 || r1.EditedBy != "user:adam@bank.test" {
		t.Fatalf("save: %+v %v", r1, err)
	}
	got, _ := s.GetReportProfile(ctx)
	if got.Version != 1 || got.IsDefault || strings.Join(got.Profile.Regulators, ",") != "RBI,CERT-In" || got.Profile.ManualControls["PM-08"].Status != StatusCompliant {
		t.Fatalf("normalized: %+v", got.Profile)
	}
	if len(got.Profile.Deadlines) != 5 || got.Profile.Deadlines[1].Priority != "critical" || got.Profile.Deadlines[1].MaxDays != 3 || got.Profile.Deadlines[1].ClockStart != "acquired" {
		t.Fatalf("deadlines filled and ordered: %+v", got.Profile.Deadlines)
	}
	// Optimistic concurrency: a stale base version is refused.
	if _, err := s.SaveReportProfile(ctx, "user:ada@bank.test", p, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale base: %v", err)
	}
	p.EntityCategory = "Tier 2 UCB"
	r2, err := s.SaveReportProfile(ctx, "user:ada@bank.test", p, -1)
	if err != nil || r2.Version != 2 || r2.SHA256 == r1.SHA256 {
		t.Fatalf("second save: %+v %v", r2, err)
	}
	hist, _ := s.ReportProfileHistory(ctx)
	if len(hist) != 2 || hist[0].Version != 2 || hist[1].EditedBy != "user:adam@bank.test" {
		t.Fatalf("history: %+v", hist)
	}
	if v1, err := s.GetReportProfileVersion(ctx, 1); err != nil || v1.Profile.EntityCategory != "" {
		t.Fatalf("version 1: %+v %v", v1, err)
	}
	if _, err := s.GetReportProfileVersion(ctx, 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	evs, _ := s.ListAudit(ctx, AuditQuery{Action: "report.profile_updated"})
	if len(evs) != 2 || !strings.Contains(string(evs[0].Details), `"entity_category"`) || !strings.Contains(string(evs[0].Details), r2.SHA256) {
		t.Fatalf("audit: %+v", evs)
	}
	for name, bad := range map[string]func(*ReportProfile){
		"regulator": func(p *ReportProfile) { p.Regulators = []string{"FCA"} },
		"priority":  func(p *ReportProfile) { p.Deadlines = []DeadlineRule{{Priority: "urgent", MaxDays: 1}} },
		"max days":  func(p *ReportProfile) { p.Deadlines = []DeadlineRule{{Priority: "low", MaxDays: 0}} },
		"clock start": func(p *ReportProfile) {
			p.Deadlines = []DeadlineRule{{Priority: "low", MaxDays: 5, ClockStart: "whenever"}}
		},
		"applicable": func(p *ReportProfile) { p.RegulatoryMappings[0].Applicable = "maybe" },
		"result":     func(p *ReportProfile) { p.RegulatoryMappings[0].Result = "RBI compliant" },
		"control id": func(p *ReportProfile) {
			p.ManualControls = map[string]ManualControl{"PM-18": {Status: StatusCompliant}}
		},
		"status":       func(p *ReportProfile) { p.ManualControls = map[string]ManualControl{"PM-01": {Status: "green"}} },
		"date":         func(p *ReportProfile) { p.Policy.ReviewDate = "next year" },
		"too long":     func(p *ReportProfile) { p.ScopeLimitations = strings.Repeat("x", 9000) },
		"exclusion":    func(p *ReportProfile) { p.Exclusions = []ReportExclusion{{System: "ATM network"}} },
		"overall":      func(p *ReportProfile) { p.OverallAssessment.Status = StatusNotApplicable },
		"signoff role": func(p *ReportProfile) { p.Signoff = []Signoff{{Name: "X"}} },
	} {
		q := s.Policy.DefaultReportProfile()
		bad(&q)
		if _, err := s.SaveReportProfile(ctx, "user:adam@bank.test", q, -1); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if h, _ := s.ReportProfileHistory(ctx); len(h) != 2 {
		t.Fatalf("invalid saves stored: %d", len(h))
	}
}

func TestPseudonymSaltStable(t *testing.T) {
	s := openTest(t)
	a, err := s.PseudonymSalt(context.Background())
	b, _ := s.PseudonymSalt(context.Background())
	if err != nil || len(a) != 32 || string(a) != string(b) {
		t.Fatalf("salt: %v", err)
	}
}
