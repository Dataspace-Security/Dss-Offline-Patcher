package acqrequest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func valid() Request {
	return Request{Format: Format, Version: Version, RequestID: NewID(time.Date(2026, 10, 17, 10, 15, 0, 0, time.UTC), "1a2b3c"),
		CreatedAt: "2026-10-17T10:15:00Z", CreatedBy: "user:otto",
		Apps: []App{{WingetID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Architectures: []string{"x64"}, Endpoints: 2,
			Installed: []Installed{{ProductCode: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.82"}}}},
		KBs: []KB{{KB: "KB5044280", Build: 22000, Arch: "x64", Endpoints: 1}}}
}

func TestParseRoundTrip(t *testing.T) {
	r := valid()
	if r.RequestID != "acq-request-20261017T101500Z-1a2b3c" {
		t.Fatalf("id %q", r.RequestID)
	}
	b, _ := json.Marshal(r)
	got, err := Parse(strings.NewReader(string(b)))
	if err != nil || got.Apps[0].WingetID != "Google.Chrome" || got.KBs[0].KB != "KB5044280" {
		t.Fatalf("%v %+v", err, got)
	}
}

// A Library import: no endpoint has the app, so no installed forms and
// endpoints 0; the architecture is the one chosen in the console.
func TestLibraryImportRequest(t *testing.T) {
	r := valid()
	r.Apps = []App{{WingetID: "Microsoft.Edge", Version: "155.0.4283.62", Architectures: []string{"arm64"}, Endpoints: 0}}
	b, _ := json.Marshal(r)
	got, err := Parse(strings.NewReader(string(b)))
	if err != nil || got.Apps[0].Architectures[0] != "arm64" || got.Apps[0].Installed != nil {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Request){
		"format":        func(r *Request) { r.Format = "x" },
		"empty":         func(r *Request) { r.Apps, r.KBs = nil, nil },
		"path in id":    func(r *Request) { r.Apps[0].WingetID = "../../etc.passwd" },
		"one segment":   func(r *Request) { r.Apps[0].WingetID = "Chrome" },
		"device name":   func(r *Request) { r.Apps[0].WingetID = "NUL.Tool" },
		"device name 2": func(r *Request) { r.Apps[0].WingetID = "com1.Tool" },
		"dup app":       func(r *Request) { r.Apps = append(r.Apps, r.Apps[0]) },
		"slash version": func(r *Request) { r.Apps[0].Version = "1/../2" },
		"dots version":  func(r *Request) { r.Apps[0].Version = "1..2" },
		"no arch":       func(r *Request) { r.Apps[0].Architectures = nil },
		"bad arch":      func(r *Request) { r.Apps[0].Architectures = []string{"mips"} },
		"bad code":      func(r *Request) { r.Apps[0].Installed[0].ProductCode = "{nope}" },
		"control char":  func(r *Request) { r.Apps[0].Installed[0].Name = "a\x1b[2Jb" },
		"bad kb":        func(r *Request) { r.KBs[0].KB = "5044280" },
		"bad time":      func(r *Request) { r.CreatedAt = "yesterday" },
	}
	for name, mut := range cases {
		r := valid()
		mut(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse(strings.NewReader(`{"format":"offpatch.acquisition-request","extra":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := Parse(strings.NewReader(strings.Repeat(" ", MaxSize+1))); err == nil {
		t.Error("oversized file accepted")
	}
}

func TestCleanText(t *testing.T) {
	if got := CleanText("Google\x00 Chrome\n"); got != "Google Chrome" {
		t.Errorf("%q", got)
	}
	if got := CleanText(strings.Repeat("é", 200)); len(got) > 256 || !strings.HasPrefix(got, "é") {
		t.Errorf("truncation: %d", len(got))
	}
}
