// Package acqstatus is the signed status report that `pmctl auto` sends
// INTO the isolated zone after every run, through the same one-way transfer
// as bundles. It lets operators see acquisition health in the console
// without any connection from the isolated zone back out.
package acqstatus

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"offpatch/internal/manifest"
)

// FileSuffix marks status reports in the drop directory.
const FileSuffix = ".status.json"

// Feed is the per-source result of one run.
type Feed struct {
	Type          string `json:"type"` // microsoft | app | intel | request
	Name          string `json:"name"` // app name, request id or "Windows 10 Version 22H2 x64"
	Title         string `json:"title,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"` // app version, or newest KB found
	Status        string `json:"status"`                   // new | up_to_date | failed
	Detail        string `json:"detail,omitempty"`
}

// Report is what pmctl auto says about one run.
type Report struct {
	Version    int               `json:"version"`
	Source     string            `json:"source"`
	Host       string            `json:"host"`
	Schedule   string            `json:"schedule,omitempty"` // human text from acquire.json
	PmctlBuild string            `json:"pmctl_build,omitempty"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
	Outcome    string            `json:"outcome"` // ok | partial | failed
	Error      string            `json:"error,omitempty"`
	New        []string          `json:"new_packages"`
	Skipped    int               `json:"already_sent"`
	Superseded []string          `json:"skipped_superseded,omitempty"`
	Failures   map[string]string `json:"failures"`
	Warnings   []string          `json:"warnings,omitempty"`
	BundleID   string            `json:"bundle_id,omitempty"`
	Sent       bool              `json:"sent"`
	Feeds      []Feed            `json:"feeds"`
}

// Signed is the on-the-wire form.
type Signed struct {
	Document  string `json:"document"` // base64 of the exact signed JSON
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
}

// Sign signs a report with any signer (file key or HSM).
func Sign(r Report, keyID string, sign func([]byte) (string, error)) (Signed, error) {
	r.Version = 1
	b, err := json.Marshal(r)
	if err != nil {
		return Signed{}, err
	}
	sig, err := sign(b)
	if err != nil {
		return Signed{}, err
	}
	return Signed{Document: base64.StdEncoding.EncodeToString(b), Signature: sig, KeyID: keyID}, nil
}

// Verify checks the signature against the trusted bundle keys.
func Verify(s Signed, keys map[string]ed25519.PublicKey) (Report, error) {
	pub, ok := keys[s.KeyID]
	if !ok {
		return Report{}, fmt.Errorf("status report signed by untrusted key %q", s.KeyID)
	}
	b, err := base64.StdEncoding.DecodeString(s.Document)
	if err != nil {
		return Report{}, errors.New("status report: bad encoding")
	}
	if err := manifest.Verify(pub, b, s.Signature); err != nil {
		return Report{}, fmt.Errorf("status report: %w", err)
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return Report{}, fmt.Errorf("status report: %w", err)
	}
	if r.Version != 1 || strings.TrimSpace(r.Source) == "" {
		return Report{}, errors.New("status report: missing version or source")
	}
	if _, err := time.Parse(time.RFC3339, r.FinishedAt); err != nil {
		return Report{}, errors.New("status report: bad finished_at")
	}
	return r, nil
}
