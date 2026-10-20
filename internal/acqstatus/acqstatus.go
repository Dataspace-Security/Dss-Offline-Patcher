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

	"offpatch/internal/acqpolicy"
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
	// Items is the per-item outcome for every item named in an import
	// request this run, so the console can say "Can't import: <reason>"
	// on the exact row the operator clicked instead of a run-wide summary.
	Items []ItemResult `json:"items,omitempty"`

	// Auto-download policy (see internal/acqpolicy): the version this run
	// merged over acquire.json (0 = none), its hash and editor, when this
	// downloader first applied it, and why a delivered policy file was
	// refused (the previous version then stays in force).
	PolicyVersion   int    `json:"policy_version,omitempty"`
	PolicySHA256    string `json:"policy_sha256,omitempty"`
	PolicyEditedBy  string `json:"policy_edited_by,omitempty"`
	PolicyAppliedAt string `json:"policy_applied_at,omitempty"`
	PolicyError     string `json:"policy_error,omitempty"`
	// PolicySignature: how the policy in force was verified ("ed25519:<key id>",
	// or "unsigned: ..." when acquire.json pins no policy key; S-4).
	PolicySignature string `json:"policy_signature,omitempty"`
	// Sources: per policy source / app / Windows entry results this run.
	Sources []SourceResult `json:"sources,omitempty"`
	// Defaults: what acquire.json configures, as policy entries (the console
	// offers it as the starting policy), plus its custom feeds by name.
	Defaults *acqpolicy.Base `json:"defaults,omitempty"`
	// RunRequest: the console "Run now" request this run served.
	RunRequest string `json:"run_request,omitempty"`
}

// SourceResult is what one policy entry did in one run.
//
// Result is one of new | up_to_date | failed | unsupported | waiting |
// disabled | applied (a source that only changes where things come from).
type SourceResult struct {
	Kind     string   `json:"kind"` // source | app | windows
	ID       string   `json:"id"`   // source id, winget id, or "<product> <build> <arch>"
	Type     string   `json:"type,omitempty"`
	Result   string   `json:"result"`
	Detail   string   `json:"detail,omitempty"`
	Packages []string `json:"packages,omitempty"`
}

// ItemResult is what happened to one requested item in one run.
//
// Result is one of:
//   - fetched: downloaded and placed in the bundle this run.
//   - already_sent: an earlier run already sent it.
//   - unsupported: can never be fetched this way (no MSI installer for the
//     arch, no ProductCode, version no longer in winget, KB not in the
//     catalog for that build/arch). Retrying will not help.
//   - failed: transient (download, hash, network); the next run may work.
type ItemResult struct {
	RequestID string `json:"request_id"`
	Kind      string `json:"kind"`    // app | kb
	Key       string `json:"key"`     // winget id or KB number
	Version   string `json:"version"` // app version, or the KB's arch
	Result    string `json:"result"`  // fetched | already_sent | unsupported | failed
	Reason    string `json:"reason,omitempty"`
	PackageID string `json:"package_id,omitempty"`
}

// Item results.
const (
	ItemFetched     = "fetched"
	ItemAlreadySent = "already_sent"
	ItemUnsupported = "unsupported"
	ItemFailed      = "failed"
)

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
