// Package intake watches the transfer-boundary drop directory, quarantines
// each bundle, validates it, and records the result. It never publishes
// content: packages land in the catalog as "quarantined".
package intake

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"offpatch/internal/acqstatus"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
	"offpatch/internal/transfer"
	"offpatch/internal/trust"
)

// TrustedKey is a bundle-signing public key and the sources it may sign for.
type TrustedKey struct {
	Pub     ed25519.PublicKey
	Sources []string
	Retired bool // valid for existing content, refused for new bundles
}

type Config struct {
	Inbox, ReceivedDir, QuarantineDir string
	// RootPub enables signed trust documents (key rotation/revocation).
	RootPub        ed25519.PublicKey
	Keys           map[string]TrustedKey // by key_id
	Limits         manifest.Limits
	MaxBundleBytes int64
	ScanCommand    []string // optional; payload path appended; exit 0 = clean
	Interval       time.Duration
	// Rate limits per rolling hour (0 = unlimited). Excess bundles stay in
	// the inbox and are processed later; nothing is dropped.
	MaxBundlesPerHour int
	MaxBytesPerHour   int64
}

type Service struct {
	cfg   Config
	store *store.Store
	log   *slog.Logger
	Now   func() time.Time

	lastLimitAudit time.Time
	keyMu          sync.Mutex
}

func New(cfg Config, st *store.Store, log *slog.Logger) (*Service, error) {
	for _, d := range []string{cfg.Inbox, cfg.ReceivedDir, cfg.QuarantineDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Service{cfg: cfg, store: st, log: log, Now: func() time.Time { return time.Now().UTC() }}, nil
}

// Run polls the inbox until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		s.ScanOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ScanOnce processes every complete *.pmb in the inbox (oldest name first).
// In-flight transfers use *.part and are ignored until renamed.
func (s *Service) ScanOnce(ctx context.Context) []store.Bundle {
	entries, err := os.ReadDir(s.cfg.Inbox)
	if err != nil {
		s.log.Error("read inbox", "err", err)
		return nil
	}
	var names, receipts, trustDocs, statuses []string
	// Trust documents first: a revocation must take effect before bundles
	// that arrived alongside it are validated.
	for _, e := range entries {
		switch {
		case !e.Type().IsRegular():
		case strings.HasSuffix(e.Name(), ".pmb"):
			names = append(names, e.Name())
		case strings.HasSuffix(e.Name(), transfer.ReceiptSuffix):
			receipts = append(receipts, e.Name())
		case strings.HasSuffix(e.Name(), trust.FileSuffix):
			trustDocs = append(trustDocs, e.Name())
		case strings.HasSuffix(e.Name(), acqstatus.FileSuffix):
			statuses = append(statuses, e.Name())
		}
	}
	sort.Strings(trustDocs)
	for _, n := range trustDocs {
		if err := s.processTrust(ctx, filepath.Join(s.cfg.Inbox, n)); err != nil {
			s.log.Error("trust document rejected", "file", n, "err", err)
		}
	}
	sort.Strings(names)
	var out []store.Bundle
	for _, n := range names {
		if why := s.overLimit(ctx, filepath.Join(s.cfg.Inbox, n)); why != "" {
			s.log.Warn("intake rate limit reached; leaving bundles in the inbox", "reason", why, "waiting", len(names)-len(out))
			if s.Now().Sub(s.lastLimitAudit) > 15*time.Minute {
				s.lastLimitAudit = s.Now()
				s.store.RaiseAlert(ctx, "warning", "intake_rate_limited", "inbox", "inbox", "intake rate limit reached: "+why)
				s.store.Audit(ctx, store.Ev{Actor: "system:intake", Action: "intake.rate_limited", ObjectType: "inbox", ObjectID: "inbox", Failure: true,
					Details: map[string]any{"reason": why, "waiting": len(names) - len(out)}})
			}
			break
		}
		b, err := s.Process(ctx, filepath.Join(s.cfg.Inbox, n))
		if err != nil {
			s.log.Error("intake failed", "file", n, "err", err)
			continue
		}
		s.log.Info("intake", "file", n, "bundle_id", b.BundleID, "state", b.State, "error", b.Error)
		out = append(out, b)
	}
	sort.Strings(statuses)
	for _, n := range statuses {
		if err := s.processStatus(ctx, filepath.Join(s.cfg.Inbox, n)); err != nil {
			s.log.Warn("acquisition status report rejected", "file", n, "err", err)
		}
	}
	sort.Strings(receipts)
	for _, n := range receipts {
		if err := s.processReceipt(ctx, filepath.Join(s.cfg.Inbox, n)); err != nil {
			s.log.Error("receipt", "file", n, "err", err)
		}
	}
	return out
}

func (s *Service) overLimit(ctx context.Context, next string) string {
	if s.cfg.MaxBundlesPerHour <= 0 && s.cfg.MaxBytesPerHour <= 0 {
		return ""
	}
	n, bytes, err := s.store.IntakeVolume(ctx, s.Now().Add(-time.Hour))
	if err != nil {
		return "stats unavailable: " + err.Error()
	}
	if s.cfg.MaxBundlesPerHour > 0 && n >= s.cfg.MaxBundlesPerHour {
		return fmt.Sprintf("%d bundles in the last hour (limit %d)", n, s.cfg.MaxBundlesPerHour)
	}
	if fi, err := os.Stat(next); err == nil && s.cfg.MaxBytesPerHour > 0 && bytes+fi.Size() > s.cfg.MaxBytesPerHour && bytes > 0 {
		return fmt.Sprintf("%d bytes in the last hour (limit %d)", bytes, s.cfg.MaxBytesPerHour)
	}
	return ""
}

// processReceipt records a sender receipt (verifying its signature against
// the trusted bundle keys) and moves it to received/receipts.
func (s *Service) processReceipt(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	f.Close()
	if err != nil {
		return err
	}
	dst := filepath.Join(s.cfg.ReceivedDir, "receipts", fmt.Sprintf("%d-%s", s.Now().UnixNano(), filepath.Base(path)))
	os.MkdirAll(filepath.Dir(dst), 0o750)
	if err := os.Rename(path, dst); err != nil {
		return err
	}
	var r transfer.Receipt
	if err := json.Unmarshal(b, &r); err != nil || len(r.SHA256) != 64 {
		return s.store.RecordReceipt(ctx, store.TransferReceipt{File: filepath.Base(path), FileSHA256: "invalid", Adapter: "unknown", SentAt: ""})
	}
	ok := false
	if k, found := s.cfg.Keys[r.KeyID]; found {
		ok = transfer.VerifyReceipt(r, k.Pub)
	}
	return s.store.RecordReceipt(ctx, store.TransferReceipt{File: r.File, FileSHA256: r.SHA256, Size: r.Size, Adapter: r.Adapter, SentAt: r.SentAt, KeyID: r.KeyID, SignatureOK: ok})
}

// Process validates one bundle file and moves it out of the inbox.
func (s *Service) Process(ctx context.Context, path string) (store.Bundle, error) {
	fname := filepath.Base(path)
	size, sha, err := manifest.HashFile(path)
	if err != nil {
		return store.Bundle{}, err
	}
	// Evidence copy: the bundle as received, by hash. Moved, not copied, so the
	// inbox only ever holds unprocessed files.
	evidence := filepath.Join(s.cfg.ReceivedDir, sha+".pmb")
	if err := os.Rename(path, evidence); err != nil {
		return store.Bundle{}, fmt.Errorf("move to received: %w", err)
	}
	os.Chmod(evidence, 0o440)

	b := store.Bundle{Filename: fname, FileSHA256: sha, FileSize: size, Checks: []store.Check{}}
	check := func(name string, ok bool, f string, a ...any) bool {
		b.Checks = append(b.Checks, store.Check{Name: name, OK: ok, Detail: fmt.Sprintf(f, a...)})
		return ok
	}
	in := store.Intake{}
	qdir := filepath.Join(s.cfg.QuarantineDir, fmt.Sprintf("%s-%s", s.Now().Format("20060102T150405"), sha[:12]))
	reject := func() (store.Bundle, error) {
		in.Bundle = b
		in.Manifest = nil
		os.RemoveAll(qdir)
		return s.store.IngestBundle(ctx, in)
	}

	if !check("size", s.cfg.MaxBundleBytes <= 0 || size <= s.cfg.MaxBundleBytes, "%d bytes (limit %d)", size, s.cfg.MaxBundleBytes) {
		return reject()
	}
	ex, err := manifest.ExtractSafe(evidence, qdir, s.cfg.Limits)
	if !check("structure", err == nil, "%s", errText(err, "tar layout ok")) {
		return reject()
	}
	in.ManifestBytes, in.Signature = ex.ManifestBytes, ex.Signature
	m, err := manifest.Parse(ex.ManifestBytes)
	if !check("manifest_parse", err == nil, "%s", errText(err, "strict JSON ok")) {
		return reject()
	}
	b.BundleID, b.Source, b.Sequence, b.KeyID = m.BundleID, m.Source, m.Sequence, m.KeyID
	err = m.ValidateSchema(s.Now())
	if !check("manifest_schema", err == nil, "%s", errText(err, "schema v1 ok")) {
		return reject()
	}
	s.keyMu.Lock()
	key, ok := s.cfg.Keys[m.KeyID]
	s.keyMu.Unlock()
	if !check("trusted_key", ok, "key_id %s %s", m.KeyID, map[bool]string{true: "trusted", false: "NOT trusted"}[ok]) {
		return reject()
	}
	if !check("key_status", !key.Retired, "key %s %s", m.KeyID, map[bool]string{true: "is retired: no new bundles accepted", false: "active"}[key.Retired]) {
		return reject()
	}
	allowed := false
	for _, src := range key.Sources {
		if src == m.Source || src == "*" {
			allowed = true
		}
	}
	if !check("source_authorized", allowed, "source %s for key %s", m.Source, m.KeyID) {
		return reject()
	}
	err = manifest.Verify(key.Pub, ex.ManifestBytes, ex.Signature)
	if !check("signature", err == nil, "%s", errText(err, "Ed25519 signature valid")) {
		return reject()
	}
	// Every manifest file present with the right size and hash, and nothing else.
	want := map[string]bool{}
	var problems []string
	for _, p := range m.Packages {
		want[p.File.Name] = true
		f, ok := ex.Files[p.File.Name]
		switch {
		case !ok:
			problems = append(problems, p.File.Name+" missing")
		case f.Size != p.File.Size:
			problems = append(problems, fmt.Sprintf("%s size %d != %d", p.File.Name, f.Size, p.File.Size))
		case f.SHA256 != p.File.SHA256:
			problems = append(problems, fmt.Sprintf("%s sha256 mismatch", p.File.Name))
		}
	}
	for name := range ex.Files {
		if !want[name] {
			problems = append(problems, name+" not in manifest")
		}
	}
	if !check("payload_hashes", len(problems) == 0, "%s", strings.Join(append(problems, fmt.Sprintf("%d file(s) checked", len(ex.Files))), "; ")) {
		return reject()
	}
	if len(s.cfg.ScanCommand) > 0 {
		var bad []string
		for name, f := range ex.Files {
			args := append(append([]string{}, s.cfg.ScanCommand[1:]...), f.Path)
			cmd := exec.CommandContext(ctx, s.cfg.ScanCommand[0], args...)
			if out, err := cmd.CombinedOutput(); err != nil {
				bad = append(bad, fmt.Sprintf("%s: %v %s", name, err, strings.TrimSpace(string(out))))
			}
		}
		if !check("content_scan", len(bad) == 0, "%s", strings.Join(append(bad, s.cfg.ScanCommand[0]), "; ")) {
			return reject()
		}
	} else {
		check("content_scan", true, "no scanner configured (skipped)")
	}
	in.Bundle, in.Manifest, in.QuarantineDir = b, m, qdir
	res, err := s.store.IngestBundle(ctx, in)
	if err == nil && res.State != "validated" {
		os.RemoveAll(qdir)
	}
	return res, err
}

func errText(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}

// ApplyTrust replaces the trusted key set from a verified trust document.
func (s *Service) ApplyTrust(d trust.Document) {
	keys := map[string]TrustedKey{}
	for _, k := range d.Keys {
		pub, err := manifest.ParsePublic(k.PublicKey)
		if err != nil {
			continue // Validate() already guarantees this parses
		}
		keys[k.KeyID] = TrustedKey{Pub: pub, Sources: k.Sources, Retired: k.Status == "retired"}
	}
	s.keyMu.Lock()
	s.cfg.Keys = keys
	s.keyMu.Unlock()
}

// processTrust verifies a trust document against the root key, stores it if
// newer, applies it, and revokes content signed by compromised keys.
func (s *Service) processTrust(ctx context.Context, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dst := filepath.Join(s.cfg.ReceivedDir, "trust", fmt.Sprintf("%d-%s", s.Now().UnixNano(), filepath.Base(path)))
	os.MkdirAll(filepath.Dir(dst), 0o750)
	if err := os.Rename(path, dst); err != nil {
		return err
	}
	fail := func(reason string) error {
		s.store.RaiseAlert(ctx, "warning", "trust_rejected", "trust", filepath.Base(path), "trust document "+filepath.Base(path)+" rejected: "+reason)
		s.store.Audit(ctx, store.Ev{Actor: "system:intake", Action: "trust.rejected", ObjectType: "trust", ObjectID: filepath.Base(path), Failure: true,
			Details: map[string]any{"reason": reason}})
		return errors.New(reason)
	}
	if s.cfg.RootPub == nil {
		return fail("no root_public_key_file configured; trust documents are not accepted")
	}
	signed, err := trust.Parse(b)
	if err != nil {
		return fail(err.Error())
	}
	doc, err := trust.Verify(signed, s.cfg.RootPub)
	if err != nil {
		return fail(err.Error())
	}
	cur, _ := s.store.GetMeta(ctx, "trust_seq")
	if curSeq, _ := strconv.ParseInt(cur, 10, 64); doc.Sequence <= curSeq {
		return fail(fmt.Sprintf("sequence %d not newer than current %d (replay)", doc.Sequence, curSeq))
	}
	raw, _ := json.Marshal(signed)
	if err := s.store.SaveTrust(ctx, string(raw), doc.Sequence, doc); err != nil {
		return err
	}
	s.ApplyTrust(doc)
	for _, r := range doc.Revoked {
		if r.Reason == "compromised" {
			n, err := s.store.RevokeKeyContent(ctx, r.KeyID)
			if err != nil {
				return err
			}
			s.log.Warn("signing key revoked as compromised; its packages were revoked", "key_id", r.KeyID, "packages", n)
			s.store.RaiseAlert(ctx, "critical", "signing_key_compromised", "key", r.KeyID, fmt.Sprintf("bundle signing key %s revoked as COMPROMISED; %d package(s) revoked and their deployments cancelled — start the incident procedure", r.KeyID, n))
		}
	}
	s.log.Info("trust document applied", "sequence", doc.Sequence, "keys", len(doc.Keys), "revoked", len(doc.Revoked))
	return nil
}

// LoadStoredTrust re-applies the latest stored trust document at startup.
func (s *Service) LoadStoredTrust(ctx context.Context) error {
	raw, err := s.store.GetMeta(ctx, "trust_doc")
	if err != nil || raw == "" || s.cfg.RootPub == nil {
		return err
	}
	signed, err := trust.Parse([]byte(raw))
	if err != nil {
		return err
	}
	doc, err := trust.Verify(signed, s.cfg.RootPub)
	if err != nil {
		return fmt.Errorf("stored trust document no longer verifies: %w", err)
	}
	s.ApplyTrust(doc)
	s.log.Info("trust document loaded", "sequence", doc.Sequence)
	return nil
}

// processStatus verifies an acquisition status report (signed with a trusted
// bundle key) and records it for the console.
func (s *Service) processStatus(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	f.Close()
	if err != nil {
		return err
	}
	dst := filepath.Join(s.cfg.ReceivedDir, "status", filepath.Base(path))
	os.MkdirAll(filepath.Dir(dst), 0o750)
	if err := os.Rename(path, dst); err != nil {
		return err
	}
	var signed acqstatus.Signed
	if err := json.Unmarshal(b, &signed); err != nil {
		return err
	}
	keys := map[string]ed25519.PublicKey{}
	s.keyMu.Lock()
	for id, k := range s.cfg.Keys {
		keys[id] = k.Pub
	}
	s.keyMu.Unlock()
	r, err := acqstatus.Verify(signed, keys)
	if err != nil {
		s.store.RaiseAlert(ctx, "warning", "acquisition_status_rejected", "acquisition", filepath.Base(path), "acquisition status report rejected: "+err.Error())
		return err
	}
	doc, _ := json.Marshal(r)
	summary := fmt.Sprintf("%d new, %d failed", len(r.New), len(r.Failures))
	if r.Error != "" {
		summary += ": " + r.Error
	}
	return s.store.RecordAcquisition(ctx, r.Source, r.FinishedAt, r.Outcome, signed.KeyID, doc, summary)
}
