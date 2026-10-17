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
	"offpatch/internal/intel"
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
	// IntelDir holds the current update-intelligence document (see intel.go).
	IntelDir string
	// RootPub enables signed trust documents (key rotation/revocation).
	RootPub        ed25519.PublicKey
	Keys           map[string]TrustedKey // by key_id
	Limits         manifest.Limits
	MaxBundleBytes int64
	ScanCommand    []string // optional; payload path appended; exit 0 = clean
	// ScanTimeout bounds one scan_command run per file (0 = DefaultScanTimeout);
	// a scanner that hangs fails the content_scan check instead of stalling intake.
	ScanTimeout time.Duration
	Interval    time.Duration
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
	// compromised: key IDs the current trust document revokes as
	// compromised (guarded by keyMu). Their content is revoked again on every
	// scan, so a revocation interrupted part-way is completed.
	compromised []string
	// recoverDone: received/ was checked for unrecorded bundles and no
	// intake has failed since (see recoverReceived).
	recoverDone bool
}

// DefaultScanTimeout applies when Config.ScanTimeout is 0.
const DefaultScanTimeout = 30 * time.Minute

func New(cfg Config, st *store.Store, log *slog.Logger) (*Service, error) {
	for _, d := range []string{cfg.Inbox, cfg.ReceivedDir, cfg.QuarantineDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = DefaultScanTimeout
	}
	return &Service{cfg: cfg, store: st, log: log, Now: func() time.Time { return time.Now().UTC() }}, nil
}

// archive moves a processed file out of the inbox. Callers run it only once
// the outcome is recorded, so a stop mid-processing leaves the file in the
// inbox to be processed again (each processor tolerates seeing a file twice).
func (s *Service) archive(path, dst string) {
	os.MkdirAll(filepath.Dir(dst), 0o750)
	if err := os.Rename(path, dst); err != nil {
		s.log.Error("could not move processed file out of the inbox", "file", path, "err", err)
	}
}

// recoverReceived re-ingests bundles that were moved to received/ but never
// recorded (the process stopped between the move and the database commit).
// It runs on the first scan and after any failed intake, not every tick.
func (s *Service) recoverReceived(ctx context.Context) []store.Bundle {
	if s.recoverDone {
		return nil
	}
	s.recoverDone = true
	entries, err := os.ReadDir(s.cfg.ReceivedDir)
	if err != nil {
		s.log.Error("read received", "err", err)
		return nil
	}
	var out []store.Bundle
	for _, e := range entries {
		name := e.Name()
		sha := strings.TrimSuffix(name, ".pmb")
		if !e.Type().IsRegular() || sha == name || len(sha) != 64 {
			continue
		}
		done, err := s.store.BundleFileRecorded(ctx, sha)
		if err != nil {
			s.recoverDone = false
			continue
		}
		if done {
			continue
		}
		s.log.Warn("re-ingesting a received bundle that was never recorded (interrupted intake)", "file", name)
		b, err := s.Process(ctx, filepath.Join(s.cfg.ReceivedDir, name))
		if err != nil {
			s.recoverDone = false
			s.log.Error("intake failed", "file", name, "err", err)
			continue
		}
		out = append(out, b)
	}
	return out
}

// reapplyRevocations revokes, again, content signed by keys the current
// trust document marks compromised. Idempotent: only packages still
// quarantined or approved are touched.
func (s *Service) reapplyRevocations(ctx context.Context) {
	s.keyMu.Lock()
	ids := append([]string(nil), s.compromised...)
	s.keyMu.Unlock()
	for _, id := range ids {
		n, err := s.store.RevokeKeyContent(ctx, id)
		if err != nil {
			s.log.Error("re-applying compromised key revocation", "key_id", id, "err", err)
			continue
		}
		if n > 0 {
			s.log.Warn("completed an interrupted compromised-key revocation", "key_id", id, "packages", n)
			s.store.RaiseAlert(ctx, "critical", "signing_key_compromised", "key", id, fmt.Sprintf("bundle signing key %s is revoked as COMPROMISED; %d more package(s) signed by it were revoked and their deployments cancelled — start the incident procedure", id, n))
		}
	}
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
	var names, receipts, trustDocs, statuses, intels []string
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
		case strings.HasSuffix(e.Name(), intel.FileSuffix):
			intels = append(intels, e.Name())
		}
	}
	sort.Strings(trustDocs)
	for _, n := range trustDocs {
		if err := s.processTrust(ctx, filepath.Join(s.cfg.Inbox, n)); err != nil {
			s.log.Error("trust document rejected", "file", n, "err", err)
		}
	}
	s.reapplyRevocations(ctx)
	sort.Strings(intels) // oldest first, so a backlog ends on the newest
	for _, n := range intels {
		if err := s.processIntel(ctx, filepath.Join(s.cfg.Inbox, n)); err != nil {
			s.log.Error("update intelligence rejected", "file", n, "err", err)
		}
	}
	sort.Strings(names)
	// Interrupted intakes first: they arrived before anything in the inbox.
	out := s.recoverReceived(ctx)
	for i, n := range names {
		if why := s.overLimit(ctx, filepath.Join(s.cfg.Inbox, n)); why != "" {
			s.log.Warn("intake rate limit reached; leaving bundles in the inbox", "reason", why, "waiting", len(names)-i)
			if s.Now().Sub(s.lastLimitAudit) > 15*time.Minute {
				s.lastLimitAudit = s.Now()
				s.store.RaiseAlert(ctx, "warning", "intake_rate_limited", "inbox", "inbox", "intake rate limit reached: "+why)
				s.store.Audit(ctx, store.Ev{Actor: "system:intake", Action: "intake.rate_limited", ObjectType: "inbox", ObjectID: "inbox", Failure: true,
					Details: map[string]any{"reason": why, "waiting": len(names) - i}})
			}
			break
		}
		b, err := s.Process(ctx, filepath.Join(s.cfg.Inbox, n))
		if err != nil {
			s.recoverDone = false // it may be in received/ without a record
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
	var r transfer.Receipt
	rec := store.TransferReceipt{File: filepath.Base(path), FileSHA256: "invalid", Adapter: "unknown", SentAt: ""}
	if err := json.Unmarshal(b, &r); err == nil && len(r.SHA256) == 64 {
		ok := false
		s.keyMu.Lock()
		k, found := s.cfg.Keys[r.KeyID]
		s.keyMu.Unlock()
		if found {
			ok = transfer.VerifyReceipt(r, k.Pub)
		}
		rec = store.TransferReceipt{File: r.File, FileSHA256: r.SHA256, Size: r.Size, Adapter: r.Adapter, SentAt: r.SentAt, KeyID: r.KeyID, SignatureOK: ok}
	}
	if err := s.store.RecordReceipt(ctx, rec); err != nil {
		return err // left in the inbox; recorded on a later scan
	}
	s.archive(path, dst)
	return nil
}

// Process validates one bundle file and moves it out of the inbox. The file
// is moved to received/<sha256>.pmb first; if the process stops before the
// result is recorded, the next scan re-ingests it from there
// (recoverReceived), so no bundle is lost.
func (s *Service) Process(ctx context.Context, path string) (store.Bundle, error) {
	fname := filepath.Base(path)
	size, sha, err := manifest.HashFile(path)
	if err != nil {
		return store.Bundle{}, err
	}
	// Evidence copy: the bundle as received, by hash. Moved, not copied, so the
	// inbox only ever holds unprocessed files.
	evidence := filepath.Join(s.cfg.ReceivedDir, sha+".pmb")
	if filepath.Clean(path) != filepath.Clean(evidence) {
		if _, err := os.Stat(evidence); err == nil {
			// Same content delivered again: the evidence (named by hash) is
			// already kept, and is read-only (Windows refuses a rename onto it).
			if err := os.Remove(path); err != nil {
				return store.Bundle{}, fmt.Errorf("remove duplicate from inbox: %w", err)
			}
		} else if err := os.Rename(path, evidence); err != nil {
			return store.Bundle{}, fmt.Errorf("move to received: %w", err)
		}
	}
	os.Chmod(evidence, 0o440)

	b := store.Bundle{Filename: fname, FileSHA256: sha, FileSize: size, Checks: []store.Check{}}
	check := func(name string, ok bool, f string, a ...any) bool {
		b.Checks = append(b.Checks, store.Check{Name: name, OK: ok, Detail: fmt.Sprintf(f, a...)})
		return ok
	}
	in := store.Intake{}
	// Unique per attempt: the same bundle delivered twice in one second must
	// not share (and, on rejection, delete) the first one's quarantine.
	qdir := filepath.Join(s.cfg.QuarantineDir, fmt.Sprintf("%s-%s-%s", s.Now().Format("20060102T150405"), sha[:12], store.NewID("")))
	interrupted := func() (store.Bundle, error) {
		os.RemoveAll(qdir)
		return store.Bundle{}, fmt.Errorf("intake of %s interrupted (%w); it is re-ingested from received/ on the next scan", fname, ctx.Err())
	}
	reject := func() (store.Bundle, error) {
		if ctx.Err() != nil {
			// Shutting down: a killed scanner or cancelled step is not a verdict.
			return interrupted()
		}
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
			if msg := s.scan(ctx, f.Path); msg != "" {
				bad = append(bad, name+": "+msg)
			}
		}
		if !check("content_scan", len(bad) == 0, "%s", strings.Join(append(bad, s.cfg.ScanCommand[0]), "; ")) {
			return reject()
		}
	} else {
		check("content_scan", true, "no scanner configured (skipped)")
	}
	if ctx.Err() != nil {
		return interrupted()
	}
	in.Bundle, in.Manifest, in.QuarantineDir = b, m, qdir
	res, err := s.store.IngestBundle(ctx, in)
	if err != nil || res.State != "validated" {
		// On error nothing was recorded; recoverReceived extracts it afresh.
		os.RemoveAll(qdir)
	}
	return res, err
}

// scan runs scan_command on one file with ScanTimeout; "" means clean.
func (s *Service) scan(ctx context.Context, path string) string {
	sctx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
	defer cancel()
	args := append(append([]string{}, s.cfg.ScanCommand[1:]...), path)
	cmd := exec.CommandContext(sctx, s.cfg.ScanCommand[0], args...)
	cmd.WaitDelay = 10 * time.Second // a scanner's children must not hold the output pipe open
	out, err := cmd.CombinedOutput()
	switch {
	case err == nil:
		return ""
	case errors.Is(sctx.Err(), context.DeadlineExceeded):
		return fmt.Sprintf("scanner timed out after %s", s.cfg.ScanTimeout)
	}
	return fmt.Sprintf("%v %s", err, strings.TrimSpace(string(out)))
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
	var compromised []string
	for _, r := range d.Revoked {
		if r.Reason == "compromised" {
			compromised = append(compromised, r.KeyID)
		}
	}
	s.keyMu.Lock()
	s.cfg.Keys = keys
	s.compromised = compromised
	s.keyMu.Unlock()
}

// processTrust verifies a trust document against the root key, stores it if
// newer, applies it, and revokes content signed by compromised keys. The file
// leaves the inbox only once that outcome is recorded; seeing the stored
// document again (a stop before the move) re-applies it instead of
// rejecting it as a replay.
func (s *Service) processTrust(ctx context.Context, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dst := filepath.Join(s.cfg.ReceivedDir, "trust", fmt.Sprintf("%d-%s", s.Now().UnixNano(), filepath.Base(path)))
	fail := func(reason string) error {
		s.store.RaiseAlert(ctx, "warning", "trust_rejected", "trust", filepath.Base(path), "trust document "+filepath.Base(path)+" rejected: "+reason)
		s.store.Audit(ctx, store.Ev{Actor: "system:intake", Action: "trust.rejected", ObjectType: "trust", ObjectID: filepath.Base(path), Failure: true,
			Details: map[string]any{"reason": reason}})
		s.archive(path, dst)
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
	raw, _ := json.Marshal(signed)
	cur, err := s.store.GetMeta(ctx, "trust_seq")
	if err != nil {
		return err
	}
	curSeq, _ := strconv.ParseInt(cur, 10, 64)
	stored, err := s.store.GetMeta(ctx, "trust_doc")
	if err != nil {
		return err
	}
	switch {
	case doc.Sequence == curSeq && stored == string(raw):
		s.log.Info("trust document already applied; completing it", "sequence", doc.Sequence)
		s.ApplyTrust(doc)
		s.reapplyRevocations(ctx)
		s.archive(path, dst)
		return nil
	case doc.Sequence <= curSeq:
		return fail(fmt.Sprintf("sequence %d not newer than current %d (replay)", doc.Sequence, curSeq))
	}
	if err := s.store.SaveTrust(ctx, string(raw), doc.Sequence, doc); err != nil {
		return err
	}
	s.ApplyTrust(doc)
	for _, r := range doc.Revoked {
		if r.Reason == "compromised" {
			n, err := s.store.RevokeKeyContent(ctx, r.KeyID)
			if err != nil {
				return err // stays in the inbox; reapplyRevocations finishes the job
			}
			s.log.Warn("signing key revoked as compromised; its packages were revoked", "key_id", r.KeyID, "packages", n)
			s.store.RaiseAlert(ctx, "critical", "signing_key_compromised", "key", r.KeyID, fmt.Sprintf("bundle signing key %s revoked as COMPROMISED; %d package(s) revoked and their deployments cancelled — start the incident procedure", r.KeyID, n))
		}
	}
	s.archive(path, dst)
	s.log.Info("trust document applied", "sequence", doc.Sequence, "keys", len(doc.Keys), "revoked", len(doc.Revoked))
	return nil
}

// LoadStoredTrust re-applies the latest stored trust document at startup,
// including any compromised-key revocation a previous run did not finish.
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
	s.reapplyRevocations(ctx)
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
	var signed acqstatus.Signed
	if err := json.Unmarshal(b, &signed); err != nil {
		s.archive(path, dst)
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
		s.archive(path, dst)
		return err
	}
	doc, _ := json.Marshal(r)
	summary := fmt.Sprintf("%d new, %d failed", len(r.New), len(r.Failures))
	if r.Error != "" {
		summary += ": " + r.Error
	}
	if err := s.store.RecordAcquisition(ctx, r.Source, r.FinishedAt, r.Outcome, signed.KeyID, doc, summary); err != nil {
		return err // left in the inbox; recorded on a later scan
	}
	s.archive(path, dst)
	return nil
}
