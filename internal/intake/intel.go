package intake

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"offpatch/internal/intel"
	"offpatch/internal/store"
)

// Meta keys shared with the server, which (re)loads the matching index
// whenever MetaIntelGenerated changes.
const (
	MetaIntelGenerated = "intel_generated_at"
	MetaIntelSummary   = "intel_summary"
	// CurrentIntelFile is the newest accepted document, as signed, in IntelDir.
	CurrentIntelFile = "current" + intel.FileSuffix
	maxIntelFile     = 64 << 20
	// A document dated further ahead than this is refused: it would lock out
	// every later (correctly dated) document until that time.
	maxIntelClockSkew = 24 * time.Hour
)

// IntelSummary is what the console shows about the current document.
type IntelSummary struct {
	Source      string   `json:"source"`
	KeyID       string   `json:"key_id"`
	GeneratedAt string   `json:"generated_at"`
	ReceivedAt  string   `json:"received_at"`
	Windows     int      `json:"windows"`
	Apps        int      `json:"apps"`
	AppsSource  string   `json:"apps_source,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	// Error is set by the server when the stored document cannot be used
	// (e.g. its signing key was revoked); nothing is matched then.
	Error string `json:"error,omitempty"`
}

// ActiveKeys returns the bundle keys currently trusted for new content
// (after trust-document rotations; retired and revoked keys excluded).
func (s *Service) ActiveKeys() map[string]ed25519.PublicKey {
	keys := map[string]ed25519.PublicKey{}
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	for id, k := range s.cfg.Keys {
		if !k.Retired {
			keys[id] = k.Pub
		}
	}
	return keys
}

// processIntel verifies update intelligence (signed with a trusted bundle
// key) and makes it current if it is newer than what we have.
func (s *Service) processIntel(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxIntelFile+1))
	f.Close()
	if err != nil {
		return err
	}
	dst := filepath.Join(s.cfg.ReceivedDir, "intel", filepath.Base(path))
	os.MkdirAll(filepath.Dir(dst), 0o750)
	if err := os.Rename(path, dst); err != nil {
		return err
	}
	reject := func(why string) error {
		s.store.RaiseAlert(ctx, "warning", "intel_rejected", "intel", filepath.Base(path), "update intelligence rejected: "+why)
		s.store.Audit(ctx, store.Ev{Actor: "system:intake", Action: "intel.rejected", ObjectType: "intel", ObjectID: filepath.Base(path), Failure: true,
			Details: map[string]any{"reason": why}})
		return fmt.Errorf("intel rejected: %s", why)
	}
	if len(b) > maxIntelFile {
		return reject("file too large")
	}
	d, kid, err := intel.Read(bytes.NewReader(b), s.ActiveKeys())
	if err != nil {
		return reject(err.Error())
	}
	gen := d.GeneratedTime()
	if gen.After(s.Now().Add(maxIntelClockSkew)) {
		return reject(fmt.Sprintf("generated_at %s is in the future (acquisition clock wrong?)", d.GeneratedAt))
	}
	if cur, _ := s.store.GetMeta(ctx, MetaIntelGenerated); cur != "" {
		if ct, err := time.Parse(time.RFC3339, cur); err == nil && !gen.After(ct) {
			return reject(fmt.Sprintf("not newer than the current document (%s, current %s)", d.GeneratedAt, cur))
		}
	}
	if err := os.MkdirAll(s.cfg.IntelDir, 0o750); err != nil {
		return err
	}
	tmp := filepath.Join(s.cfg.IntelDir, ".incoming"+intel.FileSuffix)
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.cfg.IntelDir, CurrentIntelFile)); err != nil {
		return err
	}
	sum := IntelSummary{Source: d.Source, KeyID: kid, GeneratedAt: gen.Format(time.RFC3339), ReceivedAt: s.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Windows: len(d.Windows), Apps: len(d.Apps), AppsSource: d.AppsSource, Warnings: d.Warnings}
	js, _ := json.Marshal(sum)
	if err := s.store.SetMeta(ctx, MetaIntelSummary, string(js)); err != nil {
		return err
	}
	if err := s.store.SetMeta(ctx, MetaIntelGenerated, gen.Format(time.RFC3339)); err != nil {
		return err
	}
	s.log.Info("update intelligence accepted", "source", d.Source, "generated_at", d.GeneratedAt, "windows", len(d.Windows), "apps", len(d.Apps))
	return s.store.Audit(ctx, store.Ev{Actor: "system:intake", Action: "intel.accepted", ObjectType: "intel", ObjectID: d.GeneratedAt,
		Details: map[string]any{"source": d.Source, "key_id": kid, "windows": len(d.Windows), "apps": len(d.Apps), "file": filepath.Base(path)}})
}
