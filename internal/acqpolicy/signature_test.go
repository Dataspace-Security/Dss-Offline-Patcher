package acqpolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"offpatch/internal/manifest"
)

func TestPolicySignature(t *testing.T) {
	pub, priv, _ := manifest.GenerateKey()
	other, _, _ := manifest.GenerateKey()
	p := validPolicy()
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	f := NewFile(3, "user:sam", "2026-10-20T08:00:00Z", p)
	if _, err := f.VerifySignature([]ed25519.PublicKey{pub}); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned: %v", err)
	}
	f.Sign(priv)
	// The signed file survives the JSON round trip and strict parsing.
	b, _ := json.Marshal(f)
	g, err := ParseFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if id, err := g.VerifySignature([]ed25519.PublicKey{other, pub}); err != nil || id != manifest.KeyID(pub) {
		t.Fatalf("verify: %q %v", id, err)
	}
	if _, err := g.VerifySignature([]ed25519.PublicKey{other}); !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "not in acquire.json") {
		t.Fatalf("other key: %v", err)
	}
	// Any envelope change breaks the signature.
	h := *g
	h.PolicyVersion++
	if _, err := h.VerifySignature([]ed25519.PublicKey{pub}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("changed version: %v", err)
	}
	h = *g
	h.EditedBy = "user:mallory"
	if _, err := h.VerifySignature([]ed25519.PublicKey{pub}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("changed editor: %v", err)
	}
	pins, err := ParsePins([]string{string(manifest.EncodePublic(pub)), ""})
	if err != nil || len(pins) != 1 {
		t.Fatalf("pins: %v %d", err, len(pins))
	}
	if _, err := ParsePins([]string{"not a key"}); err == nil {
		t.Error("bad pin accepted")
	}
}

func TestSourceChanges(t *testing.T) {
	prev := validPolicy()
	prev.Normalize()
	same := validPolicy()
	same.Normalize()
	// Toggling, notes and removals need no second approver.
	same.Sources[1].Enabled = !same.Sources[1].Enabled
	same.Sources[1].Note = "edited"
	same.Sources = same.Sources[:2]
	if ch := SourceChanges(prev, same); len(ch) != 0 {
		t.Fatalf("toggle/note/remove counted as source change: %q", ch)
	}
	changed := validPolicy()
	changed.Normalize()
	changed.Sources[1].URL = "https://downloads.acme.example/other.msi"
	changed.Sources = append(changed.Sources, Source{ID: "new-one", Type: SourceVendorURL})
	ch := SourceChanges(prev, changed)
	if len(ch) != 2 || !strings.Contains(ch[0], "changes vendor-url source") || !strings.Contains(ch[1], "adds vendor-url source new-one") {
		t.Fatalf("changes: %q", ch)
	}
}
