// Package trust implements signed trust documents: the list of bundle-signing
// keys the isolated zone accepts, signed by an offline ROOT key. Rotating or
// revoking a bundle key is done by issuing a new document (higher sequence),
// carried through the same one-way transfer as bundles; pmserver and every
// agent verify it against the root key they pinned. A compromised bundle key
// therefore cannot add itself or another key to the trust set.
package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"offpatch/internal/manifest"
)

const FileSuffix = ".trust.json"

type Key struct {
	KeyID     string   `json:"key_id"`
	PublicKey string   `json:"public_key"` // PEM
	Sources   []string `json:"sources"`
	// Status: active (accepts new bundles) | retired (no new bundles; content
	// already signed stays valid on endpoints).
	Status string `json:"status"`
}

type Revoked struct {
	KeyID  string `json:"key_id"`
	Reason string `json:"reason"` // compromised | other
}

type Document struct {
	Version  int       `json:"version"`
	Sequence int64     `json:"sequence"`
	IssuedAt string    `json:"issued_at"`
	Keys     []Key     `json:"keys"`
	Revoked  []Revoked `json:"revoked"`
}

// Signed is the on-the-wire form (<name>.trust.json).
type Signed struct {
	Document  string `json:"document"` // base64 of the exact signed JSON
	Signature string `json:"signature"`
	RootKeyID string `json:"root_key_id"`
}

func (d *Document) Validate() error {
	if d.Version != 1 || d.Sequence < 1 {
		return errors.New("trust: version must be 1 and sequence >= 1")
	}
	seen := map[string]bool{}
	active := 0
	for i, k := range d.Keys {
		pub, err := manifest.ParsePublic(k.PublicKey)
		if err != nil {
			return fmt.Errorf("trust: keys[%d]: %w", i, err)
		}
		if manifest.KeyID(pub) != k.KeyID {
			return fmt.Errorf("trust: keys[%d]: key_id does not match public key", i)
		}
		if seen[k.KeyID] {
			return fmt.Errorf("trust: duplicate key %s", k.KeyID)
		}
		seen[k.KeyID] = true
		switch k.Status {
		case "active":
			active++
			if len(k.Sources) == 0 {
				return fmt.Errorf("trust: active key %s needs sources", k.KeyID)
			}
		case "retired":
		default:
			return fmt.Errorf("trust: key %s status must be active or retired", k.KeyID)
		}
	}
	for _, r := range d.Revoked {
		if seen[r.KeyID] {
			return fmt.Errorf("trust: key %s is both listed and revoked", r.KeyID)
		}
	}
	if active == 0 {
		return errors.New("trust: at least one active key is required")
	}
	return nil
}

// Sign produces the signed form with the root private key.
func Sign(d Document, root ed25519.PrivateKey) (Signed, error) {
	if d.IssuedAt == "" {
		d.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := d.Validate(); err != nil {
		return Signed{}, err
	}
	b, _ := json.Marshal(d)
	return Signed{Document: base64.StdEncoding.EncodeToString(b), Signature: manifest.Sign(root, b),
		RootKeyID: manifest.KeyID(root.Public().(ed25519.PublicKey))}, nil
}

// Verify checks the signature against the pinned root key and validates.
func Verify(s Signed, root ed25519.PublicKey) (Document, error) {
	b, err := base64.StdEncoding.DecodeString(s.Document)
	if err != nil {
		return Document{}, errors.New("trust: bad encoding")
	}
	if err := manifest.Verify(root, b, s.Signature); err != nil {
		return Document{}, fmt.Errorf("trust: %w", err)
	}
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return Document{}, fmt.Errorf("trust: %w", err)
	}
	return d, d.Validate()
}

// Parse decodes a .trust.json file.
func Parse(b []byte) (Signed, error) {
	var s Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("trust: %w", err)
	}
	return s, nil
}

func (d Document) IsRevoked(keyID string) (bool, string) {
	for _, r := range d.Revoked {
		if r.KeyID == keyID {
			return true, r.Reason
		}
	}
	return false, ""
}
