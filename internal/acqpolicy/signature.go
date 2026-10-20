package acqpolicy

// Signed policy files (finding S-4). pmserver signs every policy file it
// writes for pmctl with its policy signing key (Ed25519,
// <data_dir>/policy-signing.key, created on first start). pmctl pins the
// public key in acquire.json (policy_public_keys, written by the
// installer): with a pin, an unsigned or wrongly signed file is refused and
// the last good policy stays in force; without one the file is accepted
// with a warning in the status report (upgrades from versions without
// signing).
//
// The signature covers the envelope (format, version, policy_version,
// edited_by, edited_at and sha256); sha256 covers the policy content and
// Validate checks it, so the whole file is covered.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"offpatch/internal/manifest"
)

// SignatureAlg is the only signature algorithm.
const SignatureAlg = "ed25519"

// Signature is the server's signature of a policy file.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"` // manifest.KeyID of the public key
	Value string `json:"value"`  // base64 Ed25519 signature of SigningPayload
}

var (
	// ErrUnsigned: the file carries no signature.
	ErrUnsigned = errors.New("the policy file is not signed")
	// ErrBadSignature: the signature is not from a pinned key or does not verify.
	ErrBadSignature = errors.New("the policy file's signature is not valid")
)

// SigningPayload is the byte string the server signs.
func (f *File) SigningPayload() []byte {
	return []byte(strings.Join([]string{"offpatch.acquisition-policy.signature.v1", f.Format, fmt.Sprint(f.Version),
		fmt.Sprint(f.PolicyVersion), f.EditedBy, f.EditedAt, strings.ToLower(f.SHA256)}, "\n"))
}

// Sign sets f.Signature with key k.
func (f *File) Sign(k ed25519.PrivateKey) {
	f.Signature = &Signature{Alg: SignatureAlg, KeyID: manifest.KeyID(k.Public().(ed25519.PublicKey)), Value: manifest.Sign(k, f.SigningPayload())}
}

// VerifySignature checks f.Signature against the pinned keys. It returns
// the key id that verified, ErrUnsigned or ErrBadSignature (wrapped).
func (f *File) VerifySignature(pins []ed25519.PublicKey) (string, error) {
	if f.Signature == nil || f.Signature.Value == "" {
		return "", ErrUnsigned
	}
	if f.Signature.Alg != SignatureAlg {
		return "", fmt.Errorf("%w: algorithm %q", ErrBadSignature, f.Signature.Alg)
	}
	for _, pub := range pins {
		id := manifest.KeyID(pub)
		if id != f.Signature.KeyID {
			continue
		}
		if err := manifest.Verify(pub, f.SigningPayload(), f.Signature.Value); err != nil {
			return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
		}
		return id, nil
	}
	return "", fmt.Errorf("%w: signed with key %s, which is not in acquire.json policy_public_keys", ErrBadSignature, f.Signature.KeyID)
}

// ParsePins reads acquire.json policy_public_keys entries (base64 or PEM
// Ed25519 public keys).
func ParsePins(entries []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for i, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		pub, err := manifest.ParsePublic(e)
		if err != nil {
			return nil, fmt.Errorf("policy_public_keys[%d]: %w", i, err)
		}
		out = append(out, pub)
	}
	return out, nil
}

// SourceChanges lists the sources p adds, or whose addresses or
// verification data it changes, compared with prev (by id). Switching a
// source on or off, editing its note or removing it is not a source
// change: those edits apply directly, everything listed here needs a
// second super admin (S-4).
func SourceChanges(prev, p Policy) []string {
	old := map[string]Source{}
	for _, s := range prev.Sources {
		old[s.ID] = s
	}
	var out []string
	for _, s := range p.Sources {
		o, had := old[s.ID]
		if !had {
			out = append(out, fmt.Sprintf("adds %s source %s", s.Type, s.ID))
			continue
		}
		a, b := o, s
		a.Enabled, b.Enabled, a.Note, b.Note, a.AddedBy, b.AddedBy = false, false, "", "", "", ""
		if a != b {
			out = append(out, fmt.Sprintf("changes %s source %s", s.Type, s.ID))
		}
	}
	return out
}
