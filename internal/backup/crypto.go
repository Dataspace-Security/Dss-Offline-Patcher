package backup

// Encrypted, signed backups (finding S-6).
//
// A backup (format 2) is a directory with three files:
//
//	data.tar.age  the database snapshot, repository, quarantine, received
//	              evidence and staged agent binaries
//	keys.tar.age  the keys and secrets: mfa.key, audit-signing.key/.pub,
//	              policy-signing.key/.pub, the PKI directory (ca.key) and the
//	              config file; encrypted separately (its own file key, and
//	              optionally its own recipients: -keys-recipients)
//	backup.json   the manifest: every file's path, size and SHA-256 (of the
//	              plaintext), each part's SHA-256 (of the ciphertext), the
//	              audit head, signed with the server's audit-signing key
//
// Encryption is age (age-encryption.org/v1, filippo.io/age) to the bank's
// backup recipient(s); the matching identity (private key) is kept offline
// by the bank and is needed only to restore. The server holds no key that
// decrypts its backups. verify-backup checks the signature and the part
// hashes without the identity; with -identity it also decrypts and checks
// every file.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

// LoadRecipients reads an age recipients file (one public key per line,
// "#" comments allowed).
func LoadRecipients(path string) ([]age.Recipient, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("backup recipients: %w", err)
	}
	rs, err := age.ParseRecipients(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("backup recipients %s: %w", path, err)
	}
	return rs, nil
}

// LoadIdentities reads an age identity file (the bank's private backup key).
func LoadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("backup identity: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("backup identity %s: %w", path, err)
	}
	return ids, nil
}

// GenerateIdentity returns a new age identity file body and its recipient.
// The keys are hybrid post-quantum (ML-KEM-768 + X25519) age keys:
// `age` 1.3 or later, or `pmserver decrypt-backup`, decrypts them.
func GenerateIdentity(comment string) (identityFile, recipient string, err error) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return "", "", err
	}
	recipient = id.Recipient().String()
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimSpace(comment), "\n") {
		if l != "" {
			b.WriteString("# " + l + "\n")
		}
	}
	b.WriteString("# public key: " + recipient + "\n")
	b.WriteString(id.String() + "\n")
	return b.String(), recipient, nil
}

// WriteNewFile writes b to path (mode), refusing to replace an existing file.
func WriteNewFile(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Signature is the manifest signature.
type Signature struct {
	KeyID string `json:"key_id"`
	Value string `json:"value"` // base64 Ed25519 over the manifest JSON with signature omitted
}

// Part is one encrypted archive of a format 2 backup.
type Part struct {
	Name   string `json:"name"` // data.tar.age | keys.tar.age
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"` // of the encrypted file
}

const (
	partData = "data"
	partKeys = "keys"
	// FormatPlain is the earlier unencrypted, unsigned format (still
	// verified and restored, with a warning).
	FormatPlain = 1
	// FormatEncrypted is the encrypted, signed format.
	FormatEncrypted = 2
)

func partFile(part string) string { return part + ".tar.age" }

var (
	// ErrNoRecipients: Create was called without backup recipients.
	ErrNoRecipients = errors.New("backups are encrypted: no backup recipient given (create one with `pmserver backup-keygen`, then pass -recipients <file>)")
	// ErrNeedPublicKey: a format 2 backup is verified only against the
	// server's audit-signing public key.
	ErrNeedPublicKey = errors.New("the backup manifest is signed: give the server's audit-signing.pub (-pub, or -config so it is read from data_dir)")
	// ErrNeedIdentity: decrypting needs the bank's backup identity.
	ErrNeedIdentity = errors.New("the backup is encrypted: give the backup identity (private key) file with -identity")
)

// Options configure Create.
type Options struct {
	// Recipients: who can decrypt the backup (required).
	Recipients []age.Recipient
	// KeyRecipients: who can decrypt keys.tar.age (nil = Recipients).
	KeyRecipients []age.Recipient
	// SigningKey signs backup.json (the audit-signing key).
	SigningKey ed25519.PrivateKey
	// IncludePKI: back up pki_dir (with ca.key).
	IncludePKI bool
}

// countingWriter counts bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
