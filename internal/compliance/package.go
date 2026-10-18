package compliance

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"offpatch/internal/manifest"
)

// The signed evidence package (template §6 "Export integrity and
// handling"): report.md, summary.json, evidence/*.csv, manifest.json (the
// SHA-256 of every file) and manifest.sig (Ed25519 over manifest.json with
// the server's audit-signing key, the key that signs audit checkpoints).

const (
	ManifestFile  = "manifest.json"
	SignatureFile = "manifest.sig"
	PublicKeyFile = "signing-key.pub"
)

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	Format               int               `json:"format"`
	Product              string            `json:"product"`
	ProductVersion       string            `json:"product_version"`
	ReportID             string            `json:"report_id"`
	GeneratedAt          string            `json:"generated_at"`
	GeneratedBy          User              `json:"generated_by"`
	Period               Period            `json:"period"`
	Filters              map[string]string `json:"filters"`
	Redacted             bool              `json:"redacted"`
	Files                []ManifestEntry   `json:"files"`
	KeyID                string            `json:"key_id"`
	PublicKey            string            `json:"public_key"`             // base64 Ed25519 public key
	PublicKeyFingerprint string            `json:"public_key_fingerprint"` // SHA-256 (hex) of the public key
	Signature            string            `json:"signature_algorithm"`
}

// KeyFingerprint is the SHA-256 (hex) of an Ed25519 public key.
func KeyFingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

type hashCounter struct {
	h hashWriter
	n int64
}

type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

func (c *hashCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return c.h.Write(p)
}

// WriteZip streams the signed package to w. beforeSeal runs with the
// SHA-256 of manifest.json after every file is written and before the ZIP
// is finished (the caller audits the generation there; an error leaves the
// download incomplete). It returns the manifest.
func (pk *Pack) WriteZip(w io.Writer, key ed25519.PrivateKey, beforeSeal func(manifestSHA string) error) (Manifest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("no report signing key")
	}
	pub := key.Public().(ed25519.PublicKey)
	mod, _ := time.Parse(time.RFC3339, pk.Meta.GeneratedAt)
	zw := zip.NewWriter(w)
	m := Manifest{Format: 1, Product: Product, ProductVersion: pk.Meta.ProductVersion, ReportID: pk.Meta.ReportID, GeneratedAt: pk.Meta.GeneratedAt,
		GeneratedBy: pk.Meta.GeneratedBy, Period: pk.Meta.Period, Filters: pk.Meta.Filters, Redacted: pk.Meta.Redacted, Files: []ManifestEntry{},
		KeyID: manifest.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), PublicKeyFingerprint: KeyFingerprint(pub), Signature: "ed25519"}
	put := func(path string, write func(io.Writer) error) (string, error) {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: path, Method: zip.Deflate, Modified: mod})
		if err != nil {
			return "", err
		}
		hc := &hashCounter{h: sha256.New()}
		if err := write(io.MultiWriter(f, hc)); err != nil {
			return "", err
		}
		sum := hex.EncodeToString(hc.h.Sum(nil))
		m.Files = append(m.Files, ManifestEntry{Path: path, SHA256: sum, Size: hc.n})
		return sum, nil
	}
	for _, e := range pk.EvidenceRegister {
		id := e.ID
		var rows int
		sum, err := put(EvidenceFiles()[id], func(w io.Writer) error {
			var err error
			rows, _, err = pk.WriteEvidence(id, w)
			return err
		})
		if err != nil {
			return m, err
		}
		if sum != e.SHA256 || rows != e.Records {
			return m, fmt.Errorf("evidence %s changed while the package was written", id)
		}
	}
	if _, err := put("report.md", func(w io.Writer) error {
		_, err := io.WriteString(w, pk.Markdown())
		return err
	}); err != nil {
		return m, err
	}
	if _, err := put("report.pdf", func(w io.Writer) error {
		b, err := pk.PDF()
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	}); err != nil {
		return m, err
	}
	if _, err := put("summary.json", func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(pk)
	}); err != nil {
		return m, err
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	for _, f := range []struct {
		name string
		body []byte
	}{
		{ManifestFile, mb},
		{SignatureFile, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, mb)) + "\n")},
		{PublicKeyFile, manifest.EncodePublic(pub)},
	} {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: mod})
		if err != nil {
			return m, err
		}
		if _, err := fw.Write(f.body); err != nil {
			return m, err
		}
	}
	if beforeSeal != nil {
		h := sha256.Sum256(mb)
		if err := beforeSeal(hex.EncodeToString(h[:])); err != nil {
			return m, err
		}
	}
	return m, zw.Close()
}

// VerifyZip checks a package offline: the manifest signature against pub
// (obtain the server's audit-signing.pub independently; the key inside the
// package is only a convenience), every listed file's SHA-256 and size, and
// that no unlisted file is present.
func VerifyZip(b []byte, pub ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return m, err
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if _, dup := files[f.Name]; dup {
			return m, fmt.Errorf("duplicate entry %s", f.Name)
		}
		files[f.Name] = f
	}
	read := func(name string) ([]byte, error) {
		f, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("%s missing", name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, 4<<30))
	}
	mb, err := read(ManifestFile)
	if err != nil {
		return m, err
	}
	sb, err := read(SignatureFile)
	if err != nil {
		return m, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sb)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, mb, sig) {
		return m, errors.New("manifest signature does not verify with the given public key")
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		return m, err
	}
	listed := map[string]bool{ManifestFile: true, SignatureFile: true, PublicKeyFile: true}
	for _, e := range m.Files {
		listed[e.Path] = true
		body, err := read(e.Path)
		if err != nil {
			return m, err
		}
		h := sha256.Sum256(body)
		if hex.EncodeToString(h[:]) != e.SHA256 || int64(len(body)) != e.Size {
			return m, fmt.Errorf("%s: content does not match the manifest", e.Path)
		}
	}
	for name := range files {
		if !listed[name] {
			return m, fmt.Errorf("%s is not listed in the manifest", name)
		}
	}
	return m, nil
}
