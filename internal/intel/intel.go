// Package intel is "update intelligence": what the newest Windows cumulative
// updates and Windows application versions are. The connected acquisition
// zone builds it (pmctl intel / pmctl auto) from the Microsoft Update Catalog
// and the winget community index, signs it with a bundle key, and sends it
// through the one-way transfer. The isolated server matches it against
// endpoint inventory to show every update an endpoint is missing, including
// ones not yet imported into the catalog.
//
// File format (*.intel.gz): gzip of one JSON header line
// {"key_id":…,"signature":…} followed by the document JSON. The Ed25519
// signature covers SignPrefix followed by the exact document bytes, so a
// signature can never be mistaken for one over a bundle manifest.
package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"offpatch/internal/manifest"
)

// SignPrefix separates intel signatures from other uses of bundle keys.
const SignPrefix = "offpatch-intel-v1\n"

const (
	FileSuffix = ".intel.gz"
	// MaxDocument bounds the uncompressed document (the winget index is ~10 MB).
	MaxDocument = 64 << 20
)

// Doc is one update-intelligence snapshot.
type Doc struct {
	Version     int    `json:"version"` // 1
	Source      string `json:"source"`  // acquisition zone id, e.g. acq-zone-1
	GeneratedAt string `json:"generated_at"`
	// AppsSource describes where the app list came from, e.g. "winget source2 (2026-10-17T09:38:20Z)".
	AppsSource string           `json:"apps_source,omitempty"`
	Windows    []WindowsRelease `json:"windows"`
	Apps       []App            `json:"apps"`
	Warnings   []string         `json:"warnings,omitempty"`
	// Resolved: installer and description details pmctl looked up in the
	// winget manifests for configured, requested and commonly used apps (the
	// Library). Community-supplied text: data only, never trusted for
	// deployment (the signed bundle is what gets installed).
	Resolved []Resolved `json:"resolved,omitempty"`
}

// Resolved is one winget package version's installer details.
type Resolved struct {
	ID           string              `json:"id"`
	Version      string              `json:"version"`
	Publisher    string              `json:"publisher,omitempty"`
	Homepage     string              `json:"homepage,omitempty"`
	PublisherURL string              `json:"publisher_url,omitempty"`
	License      string              `json:"license,omitempty"`
	Description  string              `json:"description,omitempty"`
	Installers   []ResolvedInstaller `json:"installers"`
	ResolvedAt   string              `json:"resolved_at"`
}

// ResolvedInstaller is one installer entry of a winget manifest.
type ResolvedInstaller struct {
	Arch string `json:"arch"`
	// Type: msi|wix|exe|inno|nullsoft|burn|msix|zip|portable…
	Type        string `json:"type"`
	Scope       string `json:"scope,omitempty"` // machine | user
	URL         string `json:"url"`
	SHA256      string `json:"sha256,omitempty"`
	ProductCode string `json:"product_code,omitempty"`
}

// WindowsRelease is the newest cumulative update for one Windows build.
type WindowsRelease struct {
	Product     string `json:"product"` // "Windows 11 Version 24H2"
	Build       int    `json:"build"`   // 26100
	Server      bool   `json:"server,omitempty"`
	Arch        string `json:"arch"` // x64 | arm64 | x86
	KB          string `json:"kb"`
	UBR         int    `json:"ubr,omitempty"` // build revision after install (0 = unknown)
	ReleaseDate string `json:"release_date,omitempty"`
	Title       string `json:"title"`
	SizeMB      int    `json:"size_mb,omitempty"`
}

// App is one application's newest version (from winget).
type App struct {
	ID      string `json:"id"` // winget id, e.g. Google.Chrome
	Name    string `json:"n"`
	Version string `json:"v"`
	// ARPMin/ARPMax: when set, the versions Windows shows in Apps & features
	// ("DisplayVersion") for this package range; compare installed versions
	// against ARPMax instead of Version.
	ARPMin string `json:"amin,omitempty"`
	ARPMax string `json:"amax,omitempty"`
	// Codes: lower-case MSI product codes and uninstall-registry key names.
	Codes []string `json:"c,omitempty"`
	// Names: normalised display names (see Normalize).
	Names      []string `json:"m,omitempty"`
	Publishers []string `json:"p,omitempty"`
}

type header struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// Write signs doc and writes the *.intel.gz form to w.
func Write(w io.Writer, doc Doc, keyID string, sign func([]byte) (string, error)) error {
	doc.Version = 1
	if doc.Windows == nil {
		doc.Windows = []WindowsRelease{}
	}
	if doc.Apps == nil {
		doc.Apps = []App{}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if len(body) > MaxDocument {
		return fmt.Errorf("intel document is %d bytes, over the %d limit", len(body), MaxDocument)
	}
	sig, err := sign(append([]byte(SignPrefix), body...))
	if err != nil {
		return fmt.Errorf("sign intel: %w", err)
	}
	h, _ := json.Marshal(header{KeyID: keyID, Signature: sig})
	zw := gzip.NewWriter(w)
	if _, err := zw.Write(append(h, '\n')); err != nil {
		return err
	}
	if _, err := zw.Write(body); err != nil {
		return err
	}
	return zw.Close()
}

// Read verifies an *.intel.gz stream against the trusted bundle keys and
// returns the document and the signing key id.
func Read(r io.Reader, keys map[string]ed25519.PublicKey) (Doc, string, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return Doc{}, "", fmt.Errorf("intel: not gzip: %w", err)
	}
	defer zr.Close()
	br := bufio.NewReaderSize(io.LimitReader(zr, MaxDocument+4096), 64<<10)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return Doc{}, "", errors.New("intel: missing header line")
	}
	var h header
	if err := json.Unmarshal(line, &h); err != nil || h.KeyID == "" || h.Signature == "" {
		return Doc{}, "", errors.New("intel: bad header")
	}
	pub, ok := keys[h.KeyID]
	if !ok {
		return Doc{}, "", fmt.Errorf("intel: signed by untrusted key %q", h.KeyID)
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return Doc{}, "", fmt.Errorf("intel: %w", err)
	}
	if len(body) > MaxDocument {
		return Doc{}, "", errors.New("intel: document too large")
	}
	if err := manifest.Verify(pub, append([]byte(SignPrefix), body...), h.Signature); err != nil {
		return Doc{}, "", fmt.Errorf("intel: %w", err)
	}
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Doc{}, "", fmt.Errorf("intel: %w", err)
	}
	if err := d.validate(); err != nil {
		return Doc{}, "", err
	}
	return d, h.KeyID, nil
}

func (d Doc) validate() error {
	if d.Version != 1 {
		return fmt.Errorf("intel: unsupported version %d", d.Version)
	}
	if strings.TrimSpace(d.Source) == "" {
		return errors.New("intel: missing source")
	}
	if _, err := time.Parse(time.RFC3339, d.GeneratedAt); err != nil {
		return errors.New("intel: bad generated_at")
	}
	for i, w := range d.Windows {
		if w.Build <= 0 || !strings.HasPrefix(strings.ToUpper(w.KB), "KB") {
			return fmt.Errorf("intel: windows[%d]: build and KB required", i)
		}
	}
	for i, a := range d.Apps {
		if a.ID == "" || a.Version == "" {
			return fmt.Errorf("intel: apps[%d]: id and version required", i)
		}
	}
	return nil
}

// GeneratedTime parses GeneratedAt (validated by Read).
func (d Doc) GeneratedTime() time.Time {
	t, _ := time.Parse(time.RFC3339, d.GeneratedAt)
	return t.UTC()
}
