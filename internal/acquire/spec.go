package acquire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"offpatch/internal/manifest"
)

// SpecEntry is one element of the spec.json consumed by `pmctl build`: a
// manifest package without "file" (computed at build time) and without
// "vendor_signature" (filled by build via Authenticode on Windows), plus
// "path" to the downloaded file relative to the spec file's directory.
type SpecEntry struct {
	PackageID   string   `json:"package_id"`
	Title       string   `json:"title"`
	Vendor      string   `json:"vendor"`
	Kind        string   `json:"kind"`
	Version     string   `json:"version,omitempty"`
	KB          string   `json:"kb,omitempty"`
	ProductCode string   `json:"product_code,omitempty"`
	PackageName string   `json:"package_name,omitempty"`
	Severity    string   `json:"severity"`
	ReleaseDate string   `json:"release_date"`
	Supersedes  []string `json:"supersedes"`
	// Prerequisites: KBs that must be installed first, e.g. the checkpoint
	// cumulative update(s) a Windows 11 24H2+ update builds on. The server
	// holds the package back on endpoints that lack them.
	Prerequisites []string `json:"prerequisites,omitempty"`
	// ExpectedUBR: for a Windows cumulative update, the build revision the
	// endpoint reports once installed (manifest.Package.ExpectedUBR).
	ExpectedUBR   int                    `json:"expected_ubr,omitempty"`
	Applicability manifest.Applicability `json:"applicability"`
	// Exe: how the agent runs an EXE installer (kind exe only). pmctl build
	// verifies the payload's Authenticode signer against Exe.Signer again.
	Exe       *manifest.ExeInstall `json:"exe,omitempty"`
	SourceURL string               `json:"source_url"`
	// VendorSignature: verified at fetch time (pmctl auto); build keeps it.
	VendorSignature *manifest.VendorSignature `json:"vendor_signature,omitempty"`
	Path            string                    `json:"path"`
	// Acquired records provenance for the operator; `pmctl build` ignores it.
	Acquired *Provenance `json:"acquired,omitempty"`
}

// Provenance records how and when a file was acquired and verified.
type Provenance struct {
	At              string `json:"at"`
	Method          string `json:"method"` // "catalog" | "url"
	CatalogUpdateID string `json:"catalog_update_id,omitempty"`
	SHA1            string `json:"sha1,omitempty"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	Verified        string `json:"verified"` // what was checked, e.g. "sha1(catalog)"
}

// ValidateEntry runs the manifest schema rules (manifest.ValidateSchema) on
// e as it will appear in a bundle, so problems surface at fetch time rather
// than at build time.
func ValidateEntry(e SpecEntry, size int64, sha256hex string) error {
	now := time.Now().UTC()
	sup := e.Supersedes
	if sup == nil {
		sup = []string{}
	}
	m := manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		BundleID:      "spec-check",
		Source:        "spec-check",
		Sequence:      1,
		KeyID:         "ed25519:0000000000000000",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
		Packages: []manifest.Package{{
			PackageID:       e.PackageID,
			Title:           e.Title,
			Vendor:          e.Vendor,
			Kind:            e.Kind,
			Version:         e.Version,
			KB:              e.KB,
			ProductCode:     e.ProductCode,
			PackageName:     e.PackageName,
			Severity:        e.Severity,
			ReleaseDate:     e.ReleaseDate,
			Supersedes:      sup,
			Prerequisites:   e.Prerequisites,
			ExpectedUBR:     e.ExpectedUBR,
			Applicability:   e.Applicability,
			Exe:             e.Exe,
			File:            manifest.FileRef{Name: "payload/" + filepath.Base(filepath.FromSlash(e.Path)), Size: size, SHA256: sha256hex},
			SourceURL:       e.SourceURL,
			VendorSignature: manifest.VendorSignature{Status: "not_checked"},
		}},
	}
	if err := m.ValidateSchema(now); err != nil {
		return fmt.Errorf("spec entry %q would be rejected by pmctl build: %w", e.PackageID, err)
	}
	return nil
}

// RelPath returns file relative to the spec file's directory (slash form),
// or the absolute path if no relative path exists.
func RelPath(specPath, file string) (string, error) {
	absSpec, err := filepath.Abs(specPath)
	if err != nil {
		return "", err
	}
	absFile, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(filepath.Dir(absSpec), absFile)
	if err != nil {
		return absFile, nil
	}
	return filepath.ToSlash(rel), nil
}

// UpsertSpec adds e to the JSON array in specPath, replacing an existing
// entry with the same package_id. Other entries are preserved verbatim
// (including fields this package does not know). The file is replaced
// atomically. It reports whether an entry was replaced.
func UpsertSpec(specPath string, e SpecEntry) (bool, error) {
	if e.PackageID == "" {
		return false, errors.New("spec entry has no package_id")
	}
	var entries []json.RawMessage
	mode := os.FileMode(0o644)
	if b, err := os.ReadFile(specPath); err == nil {
		if fi, err := os.Stat(specPath); err == nil {
			mode = fi.Mode().Perm()
		}
		if len(bytes.TrimSpace(b)) > 0 {
			if err := json.Unmarshal(b, &entries); err != nil {
				return false, fmt.Errorf("%s: not a JSON array of packages: %w", specPath, err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	nb, err := json.Marshal(e)
	if err != nil {
		return false, err
	}
	replaced := false
	out := make([]json.RawMessage, 0, len(entries)+1)
	for i, raw := range entries {
		var id struct {
			PackageID string `json:"package_id"`
		}
		if err := json.Unmarshal(raw, &id); err != nil {
			return false, fmt.Errorf("%s: entry %d: %w", specPath, i, err)
		}
		if id.PackageID == e.PackageID {
			if !replaced {
				out = append(out, nb)
				replaced = true
			}
			continue // drop duplicates of the same id
		}
		out = append(out, raw)
	}
	if !replaced {
		out = append(out, nb)
	}
	var buf bytes.Buffer
	buf.WriteString("[\n")
	for i, raw := range out {
		var ind bytes.Buffer
		if err := json.Indent(&ind, raw, "  ", "  "); err != nil {
			return false, err
		}
		buf.WriteString("  ")
		buf.Write(ind.Bytes())
		if i < len(out)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("]\n")
	return replaced, writeFileAtomic(specPath, buf.Bytes(), mode)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// kindFromName maps a file extension to a manifest kind.
func kindFromName(name string) (string, error) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".msu":
		return "msu", nil
	case ".msi":
		return "msi", nil
	case ".deb":
		return "deb", nil
	case ".rpm":
		return "rpm", nil
	case ".pkg":
		return "pkg", nil
	}
	return "", fmt.Errorf("%s: cannot infer kind from extension; pass -kind (msu|msi|exe|deb|rpm|pkg|agent)", name)
}

// osForKind maps a package kind to applicability.os (agent: caller decides).
func osForKind(kind, override string) string {
	if override != "" {
		return override
	}
	switch kind {
	case "deb", "rpm":
		return "linux"
	case "pkg":
		return "macos"
	}
	return "windows"
}
