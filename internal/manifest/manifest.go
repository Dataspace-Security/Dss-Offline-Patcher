// Package manifest defines the signed bundle manifest (schema v1), Ed25519
// key handling, and validation rules shared by pmctl, pmserver and pmagent.
// See docs/04-bundle-format.md.
package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const SchemaVersion = 1

type Applicability struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	MinBuild int    `json:"min_build"`
	MaxBuild int    `json:"max_build"`
	// Editions restricts Windows packages to EditionIDs (e.g. Enterprise,
	// Professional, ServerStandard). Empty = any edition.
	Editions []string `json:"editions,omitempty"`
}

type FileRef struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type VendorSignature struct {
	Status    string `json:"status"`
	Signer    string `json:"signer"`
	CheckedAt string `json:"checked_at"`
}

type Package struct {
	PackageID       string          `json:"package_id"`
	Title           string          `json:"title"`
	Vendor          string          `json:"vendor"`
	Kind            string          `json:"kind"`
	Version         string          `json:"version"`
	KB              string          `json:"kb"`
	ProductCode     string          `json:"product_code"`
	Severity        string          `json:"severity"`
	ReleaseDate     string          `json:"release_date"`
	Supersedes      []string        `json:"supersedes"`
	Applicability   Applicability   `json:"applicability"`
	File            FileRef         `json:"file"`
	SourceURL       string          `json:"source_url"`
	VendorSignature VendorSignature `json:"vendor_signature"`
	// PackageName identifies deb/rpm packages and macOS pkg receipts
	// (e.g. "openssl", "com.vendor.app").
	PackageName string `json:"package_name,omitempty"`
	// Prerequisites: KBs (or package names) that must already be installed.
	Prerequisites []string `json:"prerequisites,omitempty"`
	// ExpectedUBR: for a Windows cumulative update (msu), the build revision
	// (the "9711" of 26300.9711) the endpoint reports once it is installed.
	// The server then also verifies the target by UBR when Windows does not
	// list the KB itself. 0 = unknown (verify by KB only).
	ExpectedUBR int `json:"expected_ubr,omitempty"`
	// Exe: install/detect/rollback details, only for kind "exe" (see exe.go).
	Exe *ExeInstall `json:"exe,omitempty"`
	// Archive: the payload is a zip holding the installer and the files it
	// needs (kinds msi, exe, portable; see formats.go).
	Archive *Archive `json:"archive,omitempty"`
	// Portable: how a portable app is installed (kind portable only).
	Portable *Portable `json:"portable,omitempty"`
	// Msix: the package identity (kind msix only).
	Msix *Msix `json:"msix,omitempty"`
}

type Manifest struct {
	SchemaVersion int       `json:"schema_version"`
	BundleID      string    `json:"bundle_id"`
	Source        string    `json:"source"`
	Sequence      int64     `json:"sequence"`
	KeyID         string    `json:"key_id"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Packages      []Package `json:"packages"`
}

const (
	MaxPackages = 500
	MaxLifetime = 90 * 24 * time.Hour
)

var (
	idRe          = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	baseRe        = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)
	hexRe         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	kbRe          = regexp.MustCompile(`^KB[0-9]{4,10}$`)
	pkgNameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`)
	versionRe     = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}([-+][A-Za-z0-9.]+)?$`)
	displayNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .+_()-]{0,127}$`)
	editionRe     = regexp.MustCompile(`^[A-Za-z0-9]{2,40}$`)
	productRe     = regexp.MustCompile(`^\{[0-9A-Fa-f-]{36}\}$`)
	severities    = map[string]bool{"critical": true, "important": true, "moderate": true, "low": true}
	sigStatus     = map[string]bool{"valid": true, "invalid": true, "not_checked": true}
)

// validBase reports whether base is an acceptable payload file name: the
// [A-Za-z0-9._-] charset, not a dot-segment, no trailing dot (Windows strips
// it, so "a.msu." aliases "a.msu"), and not a reserved Windows device name
// (CON, NUL, COM1, LPT1.txt ...), which would open a device on a Windows host.
func validBase(base string) bool {
	if !baseRe.MatchString(base) || base == "." || base == ".." || strings.HasSuffix(base, ".") {
		return false
	}
	return !reservedDeviceName(base)
}

// reservedDeviceName: CON, PRN, AUX, NUL, COM0-9, LPT0-9, with any extension.
func reservedDeviceName(name string) bool {
	stem, _, _ := strings.Cut(strings.ToUpper(name), ".")
	stem = strings.TrimRight(stem, " ")
	switch stem {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	return len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '0' && stem[3] <= '9'
}

// ValidateSchema checks structural rules that don't depend on server state.
func (m *Manifest) ValidateSchema(now time.Time) error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	if m.SchemaVersion != SchemaVersion {
		add("schema_version must be %d", SchemaVersion)
	}
	if !idRe.MatchString(m.BundleID) {
		add("bundle_id invalid")
	}
	if !idRe.MatchString(m.Source) {
		add("source invalid")
	}
	if m.Sequence < 1 {
		add("sequence must be >= 1")
	}
	if !strings.HasPrefix(m.KeyID, "ed25519:") {
		add("key_id invalid")
	}
	if m.CreatedAt.IsZero() || m.ExpiresAt.IsZero() {
		add("created_at and expires_at required")
	} else {
		if !m.ExpiresAt.After(now) {
			add("bundle expired at %s", m.ExpiresAt.Format(time.RFC3339))
		}
		if m.ExpiresAt.Sub(m.CreatedAt) > MaxLifetime {
			add("expires_at more than 90 days after created_at")
		}
		if m.CreatedAt.After(now.Add(10 * time.Minute)) {
			add("created_at is in the future")
		}
	}
	if n := len(m.Packages); n == 0 || n > MaxPackages {
		add("packages count %d out of range 1..%d", n, MaxPackages)
	}
	seenID := map[string]bool{}
	seenFile := map[string]bool{}
	for i, p := range m.Packages {
		pfx := fmt.Sprintf("packages[%d]", i)
		if !idRe.MatchString(p.PackageID) {
			add("%s.package_id invalid", pfx)
		} else if seenID[p.PackageID] {
			add("%s.package_id %q duplicated", pfx, p.PackageID)
		}
		seenID[p.PackageID] = true
		if strings.TrimSpace(p.Title) == "" {
			add("%s.title required", pfx)
		}
		wantOS := ""
		switch p.Kind {
		case "msu":
			wantOS = "windows"
			if !kbRe.MatchString(p.KB) {
				add("%s.kb must look like KB1234567 for msu", pfx)
			}
		case "msi":
			wantOS = "windows"
			if !productRe.MatchString(p.ProductCode) {
				add("%s.product_code must be a {GUID} for msi", pfx)
			} else if IsNilGUID(p.ProductCode) {
				// A placeholder: detection and rollback would target nothing real.
				add("%s.product_code is the all-zero placeholder GUID; set the MSI's real ProductCode", pfx)
			}
			// Optional: the app's display name in Add/Remove Programs, used to
			// recognise an older installed version (product codes change per version).
			if p.PackageName != "" && !displayNameRe.MatchString(p.PackageName) {
				add("%s.package_name for msi must be a display name like \"Google Chrome\"", pfx)
			}
		case "deb", "rpm":
			wantOS = "linux"
			if !pkgNameRe.MatchString(p.PackageName) || strings.TrimSpace(p.Version) == "" {
				add("%s: %s packages need package_name and version", pfx, p.Kind)
			}
		case "pkg":
			wantOS = "macos"
			if !pkgNameRe.MatchString(p.PackageName) || strings.TrimSpace(p.Version) == "" {
				add("%s: pkg packages need package_name (receipt id) and version", pfx)
			}
		case KindExe:
			wantOS = "windows"
			validateExe(&p, pfx, add)
		case KindPortable:
			wantOS = "windows"
			validatePortable(&p, pfx, add)
		case KindMsix:
			wantOS = "windows"
			validateMsix(&p, pfx, add)
		case "agent":
			// offpatch agent self-upgrade; any supported OS.
			if !versionRe.MatchString(p.Version) {
				add("%s: agent packages need a version like 1.2.3", pfx)
			}
		default:
			add("%s.kind must be msu, msi, exe, portable, msix, deb, rpm, pkg or agent", pfx)
		}
		if err := exeBlockMisuse(&p); err != nil {
			add("%s: %v", pfx, err)
		}
		if err := formatBlockMisuse(&p); err != nil {
			add("%s: %v", pfx, err)
		} else if p.Archive != nil {
			validateArchive(&p, pfx, add)
		}
		if wantOS != "" && p.Applicability.OS != wantOS {
			add("%s: kind %s requires applicability.os %s", pfx, p.Kind, wantOS)
		}
		for _, pr := range p.Prerequisites {
			if !kbRe.MatchString(pr) && !pkgNameRe.MatchString(pr) {
				add("%s.prerequisites entry %q invalid", pfx, pr)
			}
		}
		for _, ed := range p.Applicability.Editions {
			if !editionRe.MatchString(ed) {
				add("%s.applicability.editions entry %q invalid", pfx, ed)
			}
		}
		if p.ExpectedUBR < 0 || p.ExpectedUBR > 1<<20 {
			add("%s.expected_ubr out of range", pfx)
		} else if p.ExpectedUBR > 0 && p.Kind != "msu" {
			add("%s.expected_ubr is only for msu packages", pfx)
		}
		if p.KB != "" && !kbRe.MatchString(p.KB) {
			add("%s.kb invalid", pfx)
		}
		for _, s := range p.Supersedes {
			if !kbRe.MatchString(s) {
				add("%s.supersedes entry %q invalid", pfx, s)
			}
		}
		if !severities[p.Severity] {
			add("%s.severity invalid", pfx)
		}
		switch p.Applicability.OS {
		case "windows", "linux", "macos":
		default:
			add("%s.applicability.os must be windows, linux or macos", pfx)
		}
		switch p.Applicability.Arch {
		case "x64", "x86", "arm64", "any":
		default:
			add("%s.applicability.arch must be x64|x86|arm64|any", pfx)
		}
		if p.Applicability.MaxBuild != 0 && p.Applicability.MaxBuild < p.Applicability.MinBuild {
			add("%s.applicability max_build < min_build", pfx)
		}
		if !strings.HasPrefix(p.File.Name, "payload/") || !validBase(strings.TrimPrefix(p.File.Name, "payload/")) {
			add("%s.file.name must be payload/<basename>", pfx)
		} else if seenFile[p.File.Name] {
			add("%s.file.name duplicated", pfx)
		}
		seenFile[p.File.Name] = true
		if p.File.Size <= 0 {
			add("%s.file.size must be > 0", pfx)
		}
		if !hexRe.MatchString(p.File.SHA256) {
			add("%s.file.sha256 must be 64 lowercase hex", pfx)
		}
		if !sigStatus[p.VendorSignature.Status] {
			add("%s.vendor_signature.status invalid", pfx)
		} else if p.VendorSignature.Status == "invalid" {
			add("%s vendor signature recorded as invalid", pfx)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Parse decodes manifest bytes strictly (unknown fields rejected).
func Parse(b []byte) (*Manifest, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest json: trailing data")
	}
	return &m, nil
}

// ---- keys ----

// KeyID returns "ed25519:" + first 16 hex chars of SHA-256(pub).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:])[:16]
}

func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

const (
	pemPriv = "OFFPATCH ED25519 PRIVATE KEY"
	pemPub  = "OFFPATCH ED25519 PUBLIC KEY"
)

func EncodePrivate(k ed25519.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemPriv, Bytes: k.Seed()})
}

func EncodePublic(k ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemPub, Bytes: k})
}

func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemPriv || len(blk.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not an offpatch private key", path)
	}
	return ed25519.NewKeyFromSeed(blk.Bytes), nil
}

// ParsePublic accepts PEM or a bare base64 public key.
func ParsePublic(s string) (ed25519.PublicKey, error) {
	if blk, _ := pem.Decode([]byte(s)); blk != nil {
		if blk.Type != pemPub || len(blk.Bytes) != ed25519.PublicKeySize {
			return nil, errors.New("not an offpatch public key")
		}
		return ed25519.PublicKey(blk.Bytes), nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be PEM or base64 ed25519")
	}
	return ed25519.PublicKey(b), nil
}

func LoadPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublic(string(b))
}

// Sign returns base64(Ed25519(manifestBytes)).
func Sign(k ed25519.PrivateKey, manifestBytes []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k, manifestBytes))
}

// Verify checks a base64 detached signature over the exact manifest bytes.
func Verify(pub ed25519.PublicKey, manifestBytes []byte, sigB64 string) error {
	// ed25519.Verify panics on a wrong-length key; a nil or truncated key
	// (e.g. a failed key lookup) must fail closed, not crash the caller.
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("public key is not a valid ed25519 key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature is not valid base64 ed25519")
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// IsNilGUID reports whether a {GUID} is all zeros (a config placeholder).
func IsNilGUID(g string) bool {
	return strings.Trim(g, "{}0-") == "" && strings.Contains(g, "0")
}
