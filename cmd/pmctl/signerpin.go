package main

// Installer signer pinning (finding H-7) and exact signer names (M-5).
//
// For winget EXE installers (pure-Go Authenticode, any host), winget MSIs
// (Windows acquisition hosts) and vendor-url downloads verified by
// signature, pmctl records the verified signer of each package (leaf
// certificate SHA-256 thumbprint, subject CN and O) in
// work_dir/signer-pins.json the first time it sees the package (trust on
// first use). A later version is accepted when CN and O are unchanged
// (certificate renewals change the thumbprint, which is updated and noted).
// A different CN or O is refused and reported in the status report until
// an operator approves it: `pmctl trust-signer <id>`, an exe_signer_pins
// entry for the id in acquire.json, or the new CN in exe_signers.
//
// The signing certificate is also checked against its CRL (the acquisition
// host is the only machine with internet access): revoked is refused; a
// CRL that cannot be fetched is recorded as revocation "unknown" (refused
// with require_revocation_check).
//
// The verified signer, its O, the winget Publisher (and whether they
// agree), the thumbprint and the revocation result go into the package's
// vendor_signature.signer, which the console shows next to the package for
// approval.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"offpatch/internal/acquire"
	peauth "offpatch/internal/acquire/authenticode"
	"offpatch/internal/manifest"
)

const signerPinsFile = "signer-pins.json"

// errSignerChanged: the installer's signer is not the pinned one.
var errSignerChanged = errors.New("installer signer changed")

// errSignerRevoked: the signing certificate is revoked (or revocation could
// not be checked with require_revocation_check).
var errSignerRevoked = errors.New("installer signing certificate")

// signerName is a certificate subject's CN and O.
type signerName struct {
	CN string `json:"cn"`
	O  string `json:"o,omitempty"`
}

func (n signerName) String() string {
	if n.O == "" {
		return fmt.Sprintf("CN=%q", n.CN)
	}
	return fmt.Sprintf("CN=%q O=%q", n.CN, n.O)
}

// matches: CN equal (case-insensitive, whole value) and, if want names
// one, O equal too. Never a substring match: CN "Google LLC Services Ltd"
// is not "Google LLC".
func (want signerName) matches(got signerName) bool {
	if want.CN == "" || !strings.EqualFold(cleanName(want.CN), cleanName(got.CN)) {
		return false
	}
	return want.O == "" || strings.EqualFold(cleanName(want.O), cleanName(got.O))
}

func cleanName(s string) string { return strings.Join(strings.Fields(s), " ") }

// parseSignerSpec reads a configured signer: a subject DN such as
// "CN=Google LLC, O=Google LLC, C=US" (CN and O are compared, the rest is
// ignored) or a bare CommonName ("Google LLC").
func parseSignerSpec(s string) signerName {
	s = strings.TrimSpace(s)
	if dn := parseDN(s); dn["CN"] != "" {
		return signerName{CN: dn["CN"], O: dn["O"]}
	}
	return signerName{CN: s}
}

// parseDN splits an X.500 subject string (RFC 4514 style as .NET and Go
// print it: "CN=x, O=\"a, b\", C=US") into its first value per attribute.
// Not a DN (no recognised KEY=) gives an empty map.
func parseDN(dn string) map[string]string {
	out := map[string]string{}
	var parts []string
	var cur strings.Builder
	quoted, esc := false, false
	for _, r := range dn {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == '"':
			quoted = !quoted
		case (r == ',' || r == ';' || r == '+') && !quoted:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, cur.String())
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		k = strings.ToUpper(strings.TrimSpace(k))
		if !ok || k == "" || strings.ContainsFunc(k, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' }) {
			if len(out) == 0 {
				return map[string]string{} // not a DN
			}
			continue
		}
		if _, dup := out[k]; !dup {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// signerInfo is a verified installer signer.
type signerInfo struct {
	signerName
	Thumbprint string // SHA-256 of the leaf certificate, hex ("" if unknown)
	Leaf       *x509.Certificate
	Issuer     *x509.Certificate
	SignedAt   time.Time
}

func infoFromResult(res *peauth.Result) signerInfo {
	return signerInfo{signerName: signerName{CN: res.Signer, O: res.Organization}, Thumbprint: res.Thumbprint,
		Leaf: res.Leaf, Issuer: res.IssuerCert, SignedAt: res.SignedAt}
}

func infoFromCert(leaf, issuer *x509.Certificate, subject string) signerInfo {
	if leaf == nil {
		dn := parseDN(subject)
		return signerInfo{signerName: signerName{CN: dn["CN"], O: dn["O"]}}
	}
	tp := sha256.Sum256(leaf.Raw)
	o := ""
	if len(leaf.Subject.Organization) > 0 {
		o = strings.TrimSpace(leaf.Subject.Organization[0])
	}
	return signerInfo{signerName: signerName{CN: strings.TrimSpace(leaf.Subject.CommonName), O: o},
		Thumbprint: hex.EncodeToString(tp[:]), Leaf: leaf, Issuer: issuer}
}

// ---- pins ----

// signerPinConfig is an acquire.json exe_signer_pins entry.
type signerPinConfig = signerName

type pinnedSigner struct {
	CN          string         `json:"cn"`
	O           string         `json:"o,omitempty"`
	Thumbprint  string         `json:"thumbprint,omitempty"`
	FirstSeen   string         `json:"first_seen"`
	LastSeen    string         `json:"last_seen"`
	LastVersion string         `json:"last_version,omitempty"`
	ApprovedBy  string         `json:"approved_by"` // first-use | exe_signers | exe_signer_pins | trust-signer:<user>
	Pending     *pendingSigner `json:"pending,omitempty"`
}

// pendingSigner is a refused signer change waiting for approval.
type pendingSigner struct {
	CN         string `json:"cn"`
	O          string `json:"o,omitempty"`
	Thumbprint string `json:"thumbprint,omitempty"`
	Version    string `json:"version,omitempty"`
	SeenAt     string `json:"seen_at"`
}

type signerPins struct {
	path string
	Pins map[string]*pinnedSigner `json:"pins"`
}

func loadSignerPins(path string) (*signerPins, error) {
	p := &signerPins{path: path, Pins: map[string]*pinnedSigner{}}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return p, nil
	case err != nil:
		return nil, fmt.Errorf("signer pins %s: %w", path, err)
	}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, fmt.Errorf("%s is corrupt (%v); refusing to run, because every installer signer would be trusted again on first use: restore it from a backup or repair the JSON", path, err)
	}
	if p.Pins == nil {
		p.Pins = map[string]*pinnedSigner{}
	}
	return p, nil
}

func (p *signerPins) save() error {
	if p == nil || p.path == "" {
		return nil
	}
	return saveJSON(p.path, p)
}

func pinKeyWinget(id string) string   { return "winget:" + strings.ToLower(id) }
func pinKeyVendor(id string) string   { return "vendor:" + strings.ToLower(id) }
func pinKeyDisplay(key string) string { return strings.TrimPrefix(key, "winget:") }

// configPin finds an acquire.json exe_signer_pins entry for key (keys may
// be written "Google.Chrome", "winget:Google.Chrome" or "vendor:<id>").
func configPin(c *autoConfig, key string) (signerName, bool) {
	for k, v := range c.ExeSignerPins {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == key || "winget:"+k == key {
			return v, true
		}
	}
	return signerName{}, false
}

func inExeSigners(cn string) bool {
	for _, s := range exeTrust.signers {
		if parseSignerSpec(s).matches(signerName{CN: cn}) {
			return true
		}
	}
	return false
}

// check applies the pin of key to the verified signer s of version and
// returns a short note for the metadata.
func (p *signerPins) check(c *autoConfig, key, version string, s signerInfo, now time.Time) (string, error) {
	ts := now.UTC().Format(time.RFC3339)
	rec := p.Pins[key]
	set := func(by string) {
		if rec == nil {
			rec = &pinnedSigner{FirstSeen: ts}
			p.Pins[key] = rec
		}
		rec.CN, rec.O, rec.Thumbprint, rec.LastSeen, rec.LastVersion, rec.ApprovedBy, rec.Pending = s.CN, s.O, s.Thumbprint, ts, version, by, nil
	}
	if want, ok := configPin(c, key); ok {
		if !want.matches(s.signerName) {
			return "", fmt.Errorf("%w: %s %s is signed by %s, but acquire.json exe_signer_pins requires %s", errSignerChanged,
				pinKeyDisplay(key), version, s.signerName, want)
		}
		set("exe_signer_pins")
		return "pinned in acquire.json", nil
	}
	if rec == nil {
		set("first-use")
		return "first seen: signer pinned", nil
	}
	pinned := signerName{CN: rec.CN, O: rec.O}
	switch {
	case pinned.matches(s.signerName) && strings.EqualFold(cleanName(rec.O), cleanName(s.O)):
		note := "matches the pinned signer"
		if rec.Thumbprint != "" && s.Thumbprint != "" && !strings.EqualFold(rec.Thumbprint, s.Thumbprint) {
			note = "same signer, renewed certificate"
		}
		by := rec.ApprovedBy
		set(by)
		return note, nil
	case inExeSigners(s.CN):
		set("exe_signers")
		return "signer changed from " + pinned.String() + ", accepted: listed in exe_signers", nil
	}
	rec.Pending = &pendingSigner{CN: s.CN, O: s.O, Thumbprint: s.Thumbprint, Version: version, SeenAt: ts}
	return "", fmt.Errorf("%w: %s was signed by %s, version %s by %s; refused until approved with `pmctl trust-signer %s` (or exe_signer_pins in acquire.json)",
		errSignerChanged, pinKeyDisplay(key), pinned, version, s.signerName, pinKeyDisplay(key))
}

// ---- revocation ----

// revocationCheck is the CRL check (a hook for tests).
var revocationCheck = func(ctx context.Context, c *autoConfig, s signerInfo) acquire.Revocation {
	if s.Leaf == nil {
		return acquire.Revocation{Status: acquire.RevocationUnknown, Detail: "signing certificate not available on this host"}
	}
	rc := &acquire.RevocationChecker{HTTP: (&acquire.Guard{AllowHTTP: true}).Client(nil), Now: autoNow}
	if c != nil && c.WorkDir != "" {
		rc.CacheDir = filepath.Join(c.WorkDir, "crl-cache")
	}
	return rc.Check(ctx, s.Leaf, s.Issuer, s.SignedAt)
}

// ---- the whole check, per download ----

// pinInstaller runs the revocation check and the signer pin for a verified
// installer and returns its vendor_signature (status valid, signer with
// the details approvers see).
func pinInstaller(ctx context.Context, c *autoConfig, pins *signerPins, key, version, publisher string, s signerInfo) (manifest.VendorSignature, error) {
	rev := revocationCheck(ctx, c, s)
	switch {
	case rev.Status == acquire.RevocationRevoked:
		return manifest.VendorSignature{}, fmt.Errorf("%w is revoked: %s", errSignerRevoked, rev.Detail)
	case rev.Status != acquire.RevocationGood && c.RequireRevocationCheck:
		return manifest.VendorSignature{}, fmt.Errorf("%w: revocation could not be checked (%s) and acquire.json sets require_revocation_check", errSignerRevoked, rev.Detail)
	}
	note := "not pinned"
	if pins != nil {
		n, err := pins.check(c, key, version, s, autoNow())
		if err != nil {
			return manifest.VendorSignature{}, err
		}
		note = n
	}
	pub := ""
	if publisher != "" {
		agree := "matches"
		if !publisherMatches(publisher, s.signerName) {
			agree = "DIFFERS"
			autoWarn(fmt.Sprintf("%s %s: signed by %s, but the winget manifest's Publisher is %q", pinKeyDisplay(key), version, s.signerName, publisher))
		}
		pub = fmt.Sprintf("; winget publisher %q %s", publisher, agree)
	}
	tp := ""
	if s.Thumbprint != "" {
		tp = "; cert sha256 " + s.Thumbprint[:min(16, len(s.Thumbprint))]
	}
	o := ""
	if s.O != "" {
		o = "O=" + s.O + "; "
	}
	detail := fmt.Sprintf("%s (%s%s%s; revocation %s; %s)", s.CN, strings.TrimSuffix(o, "; "), pub, tp, rev.Status, note)
	detail = strings.Replace(detail, "(; ", "(", 1)
	return manifest.VendorSignature{Status: "valid", Signer: detail, CheckedAt: autoNow().UTC().Format(time.RFC3339)}, nil
}

var corpWords = map[string]bool{"inc": true, "llc": true, "ltd": true, "limited": true, "corp": true, "corporation": true, "co": true,
	"company": true, "gmbh": true, "ag": true, "sa": true, "srl": true, "bv": true, "plc": true, "the": true, "pty": true, "oy": true, "ab": true, "as": true}

func publisherWords(s string) string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '+' }) {
		if !corpWords[w] {
			out = append(out, w)
		}
	}
	return strings.Join(out, " ")
}

// publisherMatches: the winget Publisher names the signer (CN or O),
// ignoring case, punctuation and company-form words (Inc, LLC, GmbH...).
func publisherMatches(publisher string, n signerName) bool {
	p := publisherWords(publisher)
	return p != "" && (p == publisherWords(n.CN) || (n.O != "" && p == publisherWords(n.O)))
}

// ---- pmctl trust-signer ----

// trustSignerCmd approves a refused signer change (or lists the pins).
//
//	pmctl trust-signer -config acquire.json Google.Chrome
//	pmctl trust-signer -config acquire.json -list
func trustSignerCmd(args []string) error {
	fs := flag.NewFlagSet("trust-signer", flag.ExitOnError)
	cfgPath := fs.String("config", "acquire.json", "auto-acquisition config")
	list := fs.Bool("list", false, "list the pinned installer signers")
	fs.Parse(args)
	c, err := loadAutoConfig(*cfgPath)
	if err != nil {
		return err
	}
	unlock, err := acquireLock(c.WorkDir, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("%w: try again when it has finished", err)
	}
	defer unlock()
	pins, err := loadSignerPins(filepath.Join(c.WorkDir, signerPinsFile))
	if err != nil {
		return err
	}
	if *list {
		keys := make([]string, 0, len(pins.Pins))
		for k := range pins.Pins {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			r := pins.Pins[k]
			line := fmt.Sprintf("%s\t%s\t(%s, last %s)", k, signerName{CN: r.CN, O: r.O}, r.ApprovedBy, r.LastVersion)
			if r.Pending != nil {
				line += fmt.Sprintf("\tPENDING %s (version %s)", signerName{CN: r.Pending.CN, O: r.Pending.O}, r.Pending.Version)
			}
			fmt.Println(line)
		}
		return nil
	}
	if fs.NArg() != 1 {
		return errors.New("usage: pmctl trust-signer [-config acquire.json] <winget id | vendor:<source id>>  (or -list)")
	}
	key, err := approveSigner(pins, fs.Arg(0), operatorName(), autoNow())
	if err != nil {
		return err
	}
	if err := pins.save(); err != nil {
		return err
	}
	r := pins.Pins[key]
	fmt.Printf("%s: signer %s approved; the next run downloads it\n", key, signerName{CN: r.CN, O: r.O})
	return nil
}

// approveSigner makes the pending signer of id the pinned one.
func approveSigner(pins *signerPins, id, by string, now time.Time) (string, error) {
	low := strings.ToLower(strings.TrimSpace(id))
	for _, key := range []string{low, pinKeyWinget(low), pinKeyVendor(strings.TrimPrefix(low, "vendor:"))} {
		r := pins.Pins[key]
		if r == nil {
			continue
		}
		if r.Pending == nil {
			return "", fmt.Errorf("%s: no refused signer change to approve (pinned: %s)", key, signerName{CN: r.CN, O: r.O})
		}
		p := r.Pending
		r.CN, r.O, r.Thumbprint, r.LastVersion = p.CN, p.O, p.Thumbprint, p.Version
		r.ApprovedBy = "trust-signer:" + by + " " + now.UTC().Format(time.RFC3339)
		r.Pending = nil
		return key, nil
	}
	return "", fmt.Errorf("%s: no pinned signer (see pmctl trust-signer -list)", id)
}

func operatorName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "operator"
}
