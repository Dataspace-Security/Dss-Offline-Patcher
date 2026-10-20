package acquire

// CRL revocation check of an installer's signing certificate (finding H-7).
// The acquisition host is the only machine with internet access, so this is
// where revocation can be checked at all. The CRL named in the leaf's
// CRLDistributionPoints is downloaded (size and time limited, SSRF-guarded,
// http allowed: CRLs are signed and are served over http by every CA),
// verified against the issuing certificate and cached until its NextUpdate.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Revocation results.
const (
	RevocationGood    = "good"
	RevocationRevoked = "revoked"
	RevocationUnknown = "unknown"
)

const (
	defaultMaxCRLBytes = 32 << 20
	defaultCRLTimeout  = 30 * time.Second
	// crlGrace: a CRL without NextUpdate is used for this long after ThisUpdate.
	crlGrace = 7 * 24 * time.Hour
)

// RevocationChecker checks certificates against their CRLs.
type RevocationChecker struct {
	HTTP     *http.Client // should be SSRF-guarded (Guard{AllowHTTP: true})
	CacheDir string       // "" = no cache
	MaxBytes int64        // default 32 MiB
	Timeout  time.Duration
	Now      func() time.Time
}

// Revocation is the outcome of one check.
type Revocation struct {
	Status string // good | revoked | unknown
	Detail string
}

func (rc *RevocationChecker) now() time.Time {
	if rc.Now != nil {
		return rc.Now()
	}
	return time.Now()
}

// Check reports whether leaf (issued by issuer) is revoked. signedAt is the
// verified signing time (zero if unknown): like Windows, a certificate
// revoked after a timestamped signature for a reason other than key or CA
// compromise does not invalidate it.
func (rc *RevocationChecker) Check(ctx context.Context, leaf, issuer *x509.Certificate, signedAt time.Time) Revocation {
	if leaf == nil || issuer == nil {
		return Revocation{Status: RevocationUnknown, Detail: "signing certificate chain not available"}
	}
	if len(leaf.CRLDistributionPoints) == 0 {
		return Revocation{Status: RevocationUnknown, Detail: "certificate names no CRL distribution point"}
	}
	var errs []error
	for _, u := range leaf.CRLDistributionPoints {
		rl, err := rc.crl(ctx, u, issuer)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
			continue
		}
		for _, e := range rl.RevokedCertificateEntries {
			if e.SerialNumber == nil || e.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
				continue
			}
			benign := e.ReasonCode != 0 && e.ReasonCode != 1 && e.ReasonCode != 2 // unspecified, keyCompromise, cACompromise
			if benign && !signedAt.IsZero() && signedAt.Before(e.RevocationTime) {
				return Revocation{Status: RevocationGood, Detail: fmt.Sprintf("revoked on %s (reason %d), after the timestamped signature",
					e.RevocationTime.UTC().Format("2006-01-02"), e.ReasonCode)}
			}
			return Revocation{Status: RevocationRevoked, Detail: fmt.Sprintf("certificate serial %x revoked on %s (reason %d) per %s",
				leaf.SerialNumber, e.RevocationTime.UTC().Format(time.RFC3339), e.ReasonCode, u)}
		}
		return Revocation{Status: RevocationGood, Detail: "not on the CRL " + u}
	}
	return Revocation{Status: RevocationUnknown, Detail: "CRL not available: " + errors.Join(errs...).Error()}
}

func (rc *RevocationChecker) cachePath(u string) string {
	if rc.CacheDir == "" {
		return ""
	}
	h := sha256.Sum256([]byte(u))
	return filepath.Join(rc.CacheDir, hex.EncodeToString(h[:12])+".crl")
}

// crl returns a verified, current CRL for u (cached or downloaded).
func (rc *RevocationChecker) crl(ctx context.Context, u string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	cp := rc.cachePath(u)
	if cp != "" {
		if b, err := os.ReadFile(cp); err == nil {
			if rl, err := rc.parse(b, issuer); err == nil {
				return rl, nil
			}
		}
	}
	b, err := rc.fetch(ctx, u)
	if err != nil {
		return nil, err
	}
	rl, err := rc.parse(b, issuer)
	if err != nil {
		return nil, err
	}
	if cp != "" {
		if err := os.MkdirAll(rc.CacheDir, 0o750); err == nil {
			_ = os.WriteFile(cp, b, 0o640) // a cache: a failed write only costs a download
		}
	}
	return rl, nil
}

func (rc *RevocationChecker) parse(b []byte, issuer *x509.Certificate) (*x509.RevocationList, error) {
	if blk, _ := pem.Decode(b); blk != nil && blk.Type == "X509 CRL" {
		b = blk.Bytes
	}
	rl, err := x509.ParseRevocationList(b)
	if err != nil {
		return nil, fmt.Errorf("not a CRL: %w", err)
	}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("CRL not signed by the certificate's issuer: %w", err)
	}
	now := rc.now()
	if rl.ThisUpdate.After(now.Add(time.Hour)) {
		return nil, errors.New("CRL is not valid yet")
	}
	next := rl.NextUpdate
	if next.IsZero() {
		next = rl.ThisUpdate.Add(crlGrace)
	}
	if now.After(next) {
		return nil, fmt.Errorf("CRL expired on %s", next.UTC().Format(time.RFC3339))
	}
	return rl, nil
}

func (rc *RevocationChecker) fetch(ctx context.Context, u string) ([]byte, error) {
	timeout := rc.Timeout
	if timeout <= 0 {
		timeout = defaultCRLTimeout
	}
	max := rc.MaxBytes
	if max <= 0 {
		max = defaultMaxCRLBytes
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	hc := rc.HTTP
	if hc == nil {
		hc = (&Guard{AllowHTTP: true}).Client(nil)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{Method: http.MethodGet, URL: req.URL.Redacted(), Code: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("CRL larger than %d bytes", max)
	}
	return b, nil
}
