// Package authenticode verifies the Authenticode signature embedded in a
// Windows PE file (EXE installers) in pure Go, on any acquisition host.
//
// What is verified, in order:
//  1. The PE layout: the certificate table is the last thing in the file
//     (no unsigned data after it) and holds exactly one PKCS#7 SignedData
//     attribute certificate with nothing but zero padding after it.
//  2. The content: SpcIndirectDataContent of type SPC_PE_IMAGE_DATA, whose
//     digest equals the Authenticode digest of the file (the whole image
//     except the CheckSum field, the certificate-table directory entry and
//     the certificate table). SHA-256, SHA-384 or SHA-512 only.
//  3. The signer: authenticated attributes state contentType
//     SPC_INDIRECT_DATA and messageDigest = H(content); the signature over
//     them verifies with the signer certificate (RSA PKCS#1 v1.5 or ECDSA).
//  4. The chain: the signer certificate chains, through the certificates in
//     the signature, to a trusted root with the code-signing extended key
//     usage, at the time of a verified timestamp (RFC 3161 or PKCS#9
//     countersignature, see timestamp.go) or else at the current time.
//
// A file may carry several signatures (nested ones in the primary's
// unauthenticated attributes); as on Windows it is valid if one of them
// passes all of the above on its own, and that one's signer is reported.
//
// Trusted roots are the host's system roots plus the code-signing roots
// shipped in roots.pem (Microsoft's code-signing roots are not in the
// Mozilla-derived bundles Linux distributions use). Revocation is not
// checked (acquisition hosts may have no CRL/OCSP reachability); the
// verified signer is recorded in the manifest and shown for approval.
package authenticode

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	_ "crypto/sha1" // SHA-1 timestamp imprints
)

//go:embed roots.pem
var rootsPEM []byte

// Result describes a verified signature.
type Result struct {
	Signer     string    // signer certificate subject CommonName, e.g. "Microsoft Corporation"
	Subject    string    // full subject DN
	Issuer     string    // issuer CommonName
	Thumbprint string    // SHA-256 of the signer certificate, hex
	Digest     string    // sha256 | sha384 | sha512
	SignedAt   time.Time // verified timestamp; zero if none
}

// Options control verification.
type Options struct {
	// Roots are the trust anchors; nil means DefaultRoots().
	Roots *x509.CertPool
	// Now is the verification time when there is no timestamp; zero = now.
	Now time.Time
}

// ErrDigestMismatch: the file changed after it was signed.
var ErrDigestMismatch = errors.New("Authenticode digest does not match the file (modified after signing)")

var (
	defaultOnce  sync.Once
	defaultRoots *x509.CertPool
	defaultErr   error
)

// EmbeddedRoots returns only the code-signing roots shipped in roots.pem.
func EmbeddedRoots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(rootsPEM)
	return p
}

// DefaultRoots returns the system roots plus the embedded roots.
func DefaultRoots() (*x509.CertPool, error) {
	defaultOnce.Do(func() {
		p, err := x509.SystemCertPool()
		if err != nil || p == nil {
			p = x509.NewCertPool()
		}
		if !p.AppendCertsFromPEM(rootsPEM) {
			defaultErr = errors.New("embedded Authenticode roots unreadable")
			return
		}
		defaultRoots = p
	})
	return defaultRoots, defaultErr
}

// RootsWithPEM returns DefaultRoots plus the certificates in a PEM file
// (operator-supplied trust anchors, e.g. a vendor's private code-signing CA).
func RootsWithPEM(path string) (*x509.CertPool, error) {
	base, err := DefaultRoots()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := base.Clone()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no PEM certificates", path)
	}
	return p, nil
}

// VerifyFile verifies the file at path.
func VerifyFile(path string, o Options) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return Verify(f, fi.Size(), o)
}

// Verify verifies the PE image in r (size bytes).
func Verify(r io.ReaderAt, size int64, o Options) (*Result, error) {
	if o.Roots == nil {
		roots, err := DefaultRoots()
		if err != nil {
			return nil, err
		}
		o.Roots = roots
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	img, err := parsePE(r, size)
	if err != nil {
		return nil, err
	}
	blob, err := img.pkcs7Blob(r)
	if err != nil {
		return nil, err
	}
	p, err := parseSignedData(blob)
	if err != nil {
		return nil, err
	}
	v := &verifier{r: r, img: img, o: o, digests: map[crypto.Hash][]byte{}}
	res, err := v.one(p)
	if err == nil || errors.Is(err, ErrDigestMismatch) {
		return res, err
	}
	// Like Windows, a file with several signatures (nested signatures in
	// the primary's unauthenticated attributes) is valid if one of them
	// verifies on its own: each covers the same image digest. Typical
	// cases: a SHA-1 primary with a SHA-256 nested signature, or a primary
	// whose certificate expired untimestamped next to a current one.
	nested, nerr := nestedSignatures(p)
	if nerr != nil {
		return nil, fmt.Errorf("%w (nested signatures unreadable: %v)", err, nerr)
	}
	errs := []error{err}
	for _, n := range nested {
		res, nerr := v.one(n)
		if nerr == nil {
			return res, nil
		}
		errs = append(errs, fmt.Errorf("nested signature: %w", nerr))
	}
	if errors.Is(err, errWeakDigest) && len(nested) == 0 {
		return nil, errors.New("signed with SHA-1 only; a SHA-256 (or stronger) signature is required")
	}
	return nil, errors.Join(errs...)
}

type verifier struct {
	r       io.ReaderAt
	img     *peImage
	o       Options
	digests map[crypto.Hash][]byte
}

func (v *verifier) imageDigest(h crypto.Hash) ([]byte, error) {
	if d, ok := v.digests[h]; ok {
		return d, nil
	}
	d, err := v.img.digest(v.r, h.New())
	if err != nil {
		return nil, err
	}
	v.digests[h] = d
	return d, nil
}

func (v *verifier) one(p *parsed) (*Result, error) {
	if !p.sd.ContentInfo.ContentType.Equal(oidSpcIndirectData) {
		return nil, errors.New("PKCS#7 content is not SpcIndirectDataContent")
	}
	var spc spcIndirectDataContent
	if rest, err := asn1.Unmarshal(p.sd.ContentInfo.Content.Bytes, &spc); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("SpcIndirectDataContent: %v", err)
	}
	if !spc.Data.Type.Equal(oidSpcPEImageData) {
		return nil, fmt.Errorf("signed data type %v is not a PE image", spc.Data.Type)
	}
	h, err := hashFor(spc.MessageDigest.Algorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	d, err := v.imageDigest(h)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(d, spc.MessageDigest.Digest) {
		return nil, ErrDigestMismatch
	}
	cert, _, _, err := checkSigner(p.signer, p.certs, oidSpcIndirectData, p.content)
	if err != nil {
		return nil, err
	}
	at := v.o.Now
	signedAt, tsErr := timestamp(p, v.o.Roots)
	if tsErr == nil {
		at = signedAt
	}
	if err := chain(cert, p.certs, v.o.Roots, x509.ExtKeyUsageCodeSigning, at); err != nil {
		if tsErr != nil {
			return nil, fmt.Errorf("signer certificate %q not trusted for code signing (no verified timestamp: %v): %w", cert.Subject.CommonName, tsErr, err)
		}
		return nil, fmt.Errorf("signer certificate %q not trusted for code signing at %s: %w", cert.Subject.CommonName, at.UTC().Format(time.RFC3339), err)
	}
	if strings.TrimSpace(cert.Subject.CommonName) == "" {
		return nil, errors.New("signer certificate has no subject CommonName")
	}
	tp := sha256.Sum256(cert.Raw)
	return &Result{Signer: strings.TrimSpace(cert.Subject.CommonName), Subject: cert.Subject.String(), Issuer: cert.Issuer.CommonName,
		Thumbprint: hex.EncodeToString(tp[:]), Digest: strings.ToLower(strings.ReplaceAll(h.String(), "-", "")), SignedAt: signedAt}, nil
}

func nestedSignatures(p *parsed) ([]*parsed, error) {
	if len(p.signer.UnauthenticatedAttributes.FullBytes) == 0 {
		return nil, nil
	}
	attrs, err := attributes(p.signer.UnauthenticatedAttributes)
	if err != nil {
		return nil, err
	}
	var out []*parsed
	for _, v := range attrs[oidMSNestedSig.String()] {
		n, err := parseSignedData(v.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("nested signature: %w", err)
		}
		out = append(out, n)
	}
	return out, nil
}
