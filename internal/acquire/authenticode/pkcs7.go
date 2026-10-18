package authenticode

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	_ "crypto/sha256" // register SHA-256 for crypto.Hash
	_ "crypto/sha512" // register SHA-384/512
)

// PKCS#7 / CMS structures (RFC 2315, RFC 5652) and the Authenticode
// SpcIndirectDataContent, parsed with encoding/asn1 (DER).

var (
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSpcIndirectData   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcPEImageData    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrCounterSig    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidMSTimestamp       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1} // RFC 3161 token
	oidMSNestedSig       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	oidTSTInfo           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSA          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASHA256    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSASHA384    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidRSASHA512    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSASHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	errWeakDigest   = errors.New("signature uses SHA-1 only")
	errNoSignerCert = errors.New("signer certificate not in the signature")
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version                   int
	SID                       asn1.RawValue
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue // SET OF value
}

type spcIndirectDataContent struct {
	Data          spcAttributeTypeAndValue
	MessageDigest digestInfo
}

type spcAttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

// parsed is one SignedData: its embedded content, certificates and signer.
type parsed struct {
	sd      signedData
	certs   []*x509.Certificate
	content []byte // the encapsulated content octets (what messageDigest covers)
	signer  signerInfo
}

func parseSignedData(der []byte) (*parsed, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("PKCS#7: %w", err)
	}
	if !zeros(rest) {
		return nil, errors.New("PKCS#7: data after the signature")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errors.New("PKCS#7: not SignedData")
	}
	p := &parsed{}
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &p.sd); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("PKCS#7 SignedData: %v", err)
	}
	if len(p.sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("PKCS#7: %d signers (want exactly 1)", len(p.sd.SignerInfos))
	}
	p.signer = p.sd.SignerInfos[0]
	if p.certs, err = certSet(p.sd.Certificates.Bytes); err != nil {
		return nil, err
	}
	// The content is [0] EXPLICIT <value>; messageDigest covers the value's
	// contents octets (without its own tag and length).
	if len(p.sd.ContentInfo.Content.FullBytes) > 0 {
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(p.sd.ContentInfo.Content.Bytes, &inner); err != nil {
			return nil, fmt.Errorf("PKCS#7 content: %w", err)
		}
		p.content = inner.Bytes
	}
	return p, nil
}

// certSet parses the CertificateChoices of a SignedData. Only X.509
// certificates (SEQUENCE) are used; other choices (attribute certificates,
// which Microsoft time-stamp tokens carry) and certificates this parser
// cannot read are skipped: they are only chain candidates, and the signer
// must still be found and verified.
func certSet(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(b) > 0 {
		var rv asn1.RawValue
		var err error
		if b, err = asn1.Unmarshal(b, &rv); err != nil {
			return nil, fmt.Errorf("PKCS#7 certificates: %w", err)
		}
		if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagSequence {
			continue
		}
		if c, err := x509.ParseCertificate(rv.FullBytes); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func zeros(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	case oid.Equal(oidSHA1):
		return crypto.SHA1, errWeakDigest
	}
	return 0, fmt.Errorf("digest algorithm %v not supported", oid)
}

func sigAlgFor(h crypto.Hash, enc asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	rsa := enc.Equal(oidRSA) || enc.Equal(oidRSASHA256) || enc.Equal(oidRSASHA384) || enc.Equal(oidRSASHA512)
	ec := enc.Equal(oidECPublicKey) || enc.Equal(oidECDSASHA256) || enc.Equal(oidECDSASHA384) || enc.Equal(oidECDSASHA512)
	switch {
	case rsa && h == crypto.SHA256:
		return x509.SHA256WithRSA, nil
	case rsa && h == crypto.SHA384:
		return x509.SHA384WithRSA, nil
	case rsa && h == crypto.SHA512:
		return x509.SHA512WithRSA, nil
	case ec && h == crypto.SHA256:
		return x509.ECDSAWithSHA256, nil
	case ec && h == crypto.SHA384:
		return x509.ECDSAWithSHA384, nil
	case ec && h == crypto.SHA512:
		return x509.ECDSAWithSHA512, nil
	}
	return 0, fmt.Errorf("signature algorithm %v with %v not supported", enc, h)
}

func digestOf(h crypto.Hash, b []byte) []byte {
	x := h.New()
	x.Write(b)
	return x.Sum(nil)
}

// attributes parses an [0]/[1] IMPLICIT SET OF Attribute.
func attributes(raw asn1.RawValue) (map[string][]asn1.RawValue, error) {
	out := map[string][]asn1.RawValue{}
	rest := raw.Bytes
	for len(rest) > 0 {
		var a attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return nil, fmt.Errorf("attribute: %w", err)
		}
		vals := a.Values.Bytes
		for len(vals) > 0 {
			var v asn1.RawValue
			if vals, err = asn1.Unmarshal(vals, &v); err != nil {
				return nil, fmt.Errorf("attribute %v value: %w", a.Type, err)
			}
			out[a.Type.String()] = append(out[a.Type.String()], v)
		}
	}
	return out, nil
}

func single(attrs map[string][]asn1.RawValue, oid asn1.ObjectIdentifier) (asn1.RawValue, error) {
	v := attrs[oid.String()]
	if len(v) != 1 {
		return asn1.RawValue{}, fmt.Errorf("authenticated attribute %v: %d values (want 1)", oid, len(v))
	}
	return v[0], nil
}

// findCert returns the certificate a SignerInfo names.
func findCert(certs []*x509.Certificate, sid asn1.RawValue) (*x509.Certificate, error) {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 { // subjectKeyIdentifier
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c, nil
			}
		}
		return nil, errNoSignerCert
	}
	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
		return nil, fmt.Errorf("signer identifier: %w", err)
	}
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c, nil
		}
	}
	return nil, errNoSignerCert
}

// checkSigner verifies a SignerInfo whose authenticated attributes must
// state contentType (when wantType is set) and messageDigest = H(content).
// It returns the signer certificate, the digest used and the attributes.
func checkSigner(si signerInfo, certs []*x509.Certificate, wantType asn1.ObjectIdentifier, content []byte) (*x509.Certificate, crypto.Hash, map[string][]asn1.RawValue, error) {
	h, err := hashFor(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, 0, nil, err
	}
	if len(si.AuthenticatedAttributes.FullBytes) == 0 {
		return nil, 0, nil, errors.New("signer has no authenticated attributes")
	}
	attrs, err := attributes(si.AuthenticatedAttributes)
	if err != nil {
		return nil, 0, nil, err
	}
	if wantType != nil {
		ctv, err := single(attrs, oidAttrContentType)
		if err != nil {
			return nil, 0, nil, err
		}
		var ct asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ctv.FullBytes, &ct); err != nil || !ct.Equal(wantType) {
			return nil, 0, nil, fmt.Errorf("contentType attribute %v, want %v", ct, wantType)
		}
	}
	mdv, err := single(attrs, oidAttrMessageDigest)
	if err != nil {
		return nil, 0, nil, err
	}
	var md []byte
	if _, err := asn1.Unmarshal(mdv.FullBytes, &md); err != nil {
		return nil, 0, nil, fmt.Errorf("messageDigest attribute: %w", err)
	}
	if !bytes.Equal(md, digestOf(h, content)) {
		return nil, 0, nil, errors.New("messageDigest does not match the signed content")
	}
	cert, err := findCert(certs, si.SID)
	if err != nil {
		return nil, 0, nil, err
	}
	alg, err := sigAlgFor(h, si.DigestEncryptionAlgorithm.Algorithm)
	if err != nil {
		return nil, 0, nil, err
	}
	// The signature covers the DER of the attributes as a SET (tag 0x31),
	// not as the [0] IMPLICIT field they are stored in.
	signed := append([]byte{0x31}, si.AuthenticatedAttributes.FullBytes[1:]...)
	if err := cert.CheckSignature(alg, signed, si.EncryptedDigest); err != nil {
		return nil, 0, nil, fmt.Errorf("signature does not verify: %w", err)
	}
	return cert, h, attrs, nil
}

func pool(certs []*x509.Certificate, except *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		if c != except {
			p.AddCert(c)
		}
	}
	return p
}

// chain verifies cert up to roots for usage at time t.
func chain(cert *x509.Certificate, certs []*x509.Certificate, roots *x509.CertPool, usage x509.ExtKeyUsage, t time.Time) error {
	_, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool(certs, cert), CurrentTime: t,
		KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}
