package authenticode

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// Timestamps let a signature outlive its signing certificate: the chain is
// then checked at the time a trusted time-stamping authority vouched for,
// as Windows does. Two forms are accepted, both in the signer's
// unauthenticated attributes:
//   - an RFC 3161 token (1.3.6.1.4.1.311.3.3.1), a SignedData over a
//     TSTInfo whose messageImprint is the hash of the signature value;
//   - a PKCS#9 countersignature (1.2.840.113549.1.9.6), a SignerInfo whose
//     messageDigest is the hash of the signature value, with signingTime.
// The TSA certificate must chain to the roots with the timeStamping usage
// at the stated time. A timestamp that does not verify is ignored (the
// chain is then checked at the current time).

// timestamp returns the verified signing time of p's signer.
func timestamp(p *parsed, roots *x509.CertPool) (time.Time, error) {
	if len(p.signer.UnauthenticatedAttributes.FullBytes) == 0 {
		return time.Time{}, errors.New("not timestamped")
	}
	attrs, err := attributes(p.signer.UnauthenticatedAttributes)
	if err != nil {
		return time.Time{}, err
	}
	var errs []error
	for _, v := range attrs[oidMSTimestamp.String()] {
		t, err := rfc3161(v.FullBytes, p, roots)
		if err == nil {
			return t, nil
		}
		errs = append(errs, fmt.Errorf("RFC 3161 timestamp: %w", err))
	}
	for _, v := range attrs[oidAttrCounterSig.String()] {
		t, err := counterSignature(v.FullBytes, p, roots)
		if err == nil {
			return t, nil
		}
		errs = append(errs, fmt.Errorf("countersignature: %w", err))
	}
	if len(errs) == 0 {
		return time.Time{}, errors.New("not timestamped")
	}
	return time.Time{}, errors.Join(errs...)
}

func rfc3161(der []byte, outer *parsed, roots *x509.CertPool) (time.Time, error) {
	tok, err := parseSignedData(der)
	if err != nil {
		return time.Time{}, err
	}
	if !tok.sd.ContentInfo.ContentType.Equal(oidTSTInfo) {
		return time.Time{}, errors.New("token content is not TSTInfo")
	}
	certs := append(append([]*x509.Certificate{}, tok.certs...), outer.certs...)
	cert, _, _, err := checkSigner(tok.signer, certs, oidTSTInfo, tok.content)
	if err != nil {
		return time.Time{}, err
	}
	imprintAlg, imprint, gen, err := parseTSTInfo(tok.content)
	if err != nil {
		return time.Time{}, err
	}
	h, err := hashFor(imprintAlg)
	if err != nil && !errors.Is(err, errWeakDigest) {
		return time.Time{}, err
	}
	if !bytes.Equal(imprint, digestOf(h, outer.signer.EncryptedDigest)) {
		return time.Time{}, errors.New("timestamp is for a different signature")
	}
	if err := chain(cert, certs, roots, x509.ExtKeyUsageTimeStamping, gen); err != nil {
		return time.Time{}, fmt.Errorf("time-stamping certificate: %w", err)
	}
	return gen, nil
}

// parseTSTInfo reads version, policy, messageImprint, serialNumber, genTime
// (the leading fields of TSTInfo, RFC 3161 section 2.4.2).
func parseTSTInfo(der []byte) (asn1.ObjectIdentifier, []byte, time.Time, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil || seq.Tag != asn1.TagSequence {
		return nil, nil, time.Time{}, errors.New("TSTInfo is not a SEQUENCE")
	}
	rest := seq.Bytes
	next := func(v any) error {
		var err error
		rest, err = asn1.Unmarshal(rest, v)
		return err
	}
	var version int
	var policy asn1.ObjectIdentifier
	var mi digestInfo
	var serial asn1.RawValue
	var gen time.Time
	if next(&version) != nil || next(&policy) != nil || next(&mi) != nil || next(&serial) != nil || next(&gen) != nil {
		return nil, nil, time.Time{}, errors.New("TSTInfo malformed")
	}
	if version != 1 {
		return nil, nil, time.Time{}, fmt.Errorf("TSTInfo version %d", version)
	}
	return mi.Algorithm.Algorithm, mi.Digest, gen, nil
}

func counterSignature(der []byte, outer *parsed, roots *x509.CertPool) (time.Time, error) {
	var si signerInfo
	if rest, err := asn1.Unmarshal(der, &si); err != nil || len(rest) > 0 {
		return time.Time{}, fmt.Errorf("SignerInfo malformed: %v", err)
	}
	cert, _, attrs, err := checkSigner(si, outer.certs, nil, outer.signer.EncryptedDigest)
	if err != nil {
		return time.Time{}, err
	}
	stv, err := single(attrs, oidAttrSigningTime)
	if err != nil {
		return time.Time{}, err
	}
	var t time.Time
	if _, err := asn1.Unmarshal(stv.FullBytes, &t); err != nil {
		return time.Time{}, fmt.Errorf("signingTime: %w", err)
	}
	if err := chain(cert, outer.certs, roots, x509.ExtKeyUsageTimeStamping, t); err != nil {
		return time.Time{}, fmt.Errorf("time-stamping certificate: %w", err)
	}
	return t, nil
}
