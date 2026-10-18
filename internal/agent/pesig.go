package agent

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

// peSigner reads the primary Authenticode signer of a PE file from its
// certificate table (the first WIN_CERTIFICATE, PKCS#7 SignedData, first
// SignerInfo): the certificate WinVerifyTrust validates. It returns that
// certificate's subject CN and first O. It does not verify anything itself;
// the caller runs WinVerifyTrust first.

const (
	peDirSecurity       = 4      // IMAGE_DIRECTORY_ENTRY_SECURITY
	winCertTypePKCS7    = 0x0002 // WIN_CERT_TYPE_PKCS_SIGNED_DATA
	maxCertTable        = 4 << 20
	winCertHeaderLength = 8
)

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue     `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue     `asn1:"optional,tag:1"`
	SignerInfos      []pkcs7SignerInfo `asn1:"set"`
}

type pkcs7SignerInfo struct {
	Version          int
	IssuerAndSerial  pkcs7IssuerAndSerial
	DigestAlgorithm  pkix.AlgorithmIdentifier
	AuthAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryption pkix.AlgorithmIdentifier
	EncryptedDigest  []byte
	UnauthAttributes asn1.RawValue `asn1:"optional,tag:1"`
}

type pkcs7IssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

func peSigner(path string) (cn, org string, err error) {
	blob, err := peCertificateTable(path)
	if err != nil {
		return "", "", err
	}
	cert, err := pkcs7Signer(blob)
	if err != nil {
		return "", "", err
	}
	cn = cert.Subject.CommonName
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}
	return cn, org, nil
}

// peCertificateTable returns the PKCS#7 blob of the first WIN_CERTIFICATE.
func peCertificateTable(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pf, err := pe.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("not a PE file: %w", err)
	}
	var dir pe.DataDirectory
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes > peDirSecurity {
			dir = oh.DataDirectory[peDirSecurity]
		}
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes > peDirSecurity {
			dir = oh.DataDirectory[peDirSecurity]
		}
	default:
		return nil, errors.New("PE file without an optional header")
	}
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil, errors.New("file has no embedded Authenticode signature")
	}
	if dir.Size < winCertHeaderLength || dir.Size > maxCertTable {
		return nil, fmt.Errorf("certificate table size %d out of range", dir.Size)
	}
	// The security directory's "VirtualAddress" is a file offset.
	buf := make([]byte, dir.Size)
	if _, err := f.ReadAt(buf, int64(dir.VirtualAddress)); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read certificate table: %w", err)
	}
	length := binary.LittleEndian.Uint32(buf[0:4])
	ctype := binary.LittleEndian.Uint16(buf[6:8])
	if ctype != winCertTypePKCS7 {
		return nil, fmt.Errorf("unsupported certificate type 0x%04X", ctype)
	}
	if length < winCertHeaderLength || length > dir.Size {
		return nil, fmt.Errorf("WIN_CERTIFICATE length %d out of range", length)
	}
	return buf[winCertHeaderLength:length], nil
}

// oidNestedSignature: Authenticode nested signatures (szOID_NESTED_SIGNATURE),
// stored in the primary SignerInfo's unauthenticated attributes.
var oidNestedSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}

type pkcs7Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// peSigners returns the subject (CN, O) of the primary signer and of every
// nested signature. pmctl records the signer of the signature it verified,
// which for dual-signed files may be a nested one; WinVerifyTrust has
// already accepted the file as a whole before these names are compared.
func peSigners(path string) ([][2]string, error) {
	blob, err := peCertificateTable(path)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	var walk func(der []byte, depth int) error
	walk = func(der []byte, depth int) error {
		cert, err := pkcs7Signer(der)
		if err != nil {
			return err
		}
		org := ""
		if len(cert.Subject.Organization) > 0 {
			org = cert.Subject.Organization[0]
		}
		out = append(out, [2]string{cert.Subject.CommonName, org})
		if depth >= 4 {
			return nil
		}
		for _, n := range nestedSignatureBlobs(der) {
			_ = walk(n, depth+1) // an unreadable nested signature only loses that name
		}
		return nil
	}
	if err := walk(blob, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// nestedSignatureBlobs returns the DER ContentInfo of each nested signature
// in the first SignerInfo's unauthenticated attributes (none on any error).
func nestedSignatureBlobs(der []byte) [][]byte {
	var ci pkcs7ContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil
	}
	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(sd.SignerInfos) == 0 {
		return nil
	}
	var out [][]byte
	for rest := sd.SignerInfos[0].UnauthAttributes.Bytes; len(rest) > 0; {
		var a pkcs7Attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return out
		}
		if !a.Type.Equal(oidNestedSignature) {
			continue
		}
		for vals := a.Values.Bytes; len(vals) > 0; {
			var v asn1.RawValue
			if vals, err = asn1.Unmarshal(vals, &v); err != nil {
				break
			}
			out = append(out, v.FullBytes)
		}
	}
	return out
}

// pkcs7Signer returns the certificate of the first SignerInfo.
func pkcs7Signer(der []byte) (*x509.Certificate, error) {
	var ci pkcs7ContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("signature is not PKCS#7: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errors.New("signature is not PKCS#7 SignedData")
	}
	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, errors.New("signature has no signer")
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, errors.New("signature carries no certificates")
	}
	si := sd.SignerInfos[0].IssuerAndSerial
	if si.Serial == nil {
		return nil, errors.New("signer has no serial number")
	}
	// One certificate at a time: an unparsable intermediate or timestamp
	// certificate in the bag must not hide the signer's.
	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return nil, fmt.Errorf("signature certificates: %w", err)
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			continue
		}
		if bytes.Equal(c.RawIssuer, si.Issuer.FullBytes) && c.SerialNumber.Cmp(si.Serial) == 0 {
			return c, nil
		}
	}
	return nil, errors.New("signer certificate not found in the signature")
}
