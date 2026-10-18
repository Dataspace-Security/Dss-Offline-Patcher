package authenticode

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- a tiny CA and signer for synthetic, deterministic test files ----

type testCA struct {
	root, inter, leaf, tsa *x509.Certificate
	interKey, leafKey      crypto.Signer
	tsaKey                 crypto.Signer
	roots                  *x509.CertPool
}

func mkCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var serial int64 = 100

func tmpl(cn string, ca bool, from, to time.Time, eku ...x509.ExtKeyUsage) *x509.Certificate {
	serial++
	c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: []string{cn}},
		NotBefore: from, NotAfter: to, BasicConstraintsValid: true, IsCA: ca, ExtKeyUsage: eku}
	if ca {
		c.KeyUsage = x509.KeyUsageCertSign
	} else {
		c.KeyUsage = x509.KeyUsageDigitalSignature
	}
	return c
}

func newCA(t *testing.T, leafFrom, leafTo time.Time, leafEKU ...x509.ExtKeyUsage) *testCA {
	t.Helper()
	now := time.Now()
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ik, _ := rsa.GenerateKey(rand.Reader, 2048)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca := &testCA{interKey: ik, leafKey: lk, tsaKey: tk}
	rt := tmpl("Test Root", true, now.Add(-20*365*24*time.Hour), now.Add(20*365*24*time.Hour))
	ca.root = mkCert(t, rt, rt, &rk.PublicKey, rk)
	ca.inter = mkCert(t, tmpl("Test Code Signing CA", true, now.Add(-10*365*24*time.Hour), now.Add(10*365*24*time.Hour)), ca.root, &ik.PublicKey, rk)
	if len(leafEKU) == 0 {
		leafEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	ca.leaf = mkCert(t, tmpl("Contoso Software", false, leafFrom, leafTo, leafEKU...), ca.inter, &lk.PublicKey, ik)
	ca.tsa = mkCert(t, tmpl("Test TSA", false, now.Add(-5*365*24*time.Hour), now.Add(5*365*24*time.Hour), x509.ExtKeyUsageTimeStamping), ca.inter, &tk.PublicKey, ik)
	ca.roots = x509.NewCertPool()
	ca.roots.AddCert(ca.root)
	return ca
}

// minimalPE returns a PE32+ image with no sections, body bytes appended.
func minimalPE(body []byte) []byte {
	b := make([]byte, 0x40+24+240)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], 0x40)
	copy(b[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x44:], 0x8664)
	binary.LittleEndian.PutUint16(b[0x40+20:], 240)
	opt := 0x40 + 24
	binary.LittleEndian.PutUint16(b[opt:], 0x20b)
	binary.LittleEndian.PutUint32(b[opt+64:], 0xdeadbeef) // CheckSum: excluded from the digest
	binary.LittleEndian.PutUint32(b[opt+108:], 16)
	b = append(b, body...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b
}

const certDirAt = 0x40 + 24 + 112 + 4*8

func attr(t *testing.T, oid asn1.ObjectIdentifier, valueDER []byte) []byte {
	b, err := asn1.Marshal(attribute{Type: oid, Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valueDER}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustDER(t *testing.T, v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func explicit0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

func algID(oid asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	return pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}
}

// signerInfoFor signs authenticated attributes (contentType when ctype is
// set, messageDigest of content, extra) with key/cert.
func signerInfoFor(t *testing.T, cert *x509.Certificate, key crypto.Signer, ctype asn1.ObjectIdentifier, content []byte, extra ...[]byte) signerInfo {
	t.Helper()
	md := sha256.Sum256(content)
	var attrs []byte
	if ctype != nil {
		attrs = append(attrs, attr(t, oidAttrContentType, mustDER(t, ctype))...)
	}
	attrs = append(attrs, attr(t, oidAttrMessageDigest, mustDER(t, md[:]))...)
	for _, e := range extra {
		attrs = append(attrs, e...)
	}
	signed := mustDER(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attrs})
	h := sha256.Sum256(signed)
	sig, err := key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	enc := oidRSA
	if _, ok := key.(*ecdsa.PrivateKey); ok {
		enc = oidECDSASHA256
	}
	sid := mustDER(t, issuerAndSerial{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, Serial: cert.SerialNumber})
	return signerInfo{Version: 1, SID: asn1.RawValue{FullBytes: sid}, DigestAlgorithm: algID(oidSHA256),
		AuthenticatedAttributes:   asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs},
		DigestEncryptionAlgorithm: algID(enc), EncryptedDigest: sig}
}

func signedDataDER(t *testing.T, ctype asn1.ObjectIdentifier, contentTLV []byte, certs []*x509.Certificate, si signerInfo) []byte {
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	sd := signedData{Version: 1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: mustDER(t, algID(oidSHA256))},
		ContentInfo:      contentInfo{ContentType: ctype, Content: explicit0(contentTLV)},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:      []signerInfo{si}}
	return mustDER(t, contentInfo{ContentType: oidSignedData, Content: explicit0(mustDER(t, sd))})
}

type signOpts struct {
	digestOID asn1.ObjectIdentifier // default SHA-256
	timestamp time.Time             // RFC 3161 token at this time, if set
	tsTamper  bool                  // timestamp for another signature
}

// sign returns pe with an embedded Authenticode signature by ca.leaf.
func sign(t *testing.T, ca *testCA, pe []byte, o signOpts) []byte {
	t.Helper()
	pe = append([]byte{}, pe...)
	certOff := len(pe)
	// The digest excludes the directory entry, so it can be computed first.
	img := &peImage{size: int64(certOff), checksumOff: 0x40 + 24 + 64, certDirOff: certDirAt, certOff: int64(certOff)}
	h := crypto.SHA256
	if o.digestOID == nil {
		o.digestOID = oidSHA256
	} else if o.digestOID.Equal(oidSHA1) {
		h = crypto.SHA1
	}
	d, err := img.digest(bytes.NewReader(pe), h.New())
	if err != nil {
		t.Fatal(err)
	}
	spc := mustDER(t, spcIndirectDataContent{
		Data:          spcAttributeTypeAndValue{Type: oidSpcPEImageData, Value: asn1.RawValue{FullBytes: []byte{0x30, 0x00}}},
		MessageDigest: digestInfo{Algorithm: algID(o.digestOID), Digest: d}})
	var inner asn1.RawValue
	asn1.Unmarshal(spc, &inner)
	si := signerInfoFor(t, ca.leaf, ca.leafKey, oidSpcIndirectData, inner.Bytes)
	if !o.timestamp.IsZero() {
		target := si.EncryptedDigest
		if o.tsTamper {
			target = []byte("another signature")
		}
		si.UnauthenticatedAttributes = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true,
			Bytes: attr(t, oidMSTimestamp, tsToken(t, ca, target, o.timestamp))}
	}
	blob := signedDataDER(t, oidSpcIndirectData, spc, []*x509.Certificate{ca.leaf, ca.inter}, si)
	entry := make([]byte, 8, 8+len(blob)+8)
	entry = append(entry, blob...)
	for len(entry)%8 != 0 {
		entry = append(entry, 0)
	}
	binary.LittleEndian.PutUint32(entry, uint32(8+len(blob)))
	binary.LittleEndian.PutUint16(entry[4:], winCertRevision)
	binary.LittleEndian.PutUint16(entry[6:], winCertPKCS7)
	binary.LittleEndian.PutUint32(pe[certDirAt:], uint32(certOff))
	binary.LittleEndian.PutUint32(pe[certDirAt+4:], uint32(len(entry)))
	return append(pe, entry...)
}

func tsToken(t *testing.T, ca *testCA, sigValue []byte, at time.Time) []byte {
	imprint := sha256.Sum256(sigValue)
	tst := mustDER(t, struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint digestInfo
		Serial         *big.Int
		GenTime        time.Time `asn1:"generalized"`
	}{1, asn1.ObjectIdentifier{1, 2, 3, 4}, digestInfo{Algorithm: algID(oidSHA256), Digest: imprint[:]}, big.NewInt(7), at.UTC().Truncate(time.Second)})
	si := signerInfoFor(t, ca.tsa, ca.tsaKey, oidTSTInfo, tst)
	octet := mustDER(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: tst})
	return signedDataDER(t, oidTSTInfo, octet, []*x509.Certificate{ca.tsa}, si)
}

func verifyBytes(b []byte, roots *x509.CertPool) (*Result, error) {
	return Verify(bytes.NewReader(b), int64(len(b)), Options{Roots: roots})
}

func TestVerifyValid(t *testing.T) {
	now := time.Now()
	ca := newCA(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	signed := sign(t, ca, minimalPE([]byte("installer body")), signOpts{})
	res, err := verifyBytes(signed, ca.roots)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signer != "Contoso Software" || res.Digest != "sha256" || res.Issuer != "Test Code Signing CA" || !res.SignedAt.IsZero() {
		t.Fatalf("result %+v", res)
	}
	// The CheckSum field is not covered: changing it keeps the signature.
	cs := append([]byte{}, signed...)
	cs[0x40+24+64] ^= 0xff
	if _, err := verifyBytes(cs, ca.roots); err != nil {
		t.Fatalf("checksum change broke the signature: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Now()
	ca := newCA(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	pe := minimalPE([]byte("installer body"))
	signed := sign(t, ca, pe, signOpts{})

	tampered := append([]byte{}, signed...)
	tampered[0x40+24+240] ^= 1 // first body byte
	if _, err := verifyBytes(tampered, ca.roots); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("tampered body: %v", err)
	}
	if _, err := verifyBytes(signed, newCA(t, now.Add(-time.Hour), now.Add(time.Hour)).roots); err == nil {
		t.Error("untrusted root accepted")
	}
	if _, err := verifyBytes(signed, EmbeddedRoots()); err == nil {
		t.Error("test signer accepted by the shipped roots")
	}
	if _, err := verifyBytes(append(append([]byte{}, signed...), "appended"...), ca.roots); err == nil || !strings.Contains(err.Error(), "end of the file") {
		t.Errorf("data after the signature: %v", err)
	}
	if _, err := verifyBytes(pe, ca.roots); !errors.Is(err, ErrNotSigned) {
		t.Errorf("unsigned PE: %v", err)
	}
	if _, err := verifyBytes([]byte(strings.Repeat("not a pe file ", 10)), ca.roots); err == nil {
		t.Error("non-PE accepted")
	}
	tls := newCA(t, now.Add(-time.Hour), now.Add(365*24*time.Hour), x509.ExtKeyUsageServerAuth)
	if _, err := verifyBytes(sign(t, tls, pe, signOpts{}), tls.roots); err == nil {
		t.Error("certificate without code-signing usage accepted")
	}
	if _, err := verifyBytes(sign(t, ca, pe, signOpts{digestOID: oidSHA1}), ca.roots); err == nil || !strings.Contains(err.Error(), "SHA-1") {
		t.Errorf("SHA-1 signature: %v", err)
	}
	// Wrong signer: a valid signature blob moved onto another file.
	other := sign(t, ca, minimalPE([]byte("other body....")), signOpts{})
	moved := append(append([]byte{}, pe...), other[len(pe):]...)
	copy(moved[certDirAt:certDirAt+8], other[certDirAt:certDirAt+8])
	if _, err := verifyBytes(moved, ca.roots); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("signature moved to another file: %v", err)
	}
}

func TestVerifyTimestamp(t *testing.T) {
	now := time.Now()
	// The signing certificate expired a month ago.
	ca := newCA(t, now.Add(-400*24*time.Hour), now.Add(-30*24*time.Hour))
	pe := minimalPE([]byte("old installer"))
	if _, err := verifyBytes(sign(t, ca, pe, signOpts{}), ca.roots); err == nil {
		t.Fatal("expired certificate without timestamp accepted")
	}
	at := now.Add(-200 * 24 * time.Hour)
	res, err := verifyBytes(sign(t, ca, pe, signOpts{timestamp: at}), ca.roots)
	if err != nil {
		t.Fatalf("timestamped signature: %v", err)
	}
	if !res.SignedAt.Equal(at.UTC().Truncate(time.Second)) {
		t.Fatalf("SignedAt %v", res.SignedAt)
	}
	if _, err := verifyBytes(sign(t, ca, pe, signOpts{timestamp: at, tsTamper: true}), ca.roots); err == nil {
		t.Fatal("timestamp of another signature accepted")
	}
	if _, err := verifyBytes(sign(t, ca, pe, signOpts{timestamp: now.Add(-10 * 24 * time.Hour)}), ca.roots); err == nil {
		t.Fatal("timestamp after the certificate expired accepted")
	}
}

// The shipped roots are exactly the reviewed set (SHA-256 of the DER).
func TestEmbeddedRoots(t *testing.T) {
	want := map[string]string{
		"df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e": "Microsoft Root Certificate Authority 2010",
		"847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61": "Microsoft Root Certificate Authority 2011",
		"5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270": "Microsoft Identity Verification Root Certificate Authority 2020",
		"552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988": "DigiCert Trusted Root G4",
		"3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c": "DigiCert Assured ID Root CA",
		"e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2": "USERTrust RSA Certification Authority",
	}
	rest := rootsPEM
	n := 0
	for {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(c.Raw)
		if cn, ok := want[hex.EncodeToString(sum[:])]; !ok || cn != c.Subject.CommonName {
			t.Errorf("unexpected root %q", c.Subject.CommonName)
		}
		n++
	}
	if n != len(want) {
		t.Fatalf("%d roots, want %d", n, len(want))
	}
}

// Real vendor files, when the host has them (Windows dev machines): verified
// against the shipped roots only, as a Linux acquisition host would.
func TestVerifyRealFiles(t *testing.T) {
	cands := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\EdgeWebView\Application\msedgewebview2.exe`),
		os.Getenv("OFFPATCH_AUTHENTICODE_SAMPLE"),
	}
	tested := 0
	for _, p := range cands {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		res, err := VerifyFile(p, Options{Roots: EmbeddedRoots()})
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		t.Logf("%s: signer %q issuer %q digest %s signed %v", p, res.Signer, res.Issuer, res.Digest, res.SignedAt)
		tested++
	}
	if tested == 0 {
		t.Skip("no signed sample on this host (set OFFPATCH_AUTHENTICODE_SAMPLE)")
	}
}
