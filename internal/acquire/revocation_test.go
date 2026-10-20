package acquire

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type crlCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCRLCA(t *testing.T, cn string) crlCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return crlCA{cert: c, key: k}
}

func (ca crlCA) leaf(t *testing.T, serial int64, crlURL string) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Contoso Software", Organization: []string{"Contoso Ltd"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	if crlURL != "" {
		tmpl.CRLDistributionPoints = []string{crlURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func (ca crlCA) crl(t *testing.T, revoked ...x509.RevocationListEntry) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(7 * 24 * time.Hour), RevokedCertificateEntries: revoked}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRevocationCheck(t *testing.T) {
	ca, other := newCRLCA(t, "Test Code Signing CA"), newCRLCA(t, "Someone Else")
	revokedAt := time.Now().Add(-30 * time.Minute)
	crls := map[string][]byte{
		"/ca.crl":      ca.crl(t, x509.RevocationListEntry{SerialNumber: big.NewInt(66), RevocationTime: revokedAt, ReasonCode: 1}),
		"/benign.crl":  ca.crl(t, x509.RevocationListEntry{SerialNumber: big.NewInt(67), RevocationTime: revokedAt, ReasonCode: 4}),
		"/forged.crl":  other.crl(t),
		"/garbage.crl": []byte("not a crl"),
	}
	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		b, ok := crls[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()
	rc := &RevocationChecker{HTTP: (&Guard{AllowHTTP: true, PrivateOK: map[string]bool{"127.0.0.1": true}}).Client(nil), CacheDir: t.TempDir()}
	ctx := context.Background()

	cases := []struct {
		name     string
		leaf     *x509.Certificate
		issuer   *x509.Certificate
		signedAt time.Time
		want     string
		detail   string
	}{
		{"revoked", ca.leaf(t, 66, srv.URL+"/ca.crl"), ca.cert, time.Time{}, RevocationRevoked, "revoked"},
		{"good", ca.leaf(t, 70, srv.URL+"/ca.crl"), ca.cert, time.Time{}, RevocationGood, "not on the CRL"},
		{"superseded after a timestamped signature", ca.leaf(t, 67, srv.URL+"/benign.crl"), ca.cert, revokedAt.Add(-time.Hour), RevocationGood, "after the timestamped signature"},
		{"superseded, no timestamp", ca.leaf(t, 67, srv.URL+"/benign.crl"), ca.cert, time.Time{}, RevocationRevoked, "revoked"},
		{"CRL not found", ca.leaf(t, 71, srv.URL+"/missing.crl"), ca.cert, time.Time{}, RevocationUnknown, "HTTP 404"},
		{"CRL signed by another CA", ca.leaf(t, 72, srv.URL+"/forged.crl"), ca.cert, time.Time{}, RevocationUnknown, "not signed by the certificate's issuer"},
		{"not a CRL", ca.leaf(t, 73, srv.URL+"/garbage.crl"), ca.cert, time.Time{}, RevocationUnknown, "not a CRL"},
		{"no distribution point", ca.leaf(t, 74, ""), ca.cert, time.Time{}, RevocationUnknown, "no CRL distribution point"},
		{"no issuer", ca.leaf(t, 75, srv.URL+"/ca.crl"), nil, time.Time{}, RevocationUnknown, "chain not available"},
	}
	for _, c := range cases {
		got := rc.Check(ctx, c.leaf, c.issuer, c.signedAt)
		if got.Status != c.want || !strings.Contains(got.Detail, c.detail) {
			t.Errorf("%s: %+v, want %s (%q)", c.name, got, c.want, c.detail)
		}
	}

	// Cached until NextUpdate: no download when the server is gone.
	srv.Close()
	n := fetches
	if got := rc.Check(ctx, ca.leaf(t, 66, srv.URL+"/ca.crl"), ca.cert, time.Time{}); got.Status != RevocationRevoked || fetches != n {
		t.Errorf("cached CRL: %+v (fetches %d -> %d)", got, n, fetches)
	}

	// Loopback CRL URLs are refused unless allowed (SSRF guard).
	strict := &RevocationChecker{HTTP: (&Guard{AllowHTTP: true}).Client(nil)}
	if got := strict.Check(ctx, ca.leaf(t, 80, "http://127.0.0.1:1/ca.crl"), ca.cert, time.Time{}); got.Status != RevocationUnknown ||
		!strings.Contains(got.Detail, "loopback") {
		t.Errorf("loopback CRL: %+v", got)
	}
}

func TestRevocationSizeLimit(t *testing.T) {
	ca := newCRLCA(t, "Test CA")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 4096))
	}))
	defer srv.Close()
	rc := &RevocationChecker{HTTP: (&Guard{AllowHTTP: true, PrivateOK: map[string]bool{"127.0.0.1": true}}).Client(nil), MaxBytes: 1024}
	if got := rc.Check(context.Background(), ca.leaf(t, 9, srv.URL+"/big.crl"), ca.cert, time.Time{}); got.Status != RevocationUnknown ||
		!strings.Contains(got.Detail, "larger than") {
		t.Errorf("oversized CRL: %+v", got)
	}
}
