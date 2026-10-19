// Package pki is the small internal certificate authority used inside the
// isolated zone: it issues the server's TLS certificate and per-endpoint
// client certificates (mTLS) at enrollment and renewal.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	CAFile     = "ca.pem"
	CAKeyFile  = "ca.key"
	ServerCert = "server.pem"
	ServerKey  = "server.key"

	ClientValidity = 365 * 24 * time.Hour

	// AgentALPN: TLS ALPN protocol agents (0.9.1+) offer, so the server
	// answers them with the internal certificate and a client-certificate
	// request even on a name browsers get a public certificate for.
	AgentALPN = "dss-agent/1"
)

// RenewBefore: agents renew when their certificate expires within this window.
var RenewBefore = 30 * 24 * time.Hour

type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// SerialHex is the canonical form stored in the database.
func SerialHex(c *x509.Certificate) string { return strings.ToLower(c.SerialNumber.Text(16)) }

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func writeKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	return writePEM(path, "EC PRIVATE KEY", der, 0o600)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

func ParseCertPEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// Init creates a CA and a server certificate for hosts (DNS names or IPs).
// It refuses to overwrite an existing CA.
func Init(dir string, hosts []string) error {
	if _, err := os.Stat(filepath.Join(dir, CAKeyFile)); err == nil {
		return fmt.Errorf("%s already contains a CA; refusing to overwrite", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "offpatch internal CA", Organization: []string{"offpatch"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, CAKeyFile), key); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, CAFile), "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	ca, err := Load(dir)
	if err != nil {
		return err
	}
	return ca.IssueServer(dir, hosts)
}

// Load reads the CA from dir.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CAFile))
	if err != nil {
		return nil, err
	}
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := readKey(filepath.Join(dir, CAKeyFile))
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// IssueServer writes server.pem/server.key for the given hosts.
func (ca *CA) IssueServer(dir string, hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("at least one host name or IP is required for the server certificate")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"offpatch"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if h != "" {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, ServerKey), key); err != nil {
		return err
	}
	return writePEM(filepath.Join(dir, ServerCert), "CERTIFICATE", der, 0o644)
}

// SignClientCSR issues a client certificate for an endpoint. The subject is
// forced to the endpoint ID regardless of what the CSR asks for.
func (ca *CA) SignClientCSR(csrPEM []byte, endpointID string) (certPEM []byte, cert *x509.Certificate, err error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("csr: no CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("csr signature: %w", err)
	}
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize < 256 {
			return nil, nil, errors.New("csr: ECDSA key too small")
		}
	default:
		return nil, nil, errors.New("csr: only ECDSA keys are accepted")
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: endpointID, OrganizationalUnit: []string{"offpatch-endpoint"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ClientValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	cert, _ = x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// NewClientKey creates an endpoint key and CSR (agent side).
func NewClientKey(keyPath string) (csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeKey(keyPath, key); err != nil {
		return nil, err
	}
	return csrFor(key)
}

// CSRFromKey makes a new CSR for an existing key file (renewal).
func CSRFromKey(keyPath string) ([]byte, error) {
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	return csrFor(key)
}

func csrFor(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "offpatch-endpoint"}}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Fingerprint is the SHA-256 of the certificate DER, for display.
func Fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}
