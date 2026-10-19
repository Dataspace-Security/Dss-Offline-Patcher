package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/pki"
)

// Public console certificate: with public_tls, a browser on the public name
// gets the public certificate, while agents enroll, check in and renew over
// the internal CA + mTLS exactly as before: older agents by IP (no SNI),
// agents 0.9.1+ also on the public name (ALPN dss-agent/1). A client without
// the ALPN on the public name gets a clear 421 from the agent API.
func TestPublicConsoleCertificate(t *testing.T) {
	const name = "patch.example.test"
	certDir := t.TempDir()
	certFile, keyFile := filepath.Join(certDir, "cert.pem"), filepath.Join(certDir, "key.pem")
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	kb, _ := x509.MarshalECPrivateKey(k)
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)

	e := newEnvOpts(t, true, fmt.Sprintf(`"public_tls": {"names": [%q], "cert_file": %q, "key_file": %q}, "agent_url": "https://127.0.0.1:8443",`, name, certFile, keyFile))

	// Agents by IP: enrollment, check-in, the agent API with a client certificate.
	a := e.enroll("pc-pub-01", []string{"pilot"}, agent.SimConfig{})
	e.cycle(a)
	if c := status(t, e.clientFor(a), "POST", e.srv.URL+"/api/agent/checkin"); c != 200 {
		t.Fatalf("agent check-in by IP with public_tls on: %d", c)
	}

	// The same agent pointed at the public name: the public certificate
	// verifies (browser view), no client certificate is asked for, and the
	// agent API answers 421 naming the agent URL.
	pubPool := x509.NewCertPool()
	pubPool.AddCert(func() *x509.Certificate { c, _ := x509.ParseCertificate(der); return c }())
	pair, err := tls.LoadX509KeyPair(filepath.Join(a.dir, "client.pem"), filepath.Join(a.dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: name, RootCAs: pubPool, Certificates: []tls.Certificate{pair}}}}
	resp, err := browser.Post(e.srv.URL+"/api/agent/checkin", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("public name does not verify with the public certificate: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest || !strings.Contains(string(body), "https://127.0.0.1:8443") {
		t.Fatalf("agent API on the public name: %d %s", resp.StatusCode, body)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0].SerialNumber.Int64() != 42 {
		t.Fatal("public name was not served the public certificate")
	}
	// An agent 0.9.1+ on the same name offers ALPN dss-agent/1: it gets the
	// internal certificate and the client-certificate request, and checks in.
	caPEM, _ := os.ReadFile(e.caFile)
	caBlock, _ := pem.Decode(caPEM)
	ca, _ := x509.ParseCertificate(caBlock.Bytes)
	agentTLS := &tls.Config{ServerName: name, Certificates: []tls.Certificate{pair}, NextProtos: []string{pki.AgentALPN, "http/1.1"},
		InsecureSkipVerify: true, // the test CA's server certificate names 127.0.0.1 only; checked by hand below
		VerifyConnection: func(cs tls.ConnectionState) error {
			return cs.PeerCertificates[0].CheckSignatureFrom(ca)
		}}
	newAgent := &http.Client{Transport: &http.Transport{TLSClientConfig: agentTLS}}
	if c := status(t, newAgent, "POST", e.srv.URL+"/api/agent/checkin"); c != 200 {
		t.Fatalf("agent with ALPN on the public name: %d", c)
	}
	// The console itself works on the public name.
	resp, err = browser.Get(e.srv.URL + "/auth/config")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("console on the public name: %v %v", err, resp)
	}
	resp.Body.Close()

	// The console (whatever name it is opened on) offers the agent URL.
	var setup struct {
		AgentURL    string   `json:"agent_url"`
		Configured  bool     `json:"agent_url_configured"`
		PublicNames []string `json:"public_names"`
	}
	e.api("GET", "/api/agent-setup", tokViewer, nil, &setup)
	if setup.AgentURL != "https://127.0.0.1:8443" || !setup.Configured || len(setup.PublicNames) != 1 {
		b, _ := json.Marshal(setup)
		t.Fatalf("agent-setup: %s", b)
	}
}
