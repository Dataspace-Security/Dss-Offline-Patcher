package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/pki"
	"offpatch/internal/server"
	"offpatch/internal/store"
)

// clientFor returns an HTTP client presenting the agent's current certificate.
func (e *env) clientFor(a *simAgent) *http.Client {
	e.t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(a.dir, "client.pem"), filepath.Join(a.dir, "client.key"))
	if err != nil {
		e.t.Fatal(err)
	}
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(e.caFile)
	pool.AppendCertsFromPEM(caPEM)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}}}}
}

func status(t *testing.T, c *http.Client, method, url string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(`{"hostname":"x","inventory":[]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestMTLS(t *testing.T) {
	e := newEnvOpts(t, true, "")
	if !strings.HasPrefix(e.srv.URL, "https://") {
		t.Fatal("server not on TLS")
	}

	a := e.enroll("pc-tls-01", []string{"pilot"}, agent.SimConfig{})
	st, _ := agent.LoadState(a.dir)
	if st.Secret != "" || st.CertFile == "" {
		t.Fatalf("TLS enrollment must issue a certificate and no bearer secret: %+v", st)
	}
	if fi, err := os.Stat(filepath.Join(a.dir, "client.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("client key must exist with 0600: %v", err)
	}
	e.cycle(a)

	// Agent API without a client certificate is refused, even with a bearer.
	if c := status(t, e.hc, "POST", e.srv.URL+"/api/agent/checkin"); c != 401 {
		t.Fatalf("checkin without client cert: %d", c)
	}
	// Admin console works without a client certificate.
	if c := e.api("GET", "/api/summary", tokViewer, nil, nil); c != 200 {
		t.Fatalf("admin over TLS: %d", c)
	}

	// Enrollment without a CSR is refused on a TLS server.
	var tok store.EnrollmentToken
	e.api("POST", "/api/enrollment-tokens", tokOperator, map[string]any{"groups": []string{"x"}, "site": "hq", "expires_in_hours": 1}, &tok)
	if c := e.api("POST", "/api/agent/enroll", "", store.EnrollRequest{Token: tok.Token, Hostname: "nocsr"}, nil); c != 400 {
		t.Fatalf("enroll without csr: %d", c)
	}

	// Renewal: the old certificate stops working, the new one works.
	oldClient := e.clientFor(a)
	if c := status(t, oldClient, "POST", e.srv.URL+"/api/agent/checkin"); c != 200 {
		t.Fatalf("checkin with current cert: %d", c)
	}
	saved := pki.RenewBefore
	pki.RenewBefore = 400 * 24 * time.Hour // force renewal on the next cycle
	e.cycle(a)
	pki.RenewBefore = saved
	if c := status(t, oldClient, "POST", e.srv.URL+"/api/agent/checkin"); c != 401 {
		t.Fatalf("renewed (old) certificate still accepted: %d", c)
	}
	e.cycle(a) // agent uses its new certificate

	// A certificate for another endpoint ID signed by a different CA is refused at TLS level.
	other := t.TempDir()
	if err := pki.Init(other, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	rogueCA, _ := pki.Load(other)
	csr, _ := pki.NewClientKey(filepath.Join(other, "rogue.key"))
	roguePEM, _, err := rogueCA.SignClientCSR(csr, a.id)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(other, "rogue.pem"), roguePEM, 0o600)
	pair, _ := tls.LoadX509KeyPair(filepath.Join(other, "rogue.pem"), filepath.Join(other, "rogue.key"))
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(e.caFile)
	pool.AppendCertsFromPEM(caPEM)
	rogue := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}}}}
	if resp, err := rogue.Post(e.srv.URL+"/api/agent/checkin", "application/json", strings.NewReader(`{}`)); err == nil {
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("certificate from a foreign CA accepted: %d", resp.StatusCode)
		}
	}

	// Retire: credentials stop working immediately; history stays.
	var ep store.Endpoint
	if c := e.api("POST", "/api/endpoints/"+a.id+"/retire", tokOperator, map[string]string{"reason": "laptop lost"}, &ep); c != 200 || ep.Status != "retired" {
		t.Fatalf("retire: %d %+v", c, ep)
	}
	if err := a.Cycle(context.Background()); err == nil {
		t.Fatal("retired endpoint can still check in")
	}
	if c := e.api("POST", "/api/endpoints/"+a.id+"/retire", tokOperator, map[string]string{"reason": "again"}, nil); c != 409 {
		t.Fatalf("double retire: %d", c)
	}
	var sm store.Summary
	e.api("GET", "/api/summary", tokViewer, nil, &sm)
	if sm.Endpoints.Total != 0 || sm.Endpoints.Retired != 1 {
		t.Fatalf("summary should exclude retired endpoints: %+v", sm.Endpoints)
	}
}

func TestTLSRequiredByDefault(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	os.WriteFile(p, []byte(`{"trusted_keys":[{"public_key":"x","sources":["a"]}],"admin_tokens":[{"user":"a","role":"admin","token_sha256":"`+strings.Repeat("a", 64)+`"}]}`), 0o600)
	if _, err := server.LoadConfig(p); err == nil || !strings.Contains(err.Error(), "TLS is required") {
		t.Fatalf("config without TLS or insecure_http must be refused, got %v", err)
	}
}

func TestMultiUseEnrollmentToken(t *testing.T) {
	e := newEnv(t)
	var tok store.EnrollmentToken
	if c := e.api("POST", "/api/enrollment-tokens", tokOperator, map[string]any{"groups": []string{"fleet"}, "site": "hq", "expires_in_hours": 48, "max_uses": 3}, &tok); c != 201 || tok.MaxUses != 3 {
		t.Fatalf("multi-use token: %d %+v", c, tok)
	}
	for i := 0; i < 3; i++ {
		if c := e.api("POST", "/api/agent/enroll", "", store.EnrollRequest{Token: tok.Token, Hostname: "pc-mass-" + string(rune('a'+i))}, nil); c != 201 {
			t.Fatalf("use %d: %d", i+1, c)
		}
	}
	if c := e.api("POST", "/api/agent/enroll", "", store.EnrollRequest{Token: tok.Token, Hostname: "pc-mass-d"}, nil); c != 401 {
		t.Fatalf("4th use of a 3-use token: %d", c)
	}
	if c := e.api("POST", "/api/enrollment-tokens", tokOperator, map[string]any{"groups": []string{"x"}, "expires_in_hours": 720, "max_uses": 50}, nil); c != 400 {
		t.Fatalf("long-lived multi-use token accepted: %d", c)
	}
}
