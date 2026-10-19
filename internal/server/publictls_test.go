package server

import (
	"context"
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
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/pki"
	"offpatch/internal/repo"
	"offpatch/internal/store"
)

const pubName = "patch.example.test"

// writePublicPair writes a self-signed certificate (standing in for Let's
// Encrypt) and its key, and returns the certificate's serial.
func writePublicPair(t *testing.T, certPath, keyPath string, notBefore, notAfter time.Time, names ...string) *big.Int {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Test Public CA"}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	os.MkdirAll(filepath.Dir(certPath), 0o700)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	// Distinct mtimes even on coarse file systems.
	mt := time.Now().Add(time.Duration(serial.Int64()%1000) * time.Second)
	os.Chtimes(certPath, mt, mt)
	os.Chtimes(keyPath, mt, mt)
	return serial
}

type pubEnv struct {
	s        *Server
	dir      string
	certPath string
	keyPath  string
	addr     string
	url      string
}

const serverName = "patcher.bank.example"

// newPublicTLSServer: a TLS server with the internal PKI (127.0.0.1 and
// 169.58.36.46 in its certificate) and public_tls for pubName. extra is
// spliced into the config; withCert writes a valid public certificate first.
func newPublicTLSServer(t *testing.T, extra string, withCert bool) *pubEnv {
	t.Helper()
	dir := t.TempDir()
	if err := pki.Init(filepath.Join(dir, "pki"), []string{serverName, "127.0.0.1", "169.58.36.46"}); err != nil {
		t.Fatal(err)
	}
	e := &pubEnv{dir: dir, certPath: filepath.Join(dir, "pki", "public", "cert.pem"), keyPath: filepath.Join(dir, "pki", "public", "key.pem")}
	if withCert {
		writePublicPair(t, e.certPath, e.keyPath, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), pubName)
	}
	pub, _, _ := manifest.GenerateKey()
	cfg := fmt.Sprintf(`{"listen": "0.0.0.0:8443", "pki_dir": "pki", "public_tls": {"names": [%q]}, %s "data_dir": "data",
	  "trusted_keys":[{"public_key": %q, "sources":["s"]}]}`, strings.ToUpper(pubName), extra, manifest.EncodePublic(pub))
	p := filepath.Join(dir, "pmserver.json")
	os.WriteFile(p, []byte(cfg), 0o600)
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(c.DataDir, 0o750)
	st, err := store.Open(filepath.Join(c.DataDir, "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rp, _ := repo.New(filepath.Join(c.DataDir, "repository"))
	e.s, err = New(c, st, rp, fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(e.s.Handler())
	ts.TLS = e.s.TLSConfig()
	ts.Config.ConnContext, ts.Config.ConnState = e.s.ConnContext, e.s.ConnState
	ts.StartTLS()
	t.Cleanup(ts.Close)
	e.url = ts.URL
	e.addr = strings.TrimPrefix(ts.URL, "https://")
	return e
}

// dial handshakes with SNI name ("" = none, as agents connecting by IP) and
// the given ALPN protocols, and reports the served leaf and whether a client
// certificate was requested.
func (e *pubEnv) dial(t *testing.T, name string, alpn ...string) (*x509.Certificate, bool) {
	t.Helper()
	asked := false
	conn, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: alpn,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			asked = true
			return &tls.Certificate{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// TLS 1.3 sends the CertificateRequest after the server Finished: read
	// once so the client has processed it.
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	conn.Read(make([]byte, 1))
	return conn.ConnectionState().PeerCertificates[0], asked
}

func (e *pubEnv) isInternal(c *x509.Certificate) bool {
	return e.s.ca != nil && c.CheckSignatureFrom(e.s.ca.Cert) == nil
}

func (e *pubEnv) setNow(f func() time.Time) {
	e.s.pub.mu.Lock()
	e.s.pub.now = f
	e.s.pub.mu.Unlock()
}

// Certificate selection: a browser on the public name (SNI, no agent ALPN)
// gets the public certificate and no client-certificate request. Agents get
// the internal certificate with the request: by ALPN dss-agent/1 (0.9.1+,
// also on the public name), without SNI (older agents enrolled by IP), or on
// any other name.
func TestPublicTLSSelection(t *testing.T) {
	e := newPublicTLSServer(t, "", true)
	for _, alpn := range [][]string{nil, {"h2", "http/1.1"}, {"http/1.1"}} {
		leaf, asked := e.dial(t, pubName, alpn...)
		if e.isInternal(leaf) || leaf.DNSNames[0] != pubName || asked {
			t.Fatalf("browser on the public name (ALPN %v): internal=%v names=%v client cert requested=%v", alpn, e.isInternal(leaf), leaf.DNSNames, asked)
		}
	}
	leaf, _ := e.dial(t, "PATCH.example.test.") // case and trailing dot do not matter
	if e.isInternal(leaf) {
		t.Fatal("public SNI in upper case got the internal certificate")
	}
	for _, c := range []struct {
		sni  string
		alpn []string
	}{
		{pubName, []string{pki.AgentALPN, "http/1.1"}}, // agent 0.9.1+ on the public name
		{pubName, []string{"http/1.1", pki.AgentALPN}}, // order does not matter
		{"", nil},         // agent <= 0.9.0 enrolled by IP
		{serverName, nil}, // internal name
		{serverName, []string{pki.AgentALPN, "http/1.1"}},
		{"other.example.test", nil},
		{"localhost", nil},
	} {
		leaf, asked := e.dial(t, c.sni, c.alpn...)
		if !e.isInternal(leaf) || !asked {
			t.Fatalf("SNI %q ALPN %v: internal=%v client cert requested=%v", c.sni, c.alpn, e.isInternal(leaf), asked)
		}
	}
}

// A missing, expired or wrong certificate is never served: the public name
// falls back to the internal certificate (agents are unaffected either way).
func TestPublicTLSFallback(t *testing.T) {
	e := newPublicTLSServer(t, "", false) // no files yet
	if leaf, _ := e.dial(t, pubName); !e.isInternal(leaf) {
		t.Fatal("missing public certificate: want the internal one")
	}
	if leaf, asked := e.dial(t, ""); !e.isInternal(leaf) || !asked {
		t.Fatal("agents broken by a missing public certificate")
	}

	writePublicPair(t, e.certPath, e.keyPath, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), pubName)
	e.s.ReloadPublicCert()
	if leaf, _ := e.dial(t, pubName); !e.isInternal(leaf) {
		t.Fatal("expired public certificate served")
	}

	writePublicPair(t, e.certPath, e.keyPath, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), "other.example.test")
	e.s.ReloadPublicCert()
	if leaf, _ := e.dial(t, pubName); !e.isInternal(leaf) {
		t.Fatal("public certificate for another name served")
	}

	os.WriteFile(e.keyPath, []byte("garbage"), 0o600)
	e.s.ReloadPublicCert()
	if leaf, _ := e.dial(t, pubName); !e.isInternal(leaf) {
		t.Fatal("unreadable key: want the internal certificate")
	}

	// A good certificate that expires while loaded stops being served.
	writePublicPair(t, e.certPath, e.keyPath, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), pubName)
	e.s.ReloadPublicCert()
	if leaf, _ := e.dial(t, pubName); e.isInternal(leaf) {
		t.Fatal("valid public certificate not served")
	}
	e.setNow(func() time.Time { return time.Now().Add(48 * time.Hour) })
	if leaf, _ := e.dial(t, pubName); !e.isInternal(leaf) {
		t.Fatal("public certificate served after it expired")
	}
}

// Renewal needs no restart: changed files are picked up within a minute
// (mtime check on handshake) or at once on SIGHUP (ReloadPublicCert).
func TestPublicTLSHotReload(t *testing.T) {
	e := newPublicTLSServer(t, "", true)
	first, _ := e.dial(t, pubName)

	renewed := writePublicPair(t, e.certPath, e.keyPath, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), pubName)
	if leaf, _ := e.dial(t, pubName); leaf.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("files re-read before the recheck interval")
	}
	e.setNow(func() time.Time { return time.Now().Add(2 * publicCertRecheck) })
	if leaf, _ := e.dial(t, pubName); leaf.SerialNumber.Cmp(renewed) != 0 {
		t.Fatalf("renewed certificate not picked up: serial %v, want %v", leaf.SerialNumber, renewed)
	}

	again := writePublicPair(t, e.certPath, e.keyPath, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), pubName)
	e.s.ReloadPublicCert()
	if leaf, _ := e.dial(t, pubName); leaf.SerialNumber.Cmp(again) != 0 {
		t.Fatal("SIGHUP reload did not pick up the new certificate")
	}

	// A half-written renewal (key does not match) keeps the previous good certificate.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kb, _ := x509.MarshalECPrivateKey(k)
	os.WriteFile(e.keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	e.s.ReloadPublicCert()
	if leaf, _ := e.dial(t, pubName); leaf.SerialNumber.Cmp(again) != 0 {
		t.Fatal("a mismatched key replaced the good certificate")
	}
}

// The agent API is refused (421) on connections that were served the public
// certificate (no client certificate was requested there). Agents on the
// same name with ALPN dss-agent/1, and connections by IP, reach it. The
// console and the PowerShell bootstrap (which cannot offer ALPN) work on the
// public name.
func TestPublicTLSRefusesAgentAPI(t *testing.T) {
	e := newPublicTLSServer(t, "", true)
	type result struct {
		code int
		body string
	}
	var transports []*http.Transport
	call := func(sni string, alpn []string, method, path string) result {
		t.Helper()
		tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: alpn}}
		transports = append(transports, tr)
		r, _ := http.NewRequest(method, e.url+path, strings.NewReader(`{}`))
		resp, err := (&http.Client{Transport: tr}).Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return result{resp.StatusCode, string(b)}
	}
	agentALPN := []string{pki.AgentALPN, "http/1.1"}
	for _, p := range []string{"POST /api/agent/checkin", "POST /api/agent/enroll", "GET /api/agent/content/abc", "POST /api/agent/renew"} {
		m, path, _ := strings.Cut(p, " ")
		if r := call(pubName, nil, m, path); r.code != http.StatusMisdirectedRequest || !strings.Contains(r.body, pki.AgentALPN) || !strings.Contains(r.body, "https://169.58.36.46:8443") {
			t.Fatalf("browser path %s: %d %s", p, r.code, r.body)
		}
	}
	for _, c := range []struct {
		sni  string
		alpn []string
	}{{pubName, agentALPN}, {"", nil}, {serverName, nil}} {
		if r := call(c.sni, c.alpn, "POST", "/api/agent/checkin"); r.code != 401 || !strings.Contains(r.body, "client certificate required") {
			t.Fatalf("agent path SNI %q ALPN %v: %d %s", c.sni, c.alpn, r.code, r.body)
		}
	}
	if r := call(pubName, nil, "GET", "/auth/config"); r.code != 200 {
		t.Fatalf("console on the public name: %d", r.code)
	}
	if r := call(pubName, nil, "GET", "/"); r.code != 200 || !strings.Contains(r.body, "console") {
		t.Fatalf("console page on the public name: %d", r.code)
	}
	if r := call(pubName, nil, "GET", "/api/agent-setup/bootstrap/windows.ps1"); r.code != 401 {
		t.Fatalf("bootstrap on the public name must reach the token check, got %d %s", r.code, r.body)
	}
	// Without the connection hooks (no connection in the context) nothing is refused.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/agent/checkin", strings.NewReader(`{}`))
	r.TLS = &tls.ConnectionState{ServerName: pubName}
	e.s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("request without connection hooks: %d", w.Code)
	}
	// Closed connections are forgotten.
	for _, tr := range transports {
		tr.CloseIdleConnections()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := 0
		e.s.publicConns.Range(func(any, any) bool { n++; return true })
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d public connections still tracked after close", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The agent URL: agent_url, else https://<server IP>:<port> (never the server
// name). agent-setup reports it, and an installer requested by any name gets
// the agent URL; one requested by IP keeps that IP.
func TestPublicTLSAgentURL(t *testing.T) {
	e := newPublicTLSServer(t, "", true)
	if got := e.s.agentURL(); got != "https://169.58.36.46:8443" {
		t.Fatalf("default agent URL without server_name %q (first non-loopback IP of the internal certificate)", got)
	}
	for host, want := range map[string]string{
		pubName + ":8443":        "https://169.58.36.46:8443",
		"Patch.Example.Test":     "https://169.58.36.46:8443",
		"169.58.36.46:8443":      "https://169.58.36.46:8443",
		"pm.corp.internal:8443":  "https://169.58.36.46:8443",
		"[2001:db8::1]:8443":     "https://[2001:db8::1]:8443",
		"evil.example/../x:8443": "",
		"a'b.example:8443":       "",
	} {
		r := httptest.NewRequest("GET", "/api/agent-setup/bootstrap/windows.ps1", nil)
		r.Host = host
		r.TLS = &tls.ConnectionState{}
		got, ok := e.s.serverURL(r)
		if (want == "") == ok || got != want {
			t.Errorf("Host %q: %q %v, want %q", host, got, ok, want)
		}
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/agent-setup", nil)
	r.TLS = &tls.ConnectionState{ServerName: pubName}
	e.s.agentSetup(rec, r)
	var setup struct {
		AgentURL    string   `json:"agent_url"`
		Configured  bool     `json:"agent_url_configured"`
		PublicNames []string `json:"public_names"`
		CASHA256    string   `json:"ca_sha256"`
		ServerName  string   `json:"server_name"`
		AgentIP     string   `json:"agent_ip"`
	}
	json.Unmarshal(rec.Body.Bytes(), &setup)
	if setup.AgentURL != "https://169.58.36.46:8443" || setup.Configured || len(setup.PublicNames) != 1 || setup.PublicNames[0] != pubName ||
		setup.CASHA256 != caFingerprint(e.s) || setup.ServerName != "" || setup.AgentIP != "169.58.36.46" {
		t.Fatalf("agent-setup on the public name: %+v", setup)
	}

	e2 := newPublicTLSServer(t, `"agent_url": "https://10.0.0.5:8443/",`, true)
	if got := e2.s.agentURL(); got != "https://10.0.0.5:8443" {
		t.Fatalf("configured agent_url: %q", got)
	}
	// server_name never becomes the agent URL by default.
	e3 := newPublicTLSServer(t, `"server_name": "`+pubName+`",`, true)
	if got := e3.s.agentURL(); got != "https://169.58.36.46:8443" {
		t.Fatalf("agent URL with server_name set: %q, want the IP", got)
	}
	// A name may still be the agent URL when set explicitly: agents select
	// their certificate by ALPN.
	e4 := newPublicTLSServer(t, `"agent_url": "https://`+pubName+`:8443",`, true)
	if got := e4.s.agentURL(); got != "https://"+pubName+":8443" {
		t.Fatalf("explicit agent_url on a public name: %q", got)
	}
}

// server_name is for the console only: agents get https://<agent_ip>:<port>
// and the generated installer never edits the hosts file.
func TestServerNameConsoleOnlyAgentsByIP(t *testing.T) {
	e := newPublicTLSServer(t, `"server_name": "Patcher.Bank.Example.", "agent_ip": "10.0.0.5",`, true)
	if e.s.cfg.ServerName != serverName || e.s.agentURL() != "https://10.0.0.5:8443" {
		t.Fatalf("server_name %q, agent URL %q (want the IP)", e.s.cfg.ServerName, e.s.agentURL())
	}
	// Without agent_ip the detected address is used (the internal certificate's IP here).
	e2 := newPublicTLSServer(t, `"server_name": "`+serverName+`",`, true)
	if got := e2.s.agentURL(); got != "https://169.58.36.46:8443" {
		t.Fatalf("detected agent URL %q", got)
	}

	// The template itself has no hosts-file step.
	for _, bad := range []string{`etc\hosts`, "Hosts", "Clear-DnsClientCache"} {
		if strings.Contains(windowsBootstrapSrc, bad) {
			t.Fatalf("bootstrap template contains %q", bad)
		}
	}

	ctx := context.Background()
	tok, err := e.s.store.CreateEnrollmentToken(ctx, "user:test", []string{"windows"}, "hq", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(e.s.distDir(), 0o750)
	os.WriteFile(filepath.Join(e.s.distDir(), bootstrapExe), []byte("MZ fake"), 0o644)
	script := func(host string) string {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/agent-setup/bootstrap/windows.ps1", nil)
		r.Host = host
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("X-Enrollment-Token", tok.Token)
		w := httptest.NewRecorder()
		e.s.bootstrapWindows(w, r)
		if w.Code != 200 {
			t.Fatalf("bootstrap for %s: %d %s", host, w.Code, w.Body)
		}
		return w.Body.String()
	}
	// Requested by the server name or by IP: the installer downloads from and
	// enrolls against the IP, and has no hosts-file step.
	for _, host := range []string{serverName + ":8443", "10.0.0.5:8443"} {
		ps := script(host)
		if !strings.Contains(ps, "$Server  = 'https://10.0.0.5:8443'") || !strings.Contains(ps, `-Uri "$Server/api/agent-setup/bootstrap/files/pmagent.exe"`) {
			t.Fatalf("installer requested via %s does not use the agent URL", host)
		}
		for _, bad := range []string{serverName, `drivers\etc\hosts`, "Hosts", "DSS Patcher"} {
			if strings.Contains(ps, bad) {
				t.Fatalf("installer requested via %s contains %q", host, bad)
			}
		}
	}
}

func TestPublicTLSConfigValidation(t *testing.T) {
	load := func(base, extra string) error {
		dir := t.TempDir()
		pub, _, _ := manifest.GenerateKey()
		cfg := fmt.Sprintf(`{%s %s "data_dir": "data", "trusted_keys":[{"public_key": %q, "sources":["s"]}]}`, base, extra, manifest.EncodePublic(pub))
		p := filepath.Join(dir, "pmserver.json")
		os.WriteFile(p, []byte(cfg), 0o600)
		_, err := LoadConfig(p)
		return err
	}
	const tlsBase = `"pki_dir": "/etc/offpatch/pki",`
	for extra, want := range map[string]string{
		`"public_tls": {"names": ["patch.example.com"]},`:                                                "",
		`"public_tls": {"names": ["patch.example.com"]}, "agent_url": "https://10.0.0.5:8443",`:          "",
		`"public_tls": {"names": []},`:                                                                   "at least one DNS name",
		`"public_tls": {"names": ["169.58.36.46"]},`:                                                     "not a DNS name",
		`"public_tls": {"names": ["*.example.com"]},`:                                                    "not a DNS name",
		`"public_tls": {"names": ["localhost"]},`:                                                        "not a DNS name",
		`"public_tls": {"names": ["a.example.com"], "cert_file": "/x/cert.pem"},`:                        "must both be set",
		`"public_tls": {"names": ["patch.example.com"]}, "agent_url": "https://patch.example.com:8443",`: "",
		`"server_name": "patcher.bank.example", "agent_ip": "10.0.0.5",`:                                 "",
		`"server_name": "10.0.0.5",`:                                                                     "must be a DNS name",
		`"server_name": "a'b.bank.example",`:                                                             "must be a DNS name",
		`"server_name": "pm",`:                                                                           "must be a DNS name",
		`"agent_ip": "pm.bank.example",`:                                                                 "must be the server's IP",
		`"agent_ip": "127.0.0.1",`:                                                                       "must be the server's IP",
		`"agent_ip": "10.0.0.5'; rm",`:                                                                   "must be the server's IP",
		`"agent_url": "http://10.0.0.5:8443",`:                                                           "must be https://",
		`"agent_url": "https://10.0.0.5:8443/api",`:                                                      "no path",
		`"agent_url": "https://user@10.0.0.5:8443",`:                                                     "no path",
		`"agent_url": "https://a'b.example:8443",`:                                                       "no path",
		`"agent_url": "10.0.0.5:8443",`:                                                                  "must be https://",
		`"public_tls": {"names": ["a.example.com"]}, "x": 1,`:                                            "unknown field",
	} {
		err := load(tlsBase, extra)
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: %v, want %q", extra, err, want)
		}
	}
	if err := load(`"insecure_http": true,`, `"public_tls": {"names": ["patch.example.com"]},`); err == nil || !strings.Contains(err.Error(), "requires TLS") {
		t.Errorf("public_tls with insecure_http: %v", err)
	}
	if err := load(`"insecure_http": true,`, `"agent_url": "http://10.0.0.5:8080",`); err != nil {
		t.Errorf("lab agent_url over http: %v", err)
	}

	// Defaults: <pki_dir>/public/{cert,key}.pem, names normalized and de-duplicated.
	dir := t.TempDir()
	pub, _, _ := manifest.GenerateKey()
	p := filepath.Join(dir, "pmserver.json")
	os.WriteFile(p, []byte(fmt.Sprintf(`{"pki_dir": "pki", "public_tls": {"names": ["Patch.Example.com.", "patch.example.com"]}, "data_dir": "data", "trusted_keys":[{"public_key": %q, "sources":["s"]}]}`, manifest.EncodePublic(pub))), 0o600)
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.PublicTLS.Names) != 1 || c.PublicTLS.Names[0] != "patch.example.com" ||
		c.PublicTLS.CertFile != filepath.Join(dir, "pki", "public", "cert.pem") || c.PublicTLS.KeyFile != filepath.Join(dir, "pki", "public", "key.pem") {
		t.Fatalf("defaults: %+v", c.PublicTLS)
	}
}

// public_cert_expiring: warning under 14 days, critical when unusable,
// resolved once a renewed certificate is loaded. /api/system shows expiry.
func TestPublicCertAlert(t *testing.T) {
	e := newPublicTLSServer(t, "", true)
	ctx := context.Background()
	open := func() []store.Alert {
		var out []store.Alert
		as, _ := e.s.store.ListAlerts(ctx, true)
		for _, a := range as {
			if a.Kind == alertPublicCert {
				out = append(out, a)
			}
		}
		return out
	}
	if err := e.s.checkPublicCert(ctx); err != nil || len(open()) != 0 {
		t.Fatalf("90 days left: %v %+v", err, open())
	}

	writePublicPair(t, e.certPath, e.keyPath, time.Now().Add(-80*24*time.Hour), time.Now().Add(10*24*time.Hour), pubName)
	e.s.ReloadPublicCert()
	e.s.checkPublicCert(ctx)
	if as := open(); len(as) != 1 || as[0].Severity != "warning" || !strings.Contains(as[0].Message, "certbot renew") {
		t.Fatalf("10 days left: %+v", as)
	}
	e.s.checkPublicCert(ctx)
	if len(open()) != 1 {
		t.Fatal("repeated sweep duplicated the alert")
	}

	var sys struct {
		AgentURL  string           `json:"agent_url"`
		PublicTLS publicCertStatus `json:"public_tls"`
	}
	w := httptest.NewRecorder()
	e.s.system(w, httptest.NewRequest("GET", "/api/system", nil))
	json.Unmarshal(w.Body.Bytes(), &sys)
	if !sys.PublicTLS.Active || sys.PublicTLS.DaysLeft == nil || *sys.PublicTLS.DaysLeft < 9 || *sys.PublicTLS.DaysLeft > 10 ||
		sys.PublicTLS.NotAfter == "" || sys.AgentURL != "https://169.58.36.46:8443" || sys.PublicTLS.Names[0] != pubName {
		t.Fatalf("/api/system: %s", w.Body)
	}

	e.setNow(func() time.Time { return time.Now().Add(11 * 24 * time.Hour) })
	e.s.checkPublicCert(ctx)
	if as := open(); len(as) != 1 || as[0].Severity != "critical" || !strings.Contains(as[0].Message, "internal certificate") {
		t.Fatalf("expired: %+v", as)
	}

	e.setNow(time.Now)
	writePublicPair(t, e.certPath, e.keyPath, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), pubName)
	e.s.ReloadPublicCert()
	e.s.checkPublicCert(ctx)
	if as := open(); len(as) != 0 {
		t.Fatalf("renewed: alert still open %+v", as)
	}
}
