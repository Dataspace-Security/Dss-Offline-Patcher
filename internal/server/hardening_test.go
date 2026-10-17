package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/repo"
	"offpatch/internal/store"
)

// writeConfig writes a minimal lab config; extra is spliced into the JSON.
func writeConfig(t *testing.T, dir, extra string) string {
	t.Helper()
	pub, _, _ := manifest.GenerateKey()
	cfg := fmt.Sprintf(`{"insecure_http": true, %s "data_dir": "data", "trusted_keys":[{"public_key": %q, "sources":["s"]}],
	  "admin_tokens":[{"user":"vera","role":"viewer","token_sha256":%q}]}`, extra, manifest.EncodePublic(pub), store.HashSecret("tok"))
	p := filepath.Join(dir, "pmserver.json")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg, err := LoadConfig(writeConfig(t, dir, ""))
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(cfg.DataDir, 0o750)
	st, err := store.Open(filepath.Join(cfg.DataDir, "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rp, _ := repo.New(filepath.Join(cfg.DataDir, "repository"))
	s, err := New(cfg, st, rp, fstest.MapFS{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func enrollReq(h http.Handler, remote string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/agent/enroll", bytes.NewReader(body))
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// H3: unauthenticated enrollment has a body limit, hostname validation and
// a per-IP rate limit (loopback exempt).
func TestEnrollLimits(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()
	bad, _ := json.Marshal(store.EnrollRequest{Token: "enr_nope", Hostname: "pc-1"})
	if w := enrollReq(h, "192.0.2.9:1000", append(append([]byte(`{"hostname":"`), bytes.Repeat([]byte("a"), 70<<10)...), []byte(`"}`)...)); w.Code != 400 {
		t.Fatalf("oversized body: %d", w.Code)
	}
	if w := enrollReq(h, "192.0.2.9:1000", []byte(`{"token":"enr_x","hostname":"<img src=x>"}`)); w.Code != 400 || !strings.Contains(w.Body.String(), "hostname") {
		t.Fatalf("invalid hostname: %d %s", w.Code, w.Body)
	}
	for i := 0; i < enrollBurst-2; i++ {
		if w := enrollReq(h, "192.0.2.9:1000", bad); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := enrollReq(h, "192.0.2.9:1001", bad)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("burst exceeded: %d %v", w.Code, w.Header())
	}
	if w := enrollReq(h, "192.0.2.10:1000", bad); w.Code != 401 {
		t.Fatalf("other address must not be limited: %d", w.Code)
	}
	for i := 0; i < enrollBurst+5; i++ {
		if w := enrollReq(h, "127.0.0.1:2000", bad); w.Code != 401 {
			t.Fatalf("loopback limited at %d: %d", i, w.Code)
		}
	}
	evs, _ := s.store.ListAudit(context.Background(), store.AuditQuery{Action: "endpoint.enroll_denied"})
	if len(evs) != 3 { // 192.0.2.9, 192.0.2.10, 127.0.0.1: one each per minute
		t.Fatalf("denied enroll audit events: %d", len(evs))
	}
}

func TestIPLimiterRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := newIPLimiter(2, time.Second)
	l.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatal("burst refused")
		}
	}
	if ok, wait := l.allow("a"); ok || wait <= 0 || wait > time.Second {
		t.Fatalf("empty bucket: ok=%v wait=%v", ok, wait)
	}
	now = now.Add(time.Second)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("token not refilled")
	}
	now = now.Add(time.Hour)
	l.prune(now)
	if len(l.buckets) != 0 {
		t.Fatal("idle bucket not pruned")
	}
}

// M5: lifecycle export pages through all events instead of capping.
func TestAllAuditPages(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	for i := 0; i < 7; i++ {
		s.store.Audit(ctx, store.Ev{Actor: "t", Action: "x.y", ObjectType: "package", ObjectID: "p1", PackageID: "p1"})
	}
	old := auditPage
	auditPage = 3
	defer func() { auditPage = old }()
	evs, err := s.allAudit(ctx, store.AuditQuery{PackageID: "p1"})
	if err != nil || len(evs) != 7 {
		t.Fatalf("got %d events (%v), want 7", len(evs), err)
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].Seq <= evs[i-1].Seq {
			t.Fatal("events out of order")
		}
	}
}

// M13: a relay that accepts and then stalls must not hang delivery.
func TestSendMailTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // never greets
		}
	}()
	old := smtpTimeout
	smtpTimeout = 300 * time.Millisecond
	defer func() { smtpTimeout = old }()
	start := time.Now()
	err = sendMail(ln.Addr().String(), "pm@corp", []string{"ops@corp"}, store.Alert{Severity: "critical", Kind: "k", Message: "m"})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("sendMail to a stalled relay: err=%v after %v", err, time.Since(start))
	}
}

func writeCert(t *testing.T, path string, notAfter time.Time) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "pm"}, NotBefore: notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// M4: the sweep warns 30 days before the server certificate expires.
func TestServerCertExpiryAlert(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	now := time.Now()
	s.cfg.TLSCert = filepath.Join(t.TempDir(), "server.pem")
	open := func() []store.Alert {
		as, _ := s.store.ListAlerts(ctx, true)
		return as
	}
	writeCert(t, s.cfg.TLSCert, now.Add(90*24*time.Hour))
	if err := s.checkServerCert(ctx, now); err != nil || len(open()) != 0 {
		t.Fatalf("90 days left: %v %v", err, open())
	}
	writeCert(t, s.cfg.TLSCert, now.Add(10*24*time.Hour))
	if err := s.checkServerCert(ctx, now); err != nil {
		t.Fatal(err)
	}
	if as := open(); len(as) != 1 || as[0].Kind != "server_cert_expiring" || as[0].Severity != "warning" {
		t.Fatalf("10 days left: %+v", as)
	}
	writeCert(t, s.cfg.TLSCert, now.Add(-time.Hour))
	s.checkServerCert(ctx, now)
	if as := open(); len(as) != 2 || as[0].Severity != "critical" {
		t.Fatalf("expired: %+v", as)
	}
}

// M6: with SSO configured, static admin tokens are off unless enabled
// explicitly (break-glass).
func TestStaticTokensDefault(t *testing.T) {
	oidcCfg := `"oidc": {"issuer": "https://idp.corp", "client_id": "pm", "redirect_url": "https://pm/auth/callback"},`
	for _, c := range []struct {
		extra string
		want  bool
	}{
		{"", true},
		{oidcCfg, false},
		{oidcCfg + ` "allow_static_tokens": true,`, true},
	} {
		cfg, err := LoadConfig(writeConfig(t, t.TempDir(), c.extra))
		if err != nil {
			t.Fatal(err)
		}
		if *cfg.AllowStaticTokens != c.want {
			t.Errorf("%q: allow_static_tokens=%v want %v", c.extra, *cfg.AllowStaticTokens, c.want)
		}
	}
}
