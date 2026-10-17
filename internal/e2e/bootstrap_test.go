package e2e

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/agent"
)

// One-command Windows install: the server sends its CA in the TLS chain (so a
// client can pin it), and the bootstrap routes work only with a usable
// enrollment token.
func TestWindowsBootstrap(t *testing.T) {
	e := newEnvOpts(t, true, "")
	get := func(path, tok string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
		if tok != "" {
			req.Header.Set("X-Enrollment-Token", tok)
		}
		resp, err := e.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	const script = "/api/agent-setup/bootstrap/windows.ps1"
	const exe = "/api/agent-setup/bootstrap/files/pmagent.exe"

	// The TLS chain carries the CA so it can be pinned by fingerprint.
	conn, err := tls.Dial("tcp", strings.TrimPrefix(e.srv.URL, "https://"), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	chain := conn.ConnectionState().PeerCertificates
	conn.Close()
	caPEM, _ := os.ReadFile(e.caFile)
	caBlock, _ := pem.Decode(caPEM)
	if len(chain) != 2 || caBlock == nil || !bytes.Equal(chain[1].Raw, caBlock.Bytes) {
		t.Fatalf("server must send [leaf, CA], got %d certificates", len(chain))
	}

	var tok struct{ Token string }
	if c := e.api("POST", "/api/enrollment-tokens", tokOperator, map[string]any{"groups": []string{"windows"}, "site": "hq", "expires_in_hours": 1}, &tok); c != 201 {
		t.Fatalf("create token: %d", c)
	}

	for name, tk := range map[string]string{"no token": "", "bogus token": "enr_bogus", "admin token": tokOperator} {
		if c, _ := get(script, tk); c != 401 {
			t.Fatalf("%s: script %d, want 401", name, c)
		}
		if c, _ := get(exe, tk); c != 401 {
			t.Fatalf("%s: exe %d, want 401", name, c)
		}
	}
	if c, _ := get(script, tok.Token); c != 404 {
		t.Fatalf("no pmagent.exe staged: script %d, want 404", c)
	}

	dist := filepath.Join(e.cfg.DataDir, "agent-dist")
	os.MkdirAll(dist, 0o750)
	bin := []byte("MZ fake agent")
	os.WriteFile(filepath.Join(dist, "pmagent.exe"), bin, 0o644)
	os.WriteFile(filepath.Join(dist, "other.bin"), []byte("x"), 0o644)

	c, body := get(script, tok.Token)
	if c != 200 {
		t.Fatalf("script: %d %s", c, body)
	}
	sum := sha256.Sum256(bin)
	ps := string(body)
	for _, want := range []string{"$Server  = '" + e.srv.URL + "'", "$ExeSha  = '" + hex.EncodeToString(sum[:]) + "'",
		strings.TrimSpace(e.pubPEM), "BEGIN CERTIFICATE"} {
		if !strings.Contains(ps, want) {
			t.Fatalf("script lacks %q", want)
		}
	}
	if c, b := get(exe, tok.Token); c != 200 || string(b) != string(bin) {
		t.Fatalf("exe: %d", c)
	}
	if c, _ := get("/api/agent-setup/bootstrap/files/other.bin", tok.Token); c != 404 {
		t.Fatalf("only pmagent.exe may be served, got %d", c)
	}

	// The bootstrap does not consume the token: it still enrolls a device.
	sim := agent.SimConfig{Hostname: "pc-boot-01"}
	dir := filepath.Join(e.dir, "agents", "pc-boot-01")
	p, _ := agent.PlatformFor(&agent.State{Platform: "sim", Sim: &sim}, dir)
	os.MkdirAll(dir, 0o700)
	if _, err := agent.Enroll(e.srv.URL, tok.Token, e.caFile, dir, []string{e.pubPEM}, e.rootPEM, p, "sim", &sim); err != nil {
		t.Fatalf("token unusable after bootstrap downloads: %v", err)
	}
	// A used single-use token no longer opens the bootstrap.
	if c, _ := get(script, tok.Token); c != 401 {
		t.Fatalf("used token: %d, want 401", c)
	}

	// The console gets the CA fingerprint and the availability flag.
	var setup struct {
		CASHA256         string `json:"ca_sha256"`
		WindowsBootstrap bool   `json:"windows_bootstrap"`
	}
	e.api("GET", "/api/agent-setup", tokViewer, nil, &setup)
	caSum := sha256.Sum256(chain[1].Raw)
	if !setup.WindowsBootstrap || setup.CASHA256 != strings.ToUpper(hex.EncodeToString(caSum[:])) {
		t.Fatalf("agent-setup: %+v", setup)
	}
}
