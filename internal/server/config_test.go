package server

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shipped example must stay loadable as the config schema evolves.
func TestExampleConfigLoads(t *testing.T) {
	c, err := LoadConfig("../../packaging/server/pmserver.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDC == nil || !c.RequireMFA || c.ApprovalPolicy["critical"] != 2 || c.AuditRetention.Hours() != 26280 {
		t.Fatalf("example config not parsed as expected: %+v", c)
	}
}

func TestPreinstallDefaults(t *testing.T) {
	p := PreinstallConfig{MinFreeDiskMB: map[string]int{"windows": 8192}}
	if err := p.normalize(); err != nil {
		t.Fatal(err)
	}
	if got := p.policyFor("windows"); got.MinFreeDiskMB != 8192 || got.MinBatteryPct != 40 {
		t.Fatalf("windows: %+v", got)
	}
	if got := p.policyFor("macos"); got.MinFreeDiskMB != 2048 {
		t.Fatalf("macos default: %+v", got)
	}
	bad := PreinstallConfig{MinFreeDiskMB: map[string]int{"solaris": 1}}
	if bad.normalize() == nil {
		t.Fatal("unknown OS key accepted")
	}
	c, err := LoadConfig("../../packaging/server/pmserver.example.json")
	if err != nil || c.LostAfterInstall.Hours() != 2 || c.Preinstall.policyFor("linux").MinFreeDiskMB != 1024 {
		t.Fatalf("example: %v %+v", err, c)
	}
}

// Windows 11 cumulative updates exceed 4 GiB (KB5127648 is 4.77 GB): the
// defaults must admit them, in one bundle with the rest of a monthly run.
func TestSizeLimitDefaults(t *testing.T) {
	c, err := LoadConfig("../../packaging/server/pmserver.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxFileBytes < 4775050195 || c.MaxBundleBytes < 2*c.MaxFileBytes {
		t.Fatalf("max_file_bytes %d, max_bundle_bytes %d", c.MaxFileBytes, c.MaxBundleBytes)
	}
}

func TestAcquisitionRequestsDirConfig(t *testing.T) {
	write := func(extra string) (*Config, error) {
		dir := t.TempDir()
		p := filepath.Join(dir, "pmserver.json")
		cfg := `{"insecure_http": true, ` + extra + `"trusted_keys":[{"public_key":"x","sources":["a"]}]}`
		if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(p)
	}
	if c, err := write(""); err != nil || c.AcquisitionRequestsDir != "" {
		t.Fatalf("unset: %v %q", err, c.AcquisitionRequestsDir)
	}
	if _, err := write(`"acquisition_requests_dir": "requests",`); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative path accepted: %v", err)
	}
	abs, _ := json.Marshal(t.TempDir())
	c, err := write(`"acquisition_requests_dir": ` + string(abs) + `,`)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAcquisitionRequestsDir(c.AcquisitionRequestsDir); err != nil {
		t.Errorf("writable dir reported unwritable: %v", err)
	}
	if CheckAcquisitionRequestsDir(filepath.Join(c.AcquisitionRequestsDir, "missing")) == nil {
		t.Error("missing dir reported writable")
	}
}

// The startup line names the sign-in methods.
func TestLogAuthMode(t *testing.T) {
	oidcCfg := `"oidc": {"issuer": "https://idp.corp", "client_id": "pm", "redirect_url": "https://pm/auth/callback"},`
	for _, c := range []struct{ extra, want string }{
		{"", "local users (email + password)"},
		{oidcCfg, "SSO and local users"},
	} {
		cfg, err := LoadConfig(writeConfig(t, t.TempDir(), c.extra))
		if err != nil {
			t.Fatal(err)
		}
		var buf strings.Builder
		cfg.LogAuthMode(slog.New(slog.NewTextHandler(&buf, nil)))
		if !strings.Contains(buf.String(), c.want) {
			t.Errorf("%q: log %q, want %q", c.extra, buf.String(), c.want)
		}
	}
}
