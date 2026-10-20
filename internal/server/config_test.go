package server

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestDeploymentModeConfig(t *testing.T) {
	for mode, ok := range map[string]bool{"": true, `"deployment_mode": "single-server",`: true, `"deployment_mode": "two-machine",`: true, `"deployment_mode": "lab",`: false} {
		p := filepath.Join(t.TempDir(), "pmserver.json")
		cfg := `{"insecure_http": true, ` + mode + `"trusted_keys":[{"public_key":"x","sources":["a"]}]}`
		if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(p)
		if (err == nil) != ok {
			t.Fatalf("%s: err = %v, want ok = %v", mode, err, ok)
		}
		if ok && mode != "" && !strings.Contains(mode, c.DeploymentMode) {
			t.Errorf("%s: DeploymentMode = %q", mode, c.DeploymentMode)
		}
		if !ok && !strings.Contains(err.Error(), "deployment_mode") {
			t.Errorf("error does not name the key: %v", err)
		}
	}
}

// acquisition_stale_after: 3h by default on a single server (hourly runs on
// this host), 26h otherwise; explicit values win; under 1h is refused.
func TestAcquisitionStaleAfterConfig(t *testing.T) {
	load := func(extra string) (*Config, error) {
		p := filepath.Join(t.TempDir(), "pmserver.json")
		cfg := `{"insecure_http": true, ` + extra + `"trusted_keys":[{"public_key":"x","sources":["a"]}]}`
		if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(p)
	}
	for extra, want := range map[string]time.Duration{
		``:                                    26 * time.Hour,
		`"deployment_mode": "two-machine",`:   26 * time.Hour,
		`"deployment_mode": "single-server",`: 3 * time.Hour,
		`"deployment_mode": "single-server", "acquisition_stale_after": "5h",`: 5 * time.Hour,
	} {
		c, err := load(extra)
		if err != nil {
			t.Fatalf("%s: %v", extra, err)
		}
		if c.AcquisitionStaleAfter.Duration != want {
			t.Errorf("%s: acquisition_stale_after = %v, want %v", extra, c.AcquisitionStaleAfter.Duration, want)
		}
	}
	if _, err := load(`"acquisition_stale_after": "30m",`); err == nil {
		t.Error("acquisition_stale_after under 1h accepted")
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

// Bank defaults (security review S-3): two approvers for critical and
// important packages and separation of duties, unless the file says so.
func TestApprovalDefaults(t *testing.T) {
	load := func(extra string) *Config {
		t.Helper()
		p := filepath.Join(t.TempDir(), "pmserver.json")
		if err := os.WriteFile(p, []byte(`{`+extra+`"insecure_http": true, "data_dir": "data", "trusted_keys": [{"public_key": "x", "sources": ["a"]}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := load("")
	if !c.SeparationOfDuties || c.ApprovalPolicy["critical"] != 2 || c.ApprovalPolicy["important"] != 2 || c.ApprovalPolicy["moderate"] != 0 {
		t.Fatalf("defaults: sod %v policy %v", c.SeparationOfDuties, c.ApprovalPolicy)
	}
	c = load(`"separation_of_duties": false, "approval_policy": {"critical": 3, "important": 1},`)
	if c.SeparationOfDuties || c.ApprovalPolicy["critical"] != 3 || c.ApprovalPolicy["important"] != 1 {
		t.Fatalf("explicit: sod %v policy %v", c.SeparationOfDuties, c.ApprovalPolicy)
	}
}
