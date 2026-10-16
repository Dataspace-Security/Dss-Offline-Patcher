package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"offpatch/internal/intake"
	"offpatch/internal/manifest"
	"offpatch/internal/oidc"
	"offpatch/internal/pki"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

type KeyConfig struct {
	PublicKeyFile string   `json:"public_key_file"`
	PublicKey     string   `json:"public_key"`
	Sources       []string `json:"sources"`
}

type AdminToken struct {
	User        string `json:"user"`
	Role        string `json:"role"`
	TokenSHA256 string `json:"token_sha256"`
}

type Config struct {
	Listen                  string              `json:"listen"`
	DataDir                 string              `json:"data_dir"`
	TLSCert                 string              `json:"tls_cert"`
	TLSKey                  string              `json:"tls_key"`
	PKIDir                  string              `json:"pki_dir"`
	InsecureHTTP            bool                `json:"insecure_http"`
	TrustedKeys             []KeyConfig         `json:"trusted_keys"`
	RootPublicKeyFile       string              `json:"root_public_key_file"`
	AdminTokens             []AdminToken        `json:"admin_tokens"`
	OIDC                    *oidc.Config        `json:"oidc"`
	SessionTTL              Duration            `json:"session_ttl"`
	AllowStaticTokens       *bool               `json:"allow_static_tokens"`
	RequireMFA              bool                `json:"require_mfa"`
	ApprovalPolicy          map[string]int      `json:"approval_policy"`
	SeparationOfDuties      bool                `json:"separation_of_duties"`
	OfflineAfter            Duration            `json:"offline_after"`
	StaleInventoryAfter     Duration            `json:"stale_inventory_after"`
	MaxBundleBytes          int64               `json:"max_bundle_bytes"`
	MaxFiles                int                 `json:"max_files"`
	MaxFileBytes            int64               `json:"max_file_bytes"`
	ScanCommand             []string            `json:"scan_command"`
	IntakeInterval          Duration            `json:"intake_interval"`
	CheckinIntervalSeconds  int                 `json:"checkin_interval_seconds"`
	DownloadRateKbps        int                 `json:"download_rate_kbps"`
	AuditExportDir          string              `json:"audit_export_dir"`
	PatchDeadlines          map[string]Duration `json:"patch_deadlines"`
	Notify                  *NotifyConfig       `json:"notify"`
	MetricsToken            string              `json:"metrics_token"`
	AlertSweepEvery         Duration            `json:"alert_sweep_interval"`
	IntakeMaxBundlesPerHour int                 `json:"intake_max_bundles_per_hour"`
	IntakeMaxBytesPerHour   int64               `json:"intake_max_bytes_per_hour"`
	AuditCheckpointEvery    Duration            `json:"audit_checkpoint_interval"`
	AuditRetention          Duration            `json:"audit_retention"`
	SiteDownloadKbps        map[string]int      `json:"site_download_kbps"`

	dir string // directory of the config file; relative paths resolve from here
}

var roleRank = map[string]int{"viewer": 1, "operator": 2, "approver": 3, "admin": 4}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.dir = filepath.Dir(path)
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	c.DataDir = c.abs(c.DataDir)
	if c.OfflineAfter.Duration == 0 {
		c.OfflineAfter.Duration = 30 * time.Minute
	}
	if c.StaleInventoryAfter.Duration == 0 {
		c.StaleInventoryAfter.Duration = 24 * time.Hour
	}
	if c.MaxBundleBytes == 0 {
		c.MaxBundleBytes = 8 << 30
	}
	if c.MaxFiles == 0 {
		c.MaxFiles = 500
	}
	if c.MaxFileBytes == 0 {
		c.MaxFileBytes = 4 << 30
	}
	if c.IntakeInterval.Duration == 0 {
		c.IntakeInterval.Duration = 5 * time.Second
	}
	if c.CheckinIntervalSeconds == 0 {
		c.CheckinIntervalSeconds = 60
	}
	if len(c.TrustedKeys) == 0 {
		return nil, fmt.Errorf("config: at least one trusted_keys entry is required")
	}
	if c.AllowStaticTokens == nil {
		t := true
		c.AllowStaticTokens = &t
	}
	if c.SessionTTL.Duration == 0 {
		c.SessionTTL.Duration = 8 * time.Hour
	}
	if c.OIDC == nil && (len(c.AdminTokens) == 0 || !*c.AllowStaticTokens) {
		return nil, fmt.Errorf("config: configure \"oidc\" single sign-on, or at least one admin_tokens entry")
	}
	if c.OIDC != nil {
		c.OIDC.CACertFile = c.abs(c.OIDC.CACertFile)
		if c.RequireMFA {
			c.OIDC.RequireMFA = true
		}
	}
	c.AuditExportDir = c.abs(c.AuditExportDir)
	if c.AlertSweepEvery.Duration == 0 {
		c.AlertSweepEvery.Duration = 5 * time.Minute
	}
	if c.AuditCheckpointEvery.Duration == 0 {
		c.AuditCheckpointEvery.Duration = time.Hour
	}
	if c.AuditRetention.Duration > 0 && c.AuditExportDir == "" {
		return nil, fmt.Errorf("config: audit_retention requires audit_export_dir (events are only pruned after being exported and checkpointed)")
	}
	if c.AuditRetention.Duration > 0 && c.AuditRetention.Duration < 30*24*time.Hour {
		return nil, fmt.Errorf("config: audit_retention must be at least 720h (30 days)")
	}
	for sev, n := range c.ApprovalPolicy {
		switch sev {
		case "critical", "important", "moderate", "low":
		default:
			return nil, fmt.Errorf("config: approval_policy key %q must be a severity", sev)
		}
		if n < 1 || n > 5 {
			return nil, fmt.Errorf("config: approval_policy[%s] must be 1-5", sev)
		}
	}
	for _, t := range c.AdminTokens {
		if roleRank[t.Role] == 0 || t.User == "" || len(t.TokenSHA256) != 64 {
			return nil, fmt.Errorf("config: admin token for %q needs user, role (viewer|operator|approver|admin) and token_sha256", t.User)
		}
	}
	if c.PKIDir != "" {
		c.PKIDir = c.abs(c.PKIDir)
		if c.TLSCert == "" {
			c.TLSCert = filepath.Join(c.PKIDir, pki.ServerCert)
			c.TLSKey = filepath.Join(c.PKIDir, pki.ServerKey)
		}
	}
	c.TLSCert, c.TLSKey = c.abs(c.TLSCert), c.abs(c.TLSKey)
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, fmt.Errorf("config: tls_cert and tls_key must both be set")
	}
	if c.TLSCert == "" && !c.InsecureHTTP {
		return nil, fmt.Errorf("config: TLS is required. Set pki_dir (see `pmserver init-pki`) or tls_cert/tls_key; for an isolated lab only, set \"insecure_http\": true")
	}
	if c.TLSCert != "" && c.InsecureHTTP {
		return nil, fmt.Errorf("config: insecure_http cannot be combined with TLS settings")
	}
	if c.TLSCert != "" && c.PKIDir == "" {
		return nil, fmt.Errorf("config: pki_dir is required with TLS (it issues endpoint client certificates)")
	}
	return c, nil
}

func (c *Config) abs(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// IntakeConfig resolves trusted keys and directories.
func (c *Config) IntakeConfig() (intake.Config, error) {
	keys := map[string]intake.TrustedKey{}
	for i, k := range c.TrustedKeys {
		src := k.PublicKey
		if k.PublicKeyFile != "" {
			b, err := os.ReadFile(c.abs(k.PublicKeyFile))
			if err != nil {
				return intake.Config{}, fmt.Errorf("trusted_keys[%d]: %w", i, err)
			}
			src = string(b)
		}
		pub, err := manifest.ParsePublic(src)
		if err != nil {
			return intake.Config{}, fmt.Errorf("trusted_keys[%d]: %w", i, err)
		}
		if len(k.Sources) == 0 {
			return intake.Config{}, fmt.Errorf("trusted_keys[%d]: sources required", i)
		}
		keys[manifest.KeyID(pub)] = intake.TrustedKey{Pub: pub, Sources: k.Sources}
	}
	var root ed25519.PublicKey
	if c.RootPublicKeyFile != "" {
		pub, err := manifest.LoadPublic(c.abs(c.RootPublicKeyFile))
		if err != nil {
			return intake.Config{}, fmt.Errorf("root_public_key_file: %w", err)
		}
		root = pub
	}
	d := c.DataDir
	return intake.Config{
		RootPub:           root,
		Inbox:             filepath.Join(d, "inbox"),
		ReceivedDir:       filepath.Join(d, "received"),
		QuarantineDir:     filepath.Join(d, "quarantine"),
		Keys:              keys,
		Limits:            manifest.Limits{MaxFiles: c.MaxFiles, MaxFileBytes: c.MaxFileBytes, MaxTotal: c.MaxBundleBytes},
		MaxBundleBytes:    c.MaxBundleBytes,
		ScanCommand:       c.ScanCommand,
		Interval:          c.IntakeInterval.Duration,
		MaxBundlesPerHour: c.IntakeMaxBundlesPerHour,
		MaxBytesPerHour:   c.IntakeMaxBytesPerHour,
	}, nil
}
