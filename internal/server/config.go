package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"offpatch/internal/intake"
	"offpatch/internal/manifest"
	"offpatch/internal/oidc"
	"offpatch/internal/pki"
	"offpatch/internal/store"
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
	Listen                 string         `json:"listen"`
	DataDir                string         `json:"data_dir"`
	TLSCert                string         `json:"tls_cert"`
	TLSKey                 string         `json:"tls_key"`
	PKIDir                 string         `json:"pki_dir"`
	InsecureHTTP           bool           `json:"insecure_http"`
	TrustedKeys            []KeyConfig    `json:"trusted_keys"`
	RootPublicKeyFile      string         `json:"root_public_key_file"`
	AdminTokens            []AdminToken   `json:"admin_tokens"`
	OIDC                   *oidc.Config   `json:"oidc"`
	SessionTTL             Duration       `json:"session_ttl"`
	AllowStaticTokens      *bool          `json:"allow_static_tokens"`
	RequireMFA             bool           `json:"require_mfa"`
	ApprovalPolicy         map[string]int `json:"approval_policy"`
	SeparationOfDuties     bool           `json:"separation_of_duties"`
	OfflineAfter           Duration       `json:"offline_after"`
	StaleInventoryAfter    Duration       `json:"stale_inventory_after"`
	MaxBundleBytes         int64          `json:"max_bundle_bytes"`
	MaxFiles               int            `json:"max_files"`
	MaxFileBytes           int64          `json:"max_file_bytes"`
	ScanCommand            []string       `json:"scan_command"`
	ScanTimeout            Duration       `json:"scan_timeout"` // per file; default 30m
	IntakeInterval         Duration       `json:"intake_interval"`
	CheckinIntervalSeconds int            `json:"checkin_interval_seconds"`
	DownloadRateKbps       int            `json:"download_rate_kbps"`
	AuditExportDir         string         `json:"audit_export_dir"`
	// AcquisitionRequestsDir: when set, every exported acquisition request is
	// also written there (direct hand-off to a co-located pmctl auto). Unset
	// = strict one-way transfer: the operator carries the downloaded file.
	AcquisitionRequestsDir  string              `json:"acquisition_requests_dir"`
	PatchDeadlines          map[string]Duration `json:"patch_deadlines"`
	Notify                  *NotifyConfig       `json:"notify"`
	MetricsToken            string              `json:"metrics_token"`
	AlertSweepEvery         Duration            `json:"alert_sweep_interval"`
	IntakeMaxBundlesPerHour int                 `json:"intake_max_bundles_per_hour"`
	IntakeMaxBytesPerHour   int64               `json:"intake_max_bytes_per_hour"`
	AuditCheckpointEvery    Duration            `json:"audit_checkpoint_interval"`
	AuditRetention          Duration            `json:"audit_retention"`
	SiteDownloadKbps        map[string]int      `json:"site_download_kbps"`
	// Install safety (docs/07-admin-guide.md "Install safety").
	Preinstall       PreinstallConfig `json:"preinstall"`
	LostAfterInstall Duration         `json:"lost_after_install"`
	// DeploymentApprovals: different people (bank user or admin, not the
	// creator) who must approve each deployment and rollback before it
	// starts. Default 2, 1-5 (an isolated lab may use 1).
	DeploymentApprovals *int `json:"deployment_approvals"`

	dir string // directory of the config file; relative paths resolve from here
	// staticTokensDefaulted: allow_static_tokens was not in the file.
	staticTokensDefaulted bool
}

// LogAuthMode logs, once at startup, how admins sign in: SSO and / or the
// static admin_tokens, and whether allow_static_tokens was set or defaulted,
// so a disabled break-glass token is never a surprise.
func (c *Config) LogAuthMode(log *slog.Logger) {
	if log == nil || c.AllowStaticTokens == nil { // not from LoadConfig
		return
	}
	how := "set in the config"
	if c.staticTokensDefaulted {
		how = "default (not set in the config)"
	}
	sso := c.OIDC != nil
	switch {
	case *c.AllowStaticTokens && len(c.AdminTokens) > 0 && sso:
		log.Info("admin sign-in: SSO, and static admin tokens are ENABLED as break-glass (allow_static_tokens=true); set \"allow_static_tokens\": false to switch them off",
			"tokens", len(c.AdminTokens), "allow_static_tokens", how)
	case *c.AllowStaticTokens && len(c.AdminTokens) > 0:
		log.Info("admin sign-in: static admin tokens only (no SSO configured)", "tokens", len(c.AdminTokens), "allow_static_tokens", how)
	case !sso && (len(c.AdminTokens) == 0 || !*c.AllowStaticTokens):
		log.Warn("admin sign-in: local users (email + password) only: no SSO and no static admin token. If no super admin exists yet, run `pmserver create-admin`")
	case *c.AllowStaticTokens:
		log.Info("admin sign-in: SSO only (no admin_tokens configured, so there is no break-glass token)", "allow_static_tokens", how)
	case len(c.AdminTokens) > 0:
		log.Warn("admin sign-in: SSO only; static admin tokens are DISABLED by \"allow_static_tokens\": false, so the configured admin_tokens (including break-glass) do not work",
			"tokens_ignored", len(c.AdminTokens))
	default:
		log.Info("admin sign-in: SSO only; static admin tokens disabled (allow_static_tokens=false)")
	}
}

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
	if c.LostAfterInstall.Duration == 0 {
		c.LostAfterInstall.Duration = 2 * time.Hour
	}
	if err := c.Preinstall.normalize(); err != nil {
		return nil, err
	}
	if c.MaxBundleBytes == 0 {
		c.MaxBundleBytes = 32 << 30
	}
	if c.MaxFiles == 0 {
		c.MaxFiles = 500
	}
	if c.MaxFileBytes == 0 {
		c.MaxFileBytes = 16 << 30
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
		// Default true, with or without SSO (runbook 01): the admin_tokens
		// entries are the break-glass path when the IdP is unreachable, so
		// adding "oidc" must not silently switch them off. Only an explicit
		// "allow_static_tokens": false does. LogAuthMode says which applies.
		t := true
		c.AllowStaticTokens = &t
		c.staticTokensDefaulted = true
	}
	if c.SessionTTL.Duration == 0 {
		c.SessionTTL.Duration = 8 * time.Hour
	}
	if c.DeploymentApprovals == nil {
		n := store.DefaultDeploymentApprovals
		c.DeploymentApprovals = &n
	}
	if n := *c.DeploymentApprovals; n < 1 || n > 5 {
		return nil, fmt.Errorf("config: deployment_approvals must be 1-5 (got %d)", n)
	}
	if c.OIDC != nil {
		c.OIDC.CACertFile = c.abs(c.OIDC.CACertFile)
		if c.RequireMFA {
			c.OIDC.RequireMFA = true
		}
	}
	c.AuditExportDir = c.abs(c.AuditExportDir)
	if c.AcquisitionRequestsDir != "" {
		if !filepath.IsAbs(c.AcquisitionRequestsDir) {
			return nil, fmt.Errorf("config: acquisition_requests_dir must be an absolute path (got %q)", c.AcquisitionRequestsDir)
		}
		c.AcquisitionRequestsDir = filepath.Clean(c.AcquisitionRequestsDir)
	}
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
	for i, t := range c.AdminTokens {
		role := store.CanonicalRole(t.Role)
		if role == "" || t.User == "" || len(t.TokenSHA256) != 64 {
			return nil, fmt.Errorf("config: admin token for %q needs user, role (viewer|user|admin|super_admin; operator and approver mean user) and token_sha256", t.User)
		}
		c.AdminTokens[i].Role = role
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
		IntelDir:          filepath.Join(d, "intel"),
		QuarantineDir:     filepath.Join(d, "quarantine"),
		Keys:              keys,
		Limits:            manifest.Limits{MaxFiles: c.MaxFiles, MaxFileBytes: c.MaxFileBytes, MaxTotal: c.MaxBundleBytes},
		MaxBundleBytes:    c.MaxBundleBytes,
		ScanCommand:       c.ScanCommand,
		ScanTimeout:       c.ScanTimeout.Duration,
		Interval:          c.IntakeInterval.Duration,
		MaxBundlesPerHour: c.IntakeMaxBundlesPerHour,
		MaxBytesPerHour:   c.IntakeMaxBytesPerHour,
	}, nil
}

// PreinstallConfig: checks agents run before downloading an install. Failing
// one defers the install to the next check-in (not a failure).
type PreinstallConfig struct {
	// MinFreeDiskMB by endpoint OS (windows, linux, macos): free space needed
	// on the system volume, or 2 × the package size if larger. 0 = only the
	// 2 × size rule. Defaults: windows 5120, macos 2048, linux 1024.
	MinFreeDiskMB map[string]int `json:"min_free_disk_mb"`
	// MinBatteryPct: laptops on battery below this wait for AC power.
	// Default 40; 0 = no battery check.
	MinBatteryPct *int `json:"min_battery_pct"`
}

func (p *PreinstallConfig) normalize() error {
	def := map[string]int{"windows": 5120, "macos": 2048, "linux": 1024}
	for k, v := range p.MinFreeDiskMB {
		if _, ok := def[k]; !ok {
			return fmt.Errorf("config: preinstall.min_free_disk_mb key %q must be windows, linux or macos", k)
		}
		if v < 0 {
			return fmt.Errorf("config: preinstall.min_free_disk_mb[%s] must be >= 0", k)
		}
	}
	for k, v := range def {
		if _, ok := p.MinFreeDiskMB[k]; !ok {
			if p.MinFreeDiskMB == nil {
				p.MinFreeDiskMB = map[string]int{}
			}
			p.MinFreeDiskMB[k] = v
		}
	}
	if p.MinBatteryPct == nil {
		v := 40
		p.MinBatteryPct = &v
	}
	if *p.MinBatteryPct < 0 || *p.MinBatteryPct > 100 {
		return fmt.Errorf("config: preinstall.min_battery_pct must be 0-100")
	}
	return nil
}

// policyFor is what an endpoint of this OS is told on check-in.
func (p PreinstallConfig) policyFor(osName string) store.PreinstallPolicy {
	mb, ok := p.MinFreeDiskMB[osName]
	if !ok {
		mb = p.MinFreeDiskMB["linux"]
	}
	pct := 40
	if p.MinBatteryPct != nil {
		pct = *p.MinBatteryPct
	}
	return store.PreinstallPolicy{MinFreeDiskMB: mb, MinBatteryPct: pct}
}
