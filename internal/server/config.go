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

// Values of Config.DeploymentMode.
const (
	DeploymentSingleServer = "single-server"
	DeploymentTwoMachine   = "two-machine"
)

type Config struct {
	Listen                 string         `json:"listen"`
	DataDir                string         `json:"data_dir"`
	TLSCert                string         `json:"tls_cert"`
	TLSKey                 string         `json:"tls_key"`
	PKIDir                 string         `json:"pki_dir"`
	InsecureHTTP           bool           `json:"insecure_http"`
	TrustedKeys            []KeyConfig    `json:"trusted_keys"`
	RootPublicKeyFile      string         `json:"root_public_key_file"`
	OIDC                   *oidc.Config   `json:"oidc"`
	SessionTTL             Duration       `json:"session_ttl"`
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
	// MFAKeyFile: 32-byte key (64 hex characters) that encrypts local
	// users' authenticator secrets (AES-256-GCM). Default
	// <data_dir>/mfa.key; created (0600) on first start when missing.
	MFAKeyFile string `json:"mfa_key_file"`
	// DeploymentMode: how the product is laid out, disclosed in the
	// compliance report. "single-server" = the internet-facing downloader
	// runs on this server (egress limited to its account by host firewall
	// rules); "two-machine" = separate acquisition host. Empty = not stated.
	DeploymentMode string `json:"deployment_mode"`
	// AcquisitionStaleAfter: warn when an acquisition source has sent no
	// status report for this long. Default 3h with deployment_mode
	// single-server (hourly runs on this host), else 26h.
	AcquisitionStaleAfter Duration `json:"acquisition_stale_after"`
	// PublicTLS: optional publicly trusted certificate for the console,
	// served only to browsers asking for one of its names (SNI); agents keep
	// the internal CA and mTLS (publictls.go).
	PublicTLS *PublicTLSConfig `json:"public_tls"`
	// ServerName: DNS name of this server (e.g. patcher.bank.example) for
	// the console only: browsers open https://<server_name>:<port> (the name
	// resolves through internal DNS or admins' hosts files). Agents never use
	// it unless agent_url is set to it explicitly. The internal server
	// certificate must include it.
	ServerName string `json:"server_name"`
	// AgentIP: the server's IP as endpoints reach it; agents connect to
	// https://<agent_ip>:<port>. Default: detected (listen address, the
	// internal certificate's IP, else this host's first IPv4 address).
	AgentIP string `json:"agent_ip"`
	// AgentURL: base URL agents enroll against (explicit override). Default
	// https://<agent_ip>:<port>; never derived from server_name.
	AgentURL string `json:"agent_url"`

	dir string // directory of the config file; relative paths resolve from here
	// fromFile: loaded by LoadConfig (LogAuthMode logs only then).
	fromFile bool
}

// LogAuthMode logs, once at startup, how admins sign in: local users
// (email + password, MFA for bank roles) and SSO when configured. Static
// admin tokens no longer exist.
func (c *Config) LogAuthMode(log *slog.Logger) {
	if log == nil || !c.fromFile {
		return
	}
	if c.OIDC != nil {
		log.Info("admin sign-in: SSO and local users (email + password)", "require_mfa", c.RequireMFA)
		return
	}
	log.Info("admin sign-in: local users (email + password). If no super admin exists yet, run `pmserver create-admin`")
}

// removedKeys refuses configuration keys of removed features with what to
// do instead (DisallowUnknownFields would only say "unknown field").
func removedKeys(path string, b []byte) error {
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) != nil {
		return nil // the strict decode reports the syntax error
	}
	for _, k := range []string{"admin_tokens", "allow_static_tokens"} {
		if _, ok := top[k]; ok {
			return fmt.Errorf("config %s: %q is no longer supported: static admin tokens were removed. Delete \"admin_tokens\" and \"allow_static_tokens\" from the file and sign in to the console with email + password (first super admin: pmserver create-admin; lost password: pmserver reset-admin)", path, k)
		}
	}
	return nil
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := removedKeys(path, b); err != nil {
		return nil, err
	}
	c := &Config{fromFile: true}
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
	if c.MFAKeyFile == "" {
		c.MFAKeyFile = filepath.Join(c.DataDir, "mfa.key")
	}
	c.MFAKeyFile = c.abs(c.MFAKeyFile)
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
		for role := range c.OIDC.RoleGroups {
			if store.CanonicalRole(role) != role {
				return nil, fmt.Errorf("config: oidc.role_groups: role %q is not supported; use viewer, user, admin or super_admin (the old names operator and approver were removed: rename them to user)", role)
			}
		}
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
	switch c.DeploymentMode {
	case "", DeploymentSingleServer, DeploymentTwoMachine:
	default:
		return nil, fmt.Errorf("config: deployment_mode must be %q or %q (got %q)", DeploymentSingleServer, DeploymentTwoMachine, c.DeploymentMode)
	}
	if c.AcquisitionStaleAfter.Duration == 0 {
		c.AcquisitionStaleAfter.Duration = store.DefaultAcqStaleAfter
		if c.DeploymentMode == DeploymentSingleServer {
			c.AcquisitionStaleAfter.Duration = store.SingleServerAcqStaleAfter
		}
	}
	if c.AcquisitionStaleAfter.Duration < time.Hour {
		return nil, fmt.Errorf("config: acquisition_stale_after must be at least 1h (the acquisition run is hourly)")
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
	if err := c.normalizePublicTLS(); err != nil {
		return nil, err
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
