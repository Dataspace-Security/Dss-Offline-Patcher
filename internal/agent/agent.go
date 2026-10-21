// Package agent is the endpoint agent: enroll, check in with inventory,
// download approved content from the internal server only, re-verify the
// signed manifest and payload hash, install, and report each stage.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/pki"
	"offpatch/internal/store"
	"offpatch/internal/trust"
)

// Version is set at build time: -ldflags "-X offpatch/internal/agent.Version=1.2.3".
var Version = "0.10.0"

// State is persisted in <state-dir>/agent.json (0600).
type State struct {
	ServerURL   string            `json:"server_url"`
	EndpointID  string            `json:"endpoint_id"`
	Secret      string            `json:"secret"`
	TrustedKeys map[string]string `json:"trusted_keys"`       // key_id → PEM public key
	CAFile      string            `json:"ca_file"`            // relative to the state dir
	CertFile    string            `json:"cert_file"`          // mTLS client certificate (relative)
	KeyFile     string            `json:"key_file"`           // mTLS client key (relative)
	Platform    string            `json:"platform"`           // windows | sim | linux | macos
	RootKey     string            `json:"root_key,omitempty"` // pinned root public key (PEM) for trust updates
	TrustSeq    int64             `json:"trust_seq,omitempty"`
	Revoked     []string          `json:"revoked,omitempty"` // key IDs revoked as compromised
	Sim         *SimConfig        `json:"sim,omitempty"`
}

func statePath(dir string) string { return filepath.Join(dir, "agent.json") }

func readState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.EndpointID == "" || s.ServerURL == "" {
		return nil, errors.New("no endpoint_id/server_url")
	}
	return &s, nil
}

// LoadState reads agent.json. If it exists but is unreadable (a crash on a
// file system that lost the write), the previous copy agent.json.bak is used.
func LoadState(dir string) (*State, error) {
	s, err := readState(statePath(dir))
	if err == nil {
		return s, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agent not enrolled (%w)", err)
	}
	if b, berr := readState(statePath(dir) + ".bak"); berr == nil {
		return b, nil
	}
	return nil, fmt.Errorf("agent state %s is damaged (%v) and has no usable backup; re-enroll with -force", statePath(dir), err)
}

// Save replaces agent.json atomically, keeping the previous version as
// agent.json.bak.
func (s *State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	p := statePath(dir)
	if cur, err := os.ReadFile(p); err == nil {
		if _, err := readState(p); err == nil {
			if err := writeFileAtomic(p+".bak", cur, 0o600); err != nil {
				return fmt.Errorf("back up agent state: %w", err)
			}
		}
	}
	return writeFileAtomic(p, b, 0o600)
}

// PlatformFor builds the platform for a state.
func PlatformFor(s *State, dir string) (Platform, error) {
	switch s.Platform {
	case "sim":
		cfg := SimConfig{}
		if s.Sim != nil {
			cfg = *s.Sim
		}
		return NewSim(cfg, filepath.Join(dir, "sim-state.json")), nil
	case "windows", "linux", "macos", "":
		return NativePlatform(filepath.Join(dir, "logs"))
	}
	return nil, fmt.Errorf("unknown platform %q", s.Platform)
}

// httpClient talks only to the configured server. Proxies from the
// environment are ignored so there is no path to anywhere else.
func httpClient(caFile, certFile, keyFile string) (*http.Client, error) {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		// ALPN dss-agent/1 asks for the internal certificate (and the client
		// certificate request) even on a name browsers get a public certificate for.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{pki.AgentALPN, "http/1.1"}},
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file contains no certificates")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	if certFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{
		Transport: tr,
		// Never follow redirects: a redirect could point outside the server.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

type Agent struct {
	st       *State
	dir      string
	plat     Platform
	hc       *http.Client
	base     *url.URL
	keys     map[string]ed25519.PublicKey
	log      *slog.Logger
	interval time.Duration
	rateKbps int // download limit from the server (0 = unlimited)
	// preinstall: disk/battery thresholds from the server (nil = built-in defaults).
	preinstall *store.PreinstallPolicy
	lastBoot   time.Time
	restart    bool // set after a self-upgrade

	// Collected data, cached between check-ins on platforms where collecting
	// is expensive (slowInventory) and reused when a collection fails.
	facts    *Facts
	inv      []store.InventoryItem
	invOK    bool
	invBoot  bool
	invAt    time.Time // last inventory attempt; zero forces a refresh
	hw       *store.Hardware
	hwAt     time.Time
	started  time.Time
	cleanAt  time.Time
	failures int // consecutive failed cycles (check-in backoff)
	// nextHint: the server's next_checkin_seconds from the last check-in
	// (0 = use interval); it shortens the wait while a deployment is active.
	nextHint time.Duration
	// awaitingReboot: targets installed but waiting for a reboot (progress
	// key → waiting_reboot progress), re-sent while the reboot is pending.
	awaitingReboot map[string]Progress
	// recheckSoon: an installer (or uninstaller) ran this cycle: check in
	// again after postInstallRecheck with a fresh inventory, so the server
	// verifies the target and the console shows the new version promptly.
	recheckSoon bool
}

const (
	// inventoryTTL: how long cached inventory/hardware is reused on platforms
	// where collecting it is expensive. An install forces a refresh.
	inventoryTTL = 15 * time.Minute
	// maxBackoff caps the delay between check-ins after failures.
	maxBackoff = 15 * time.Minute
	// rebootRecheckAfter: if installs took longer than this since the
	// check-in, the reboot permission (maintenance window) may be stale, so
	// the reboot is left to the server's reboot_now at the next check-in.
	rebootRecheckAfter = 15 * time.Minute
	// reportTimeout bounds the final report sent after an installer, which
	// must go out even when the agent is stopping.
	reportTimeout = 2 * time.Minute
	// postInstallRecheck: the next check-in after a cycle that ran an
	// installer comes this soon (with a fresh inventory), whatever the
	// check-in interval.
	postInstallRecheck = 20 * time.Second
)

// downloadIdleTimeout aborts a download that stops receiving data (the
// .part file is kept and resumed at the next attempt). A var for tests.
var downloadIdleTimeout = 2 * time.Minute

// slowInventory marks platforms whose inventory and hardware collection is
// expensive (PowerShell/WMI on Windows); the agent caches it for inventoryTTL.
type slowInventory interface{ slowInventory() }

func New(st *State, dir string, plat Platform, log *slog.Logger) (*Agent, error) {
	hc, err := httpClient(st.path(dir, st.CAFile), st.path(dir, st.CertFile), st.path(dir, st.KeyFile))
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(st.ServerURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("invalid server_url %q", st.ServerURL)
	}
	keys := map[string]ed25519.PublicKey{}
	for id, p := range st.TrustedKeys {
		k, err := manifest.ParsePublic(p)
		if err != nil {
			return nil, fmt.Errorf("trusted key %s: %w", id, err)
		}
		if manifest.KeyID(k) != id {
			return nil, fmt.Errorf("trusted key %s: key_id mismatch", id)
		}
		keys[id] = k
	}
	if len(keys) == 0 {
		return nil, errors.New("no trusted bundle keys pinned")
	}
	return &Agent{st: st, dir: dir, plat: plat, hc: hc, base: base, keys: keys, log: log, interval: time.Minute, started: time.Now()}, nil
}

// path resolves a state-relative file name ("" stays "").
func (s *State) path(dir, name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
}

const (
	caName   = "ca.pem"
	certName = "client.pem"
	keyName  = "client.key"
)

// EnrollOption modifies Enroll.
type EnrollOption func(*enrollOpts)

type enrollOpts struct{ force bool }

// WithForce replaces an existing enrollment (new device key and identity).
func WithForce() EnrollOption { return func(o *enrollOpts) { o.force = true } }

// Enroll registers with the server using a one-time token. Over HTTPS the
// agent generates its own key (it never leaves the endpoint), sends a CSR,
// and receives an mTLS client certificate; over plain HTTP (lab mode only)
// it receives a bearer secret instead. It refuses to replace an existing
// enrollment unless WithForce is given; even then the current key,
// certificate and CA stay in place until the new identity is saved.
func Enroll(serverURL, token, caFile, dir string, pubKeys []string, rootPEM string, plat Platform, platName string, sim *SimConfig, opts ...EnrollOption) (*State, error) {
	var o enrollOpts
	for _, f := range opts {
		f(&o)
	}
	serverURL = strings.TrimRight(serverURL, "/")
	if err := SecureStateDir(dir); err != nil {
		return nil, err
	}
	if _, err := os.Stat(statePath(dir)); err == nil && !o.force {
		return nil, fmt.Errorf("already enrolled (%s exists); use -force to replace this device identity", statePath(dir))
	}
	st := &State{ServerURL: serverURL, TrustedKeys: map[string]string{}, Platform: platName, Sim: sim, RootKey: rootPEM}
	if rootPEM != "" {
		if _, err := manifest.ParsePublic(rootPEM); err != nil {
			return nil, fmt.Errorf("root key: %w", err)
		}
	}
	for _, p := range pubKeys {
		k, err := manifest.ParsePublic(p)
		if err != nil {
			return nil, err
		}
		st.TrustedKeys[manifest.KeyID(k)] = p
	}
	// New files are staged as <name>.new and moved into place only after
	// agent.json is saved.
	staged := map[string]string{}
	defer func() {
		for _, tmp := range staged {
			os.Remove(tmp)
		}
	}()
	stage := func(name string) string {
		tmp := filepath.Join(dir, name+".new")
		staged[name] = tmp
		return tmp
	}
	caPath := ""
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		caPath = stage(caName)
		if err := writeFileAtomic(caPath, b, 0o644); err != nil {
			return nil, err
		}
		st.CAFile = caName
	}
	hc, err := httpClient(caPath, "", "")
	if err != nil {
		return nil, err
	}
	f, err := plat.Facts()
	if err != nil {
		return nil, err
	}
	req := store.EnrollRequest{Token: token, Hostname: f.Hostname, OS: f.OS, OSVersion: f.OSVersion, Build: f.Build, Arch: f.Arch, AgentVersion: Version}
	tlsMode := strings.HasPrefix(serverURL, "https://")
	keyPath := ""
	if tlsMode {
		keyPath = stage(keyName)
		csr, err := pki.NewClientKey(keyPath)
		if err != nil {
			return nil, err
		}
		req.CSR = string(csr)
	}
	body, _ := json.Marshal(req)
	resp, err := hc.Post(serverURL+"/api/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, apiError(resp)
	}
	var r struct {
		EndpointID  string `json:"endpoint_id"`
		Secret      string `json:"secret"`
		Certificate string `json:"certificate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if r.EndpointID == "" {
		return nil, errors.New("server returned no endpoint_id")
	}
	st.EndpointID, st.Secret = r.EndpointID, r.Secret
	if tlsMode {
		if r.Certificate == "" {
			return nil, errors.New("server did not issue a client certificate")
		}
		if _, err := checkClientCert([]byte(r.Certificate), keyPath); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(stage(certName), []byte(r.Certificate), 0o644); err != nil {
			return nil, err
		}
		st.CertFile, st.KeyFile = certName, keyName
	}
	if err := st.Save(dir); err != nil {
		return nil, err
	}
	for name, tmp := range staged {
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			return nil, fmt.Errorf("install %s: %w", name, err)
		}
		delete(staged, name)
	}
	syncDir(dir)
	return st, nil
}

// checkClientCert verifies that certPEM is a certificate for the private key
// in keyPath and is currently valid, before it replaces anything.
func checkClientCert(certPEM []byte, keyPath string) (*x509.Certificate, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("issued certificate rejected (does not match the device key): %w", err)
	}
	c, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("issued certificate rejected: %w", err)
	}
	if time.Now().After(c.NotAfter) {
		return nil, fmt.Errorf("issued certificate rejected: expired at %s", c.NotAfter.Format(time.RFC3339))
	}
	return c, nil
}

// renewDue: renew once half of the certificate lifetime has passed (or
// within renewBefore of expiry, whichever comes first), which leaves months
// to retry while the server is unreachable.
func renewDue(notBefore, notAfter, now time.Time, renewBefore time.Duration) bool {
	window := notAfter.Sub(notBefore) / 2
	if renewBefore > window {
		window = renewBefore
	}
	return !now.Before(notAfter.Add(-window))
}

// maybeRenew renews the client certificate when it is due. The key stays
// the same; the new certificate is checked against it before it atomically
// replaces the current one.
func (a *Agent) maybeRenew(ctx context.Context) error {
	if a.st.CertFile == "" {
		return nil
	}
	certPath, keyPath := a.st.path(a.dir, a.st.CertFile), a.st.path(a.dir, a.st.KeyFile)
	b, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	c, err := pki.ParseCertPEM(b)
	if err != nil {
		return err
	}
	if !renewDue(c.NotBefore, c.NotAfter, time.Now(), pki.RenewBefore) {
		return nil
	}
	csr, err := pki.CSRFromKey(keyPath)
	if err != nil {
		return err
	}
	var r struct {
		Certificate string `json:"certificate"`
	}
	if err := a.do(ctx, "POST", "/api/agent/renew", map[string]string{"csr": string(csr)}, &r); err != nil {
		return fmt.Errorf("certificate renewal: %w", err)
	}
	if _, err := checkClientCert([]byte(r.Certificate), keyPath); err != nil {
		return fmt.Errorf("certificate renewal: %w", err)
	}
	if err := writeFileAtomic(certPath, []byte(r.Certificate), 0o644); err != nil {
		return err
	}
	hc, err := httpClient(a.st.path(a.dir, a.st.CAFile), certPath, keyPath)
	if err != nil {
		return err
	}
	a.hc = hc
	a.log.Info("client certificate renewed")
	return nil
}

// serverError is a non-2xx answer from the server.
type serverError struct {
	Code int
	Msg  string
}

func (e *serverError) Error() string { return fmt.Sprintf("server %d: %s", e.Code, e.Msg) }

func apiError(resp *http.Response) error {
	var e struct{ Error string }
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	json.Unmarshal(b, &e)
	if e.Error == "" {
		e.Error = strings.TrimSpace(string(b))
	}
	return &serverError{Code: resp.StatusCode, Msg: e.Error}
}

// sameOrigin resolves a server-supplied path and refuses anything that is
// not a path on the configured server.
func (a *Agent) sameOrigin(path, prefix string) (string, error) {
	if !strings.HasPrefix(path, prefix) || strings.Contains(path, "..") || strings.Contains(path, "//") {
		return "", fmt.Errorf("refusing URL %q: not a %s path on the management server", path, prefix)
	}
	u := *a.base
	u.Path = strings.TrimRight(a.base.Path, "/") + path
	return u.String(), nil
}

func (a *Agent) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	u := *a.base
	u.Path = strings.TrimRight(a.base.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	if a.st.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+a.st.Secret)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return apiError(resp)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
	}
	return nil
}

func (a *Agent) report(ctx context.Context, as store.Assignment, state string, code int, detail string) {
	a.reportHealth(ctx, as, state, code, detail, "", "")
}

func (a *Agent) reportHealth(ctx context.Context, as store.Assignment, state string, code int, detail, health, hdetail string) {
	err := a.do(ctx, "POST", "/api/agent/report", store.Report{DeploymentID: as.DeploymentID, PackageID: as.PackageID, State: state, ExitCode: code, Detail: detail, Health: health, HealthDetail: hdetail}, nil)
	if err != nil {
		a.log.Warn("report failed", "package", as.PackageID, "state", state, "err", err)
	}
}

// Run loops until ctx is cancelled. With once=true it does a single cycle.
// After failed cycles (server unreachable) it backs off exponentially up to
// maxBackoff, so thousands of endpoints don't hammer a recovering server.
func (a *Agent) Run(ctx context.Context, once bool) error {
	if err := a.checkUpgrade(); err != nil {
		if errors.Is(err, ErrRestart) {
			a.log.Info("exiting so the service manager starts the restored agent")
			return err
		}
		a.log.Warn("upgrade bookkeeping failed", "err", err)
	}
	for {
		err := a.Cycle(ctx)
		if err != nil {
			a.failures++
			a.log.Error("cycle failed", "err", err, "consecutive_failures", a.failures)
		} else {
			a.failures = 0
		}
		if a.restart {
			a.log.Info("exiting so the service manager starts the upgraded agent")
			return ErrRestart
		}
		if time.Since(a.started) >= upgradeHealthyAfter {
			a.upgradeHealthy(ctx, false)
		}
		if once {
			return err
		}
		wait := nextWait(a.interval, a.nextHint, a.failures)
		if a.failures > 0 {
			wait += rand.N(wait/10 + 1) // spread retries across the fleet
		}
		wait = a.afterInstallWait(wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// backoffDelay doubles the check-in interval per consecutive failure, up to
// maxBackoff (or the interval itself if that is longer).
func backoffDelay(interval time.Duration, failures int) time.Duration {
	limit := max(maxBackoff, interval)
	d := interval
	for i := 0; i < failures && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

// collect returns facts and inventory, cached for inventoryTTL on slow
// platforms. A failed collection falls back to the last good data; with
// none, it fails (a check-in replaces the server's inventory, so sending an
// empty one would wrongly verify rollbacks and reopen installs).
func (a *Agent) collect() (Facts, []store.InventoryItem, bool, error) {
	f, err := a.plat.Facts()
	switch {
	case err == nil:
		a.facts = &f
	case a.facts == nil:
		return Facts{}, nil, false, fmt.Errorf("facts: %w", err)
	default:
		a.log.Warn("facts collection failed; using the last known facts", "err", err)
		f = *a.facts
	}
	if !a.invOK || a.cacheTTL() == 0 || time.Since(a.invAt) >= a.cacheTTL() {
		inv, reboot, err := a.plat.Inventory()
		a.invAt = time.Now()
		switch {
		case err == nil:
			a.inv, a.invBoot, a.invOK = inv, reboot, true
		case !a.invOK:
			return Facts{}, nil, false, fmt.Errorf("inventory: %w", err)
		default:
			a.log.Warn("inventory collection failed; reusing the last inventory", "err", err)
		}
	}
	return f, slices.Clone(a.inv), a.invBoot, nil
}

func (a *Agent) cacheTTL() time.Duration {
	if _, ok := a.plat.(slowInventory); ok {
		return inventoryTTL
	}
	return 0
}

func (a *Agent) hardware(ctx context.Context) *store.Hardware {
	hr, ok := a.plat.(hardwareReporter)
	if !ok {
		return nil
	}
	if a.hw == nil || a.cacheTTL() == 0 || time.Since(a.hwAt) >= a.cacheTTL() {
		h := hr.Hardware(ctx)
		a.hw, a.hwAt = &h, time.Now()
	}
	return a.hw
}

// Cycle: check in with inventory, then work through assignments
// sequentially (one installer at a time).
func (a *Agent) Cycle(ctx context.Context) error {
	a.nextHint = 0 // only a successful check-in sets it
	if err := a.maybeRenew(ctx); err != nil {
		a.log.Warn("renewal failed; will retry", "err", err)
	}
	if time.Since(a.cleanAt) >= cleanupEvery {
		a.cleanAt = time.Now()
		if n := cleanCache(filepath.Join(a.dir, "cache"), cacheMaxAge, time.Now()); n > 0 {
			a.log.Info("removed stale cached payloads", "files", n)
		}
	}
	f, inv, reboot, err := a.collect()
	if err != nil {
		// Stay visible as online; assignments wait for usable inventory.
		if herr := a.heartbeat(ctx, nil); herr != nil {
			return fmt.Errorf("%w (heartbeat: %v)", err, herr)
		}
		return fmt.Errorf("%w; sent a heartbeat instead of a check-in", err)
	}
	// Before the check-in: the check-in verifies targets, after which the
	// server takes no more reports for them.
	a.postRebootHealth(ctx, reboot)
	inv = append(inv, store.InventoryItem{Kind: "agent", ID: "offpatch-agent", Name: "offpatch agent", Version: a.agentVersion()})
	var resp struct {
		Assignments            []store.Assignment      `json:"assignments"`
		CheckinIntervalSeconds int                     `json:"checkin_interval_seconds"`
		RebootNow              bool                    `json:"reboot_now"`
		Trust                  *trust.Signed           `json:"trust"`
		DownloadRateKbps       int                     `json:"download_rate_kbps"`
		Preinstall             *store.PreinstallPolicy `json:"preinstall"`
		// Decoded here rather than via store.CheckinResult so the agent does
		// not depend on the server's struct; unknown fields are ignored.
		NextCheckinSeconds int `json:"next_checkin_seconds"`
	}
	req := store.CheckinRequest{Hostname: f.Hostname, OSVersion: f.OSVersion, Build: f.Build, Arch: f.Arch, AgentVersion: a.agentVersion(), RebootPending: reboot, Inventory: inv, Edition: f.Edition,
		Hardware: a.hardware(ctx)}
	if err := a.do(ctx, "POST", "/api/agent/checkin", req, &resp); err != nil {
		return fmt.Errorf("checkin: %w", err)
	}
	checkedIn := time.Now()
	a.upgradeHealthy(ctx, true)
	if resp.CheckinIntervalSeconds > 0 {
		a.interval = time.Duration(resp.CheckinIntervalSeconds) * time.Second
	}
	if resp.NextCheckinSeconds > 0 {
		a.nextHint = time.Duration(resp.NextCheckinSeconds) * time.Second
	}
	a.rateKbps = resp.DownloadRateKbps
	a.preinstall = resp.Preinstall
	if resp.Trust != nil {
		if err := a.applyTrust(*resp.Trust); err != nil {
			a.log.Warn("trust update not applied", "err", err)
		}
	}
	a.log.Info("checked in", "inventory", len(inv), "reboot_pending", reboot, "assignments", len(resp.Assignments), "reboot_now", resp.RebootNow)
	a.reportAwaitingReboot(ctx, reboot)
	needReboot := resp.RebootNow
	for _, as := range resp.Assignments {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if a.process(ctx, as, f, inv) && as.RebootAllowed {
			needReboot = true
		}
	}
	if needReboot {
		if took := time.Since(checkedIn); took > rebootRecheckAfter {
			// The window that allowed the reboot may have closed meanwhile;
			// the server re-decides (reboot_now) at the next check-in.
			a.log.Info("installs took long; leaving the reboot decision to the next check-in", "took", took.Round(time.Second))
		} else {
			a.reboot(ctx)
		}
	}
	return nil
}

// reboot asks the platform to restart, at most once per 30 minutes per run.
func (a *Agent) reboot(ctx context.Context) {
	if !a.lastBoot.IsZero() && time.Since(a.lastBoot) < 30*time.Minute {
		return
	}
	a.lastBoot = time.Now()
	if err := a.plat.Reboot(ctx, "Requested by offpatch maintenance policy."); err != nil {
		a.log.Error("reboot failed", "err", err)
		return
	}
	a.log.Info("reboot scheduled to complete pending updates")
}

// process handles one assignment and reports whether a reboot is pending.
func (a *Agent) process(ctx context.Context, as store.Assignment, f Facts, inv []store.InventoryItem) (rebootPending bool) {
	log := a.log.With("deployment", as.DeploymentID, "package", as.PackageID)

	// 1. Signed manifest: the server tells us what to install, but the
	//    content must match what the organisation signed.
	pkg, err := a.signedPackage(ctx, as)
	if err != nil {
		log.Error("manifest verification failed", "err", err)
		a.report(ctx, as, "failed", -1, "manifest verification failed: "+err.Error())
		return
	}
	// 2. Local applicability and idempotency.
	if ok, why := locallyApplicable(pkg, f); !ok {
		a.report(ctx, as, "not_applicable", 0, why)
		return
	}
	if as.Operation == "rollback" {
		return a.rollback(ctx, as, pkg, f, inv)
	}
	if pkg.Kind == "agent" && store.VersionAtLeast(a.agentVersion(), pkg.Version) {
		a.report(ctx, as, "installed", 0, "agent already at "+a.agentVersion())
		return
	}
	if pkg.Kind == "agent" {
		if why, blocked := a.upgradeBlocked(pkg.Version, pkg.File.SHA256); blocked {
			// Already reported as failed; retrying would fail (or restart-loop) again.
			log.Info("agent upgrade not retried", "version", pkg.Version, "reason", why)
			return
		}
	}
	// A Windows app (MSI, EXE, portable, MSIX) counts as present only when
	// every copy of it is current (appUpToDate), as on the server.
	if appUpToDate(pkg, inv) {
		a.report(ctx, as, "installed", 0, "already present in local inventory")
		return
	}
	if d := msixProvisionedOnly(pkg, inv); d != "" {
		a.report(ctx, as, "installed", 0, d)
		return
	}
	for _, it := range inv {
		if (pkg.KB != "" && it.Kind == "kb" && strings.EqualFold(it.ID, pkg.KB)) ||
			(pkg.PackageName != "" && (it.Kind == "pkg" || (it.Kind == "app" && pkg.Kind == "pkg")) && it.ID == pkg.PackageName && store.VersionAtLeast(it.Version, pkg.Version)) {
			a.report(ctx, as, "installed", 0, "already present in local inventory")
			return
		}
		if pkg.Kind == "pkg" && it.Kind == "app" && it.Source == "appstore" && it.ID == pkg.PackageName {
			a.report(ctx, as, "not_applicable", 0, "installed from the Mac App Store, which keeps it updated")
			return
		}
	}
	// A per-user installer needs someone signed in: until then the target
	// is deferred (no attempt used) and tried again at later check-ins.
	if perUserExe(pkg) {
		if us, ok := a.plat.(userSessions); ok {
			if n, err := us.SignedInUsers(); err == nil && n == 0 {
				a.report(ctx, as, "deferred", 0, waitingForUser)
				return
			}
		}
	}
	// 3. Pre-install checks (disk space, power): failing them defers the
	//    install to a later check-in; it is not a failure. An archive
	//    package also needs room for its extracted files.
	if why := a.preflight(ctx, installSize(pkg), f.OS); why != "" {
		log.Info("install deferred", "why", why)
		a.report(ctx, as, "deferred", 0, why)
		return
	}
	// 4. Download (resumable) and verify against the signed hash.
	a.report(ctx, as, "downloading", 0, fmt.Sprintf("%d bytes", pkg.File.Size))
	file, err := func() (string, error) {
		lp := newLive(as, stageDownloading, 0, pkg.File.Size)
		defer a.keepAlive(ctx, lp)() // large downloads over slow links take a while too
		return a.download(ctx, as, pkg, lp)
	}()
	if err != nil {
		log.Error("download failed", "err", err)
		a.report(ctx, as, "failed", -1, "download/verify failed: "+err.Error())
		return
	}
	a.report(ctx, as, "downloaded", 0, "sha256 verified "+pkg.File.SHA256[:16])
	// 5. Install. A stop request does not interrupt the installer (that can
	//    leave a half-applied update); the platform bounds it with a timeout,
	//    and the result is still reported.
	a.report(ctx, as, "installing", 0, a.plat.Name()+" installer started")
	ictx := context.WithoutCancel(ctx)
	res := func() Result {
		defer a.keepAlive(ctx, newLive(as, stageInstalling, pkg.File.Size, pkg.File.Size))()
		if pkg.Kind == "agent" {
			return a.selfUpgrade(ictx, as.DeploymentID, pkg, file)
		}
		return a.plat.Install(ictx, pkg, file)
	}()
	a.invAt = time.Time{} // refresh inventory at the next check-in
	a.recheckSoon = a.recheckSoon || refreshesInventory(res)
	log.Info("install finished", "state", res.State, "exit", res.ExitCode, "detail", res.Detail)
	rctx, cancel := context.WithTimeout(ictx, reportTimeout)
	defer cancel()
	a.finish(rctx, as, res)
	if res.State != "failed" && res.State != "deferred" {
		os.Remove(file)
	}
	a.afterInstall(rctx, as, res, pkg.File.Size)
	return res.State == "pending_reboot"
}

// userSessions is implemented by platforms that run per-user installers:
// how many users are signed in (an installer can run in their sessions).
type userSessions interface {
	SignedInUsers() (int, error)
}

// refreshesInventory: an installer (or uninstaller) result that changed,
// or may have changed, what is installed, so a fresh inventory soon is
// worth a quick check-in: installed, pending reboot, or a definite failure.
// A deferred or "retry later: installer busy" result changed nothing; an
// early recheck would only repeat it and spend the server's busy grace
// (installerBusyGrace consecutive busy results) in a few minutes.
func refreshesInventory(r Result) bool {
	switch r.State {
	case "deferred":
		return false
	case "failed":
		return !strings.HasPrefix(r.Detail, retryLater)
	}
	return true
}

// afterInstallWait shortens the wait before the next check-in after a
// cycle that ran an installer: the fresh inventory then verifies it.
func (a *Agent) afterInstallWait(wait time.Duration) time.Duration {
	if !a.recheckSoon {
		return wait
	}
	a.recheckSoon = false
	return min(wait, postInstallRecheck)
}

// uninstaller is implemented by platforms that can roll a package back.
type uninstaller interface {
	Uninstall(ctx context.Context, p manifest.Package) Result
}

// rollback runs the platform uninstaller for a rollback assignment. Nothing
// is downloaded; the signed manifest identifies what to remove.
func (a *Agent) rollback(ctx context.Context, as store.Assignment, pkg manifest.Package, f Facts, inv []store.InventoryItem) (rebootPending bool) {
	log := a.log.With("deployment", as.DeploymentID, "package", as.PackageID, "operation", "rollback")
	u, ok := a.plat.(uninstaller)
	if !ok {
		a.report(ctx, as, "failed", -1, "rollback is not supported on platform "+a.plat.Name())
		return
	}
	if !pkg.RollbackSupported() {
		a.report(ctx, as, "failed", -1, exeRollbackUnsupported)
		return
	}
	present := false
	for _, it := range inv {
		if (pkg.KB != "" && it.Kind == "kb" && strings.EqualFold(it.ID, pkg.KB)) || (pkg.ProductCode != "" && it.Kind == "product" && strings.EqualFold(it.ID, pkg.ProductCode)) ||
			(pkg.PackageName != "" && it.Kind == "pkg" && it.ID == pkg.PackageName) || (pkg.Kind == manifest.KindExe && exeAppMatch(pkg, it)) || formatAppMatch(pkg, it) {
			present = true
		}
	}
	if !present {
		a.report(ctx, as, "not_applicable", 0, "not present in local inventory; nothing to roll back")
		return
	}
	if why := a.preflight(ctx, 0, f.OS); why != "" {
		log.Info("rollback deferred", "why", why)
		a.report(ctx, as, "deferred", 0, why)
		return
	}
	a.report(ctx, as, "installing", 0, a.plat.Name()+" uninstall started")
	ictx := context.WithoutCancel(ctx) // see process: never kill an installer on stop
	res := func() Result {
		defer a.keepAlive(ctx, newLive(as, stageInstalling, 0, 0))()
		return u.Uninstall(ictx, pkg)
	}()
	a.invAt = time.Time{}
	a.recheckSoon = a.recheckSoon || refreshesInventory(res)
	log.Info("uninstall finished", "state", res.State, "exit", res.ExitCode, "detail", res.Detail)
	rctx, cancel := context.WithTimeout(ictx, reportTimeout)
	defer cancel()
	a.finish(rctx, as, res)
	a.afterInstall(rctx, as, res, 0)
	return res.State == "pending_reboot"
}

// afterInstall: an install that needs a reboot reports waiting_reboot
// progress now and at every cycle until the reboot has happened.
func (a *Agent) afterInstall(ctx context.Context, as store.Assignment, res Result, size int64) {
	if res.State != "pending_reboot" {
		return
	}
	a.rememberReboot(as, size)
	a.rememberRebootHealth(as, res)
	p := a.awaitingReboot[rebootKey(as)]
	if err := a.heartbeat(ctx, &p); err != nil {
		a.log.Debug("waiting_reboot heartbeat failed", "err", err)
	}
}

// finish runs post-install health checks and reports the final state.
func (a *Agent) finish(ctx context.Context, as store.Assignment, res Result) {
	health, hdetail := "", ""
	if (res.State == "installed" || res.State == "pending_reboot") && len(as.HealthChecks) > 0 {
		ok, d := a.plat.Health(ctx, as.HealthChecks)
		health, hdetail = map[bool]string{true: "ok", false: "failed"}[ok], d
		if !ok {
			a.log.Warn("post-install health check failed", "deployment", as.DeploymentID, "package", as.PackageID, "detail", d)
		}
	}
	a.reportHealth(ctx, as, res.State, res.ExitCode, res.Detail, health, hdetail)
}

func (a *Agent) signedPackage(ctx context.Context, as store.Assignment) (manifest.Package, error) {
	if _, err := a.sameOrigin(as.ManifestURL, "/api/agent/manifest/"); err != nil {
		return manifest.Package{}, err
	}
	var r struct {
		Manifest  string `json:"manifest"`
		Signature string `json:"signature"`
		KeyID     string `json:"key_id"`
	}
	if err := a.do(ctx, "GET", as.ManifestURL, nil, &r); err != nil {
		return manifest.Package{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(r.Manifest)
	if err != nil {
		return manifest.Package{}, err
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return manifest.Package{}, err
	}
	for _, r := range a.st.Revoked {
		if r == m.KeyID {
			return manifest.Package{}, fmt.Errorf("manifest signed by revoked key %s", m.KeyID)
		}
	}
	key, ok := a.keys[m.KeyID]
	if !ok {
		return manifest.Package{}, fmt.Errorf("manifest signed by untrusted key %s", m.KeyID)
	}
	if err := manifest.Verify(key, raw, r.Signature); err != nil {
		return manifest.Package{}, err
	}
	// Structural rules (ids, file names, hashes, kinds). Validated "as of"
	// the bundle's creation time: expiry is enforced when the server imports
	// a bundle, and an approved deployment must not break on an endpoint
	// whose clock is skewed or because the bundle aged after approval.
	if err := m.ValidateSchema(m.CreatedAt); err != nil {
		return manifest.Package{}, fmt.Errorf("signed manifest fails schema validation: %w", err)
	}
	for _, p := range m.Packages {
		if p.PackageID == as.PackageID {
			if p.File.SHA256 != as.SHA256 || p.File.Size != as.Size || p.Kind != as.Kind {
				return manifest.Package{}, errors.New("assignment does not match signed manifest (hash/size/kind)")
			}
			return p, nil
		}
	}
	return manifest.Package{}, errors.New("package not in signed manifest")
}

func locallyApplicable(p manifest.Package, f Facts) (bool, string) {
	ap := p.Applicability
	if ap.Arch != "any" && ap.Arch != f.Arch {
		return false, fmt.Sprintf("arch %s != %s", f.Arch, ap.Arch)
	}
	if ap.MinBuild > 0 && f.Build < ap.MinBuild {
		return false, fmt.Sprintf("build %d < %d", f.Build, ap.MinBuild)
	}
	if ap.MaxBuild > 0 && f.Build > ap.MaxBuild {
		return false, fmt.Sprintf("build %d > %d", f.Build, ap.MaxBuild)
	}
	if ap.OS != "" && f.OS != "" && ap.OS != f.OS {
		return false, fmt.Sprintf("os %s != %s", f.OS, ap.OS)
	}
	if len(ap.Editions) > 0 && f.Edition != "" {
		for _, ed := range ap.Editions {
			if strings.EqualFold(ed, f.Edition) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("edition %s not in %v", f.Edition, ap.Editions)
	}
	return true, ""
}

// download fetches into <dir>/cache/<sha>.part, resuming with Range, then
// verifies size and SHA-256 before renaming into place.
// lp (may be nil) receives byte counts and the verifying stage.
func (a *Agent) download(ctx context.Context, as store.Assignment, p manifest.Package, lp *liveProgress) (string, error) {
	path, err := a.sameOrigin(as.URL, "/api/agent/content/")
	if err != nil {
		return "", err
	}
	cache := filepath.Join(a.dir, "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return "", err
	}
	final := filepath.Join(cache, p.File.SHA256+filepath.Ext(p.File.Name))
	if fi, err := os.Stat(final); err == nil && fi.Size() == p.File.Size {
		lp.setDone(p.File.Size)
		lp.setStage(stageVerifying)
		if n, h, err := manifest.HashFile(final); err == nil && n == p.File.Size && h == p.File.SHA256 {
			return final, nil
		}
		lp.setStage(stageDownloading)
	}
	part := final + ".part"
	var have int64
	if st, err := os.Stat(part); err == nil && st.Size() < p.File.Size {
		have = st.Size()
	} else {
		os.Remove(part)
	}
	lp.setDone(have)
	dctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	req, err := http.NewRequestWithContext(dctx, "GET", path, nil)
	if err != nil {
		return "", err
	}
	if a.st.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+a.st.Secret)
	}
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// Abort when no data arrives for downloadIdleTimeout (a half-open TCP
	// connection would otherwise block this endpoint forever).
	idle := time.AfterFunc(downloadIdleTimeout, func() { cancel(errStalled) })
	defer idle.Stop()
	flags := os.O_CREATE | os.O_WRONLY
	switch resp.StatusCode {
	case http.StatusPartialContent:
		flags |= os.O_APPEND
	case http.StatusOK:
		flags |= os.O_TRUNC
	default:
		return "", apiError(resp)
	}
	out, err := os.OpenFile(part, flags, 0o600)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusOK {
		lp.setDone(0) // the server sent the whole file again
	}
	var dst io.Writer = out
	if lp != nil {
		dst = countingWriter{w: out, lp: lp}
	}
	body := &idleReader{r: resp.Body, t: idle, d: downloadIdleTimeout}
	_, err = io.Copy(dst, throttle(ctx, io.LimitReader(body, p.File.Size+1), a.rateKbps))
	cerr := out.Close()
	if err != nil {
		if errors.Is(context.Cause(dctx), errStalled) {
			return "", fmt.Errorf("download stalled: no data for %s (will resume)", downloadIdleTimeout)
		}
		return "", err
	}
	if cerr != nil {
		return "", cerr
	}
	lp.setStage(stageVerifying)
	n, h, err := manifest.HashFile(part)
	if err != nil {
		return "", err
	}
	if n != p.File.Size || h != p.File.SHA256 {
		os.Remove(part)
		return "", fmt.Errorf("content does not match signed manifest (size %d/%d, sha256 %s) — possible tampering", n, p.File.Size, h[:16])
	}
	return final, os.Rename(part, final)
}

var errStalled = errors.New("download stalled")

// idleReader re-arms the stall timer whenever data arrives.
type idleReader struct {
	r io.Reader
	t *time.Timer
	d time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.t.Reset(r.d)
	}
	return n, err
}

// throttle limits a reader to kbps kilobits per second (0 = unlimited) so
// patch downloads don't saturate WAN links to remote sites.
func throttle(ctx context.Context, r io.Reader, kbps int) io.Reader {
	if kbps <= 0 {
		return r
	}
	return &throttled{ctx: ctx, r: r, bps: float64(kbps) * 1000 / 8, start: time.Now()}
}

type throttled struct {
	ctx   context.Context
	r     io.Reader
	bps   float64
	start time.Time
	n     int64
}

func (t *throttled) Read(p []byte) (int, error) {
	if max := int(t.bps / 4); max > 0 && len(p) > max {
		p = p[:max] // ~250 ms worth per read keeps the rate smooth
	}
	n, err := t.r.Read(p)
	t.n += int64(n)
	if wait := time.Duration(float64(t.n)/t.bps*float64(time.Second)) - time.Since(t.start); wait > 0 {
		select {
		case <-time.After(wait):
		case <-t.ctx.Done():
			return n, t.ctx.Err()
		}
	}
	return n, err
}

// applyTrust verifies a trust document against the pinned root key and, if
// newer, replaces the pinned bundle keys (rotation) and records revocations.
func (a *Agent) applyTrust(s trust.Signed) error {
	if a.st.RootKey == "" {
		return errors.New("no root key pinned at enrollment (-root-pubkey); key rotation unavailable")
	}
	root, err := manifest.ParsePublic(a.st.RootKey)
	if err != nil {
		return err
	}
	doc, err := trust.Verify(s, root)
	if err != nil {
		return err
	}
	if doc.Sequence <= a.st.TrustSeq {
		return nil // already applied (or a replay of an older one)
	}
	keys := map[string]string{}
	parsed := map[string]ed25519.PublicKey{}
	for _, k := range doc.Keys {
		pub, err := manifest.ParsePublic(k.PublicKey)
		if err != nil {
			return err
		}
		keys[k.KeyID] = k.PublicKey
		parsed[k.KeyID] = pub
	}
	var revoked []string
	for _, r := range doc.Revoked {
		revoked = append(revoked, r.KeyID)
	}
	// Only switch to the new keys once they are on disk.
	ns := *a.st
	ns.TrustedKeys, ns.TrustSeq, ns.Revoked = keys, doc.Sequence, revoked
	if err := ns.Save(a.dir); err != nil {
		return err
	}
	a.st, a.keys = &ns, parsed
	a.log.Info("trust document applied", "sequence", doc.Sequence, "keys", len(keys), "revoked", len(revoked))
	return nil
}
