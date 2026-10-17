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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/pki"
	"offpatch/internal/store"
	"offpatch/internal/trust"
)

// Version is set at build time: -ldflags "-X offpatch/internal/agent.Version=1.2.3".
var Version = "0.1.0"

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

func LoadState(dir string) (*State, error) {
	b, err := os.ReadFile(statePath(dir))
	if err != nil {
		return nil, fmt.Errorf("agent not enrolled (%w)", err)
	}
	var s State
	return &s, json.Unmarshal(b, &s)
}

func (s *State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(statePath(dir), b, 0o600)
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
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
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
	lastBoot time.Time
	restart  bool // set after a self-upgrade
}

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
	return &Agent{st: st, dir: dir, plat: plat, hc: hc, base: base, keys: keys, log: log, interval: time.Minute}, nil
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

// Enroll registers with the server using a one-time token. Over HTTPS the
// agent generates its own key (it never leaves the endpoint), sends a CSR,
// and receives an mTLS client certificate; over plain HTTP (lab mode only)
// it receives a bearer secret instead.
func Enroll(serverURL, token, caFile, dir string, pubKeys []string, rootPEM string, plat Platform, platName string, sim *SimConfig) (*State, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
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
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, caName), b, 0o644); err != nil {
			return nil, err
		}
		st.CAFile = caName
	}
	hc, err := httpClient(st.path(dir, st.CAFile), "", "")
	if err != nil {
		return nil, err
	}
	f, err := plat.Facts()
	if err != nil {
		return nil, err
	}
	req := store.EnrollRequest{Token: token, Hostname: f.Hostname, OS: f.OS, OSVersion: f.OSVersion, Build: f.Build, Arch: f.Arch, AgentVersion: Version}
	tlsMode := strings.HasPrefix(serverURL, "https://")
	if tlsMode {
		csr, err := pki.NewClientKey(filepath.Join(dir, keyName))
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
	st.EndpointID, st.Secret = r.EndpointID, r.Secret
	if tlsMode {
		if r.Certificate == "" {
			return nil, errors.New("server did not issue a client certificate")
		}
		if err := os.WriteFile(filepath.Join(dir, certName), []byte(r.Certificate), 0o644); err != nil {
			return nil, err
		}
		st.CertFile, st.KeyFile = certName, keyName
	}
	return st, st.Save(dir)
}

// maybeRenew renews the client certificate when it is close to expiry. The
// key stays the same; the old certificate stops working once renewed.
func (a *Agent) maybeRenew(ctx context.Context) error {
	if a.st.CertFile == "" {
		return nil
	}
	b, err := os.ReadFile(a.st.path(a.dir, a.st.CertFile))
	if err != nil {
		return err
	}
	c, err := pki.ParseCertPEM(b)
	if err != nil {
		return err
	}
	if time.Until(c.NotAfter) > pki.RenewBefore {
		return nil
	}
	csr, err := pki.CSRFromKey(a.st.path(a.dir, a.st.KeyFile))
	if err != nil {
		return err
	}
	var r struct {
		Certificate string `json:"certificate"`
	}
	if err := a.do(ctx, "POST", "/api/agent/renew", map[string]string{"csr": string(csr)}, &r); err != nil {
		return fmt.Errorf("certificate renewal: %w", err)
	}
	tmp := a.st.path(a.dir, a.st.CertFile) + ".new"
	if err := os.WriteFile(tmp, []byte(r.Certificate), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.st.path(a.dir, a.st.CertFile)); err != nil {
		return err
	}
	hc, err := httpClient(a.st.path(a.dir, a.st.CAFile), a.st.path(a.dir, a.st.CertFile), a.st.path(a.dir, a.st.KeyFile))
	if err != nil {
		return err
	}
	a.hc = hc
	a.log.Info("client certificate renewed")
	return nil
}

func apiError(resp *http.Response) error {
	var e struct{ Error string }
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	json.Unmarshal(b, &e)
	if e.Error == "" {
		e.Error = strings.TrimSpace(string(b))
	}
	return fmt.Errorf("server %d: %s", resp.StatusCode, e.Error)
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
func (a *Agent) Run(ctx context.Context, once bool) error {
	for {
		err := a.Cycle(ctx)
		if err != nil {
			a.log.Error("cycle failed", "err", err)
		}
		if a.restart {
			a.log.Info("exiting so the service manager starts the upgraded agent")
			return ErrRestart
		}
		if once {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(a.interval):
		}
	}
}

// Cycle: check in with fresh inventory, then work through assignments
// sequentially (one installer at a time).
func (a *Agent) Cycle(ctx context.Context) error {
	if err := a.maybeRenew(ctx); err != nil {
		a.log.Warn("renewal failed; will retry", "err", err)
	}
	f, err := a.plat.Facts()
	if err != nil {
		return fmt.Errorf("facts: %w", err)
	}
	inv, reboot, err := a.plat.Inventory()
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	inv = append(inv, store.InventoryItem{Kind: "agent", ID: "offpatch-agent", Name: "offpatch agent", Version: a.agentVersion()})
	var resp struct {
		Assignments            []store.Assignment `json:"assignments"`
		CheckinIntervalSeconds int                `json:"checkin_interval_seconds"`
		RebootNow              bool               `json:"reboot_now"`
		Trust                  *trust.Signed      `json:"trust"`
		DownloadRateKbps       int                `json:"download_rate_kbps"`
	}
	req := store.CheckinRequest{Hostname: f.Hostname, OSVersion: f.OSVersion, Build: f.Build, Arch: f.Arch, AgentVersion: a.agentVersion(), RebootPending: reboot, Inventory: inv, Edition: f.Edition}
	if err := a.do(ctx, "POST", "/api/agent/checkin", req, &resp); err != nil {
		return fmt.Errorf("checkin: %w", err)
	}
	if resp.CheckinIntervalSeconds > 0 {
		a.interval = time.Duration(resp.CheckinIntervalSeconds) * time.Second
	}
	a.rateKbps = resp.DownloadRateKbps
	if resp.Trust != nil {
		if err := a.applyTrust(*resp.Trust); err != nil {
			a.log.Warn("trust update not applied", "err", err)
		}
	}
	a.log.Info("checked in", "inventory", len(inv), "reboot_pending", reboot, "assignments", len(resp.Assignments), "reboot_now", resp.RebootNow)
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
		a.reboot(ctx)
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
	if pkg.Kind == "agent" && store.VersionAtLeast(a.agentVersion(), pkg.Version) {
		a.report(ctx, as, "installed", 0, "agent already at "+a.agentVersion())
		return
	}
	for _, it := range inv {
		if (pkg.KB != "" && it.Kind == "kb" && strings.EqualFold(it.ID, pkg.KB)) || (pkg.ProductCode != "" && it.Kind == "product" && strings.EqualFold(it.ID, pkg.ProductCode)) ||
			(pkg.PackageName != "" && (it.Kind == "pkg" || (it.Kind == "app" && pkg.Kind == "pkg")) && it.ID == pkg.PackageName && store.VersionAtLeast(it.Version, pkg.Version)) {
			a.report(ctx, as, "installed", 0, "already present in local inventory")
			return
		}
		if pkg.Kind == "pkg" && it.Kind == "app" && it.Source == "appstore" && it.ID == pkg.PackageName {
			a.report(ctx, as, "not_applicable", 0, "installed from the Mac App Store, which keeps it updated")
			return
		}
	}
	// 3. Download (resumable) and verify against the signed hash.
	a.report(ctx, as, "downloading", 0, fmt.Sprintf("%d bytes", pkg.File.Size))
	file, err := a.download(ctx, as, pkg)
	if err != nil {
		log.Error("download failed", "err", err)
		a.report(ctx, as, "failed", -1, "download/verify failed: "+err.Error())
		return
	}
	a.report(ctx, as, "downloaded", 0, "sha256 verified "+pkg.File.SHA256[:16])
	// 4. Install.
	a.report(ctx, as, "installing", 0, a.plat.Name()+" installer started")
	var res Result
	if pkg.Kind == "agent" {
		res = a.selfUpgrade(ctx, pkg, file)
	} else {
		res = a.plat.Install(ctx, pkg, file)
	}
	log.Info("install finished", "state", res.State, "exit", res.ExitCode, "detail", res.Detail)
	health, hdetail := "", ""
	if (res.State == "installed" || res.State == "pending_reboot") && len(as.HealthChecks) > 0 {
		ok, d := a.plat.Health(ctx, as.HealthChecks)
		health, hdetail = map[bool]string{true: "ok", false: "failed"}[ok], d
		if !ok {
			log.Warn("post-install health check failed", "detail", d)
		}
	}
	a.reportHealth(ctx, as, res.State, res.ExitCode, res.Detail, health, hdetail)
	if res.State != "failed" {
		os.Remove(file)
	}
	return res.State == "pending_reboot"
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
func (a *Agent) download(ctx context.Context, as store.Assignment, p manifest.Package) (string, error) {
	path, err := a.sameOrigin(as.URL, "/api/agent/content/")
	if err != nil {
		return "", err
	}
	cache := filepath.Join(a.dir, "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return "", err
	}
	final := filepath.Join(cache, p.File.SHA256+filepath.Ext(p.File.Name))
	if n, h, err := manifest.HashFile(final); err == nil && n == p.File.Size && h == p.File.SHA256 {
		return final, nil
	}
	part := final + ".part"
	var have int64
	if st, err := os.Stat(part); err == nil && st.Size() < p.File.Size {
		have = st.Size()
	} else {
		os.Remove(part)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
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
	_, err = io.Copy(out, throttle(ctx, io.LimitReader(resp.Body, p.File.Size+1), a.rateKbps))
	cerr := out.Close()
	if err != nil {
		return "", err
	}
	if cerr != nil {
		return "", cerr
	}
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
	a.st.TrustedKeys, a.st.TrustSeq, a.st.Revoked = keys, doc.Sequence, revoked
	if err := a.st.Save(a.dir); err != nil {
		return err
	}
	a.keys = parsed
	a.log.Info("trust document applied", "sequence", doc.Sequence, "keys", len(keys), "revoked", len(revoked))
	return nil
}
