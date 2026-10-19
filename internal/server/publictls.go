package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"offpatch/internal/pki"
)

// Public certificate for the console (docs/07-admin-guide.md section 5.5)
// and how the server is addressed (server_name, agent_ip, agent_url).
//
// Certificate selection per TLS handshake (GetConfigForClient):
//   - the ClientHello offers ALPN "dss-agent/1" (agents 0.9.1+), or has no
//     SNI (older agents enrolled by IP), or its SNI is not a public_tls name:
//     internal CA certificate + client-certificate request (the agent path,
//     unchanged);
//   - otherwise (a browser on a public_tls name): the public certificate
//     (Let's Encrypt or the bank's own), no client-certificate request. The
//     agent API answers 421 on such connections.
// A missing, unreadable or expired public certificate is never served: the
// handshake falls back to the internal certificate.

// PublicTLSConfig is the optional "public_tls" block of pmserver.json.
type PublicTLSConfig struct {
	// Names: DNS names served with the public certificate (exact match on
	// the TLS SNI, case-insensitive). Never an IP address.
	Names []string `json:"names"`
	// CertFile / KeyFile: PEM certificate chain (leaf first, e.g. certbot's
	// fullchain.pem) and private key. Default <pki_dir>/public/cert.pem and
	// key.pem. Re-read when they change; no restart needed.
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// publicCertRecheck: how often a handshake may look at the files' mtimes.
const publicCertRecheck = time.Minute

// publicCertWarn: alert public_cert_expiring this long before expiry
// (certbot renews 30 days before, so this only fires when renewal fails).
const publicCertWarn = 14 * 24 * time.Hour

const alertPublicCert = "public_cert_expiring"

var dnsNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// normHost lower-cases a host name and drops a trailing dot.
func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".") }

// normalizePublicTLS validates public_tls, server_name, agent_ip and
// agent_url (LoadConfig).
func (c *Config) normalizePublicTLS() error {
	if c.ServerName != "" {
		h := normHost(c.ServerName)
		if net.ParseIP(h) != nil || !dnsNameRe.MatchString(h) {
			return fmt.Errorf("config: server_name %q must be a DNS name such as patcher.bank.example", c.ServerName)
		}
		c.ServerName = h
	}
	if c.AgentIP != "" {
		ip := net.ParseIP(strings.TrimSpace(c.AgentIP))
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
			return fmt.Errorf("config: agent_ip %q must be the server's IP address as endpoints reach it", c.AgentIP)
		}
		c.AgentIP = ip.String()
	}
	if p := c.PublicTLS; p != nil {
		if c.TLSCert == "" {
			return fmt.Errorf("config: public_tls requires TLS (pki_dir); it cannot be used with insecure_http")
		}
		if len(p.Names) == 0 {
			return fmt.Errorf("config: public_tls.names must list at least one DNS name (e.g. [\"patch.example.com\"])")
		}
		seen := map[string]bool{}
		names := make([]string, 0, len(p.Names))
		for _, n := range p.Names {
			h := normHost(n)
			if net.ParseIP(h) != nil || !dnsNameRe.MatchString(h) || h == "localhost" {
				return fmt.Errorf("config: public_tls.names: %q is not a DNS name (IP addresses stay on the internal certificate)", n)
			}
			if !seen[h] {
				seen[h] = true
				names = append(names, h)
			}
		}
		p.Names = names
		if p.CertFile == "" && p.KeyFile == "" {
			p.CertFile = filepath.Join(c.PKIDir, "public", "cert.pem")
			p.KeyFile = filepath.Join(c.PKIDir, "public", "key.pem")
		}
		if p.CertFile == "" || p.KeyFile == "" {
			return fmt.Errorf("config: public_tls.cert_file and key_file must both be set (or both left out for <pki_dir>/public/cert.pem and key.pem)")
		}
		p.CertFile, p.KeyFile = c.abs(p.CertFile), c.abs(p.KeyFile)
	}
	if c.AgentURL == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(c.AgentURL))
	want := "https"
	if c.InsecureHTTP {
		want = "http"
	}
	if err != nil || u.Scheme != want || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !hostRe.MatchString(u.Host) {
		return fmt.Errorf("config: agent_url must be %s://host:port with no path (got %q)", want, c.AgentURL)
	}
	c.AgentURL = u.Scheme + "://" + strings.ToLower(u.Host)
	return nil
}

func (c *Config) isPublicName(host string) bool {
	if c.PublicTLS == nil {
		return false
	}
	h := normHost(host)
	for _, n := range c.PublicTLS.Names {
		if n == h {
			return true
		}
	}
	return false
}

// publicCert holds the public certificate and reloads it when its files
// change. A missing, unreadable, expired or not-yet-valid certificate is
// never served: those handshakes get the internal certificate instead.
type publicCert struct {
	certFile, keyFile string
	log               *slog.Logger
	now               func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate // last good pair; nil = none
	leaf    *x509.Certificate
	err     error     // last load / validity problem ("" when fine)
	certMod time.Time // mtimes of the loaded files (zero after a failed load: retry)
	keyMod  time.Time
	checked time.Time // last mtime check
	logged  time.Time // last ERROR logged about an unusable certificate
}

func newPublicCert(p *PublicTLSConfig, log *slog.Logger) *publicCert {
	pc := &publicCert{certFile: p.CertFile, keyFile: p.KeyFile, log: log, now: time.Now}
	pc.mu.Lock()
	pc.reloadLocked()
	pc.mu.Unlock()
	return pc
}

// reloadLocked loads the pair if the files changed since the last good load.
// A failed load keeps the previous good certificate (still checked for
// expiry on use) and is retried on the next check.
func (p *publicCert) reloadLocked() {
	p.checked = p.now()
	cs, err1 := os.Stat(p.certFile)
	ks, err2 := os.Stat(p.keyFile)
	if err := errors.Join(err1, err2); err != nil {
		p.fail(fmt.Errorf("public certificate files: %w", err))
		return
	}
	if p.cert != nil && cs.ModTime().Equal(p.certMod) && ks.ModTime().Equal(p.keyMod) {
		return
	}
	pair, err := tls.LoadX509KeyPair(p.certFile, p.keyFile)
	if err != nil {
		p.fail(fmt.Errorf("public certificate %s / %s: %w", p.certFile, p.keyFile, err))
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		p.fail(fmt.Errorf("public certificate %s: %w", p.certFile, err))
		return
	}
	pair.Leaf = leaf
	reloaded := p.cert != nil
	p.cert, p.leaf, p.err = &pair, leaf, nil
	p.certMod, p.keyMod = cs.ModTime(), ks.ModTime()
	p.log.Info("public console certificate loaded", "file", p.certFile, "names", strings.Join(leaf.DNSNames, ","),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339), "reloaded", reloaded)
}

func (p *publicCert) fail(err error) {
	p.err = err
	p.certMod, p.keyMod = time.Time{}, time.Time{}
	p.logUnusable(err)
}

func (p *publicCert) logUnusable(err error) {
	now := p.now()
	if !p.logged.IsZero() && now.Sub(p.logged) < publicCertRecheck {
		return
	}
	p.logged = now
	fallback := "browsers get the internal certificate until it is fixed"
	if p.cert != nil && p.usableLocked(now) == nil {
		fallback = "the previously loaded certificate stays in use"
	}
	p.log.Error("public console certificate unusable; "+fallback+" (agents are not affected)", "err", err)
}

// usableLocked: why the loaded certificate cannot be served now (nil = ok).
func (p *publicCert) usableLocked(now time.Time) error {
	switch {
	case p.cert == nil:
		if p.err != nil {
			return p.err
		}
		return errors.New("no public certificate loaded")
	case now.After(p.leaf.NotAfter):
		return fmt.Errorf("public certificate %s expired %s", p.certFile, p.leaf.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(p.leaf.NotBefore):
		return fmt.Errorf("public certificate %s is not valid before %s", p.certFile, p.leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

func (p *publicCert) maybeReloadLocked(force bool) {
	if force || p.now().Sub(p.checked) >= publicCertRecheck {
		p.reloadLocked()
	}
}

// get returns the certificate to serve for name, or nil to fall back to the
// internal certificate.
func (p *publicCert) get(name string) *tls.Certificate {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maybeReloadLocked(false)
	now := p.now()
	if err := p.usableLocked(now); err != nil {
		p.logUnusable(err)
		return nil
	}
	if err := p.leaf.VerifyHostname(name); err != nil {
		p.logUnusable(fmt.Errorf("public certificate %s does not cover %s: %w", p.certFile, name, err))
		return nil
	}
	return p.cert
}

// reload re-reads the files now (SIGHUP).
func (p *publicCert) reload() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certMod, p.keyMod = time.Time{}, time.Time{}
	p.maybeReloadLocked(true)
}

// publicCertStatus is what /api/system reports.
type publicCertStatus struct {
	Names    []string `json:"names"`
	CertFile string   `json:"cert_file"`
	Active   bool     `json:"active"` // served to browsers now
	DNSNames []string `json:"dns_names,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	NotAfter string   `json:"not_after,omitempty"`
	DaysLeft *int     `json:"days_left,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func (p *publicCert) status(names []string) publicCertStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maybeReloadLocked(false)
	now := p.now()
	st := publicCertStatus{Names: names, CertFile: p.certFile}
	if p.leaf != nil {
		st.DNSNames = p.leaf.DNSNames
		st.Issuer = p.leaf.Issuer.CommonName
		st.NotAfter = p.leaf.NotAfter.UTC().Format(time.RFC3339)
		d := int(p.leaf.NotAfter.Sub(now).Hours() / 24)
		st.DaysLeft = &d
	}
	err := p.usableLocked(now)
	if err == nil {
		for _, n := range names {
			if e := p.leaf.VerifyHostname(n); e != nil {
				err = fmt.Errorf("the certificate does not cover %s", n)
				break
			}
		}
	}
	st.Active = err == nil
	switch {
	case err != nil:
		st.Error = err.Error()
	case p.err != nil:
		st.Error = "renewed files not loaded (the previous certificate stays in use): " + p.err.Error()
	}
	return st
}

// ---- server integration ----

// keyTLSConn: the connection's *tls.Conn in the request context (ConnContext).
const keyTLSConn ctxKey = 100

// helloOffersAgent: the client offered the agents' ALPN protocol.
func helloOffersAgent(hello *tls.ClientHelloInfo) bool {
	for _, p := range hello.SupportedProtos {
		if p == pki.AgentALPN {
			return true
		}
	}
	return false
}

// ConfigureHTTPServer installs the TLS configuration and the connection hooks
// that tell handlers which certificate a connection was served.
func (s *Server) ConfigureHTTPServer(srv *http.Server) {
	srv.TLSConfig = s.TLSConfig()
	srv.ConnContext = s.ConnContext
	srv.ConnState = s.ConnState
}

// ConnContext remembers the connection for isPublicPath.
func (s *Server) ConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		return context.WithValue(ctx, keyTLSConn, tc)
	}
	return ctx
}

// ConnState forgets closed connections.
func (s *Server) ConnState(c net.Conn, st http.ConnState) {
	if st != http.StateClosed && st != http.StateHijacked {
		return
	}
	if tc, ok := c.(*tls.Conn); ok {
		s.publicConns.Delete(tc.NetConn())
	}
}

// isPublicPath: this request's connection was served the public certificate
// (a browser on a public name; no client certificate was requested).
func (s *Server) isPublicPath(r *http.Request) bool {
	if s.pub == nil || r.TLS == nil {
		return false
	}
	tc, _ := r.Context().Value(keyTLSConn).(*tls.Conn)
	if tc == nil {
		return false
	}
	_, ok := s.publicConns.Load(tc.NetConn())
	return ok
}

// refusePublicAgent answers the agent API on a public-certificate connection
// with 421 Misdirected Request: no client certificate is asked for there.
// Agents offer ALPN dss-agent/1 (or connect by IP) and get the internal
// certificate on the same name. The one-command bootstrap stays reachable:
// PowerShell cannot offer ALPN, and its pin also accepts a certificate that
// Windows trusts for the name.
func (s *Server) refusePublicAgent(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/agent/") && s.isPublicPath(r) {
			writeErr(w, http.StatusMisdirectedRequest, fmt.Sprintf(
				"the agent API is not served with the public console certificate of %s: agents 0.9.1+ select the agent certificate themselves (ALPN %s); older agents connect to %s",
				normHost(r.TLS.ServerName), pki.AgentALPN, s.agentURL()))
			return
		}
		h.ServeHTTP(w, r)
	})
}

// withPublicTLS adds the certificate selection to the internal TLS configuration.
func (s *Server) withPublicTLS(base *tls.Config) *tls.Config {
	if s.pub == nil {
		return base
	}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		name := normHost(hello.ServerName)
		if helloOffersAgent(hello) || name == "" || !s.cfg.isPublicName(name) {
			return nil, nil // agent path: internal certificate, client certificate requested
		}
		c := s.pub.get(name)
		if c == nil {
			return nil, nil // unusable public certificate: fall back, never fail the handshake
		}
		if hello.Conn != nil {
			s.publicConns.Store(hello.Conn, struct{}{})
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*c},
			ClientAuth:   tls.NoClientCert,
			NextProtos:   []string{"h2", "http/1.1"},
		}, nil
	}
	return base
}

// ReloadPublicCert re-reads the public certificate now (SIGHUP).
func (s *Server) ReloadPublicCert() {
	if s.pub != nil {
		s.pub.reload()
	}
}

// agentURL is the base URL agents enroll against and the console hands out:
// agent_url, else https://<server_name>:<port>, else https://<server IP>:<port>.
func (s *Server) agentURL() string {
	if s.cfg.AgentURL != "" {
		return s.cfg.AgentURL
	}
	scheme := "https"
	if s.cfg.InsecureHTTP {
		scheme = "http"
	}
	_, port, err := net.SplitHostPort(s.cfg.Listen)
	if err != nil {
		port = "8443"
	}
	h := s.cfg.ServerName
	if h == "" {
		h = s.agentIP()
	}
	if h == "" {
		h = "localhost"
	}
	return scheme + "://" + net.JoinHostPort(h, port)
}

// agentIP is the server's address for endpoints' hosts files: agent_ip,
// else the listen address, else the first non-loopback IP of the internal
// server certificate, else of this host ("" when none).
func (s *Server) agentIP() string {
	if s.cfg.AgentIP != "" {
		return s.cfg.AgentIP
	}
	host, _, _ := net.SplitHostPort(s.cfg.Listen)
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
		return ip.String()
	}
	for _, h := range s.certHosts {
		if c := net.ParseIP(h); c != nil && !c.IsLoopback() && !c.IsUnspecified() {
			return c.String()
		}
	}
	if ip := firstHostIP(); ip != nil {
		return ip.String()
	}
	return ""
}

// hostsEntry: the name and IP endpoints put in their hosts file when they
// reach the server by server_name (offline networks without DNS); empty
// unless host is server_name and the IP is known.
func (s *Server) hostsEntry(host string) (name, ip string) {
	if s.cfg.ServerName == "" || normHost(host) != s.cfg.ServerName {
		return "", ""
	}
	if ip = s.agentIP(); ip == "" {
		return "", ""
	}
	return s.cfg.ServerName, ip
}

// firstHostIP: the first global unicast IPv4 address of this machine.
func firstHostIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if v4 := n.IP.To4(); v4 != nil && v4.IsGlobalUnicast() {
				return v4
			}
		}
	}
	return nil
}

// certCovers: host is a DNS name or IP of the internal server certificate.
func (s *Server) certCovers(host string) bool {
	h := strings.Trim(normHost(host), "[]")
	for _, c := range s.certHosts {
		if normHost(c) == h {
			return true
		}
	}
	return false
}

// checkAgentURLCert warns when server_name or the agent URL's host is not
// covered by the internal server certificate (agents would refuse it).
func (s *Server) checkAgentURLCert() {
	if len(s.certHosts) == 0 {
		return
	}
	check := [][2]string{}
	if s.cfg.ServerName != "" {
		check = append(check, [2]string{"server_name", s.cfg.ServerName})
	}
	if u, err := url.Parse(s.agentURL()); err == nil && u.Hostname() != "" {
		check = append(check, [2]string{"agent_url", u.Hostname()})
	}
	for _, c := range check {
		if !s.certCovers(c[1]) {
			s.log.Warn(c[0]+" is not covered by the internal server certificate: agents will refuse it; reissue it with pmserver reissue-server-cert -hosts ...",
				c[0], c[1], "certificate_hosts", strings.Join(s.certHosts, ","))
		}
	}
}

// checkPublicCert raises public_cert_expiring (warning under 14 days,
// critical when expired or unusable) and resolves it once a good
// certificate is loaded.
func (s *Server) checkPublicCert(ctx context.Context) error {
	if s.pub == nil {
		return s.store.ResolveAlert(ctx, alertPublicCert, "", "public_tls is not configured")
	}
	st := s.pub.status(s.cfg.PublicTLS.Names)
	names := strings.Join(st.Names, ", ")
	var sev, msg string
	switch {
	case !st.Active:
		sev = "critical"
		msg = fmt.Sprintf("public console certificate for %s is unusable (%s): browsers get the internal certificate. Check: sudo certbot renew --dry-run; journalctl -u offpatch-server", names, st.Error)
	case st.DaysLeft != nil && time.Duration(*st.DaysLeft)*24*time.Hour < publicCertWarn:
		sev = "warning"
		msg = fmt.Sprintf("public console certificate for %s expires %s (in %d days) and was not renewed. Check: sudo certbot renew --dry-run; systemctl status certbot.timer", names, st.NotAfter[:10], *st.DaysLeft)
	default:
		return s.store.ResolveAlert(ctx, alertPublicCert, "", "the public certificate was renewed")
	}
	// One open alert: a change of severity closes the old one first.
	open, err := s.store.ListAlerts(ctx, true)
	if err != nil {
		return err
	}
	for _, a := range open {
		if a.Kind == alertPublicCert && a.Severity != sev {
			if err := s.store.ResolveAlert(ctx, alertPublicCert, a.ObjectID, "severity changed"); err != nil {
				return err
			}
		}
	}
	return s.store.SetConditionAlert(ctx, sev, alertPublicCert, "server", "console", msg, nil)
}
