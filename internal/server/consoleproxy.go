package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// Console behind a reverse proxy (docs/07-admin-guide.md "Console behind a
// reverse proxy"). On a shared host another process (Temps, nginx, a load
// balancer) owns 443, terminates TLS for the console's public name and
// forwards to pmserver over plain HTTP on loopback / a private address.
// console_proxy adds a second, plain-HTTP listener for exactly that:
//
//   - it serves only the browser surface (console, /api/* admin routes,
//     /auth/*, /api/auth/*); the agent API, the enrollment bootstrap and
//     /metrics are refused there. Agents keep connecting to the main
//     listener directly (TLS + mTLS); it is unchanged.
//   - it accepts connections only from trusted_proxies, and only from them
//     honours X-Forwarded-For / X-Real-IP (client IP for rate limits and
//     logs) and X-Forwarded-Proto. The main listener never reads those
//     headers (no spoofing).
//   - it serves nothing over plain HTTP: X-Forwarded-Proto must be "https"
//     (GET/HEAD are redirected to https://, everything else gets 403), so
//     credentials and cookies never travel unencrypted, and session cookies
//     keep Secure.

// ConsoleProxyConfig: the reverse-proxy listener (config key console_proxy).
type ConsoleProxyConfig struct {
	// Listen: host:port on a loopback or private address (never 0.0.0.0 or a
	// public address: it is plain HTTP). Example "127.0.0.1:8090".
	Listen string `json:"listen"`
	// TrustedProxies: CIDRs of the reverse proxy; only they may connect, and
	// only their X-Forwarded-* headers are believed. Example
	// ["127.0.0.1/32", "::1/128"].
	TrustedProxies []string `json:"trusted_proxies"`

	nets []*net.IPNet
}

// hstsValue: sent on the proxy listener (the browser saw HTTPS).
const hstsValue = "max-age=31536000"

func (c *Config) normalizeConsoleProxy() error {
	p := c.ConsoleProxy
	if p == nil {
		return nil
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(p.Listen))
	if err != nil {
		return fmt.Errorf("config: console_proxy.listen must be host:port such as 127.0.0.1:8090 (got %q)", p.Listen)
	}
	ip := net.ParseIP(host)
	if host == "localhost" {
		ip = net.IPv4(127, 0, 0, 1)
		host = ip.String()
	}
	if ip == nil {
		return fmt.Errorf("config: console_proxy.listen must use an IP address (loopback such as 127.0.0.1, or a private address), not %q", host)
	}
	if ip.IsUnspecified() || !(ip.IsLoopback() || ip.IsPrivate()) {
		return fmt.Errorf("config: console_proxy.listen %q is not allowed: this listener is plain HTTP for a reverse proxy on this host or a private network; use 127.0.0.1:<port> (or a private address), never 0.0.0.0 or a public address", p.Listen)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("config: console_proxy.listen port must be 1-65535 (got %q)", port)
	}
	p.Listen = net.JoinHostPort(host, port)
	if mh, mp, err := net.SplitHostPort(c.Listen); err == nil && mp == port {
		if mip := net.ParseIP(mh); mh == "" || mh == host || (mip != nil && mip.IsUnspecified()) {
			return fmt.Errorf("config: console_proxy.listen %s uses the same port as listen %s; pick another port (e.g. 8090)", p.Listen, c.Listen)
		}
	}
	if len(p.TrustedProxies) == 0 {
		return fmt.Errorf("config: console_proxy.trusted_proxies is required: the CIDRs the reverse proxy connects from, e.g. [\"127.0.0.1/32\", \"::1/128\"]")
	}
	p.nets = nil
	for _, s := range p.TrustedProxies {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("config: console_proxy.trusted_proxies: %q is not a CIDR (write 127.0.0.1/32, ::1/128, 10.0.0.0/24)", s)
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			return fmt.Errorf("config: console_proxy.trusted_proxies: %q trusts every address; list only the reverse proxy's addresses", s)
		}
		p.nets = append(p.nets, n)
	}
	return nil
}

// trusted: ip is one of the reverse proxy's addresses.
func (p *ConsoleProxyConfig) trusted(ip net.IP) bool {
	if p == nil || ip == nil {
		return false
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// proxied: a request that arrived through the reverse proxy (context value,
// set only by ConsoleProxyHandler).
type proxied struct {
	ClientIP string // the browser's address per X-Forwarded-For / X-Real-IP
	HTTPS    bool   // X-Forwarded-Proto: https
}

const keyProxied ctxKey = 101

func proxiedInfo(r *http.Request) *proxied {
	p, _ := r.Context().Value(keyProxied).(*proxied)
	return p
}

// secureRequest: the browser reached the console over HTTPS (directly, or
// through the reverse proxy). Decides the cookies' Secure flag.
func secureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	p := proxiedInfo(r)
	return p != nil && p.HTTPS
}

// parseHop reads one X-Forwarded-For entry ("1.2.3.4", "1.2.3.4:5678",
// "[2001:db8::1]:443", "2001:db8::1").
func parseHop(s string) net.IP {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(h)
	}
	return net.ParseIP(strings.Trim(s, "[]"))
}

func peerIP(remoteAddr string) net.IP {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return net.ParseIP(h)
	}
	return net.ParseIP(remoteAddr)
}

// forwardedClientIP: the right-most address in X-Forwarded-For that is not a
// trusted proxy (entries further left could be written by the client). With
// no X-Forwarded-For, X-Real-IP; with neither, the proxy's own address.
func forwardedClientIP(r *http.Request, cp *ConsoleProxyConfig, peer net.IP) string {
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		ip := parseHop(hops[i])
		if ip == nil {
			break // garbage: keep the last address a trusted hop vouched for
		}
		client = ip
		if !cp.trusted(ip) {
			break
		}
	}
	if len(hops) == 0 {
		if ip := parseHop(r.Header.Get("X-Real-IP")); ip != nil {
			client = ip
		}
	}
	return client.String()
}

// forwardedHTTPS: the reverse proxy says the browser used HTTPS. With a
// chain of proxies the first value is the browser's.
func forwardedHTTPS(r *http.Request) bool {
	v := r.Header.Get("X-Forwarded-Proto")
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.EqualFold(strings.TrimSpace(v), "https")
}

// forwardedHost: the name the browser used (X-Forwarded-Host, else Host).
func forwardedHost(r *http.Request) string {
	h := r.Header.Get("X-Forwarded-Host")
	if i := strings.IndexByte(h, ','); i >= 0 {
		h = h[:i]
	}
	if h = strings.TrimSpace(h); h == "" {
		h = r.Host
	}
	return h
}

// consoleProxyRefused: what the proxy listener never serves (agents, the
// enrollment bootstrap they download, the metrics scrape).
func consoleProxyRefused(p string) (int, bool) {
	p = path.Clean("/" + p)
	switch {
	case p == "/api/agent" || strings.HasPrefix(p, "/api/agent/"),
		p == "/api/agent-setup/bootstrap" || strings.HasPrefix(p, "/api/agent-setup/bootstrap/"):
		return http.StatusMisdirectedRequest, true
	case p == "/metrics" || strings.HasPrefix(p, "/metrics/"):
		return http.StatusNotFound, true
	}
	return 0, false
}

// ConsoleProxyHandler serves the console_proxy listener (plain HTTP behind
// the reverse proxy). See the comment at the top of this file.
func (s *Server) ConsoleProxyHandler() http.Handler {
	inner := s.Handler()
	cp := s.cfg.ConsoleProxy
	return securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := peerIP(r.RemoteAddr)
		if !cp.trusted(peer) {
			s.log.Warn("console proxy listener: connection from an address outside console_proxy.trusted_proxies refused", "remote", r.RemoteAddr)
			writeErr(w, http.StatusForbidden, "this listener only serves the reverse proxy listed in console_proxy.trusted_proxies")
			return
		}
		if code, refused := consoleProxyRefused(r.URL.Path); refused {
			msg := "not served through the console reverse proxy"
			if code == http.StatusMisdirectedRequest {
				msg = fmt.Sprintf("the agent API is not served through the console reverse proxy: agents connect to %s directly (mutual TLS)", s.agentURL())
			}
			writeErr(w, code, msg)
			return
		}
		info := &proxied{ClientIP: forwardedClientIP(r, cp, peer), HTTPS: forwardedHTTPS(r)}
		if !info.HTTPS {
			s.refusePlainHTTP(w, r, info.ClientIP)
			return
		}
		w.Header().Set("Strict-Transport-Security", hstsValue)
		inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyProxied, info)))
	}))
}

// refusePlainHTTP: the browser reached the reverse proxy over plain HTTP
// (X-Forwarded-Proto http or missing). GET/HEAD go to the same URL on
// https://; anything else (a sign-in, a change) is refused so no password or
// cookie is ever accepted over plain HTTP.
func (s *Server) refusePlainHTTP(w http.ResponseWriter, r *http.Request, client string) {
	host := forwardedHost(r)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.log.Warn("console proxy: request over plain HTTP refused", "ip", client, "method", r.Method, "path", r.URL.Path)
		writeErr(w, http.StatusForbidden, "the console only accepts HTTPS: open https://"+host+" (the reverse proxy did not send X-Forwarded-Proto: https; never sign in over plain HTTP)")
		return
	}
	if !hostRe.MatchString(host) {
		writeErr(w, http.StatusBadRequest, "invalid Host header")
		return
	}
	target := "https://" + host + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

// consoleProxyStatus: for /api/system (nil when not configured).
func (c *Config) consoleProxyStatus() map[string]any {
	if c.ConsoleProxy == nil {
		return nil
	}
	return map[string]any{"listen": c.ConsoleProxy.Listen, "trusted_proxies": c.ConsoleProxy.TrustedProxies}
}
