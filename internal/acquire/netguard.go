package acquire

// Network guard for the acquisition host (findings H-6 / L-20).
//
// Two independent checks, both applied to every request and every redirect
// hop (a redirect is a new RoundTrip):
//
//   - SSRF: the destination must not be a loopback, private, link-local,
//     CGNAT, multicast or otherwise non-public address. IP literals are
//     refused before anything is sent; host names are resolved at dial time
//     and the connection is made to the checked address (no second lookup
//     that DNS rebinding could change). Hosts the operator lists in
//     acquire.json (PrivateOK) may resolve to private addresses (an internal
//     mirror).
//   - Host allowlist (optional): only hosts on the list may be contacted.
//     pmctl applies it to the download sources an auto-download policy sets
//     (winget index / manifests, Microsoft Catalog, MSRC, vendor-url), so a
//     policy can never point pmctl at a host acquire.json does not allow.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultSourceHosts are the official hosts pmctl downloads from with its
// built-in addresses: the winget community index and the winget-pkgs
// manifests, the Microsoft Update Catalog (search pages and the content
// hosts its download links point at) and the MSRC API.
var DefaultSourceHosts = []string{
	"cdn.winget.microsoft.com",
	"raw.githubusercontent.com",
	"www.catalog.update.microsoft.com",
	"catalog.update.microsoft.com",
	"api.msrc.microsoft.com",
	"download.windowsupdate.com",
	"*.download.windowsupdate.com",
	"*.delivery.mp.microsoft.com",
	"download.microsoft.com",
}

// SharedHostingHosts serve files anyone can publish (a GitHub account is
// enough). They stay allowed for the winget index / manifests feed, whose
// content is checked against the manifest hashes, but are never a
// vendor-url download source or redirect target (finding S-4).
var SharedHostingHosts = []string{
	"raw.githubusercontent.com",
	"gist.githubusercontent.com",
}

// ErrNetworkRefused marks a request the guard did not send.
var ErrNetworkRefused = errors.New("refused by the acquisition network policy")

// HostList is an allowlist of exact host names and "*.suffix" entries
// ("*.example.com" matches a.example.com and a.b.example.com, not
// example.com itself).
type HostList struct {
	exact    map[string]bool
	suffixes []string // ".example.com"
}

// ParseHostList validates entries (host names or IP literals, optionally
// "*." wildcards); the token "default" stands for DefaultSourceHosts.
func ParseHostList(entries []string) (HostList, error) {
	h := HostList{exact: map[string]bool{}}
	for _, raw := range entries {
		e := normHost(raw)
		if e == "default" {
			for _, d := range DefaultSourceHosts {
				h.add(d)
			}
			continue
		}
		name := strings.TrimPrefix(e, "*.")
		if name == "" || strings.ContainsAny(name, "*/:@ ") && !isIPLiteral(name) || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
			return HostList{}, fmt.Errorf("%q is not a host name, IP address or *.domain entry", raw)
		}
		if strings.HasPrefix(e, "*.") && (isIPLiteral(name) || !strings.Contains(name, ".")) {
			return HostList{}, fmt.Errorf("%q: a wildcard needs a domain with at least two labels, like *.example.com", raw)
		}
		h.add(e)
	}
	return h, nil
}

// MustHostList is ParseHostList for built-in lists.
func MustHostList(entries ...string) HostList {
	h, err := ParseHostList(entries)
	if err != nil {
		panic(err)
	}
	return h
}

func (h *HostList) add(e string) {
	e = normHost(e)
	if s, ok := strings.CutPrefix(e, "*"); ok {
		h.suffixes = append(h.suffixes, s)
		return
	}
	h.exact[e] = true
}

// Empty reports whether the list has no entries.
func (h HostList) Empty() bool { return len(h.exact) == 0 && len(h.suffixes) == 0 }

// Allows reports whether host (a URL host name, without port) is listed.
func (h HostList) Allows(host string) bool {
	host = normHost(host)
	if host == "" {
		return false
	}
	if h.exact[host] {
		return true
	}
	if isIPLiteral(host) {
		return false // wildcards never match addresses
	}
	for _, s := range h.suffixes {
		if strings.HasSuffix(host, s) && len(host) > len(s) {
			return true
		}
	}
	return false
}

// String lists the entries (for messages).
func (h HostList) String() string {
	var out []string
	for e := range h.exact {
		out = append(out, e)
	}
	for _, s := range h.suffixes {
		out = append(out, "*"+s)
	}
	return strings.Join(out, ", ")
}

func normHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
}

func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// BlockedIP reports whether ip is not a public unicast address: loopback,
// private (RFC 1918, fc00::/7), link-local (169.254/16 incl. cloud metadata,
// fe80::/10), unspecified, multicast, CGNAT and reserved ranges.
func BlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Guard checks outgoing requests. The zero value enforces only the SSRF rule
// and https.
type Guard struct {
	// Hosts, if not empty, is the only hosts requests may go to.
	Hosts HostList
	// HostsWhat names the list in messages (e.g. "allowed_source_hosts").
	HostsWhat string
	// Deny: hosts never contacted, even when Hosts lists them; DenyWhy
	// says why in messages.
	Deny    HostList
	DenyWhy string
	// PrivateOK: exact host names (or IP literals) that may resolve to
	// non-public addresses.
	PrivateOK map[string]bool
	// AllowHTTP permits plain http (CRL downloads only).
	AllowHTTP bool
	// Resolver: nil = net.DefaultResolver.
	Resolver interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
}

func (g *Guard) privateOK(host string) bool { return g.PrivateOK[normHost(host)] }

// CheckURL checks scheme, host allowlist and IP literals of u (no DNS).
func (g *Guard) CheckURL(u *url.URL) error {
	if u == nil || u.Hostname() == "" {
		return fmt.Errorf("%w: URL has no host", ErrNetworkRefused)
	}
	if u.Scheme != "https" && !(g.AllowHTTP && u.Scheme == "http") {
		return fmt.Errorf("%w: %s is not https", ErrNetworkRefused, u.Redacted())
	}
	host := normHost(u.Hostname())
	if g.Deny.Allows(host) {
		return fmt.Errorf("%w: host %s %s", ErrNetworkRefused, host, g.DenyWhy)
	}
	if !g.Hosts.Empty() && !g.Hosts.Allows(host) {
		what := g.HostsWhat
		if what == "" {
			what = "the allowed hosts"
		}
		return fmt.Errorf("%w: host %s is not in %s", ErrNetworkRefused, host, what)
	}
	if ip, err := netip.ParseAddr(host); err == nil && BlockedIP(ip) && !g.privateOK(host) {
		return fmt.Errorf("%w: %s is a loopback, private or link-local address", ErrNetworkRefused, host)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		if !g.privateOK(host) {
			return fmt.Errorf("%w: %s is a loopback name", ErrNetworkRefused, host)
		}
	}
	return nil
}

// CheckRawURL is CheckURL for a string.
func (g *Guard) CheckRawURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: not a URL", ErrNetworkRefused)
	}
	return g.CheckURL(u)
}

func (g *Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(normHost(host)); err == nil {
		return []netip.Addr{ip}, nil
	}
	var r interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	} = net.DefaultResolver
	if g.Resolver != nil {
		r = g.Resolver
	}
	return r.LookupNetIP(ctx, "ip", host)
}

// checkResolved resolves host and refuses it if any address is non-public.
func (g *Guard) checkResolved(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := g.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s: no addresses", host)
	}
	if g.privateOK(host) {
		return ips, nil
	}
	for _, ip := range ips {
		if BlockedIP(ip) {
			return nil, fmt.Errorf("%w: %s resolves to the non-public address %s", ErrNetworkRefused, host, ip.Unmap())
		}
	}
	return ips, nil
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Client returns a copy of hc (nil = DefaultHTTPClient()) whose requests,
// including every redirect hop, pass the guard. When hc's transport is an
// *http.Transport its dialer is wrapped too, so host names are checked
// after resolution; connections to the configured proxy are not checked
// (the proxy's target is, by name, before the request is sent).
func (g *Guard) Client(hc *http.Client) *http.Client {
	if hc == nil {
		hc = DefaultHTTPClient()
	}
	c := *hc
	rt := c.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	gt := &guardTransport{g: g, rt: rt}
	if t, ok := rt.(*http.Transport); ok {
		t2 := t.Clone()
		proxies := &sync.Map{}
		if orig := t2.Proxy; orig != nil {
			gt.proxy = orig
			t2.Proxy = func(r *http.Request) (*url.URL, error) {
				u, err := orig(r)
				if u != nil {
					proxies.Store(proxyAddr(u), true)
				}
				return u, err
			}
		}
		next := dialFunc(t2.DialContext)
		if next == nil {
			next = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		}
		t2.DialContext = g.dialer(next, proxies)
		gt.rt = t2
	}
	c.Transport = gt
	return &c
}

func proxyAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "socks5": "1080"}[u.Scheme]
		if port == "" {
			port = "80"
		}
	}
	return net.JoinHostPort(normHost(u.Hostname()), port)
}

func (g *Guard) dialer(next dialFunc, proxies *sync.Map) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if _, ok := proxies.Load(net.JoinHostPort(normHost(host), port)); ok {
			return next(ctx, network, addr)
		}
		ips, err := g.checkResolved(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := next(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

type guardTransport struct {
	g     *Guard
	rt    http.RoundTripper
	proxy func(*http.Request) (*url.URL, error)
}

func (t *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.g.CheckURL(req.URL); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	if t.proxy != nil {
		// Through a proxy the dialer only sees the proxy: check the target
		// by name here (best effort; the proxy resolves it again).
		if pu, _ := t.proxy(req); pu != nil {
			if _, err := t.g.checkResolved(req.Context(), req.URL.Hostname()); err != nil {
				if req.Body != nil {
					req.Body.Close()
				}
				return nil, err
			}
		}
	}
	return t.rt.RoundTrip(req)
}
