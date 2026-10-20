package main

// Where pmctl auto may connect (findings H-6 / L-20).
//
//   - Every request (and redirect hop) goes through an SSRF guard: https
//     only, never to loopback, private, link-local or other non-public
//     addresses (IP literals refused up front, host names checked at dial
//     time). Hosts named in acquire.json's own URLs and in
//     allowed_private_hosts may resolve to private addresses.
//   - Download sources set by the auto-download policy (winget index and
//     manifests, Microsoft Catalog, MSRC, internal mirrors, vendor-url) must
//     also be on acquire.json's allowed_source_hosts (default: the official
//     hosts pmctl uses, acquire.DefaultSourceHosts). That list is local to
//     the acquisition host: the policy cannot extend it. A source outside it
//     is refused and reported; requests to an accepted policy source,
//     including redirects and the download links a mirrored catalog page
//     returns, are held to the list too.
//   - vendor-url sources (and their redirects) never go to shared hosting
//     where anyone can publish a file (acquire.SharedHostingHosts:
//     raw.githubusercontent.com), even though the winget feed uses it
//     (finding S-4).
//   - Installer URLs read from winget manifests point at each vendor's own
//     host, so they are not held to the list: they get the SSRF guard, the
//     manifest SHA-256 and, for EXE (and MSI on Windows hosts), the
//     Authenticode signer pin (signerpin.go).

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/acquire"
)

type netPolicy struct {
	base   *acquire.Guard // SSRF + https
	strict *acquire.Guard // base + allowed_source_hosts
	// vendor: strict, minus shared hosting (acquire.SharedHostingHosts):
	// vendor-url downloads and their redirects (S-4).
	vendor *acquire.Guard
	// fromPolicy: upstreams (acqpolicy.Upstream*, or "vendor-url") whose
	// address the auto-download policy set this run.
	fromPolicy map[string]bool
}

// setupNet builds c.net from acquire.json; call before applyPolicy changes
// any URL in c.
func setupNet(c *autoConfig) error {
	hosts := c.AllowedSourceHosts
	if len(hosts) == 0 {
		hosts = []string{"default"}
	}
	hl, err := acquire.ParseHostList(hosts)
	if err != nil {
		return fmt.Errorf("config: allowed_source_hosts: %w", err)
	}
	priv := map[string]bool{}
	for _, h := range c.AllowedPrivateHosts {
		h = normHostName(h)
		if h == "" || strings.ContainsAny(h, "/*@ ") {
			return fmt.Errorf("config: allowed_private_hosts: %q is not a host name", h)
		}
		priv[h] = true
	}
	for _, raw := range c.ownURLs() {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			priv[normHostName(u.Hostname())] = true
		}
	}
	c.net = &netPolicy{
		base:       &acquire.Guard{PrivateOK: priv},
		strict:     &acquire.Guard{Hosts: hl, HostsWhat: "allowed_source_hosts (acquire.json)", PrivateOK: priv},
		vendor:     vendorGuard(hl, priv),
		fromPolicy: map[string]bool{},
	}
	return nil
}

func vendorGuard(hl acquire.HostList, priv map[string]bool) *acquire.Guard {
	return &acquire.Guard{Hosts: hl, HostsWhat: "allowed_source_hosts (acquire.json)", PrivateOK: priv,
		Deny: acquire.MustHostList(acquire.SharedHostingHosts...), DenyWhy: "hosts files anyone can publish: it is never a vendor-url download source"}
}

func normHostName(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"), ".")
}

// ownURLs: the addresses acquire.json itself configures (trusted: the file
// is written by the installer and owned by root).
func (c *autoConfig) ownURLs() []string {
	out := []string{c.CatalogURL, c.MSRCURL, c.WingetManifestsURL}
	if c.Intel != nil {
		out = append(out, c.Intel.WingetURL)
	}
	for _, a := range c.Apps {
		out = append(out, a.Version.URL, a.DownloadURL)
		if a.SHA256 != nil {
			out = append(out, a.SHA256.URL)
		}
	}
	return out
}

// netFor returns c.net, setting it up with acquire.json defaults if needed
// (unit tests build autoConfig by hand).
func (c *autoConfig) netFor() *netPolicy {
	if c.net == nil {
		if err := setupNet(c); err != nil {
			hl := acquire.MustHostList("default")
			c.net = &netPolicy{base: &acquire.Guard{}, strict: &acquire.Guard{Hosts: hl}, vendor: vendorGuard(hl, nil), fromPolicy: map[string]bool{}}
		}
	}
	return c.net
}

// checkPolicyURL: nil if the policy may use raw as a download source.
func (c *autoConfig) checkPolicyURL(raw string) error {
	return c.netFor().strict.CheckRawURL(raw)
}

// checkVendorURL: nil if the policy may use raw as a vendor-url source
// (allowed_source_hosts, and never shared hosting such as
// raw.githubusercontent.com).
func (c *autoConfig) checkVendorURL(raw string) error {
	return c.netFor().vendor.CheckRawURL(raw)
}

// guarded wraps hc in the SSRF guard.
func (c *autoConfig) guarded(hc *http.Client) *http.Client {
	return c.netFor().base.Client(hc)
}

// sourceClient: hc, held to allowed_source_hosts when the policy set the
// address of upstream.
func (c *autoConfig) sourceClient(hc *http.Client, upstream string) *http.Client {
	n := c.netFor()
	if n.fromPolicy[upstream] {
		return n.strict.Client(hc)
	}
	return hc
}

// msClient: the client for the Microsoft Catalog and MSRC (one run uses
// both, and the catalog's download links).
func (c *autoConfig) msClient(hc *http.Client) *http.Client {
	n := c.netFor()
	if n.fromPolicy[acqpolicy.UpstreamCatalog] || n.fromPolicy[acqpolicy.UpstreamMSRC] {
		return n.strict.Client(hc)
	}
	return hc
}

const upstreamVendorURL = "vendor-url"
