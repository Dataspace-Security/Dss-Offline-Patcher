package acquire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestHostList(t *testing.T) {
	h, err := ParseHostList([]string{"default", "Mirror.Bank.Example.", "*.cdn.example.com", "10.1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"raw.githubusercontent.com":            true,
		"catalog.s.download.windowsupdate.com": true,
		"download.windowsupdate.com":           true,
		"mirror.bank.example":                  true,
		"MIRROR.bank.example.":                 true,
		"a.cdn.example.com":                    true,
		"a.b.cdn.example.com":                  true,
		"cdn.example.com":                      false, // a wildcard does not match its apex
		"evilcdn.example.com":                  false,
		"cdn.example.com.evil.net":             false,
		"10.1.2.3":                             true,
		"10.1.2.4":                             false,
		"githubusercontent.com":                false,
		"":                                     false,
	} {
		if got := h.Allows(host); got != want {
			t.Errorf("Allows(%q) = %v, want %v", host, got, want)
		}
	}
	for _, bad := range []string{"*", "*.com", "https://x.example", "a/b", "*.10.0.0.1", "us er@x"} {
		if _, err := ParseHostList([]string{bad}); err == nil {
			t.Errorf("ParseHostList(%q) accepted", bad)
		}
	}
}

func TestBlockedIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "10.0.0.5": true, "172.16.3.4": true, "192.168.88.129": true, "169.254.169.254": true,
		"100.64.1.1": true, "0.0.0.0": true, "224.0.0.1": true, "::1": true, "fe80::1": true, "fd00::1": true,
		"::ffff:127.0.0.1": true, "::ffff:10.0.0.1": true,
		"20.190.128.10": false, "8.8.8.8": false, "2606:4700::1111": false,
	} {
		if got := BlockedIP(netip.MustParseAddr(ip)); got != want {
			t.Errorf("BlockedIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestGuardCheckURL(t *testing.T) {
	g := &Guard{Hosts: MustHostList("default", "10.0.0.7", "mirror.example"), PrivateOK: map[string]bool{"10.0.0.7": true}}
	for raw, ok := range map[string]bool{
		"https://raw.githubusercontent.com/microsoft/winget-pkgs": true,
		"https://mirror.example/x":                                true,
		"http://mirror.example/x":                                 false, // not https
		"https://evil.example/x":                                  false, // not on the list
		"https://10.0.0.7/x":                                      true,  // listed and allowed private
		"https://127.0.0.1/x":                                     false,
		"https://[::1]/x":                                         false,
		"https://169.254.169.254/latest":                          false,
	} {
		err := g.CheckRawURL(raw)
		if (err == nil) != ok {
			t.Errorf("%s: err %v, want ok=%v", raw, err, ok)
		}
		if err != nil && !errors.Is(err, ErrNetworkRefused) {
			t.Errorf("%s: %v is not ErrNetworkRefused", raw, err)
		}
	}
	// Without an allowlist only the SSRF rule applies.
	open := &Guard{}
	if err := open.CheckRawURL("https://vendor.example/a.exe"); err != nil {
		t.Error(err)
	}
	for _, raw := range []string{"https://10.1.1.1/a", "https://localhost/a", "https://192.168.1.1:8443/a"} {
		if err := open.CheckRawURL(raw); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host " + host)
}

// The dial-time check: a public-looking name that resolves to loopback is
// refused before anything is sent; the operator's private hosts connect.
func TestGuardClientDialTime(t *testing.T) {
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	res := fakeResolver{"rebind.example": {netip.MustParseAddr("127.0.0.1")}}

	g := &Guard{Resolver: res}
	_, err := g.Client(srv.Client()).Get("https://rebind.example:" + u.Port() + "/")
	if err == nil || !errors.Is(err, ErrNetworkRefused) || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("name resolving to loopback: %v", err)
	}
	if _, err := g.Client(srv.Client()).Get(srv.URL); err == nil || !errors.Is(err, ErrNetworkRefused) {
		t.Fatalf("loopback literal: %v", err)
	}
	if hits != 0 {
		t.Fatalf("%d requests reached the server", hits)
	}
	ok := &Guard{PrivateOK: map[string]bool{"127.0.0.1": true}}
	resp, err := ok.Client(srv.Client()).Get(srv.URL)
	if err != nil {
		t.Fatalf("allowed private host: %v", err)
	}
	resp.Body.Close()
	if hits != 1 {
		t.Fatalf("hits %d", hits)
	}
}

// Redirect hops are checked like the first request: a listed source
// cannot bounce pmctl to a host that is not listed.
func TestGuardRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, strings.Replace("https://"+r.Host+"/next", "127.0.0.1", "localhost", 1), http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	g := &Guard{Hosts: MustHostList("127.0.0.1"), PrivateOK: map[string]bool{"127.0.0.1": true, "localhost": true}}
	_, err := g.Client(srv.Client()).Get(srv.URL + "/start")
	if err == nil || !strings.Contains(err.Error(), "host localhost is not in") {
		t.Fatalf("redirect to an unlisted host: %v", err)
	}
	resp, err := g.Client(srv.Client()).Get(srv.URL + "/next")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
