package server

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const proxyCfg = `"console_proxy": {"listen": "127.0.0.1:8090", "trusted_proxies": ["127.0.0.1/32", "::1/128"]},`

type preq struct {
	method, path string
	remote       string // default 127.0.0.1:40000 (the trusted proxy)
	proto        string // X-Forwarded-Proto; default https, "-" = none
	xff, realIP  string // xff default 203.0.113.200 (unless realIP), "-" = none
	fwdHost      string
	body         any
	cookie       *http.Cookie
}

func pdo(h http.Handler, q preq) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if q.body != nil {
		b, _ := json.Marshal(q.body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(q.method, q.path, rd)
	r.Host = "patch.example.com"
	r.RemoteAddr = "127.0.0.1:40000"
	if q.remote != "" {
		r.RemoteAddr = q.remote
	}
	switch q.proto {
	case "":
		r.Header.Set("X-Forwarded-Proto", "https")
	case "-":
	default:
		r.Header.Set("X-Forwarded-Proto", q.proto)
	}
	switch {
	case q.xff == "-": // no X-Forwarded-For
	case q.xff != "":
		r.Header.Set("X-Forwarded-For", q.xff)
	case q.realIP == "":
		r.Header.Set("X-Forwarded-For", "203.0.113.200") // a browser behind the proxy
	}
	if q.realIP != "" {
		r.Header.Set("X-Real-IP", q.realIP)
	}
	if q.fwdHost != "" {
		r.Header.Set("X-Forwarded-Host", q.fwdHost)
	}
	if q.cookie != nil {
		r.AddCookie(q.cookie)
	}
	if q.method != "GET" && q.method != "HEAD" {
		r.Header.Set(csrfHeader, "1")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestConsoleProxyRefusesAgentRoutes(t *testing.T) {
	s := newRolesServer(t, proxyCfg, true)
	h := s.ConsoleProxyHandler()
	for _, c := range []struct {
		method, path string
		code         int
	}{
		{"POST", "/api/agent/enroll", 421},
		{"POST", "/api/agent/checkin", 421},
		{"GET", "/api/agent/content/abc", 421},
		{"POST", "/api//agent/checkin", 421},
		{"GET", "/api/agent-setup/bootstrap/windows.ps1", 421},
		{"GET", "/api/agent-setup/bootstrap/files/pmagent.exe", 421},
		{"GET", "/metrics", 404},
	} {
		w := pdo(h, preq{method: c.method, path: c.path, xff: "203.0.113.7"})
		if w.Code != c.code {
			t.Errorf("%s %s: %d %s (want %d)", c.method, c.path, w.Code, w.Body, c.code)
		}
	}
	// The console surface is served (with HSTS: the browser used HTTPS).
	for _, p := range []string{"/", "/endpoints", "/auth/config"} {
		w := pdo(h, preq{method: "GET", path: p})
		if w.Code != 200 || w.Header().Get("Strict-Transport-Security") != hstsValue {
			t.Errorf("GET %s: %d %v", p, w.Code, w.Header())
		}
	}
	if w := pdo(h, preq{method: "GET", path: "/api/me"}); w.Code != 401 {
		t.Errorf("admin API without a session: %d", w.Code)
	}
	// The main listener still serves agents (enrollment answers, not 421).
	if w := enrollReq(s.Handler(), "192.0.2.9:1000", []byte(`{}`)); w.Code == 421 || w.Code == 404 {
		t.Errorf("main listener enroll: %d", w.Code)
	}
	// Only the trusted proxy may connect.
	if w := pdo(h, preq{method: "GET", path: "/", remote: "10.0.0.9:5000"}); w.Code != 403 {
		t.Errorf("untrusted peer: %d", w.Code)
	}
	if w := pdo(h, preq{method: "GET", path: "/", remote: "[::1]:5000"}); w.Code != 200 {
		t.Errorf("trusted ::1 peer: %d", w.Code)
	}
}

func TestConsoleProxyPlainHTTP(t *testing.T) {
	s := newRolesServer(t, proxyCfg+`"server_name": "patch.dataspacesecurity.com",`, true)
	mkLocal(t, s, "uma@bank.example", "user", false)
	h := s.ConsoleProxyHandler()
	login := map[string]string{"email": "uma@bank.example", "password": testPW}
	for _, proto := range []string{"-", "http"} {
		w := pdo(h, preq{method: "POST", path: "/api/auth/login", proto: proto, body: login, fwdHost: "evil.example"})
		if w.Code != 403 || !strings.Contains(errBody(w), "HTTPS") || cookieNamed(w, sessionCookie) != nil || cookieNamed(w, mfaCookie) != nil {
			t.Fatalf("sign-in over plain HTTP (proto %q): %d %s", proto, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "evil.example") {
			t.Fatalf("unchecked host echoed: %s", w.Body)
		}
		if w.Header().Get("Strict-Transport-Security") != "" {
			t.Fatalf("HSTS over plain HTTP")
		}
	}
	// Redirects only to server_name / public_tls names (any case, any port).
	for _, c := range []struct{ method, host, loc string }{
		{"GET", "patch.dataspacesecurity.com", "https://patch.dataspacesecurity.com/endpoints?x=1"},
		{"HEAD", "PATCH.DataSpaceSecurity.com", "https://patch.dataspacesecurity.com/endpoints?x=1"},
		{"GET", "patch.dataspacesecurity.com:80", "https://patch.dataspacesecurity.com/endpoints?x=1"},
	} {
		w := pdo(h, preq{method: c.method, path: "/endpoints?x=1", proto: "http", fwdHost: c.host})
		if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != c.loc {
			t.Fatalf("%s %s over plain HTTP: %d %v", c.method, c.host, w.Code, w.Header())
		}
	}
	for _, host := range []string{"evil.example", "evil.example/x\r\n", "patch.dataspacesecurity.com.evil.example", ""} {
		w := pdo(h, preq{method: "GET", path: "/", proto: "http", fwdHost: host}) // "": the Host header patch.example.com
		if w.Code != 400 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "evil") {
			t.Fatalf("redirect to %q: %d %v %s", host, w.Code, w.Header(), w.Body)
		}
	}
	// No names configured: nothing to redirect to.
	s2 := newRolesServer(t, proxyCfg, true)
	if w := pdo(s2.ConsoleProxyHandler(), preq{method: "GET", path: "/", proto: "-"}); w.Code != 400 {
		t.Fatalf("redirect without server_name: %d %v", w.Code, w.Header())
	}
}

// N-3, N-4: the proxy must name the client; the right-most proto counts.
func TestConsoleProxyForwardedHeaders(t *testing.T) {
	s := newRolesServer(t, proxyCfg, true)
	h := s.ConsoleProxyHandler()
	for _, c := range []struct {
		xff, realIP string
		code        int
	}{
		{"-", "", 400},          // neither header
		{"garbage", "", 400},    // not an IP
		{"-", "not-an-ip", 400}, // X-Real-IP not an IP
		{"203.0.113.9", "", 200},
		{"-", "203.0.113.9", 200},
	} {
		if w := pdo(h, preq{method: "GET", path: "/", xff: c.xff, realIP: c.realIP}); w.Code != c.code {
			t.Errorf("xff %q real %q: %d %s (want %d)", c.xff, c.realIP, w.Code, w.Body, c.code)
		}
	}
	for _, c := range []struct {
		proto []string
		https bool
	}{
		{[]string{"https"}, true},
		{[]string{"http, https"}, true}, // the proxy appended https
		{[]string{"https, http"}, false},
		{[]string{"https", "http"}, false},
		{[]string{"HTTPS"}, true},
		{nil, false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		for _, v := range c.proto {
			r.Header.Add("X-Forwarded-Proto", v)
		}
		if got := forwardedHTTPS(r); got != c.https {
			t.Errorf("X-Forwarded-Proto %q: %v", c.proto, got)
		}
	}
}

// N-2: every sign-in step through the proxy shares one limit, so rotating
// X-Forwarded-For (a local process can) does not give unlimited guesses.
func TestConsoleProxyGlobalAuthLimit(t *testing.T) {
	s := newRolesServer(t, proxyCfg, true)
	h := s.ConsoleProxyHandler()
	bad := map[string]string{"email": "nobody@x.example", "password": "x"}
	for i := 0; i < proxyAuthBurst; i++ {
		xff := "198.51.100." + strconv.Itoa(i+1)
		if w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: xff, body: bad}); w.Code != 401 {
			t.Fatalf("attempt %d: %d %s", i, w.Code, w.Body)
		}
	}
	w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "192.0.2.250", body: bad})
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("listener-wide limit: %d %v", w.Code, w.Header())
	}
	if w := pdo(h, preq{method: "POST", path: "/api/auth/mfa", xff: "192.0.2.251", body: map[string]string{"code": "1"}}); w.Code != 429 {
		t.Fatalf("listener-wide limit (mfa): %d", w.Code)
	}
	// Other routes are not affected, nor is the main listener.
	if w := pdo(h, preq{method: "GET", path: "/auth/config"}); w.Code != 200 {
		t.Fatalf("console page: %d", w.Code)
	}
	if w := do(s.Handler(), req{method: "POST", path: "/api/auth/login", body: bad, csrf: true, ip: "192.0.2.252"}); w.Code != 401 {
		t.Fatalf("main listener: %d", w.Code)
	}
}

func TestConsoleProxyCookieSecure(t *testing.T) {
	s := newRolesServer(t, proxyCfg, true)
	mkLocal(t, s, "uma@bank.example", "user", false)
	h := s.ConsoleProxyHandler()
	w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "203.0.113.20", body: map[string]string{"email": "uma@bank.example", "password": testPW}})
	ck := cookieNamed(w, sessionCookie)
	if w.Code != 200 || ck == nil || !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("login behind the proxy: %d %s cookie %+v", w.Code, w.Body, ck)
	}
	if w.Header().Get("Strict-Transport-Security") != hstsValue {
		t.Fatalf("HSTS: %v", w.Header())
	}
	if w := pdo(h, preq{method: "GET", path: "/api/me", cookie: ck}); w.Code != 200 {
		t.Fatalf("me behind the proxy: %d %s", w.Code, w.Body)
	}
	if w := pdo(h, preq{method: "POST", path: "/api/auth/logout", cookie: ck}); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	} else if c := w.Result().Cookies(); len(c) == 0 || !c[0].Secure {
		t.Fatalf("logout cookie not Secure: %+v", c)
	}
	// /api/system names the listener.
	s2 := newRolesServer(t, proxyCfg, false)
	w = do(s2.Handler(), req{method: "GET", path: "/api/system", token: roleTokens["viewer"]})
	var sys map[string]any
	json.Unmarshal(w.Body.Bytes(), &sys)
	cp, _ := sys["console_proxy"].(map[string]any)
	if w.Code != 200 || cp["listen"] != "127.0.0.1:8090" {
		t.Fatalf("system console_proxy: %d %v", w.Code, sys["console_proxy"])
	}
}

func TestConsoleProxyRateLimitByForwardedIP(t *testing.T) {
	s := newRolesServer(t, proxyCfg, true)
	h := s.ConsoleProxyHandler()
	bad := map[string]string{"email": "nobody@x.example", "password": "x"}
	// The client may prepend anything; the proxy appends the real address.
	for i := 0; i < loginBurst; i++ {
		xff := "198.51.100." + string(rune('1'+i%9)) + ", 203.0.113.50"
		if w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: xff, body: bad}); w.Code != 401 {
			t.Fatalf("attempt %d: %d %s", i, w.Code, w.Body)
		}
	}
	if w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "192.0.2.77, 203.0.113.50", body: bad}); w.Code != 429 {
		t.Fatalf("forwarded client over the limit: %d", w.Code)
	}
	// Another browser behind the same proxy has its own bucket.
	if w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "203.0.113.51", body: bad}); w.Code != 401 {
		t.Fatalf("other forwarded client: %d", w.Code)
	}
	if w := pdo(h, preq{method: "POST", path: "/api/auth/login", realIP: "203.0.113.52", body: bad}); w.Code != 401 {
		t.Fatalf("X-Real-IP client: %d", w.Code)
	}

	// The main listener ignores forwarded headers: rotating X-Forwarded-For
	// does not escape the limit of the TCP peer.
	s2 := newRolesServer(t, proxyCfg, true)
	m := s2.Handler()
	try := func(xff string) int {
		b, _ := json.Marshal(bad)
		r := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(b))
		r.RemoteAddr = "192.0.2.200:5000"
		r.Header.Set(csrfHeader, "1")
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Real-IP", xff)
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		if c := cookieNamed(w, sessionCookie); c != nil {
			t.Fatal("unexpected cookie")
		}
		return w.Code
	}
	for i := 0; i < loginBurst; i++ {
		if c := try("203.0.113." + string(rune('1'+i%9))); c != 401 {
			t.Fatalf("main attempt %d: %d", i, c)
		}
	}
	if c := try("203.0.113.99"); c != 429 {
		t.Fatalf("main listener honoured X-Forwarded-For: %d", c)
	}
	// And a request with no proxy context reports the TCP peer, headers or not.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.5:1"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	if clientIP(r) != "192.0.2.5" || secureRequest(r) {
		t.Fatalf("clientIP without proxy: %s", clientIP(r))
	}
}

func TestForwardedClientIP(t *testing.T) {
	cp := &ConsoleProxyConfig{}
	for _, c := range []string{"127.0.0.1/32", "::1/128", "10.0.0.0/24"} {
		_, n, _ := net.ParseCIDR(c)
		cp.nets = append(cp.nets, n)
	}
	for _, c := range []struct{ xff, real, want string }{ // want "" = refused
		{"", "", ""}, // no forwarded address: refused, not the proxy's own
		{"203.0.113.5", "", "203.0.113.5"},
		{"1.1.1.1, 203.0.113.5", "", "203.0.113.5"},
		{"203.0.113.5, 10.0.0.4", "", "203.0.113.5"},          // a second trusted hop is skipped
		{"203.0.113.5:4431", "", "203.0.113.5"},               // port
		{"[2001:db8::7]:443", "", "2001:db8::7"},              // IPv6 with port
		{"garbage, 203.0.113.5", "", "203.0.113.5"},           // right-most untrusted wins
		{"203.0.113.5, garbage", "", ""},                      // the proxy's own entry is not an IP
		{"203.0.113.5, garbage, 10.0.0.4", "", "10.0.0.4"},    // garbage behind a trusted hop: that hop
		{"", "198.51.100.3", "198.51.100.3"},                  // X-Real-IP
		{"", "nonsense", ""},                                  // X-Real-IP not an IP
		{"10.0.0.1, 10.0.0.2", "", "10.0.0.1"},                // all trusted: the left-most
		{"203.0.113.9", "198.51.100.3", "203.0.113.9"},        // X-Forwarded-For first
		{"1.1.1.1,203.0.113.5 , 10.0.0.9", "", "203.0.113.5"}, // spacing
	} {
		r := httptest.NewRequest("GET", "/", nil)
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.real != "" {
			r.Header.Set("X-Real-IP", c.real)
		}
		got, ok := forwardedClientIP(r, cp)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("xff %q real %q: %q %v, want %q", c.xff, c.real, got, ok, c.want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("X-Forwarded-For", "1.1.1.1")
	r.Header.Add("X-Forwarded-For", "203.0.113.8")
	if got, _ := forwardedClientIP(r, cp); got != "203.0.113.8" {
		t.Errorf("repeated header: %s", got)
	}
}

func TestConsoleProxyConfigValidation(t *testing.T) {
	for _, c := range []struct {
		extra, err string
	}{
		{`"console_proxy": {"listen": "0.0.0.0:8090", "trusted_proxies": ["127.0.0.1/32"]},`, "never 0.0.0.0"},
		{`"console_proxy": {"listen": ":8090", "trusted_proxies": ["127.0.0.1/32"]},`, "IP address"},
		{`"console_proxy": {"listen": "[::]:8090", "trusted_proxies": ["127.0.0.1/32"]},`, "never 0.0.0.0"},
		{`"console_proxy": {"listen": "203.0.113.5:8090", "trusted_proxies": ["127.0.0.1/32"]},`, "public address"},
		{`"console_proxy": {"listen": "patch.example.com:8090", "trusted_proxies": ["127.0.0.1/32"]},`, "IP address"},
		{`"console_proxy": {"listen": "127.0.0.1", "trusted_proxies": ["127.0.0.1/32"]},`, "host:port"},
		{`"console_proxy": {"listen": "127.0.0.1:0", "trusted_proxies": ["127.0.0.1/32"]},`, "1-65535"},
		{`"console_proxy": {"listen": "127.0.0.1:8090"},`, "trusted_proxies is required"},
		{`"console_proxy": {"listen": "127.0.0.1:8090", "trusted_proxies": ["127.0.0.1"]},`, "not a CIDR"},
		{`"console_proxy": {"listen": "127.0.0.1:8090", "trusted_proxies": ["0.0.0.0/0"]},`, "every address"},
		{`"listen": "0.0.0.0:8090", "console_proxy": {"listen": "127.0.0.1:8090", "trusted_proxies": ["127.0.0.1/32"]},`, "same port"},
	} {
		_, err := LoadConfig(writeConfig(t, t.TempDir(), c.extra))
		if err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v (want %q)", c.extra, err, c.err)
		}
	}
	for _, extra := range []string{
		proxyCfg,
		`"console_proxy": {"listen": "10.0.0.5:8090", "trusted_proxies": ["10.0.0.0/24"]},`,
		`"console_proxy": {"listen": "[::1]:8090", "trusted_proxies": ["::1/128"]},`,
		`"console_proxy": {"listen": "localhost:8090", "trusted_proxies": ["127.0.0.1/32"]},`,
	} {
		c, err := LoadConfig(writeConfig(t, t.TempDir(), extra))
		if err != nil || c.ConsoleProxy == nil || len(c.ConsoleProxy.nets) == 0 {
			t.Errorf("%s: %v", extra, err)
		}
	}
	c, err := LoadConfig(writeConfig(t, t.TempDir(), ""))
	if err != nil || c.ConsoleProxy != nil {
		t.Fatalf("no console_proxy: %v", err)
	}
}
