package server

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// S-10: one client flooding sign-ins through the proxy is stopped by its
// own limit before it costs the shared budget anything, so another client
// still signs in.
func TestConsoleProxyFloodingClientDoesNotBlockOthers(t *testing.T) {
	s := newRolesServer(t, proxyCfg, true)
	mkLocal(t, s, "uma@bank.example", "user", false)
	h := s.ConsoleProxyHandler()
	frozen := time.Now() // no refill while the test runs, however slow
	now := func() time.Time { return frozen }
	s.proxyAuth.shared.now, s.loginLimit.now = now, now
	bad := map[string]string{"email": "nobody@x.example", "password": "x"}
	limited := 0
	for i := 0; i < 5*proxyAuthBurst; i++ {
		w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "198.51.100.66", body: bad})
		if w.Code == 429 {
			limited++
		} else if w.Code != 401 {
			t.Fatalf("flood attempt %d: %d %s", i, w.Code, w.Body)
		}
	}
	if limited != 5*proxyAuthBurst-loginBurst {
		t.Fatalf("flooding client: %d refused, want %d", limited, 5*proxyAuthBurst-loginBurst)
	}
	w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "203.0.113.20", body: map[string]string{"email": "uma@bank.example", "password": testPW}})
	if w.Code != 200 || cookieNamed(w, sessionCookie) == nil {
		t.Fatalf("other client blocked by the flood: %d %s", w.Code, w.Body)
	}
}

// Many (forged) addresses exhaust the shared budget: unknown addresses are
// refused, an address that signed in recently still gets in (reserved
// share), and a sustained flood raises one alert.
func TestConsoleProxyReservedShareAndFloodAlert(t *testing.T) {
	s := newRolesServer(t, proxyCfg, true)
	mkLocal(t, s, "uma@bank.example", "user", false)
	h := s.ConsoleProxyHandler()
	clock := time.Now()
	now := func() time.Time { return clock }
	s.proxyAuth.now, s.proxyAuth.shared.now, s.proxyAuth.reserved.now, s.loginLimit.now = now, now, now, now
	good := map[string]string{"email": "uma@bank.example", "password": testPW}
	bad := map[string]string{"email": "nobody@x.example", "password": "x"}

	if w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "203.0.113.20", body: good}); w.Code != 200 {
		t.Fatalf("first sign-in: %d %s", w.Code, w.Body)
	}
	n := 0
	flood := func(k int) {
		for i := 0; i < k; i++ {
			n++
			pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "10.9." + strconv.Itoa(n/250) + "." + strconv.Itoa(n%250+1), body: bad})
		}
	}
	flood(proxyAuthBurst + 5)
	if w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "192.0.2.10", body: bad}); w.Code != 429 {
		t.Fatalf("unknown address during the flood: %d", w.Code)
	}
	if w := pdo(h, preq{method: "POST", path: "/api/auth/login", xff: "203.0.113.20", body: good}); w.Code != 200 {
		t.Fatalf("recently signed-in address during the flood: %d %s", w.Code, w.Body)
	}
	alerts := func() int {
		as, err := s.store.ListAlerts(context.Background(), true)
		if err != nil {
			t.Fatal(err)
		}
		c := 0
		for _, a := range as {
			if a.Kind == alertSignInFlood {
				c++
			}
		}
		return c
	}
	if alerts() != 0 {
		t.Fatal("alert before the flood was sustained")
	}
	for sec := 0; sec <= int(proxyAlertAfter/time.Second)+1; sec++ {
		clock = clock.Add(time.Second)
		flood(3) // one gets the refilled token, the others are refused
	}
	if c := alerts(); c != 1 {
		t.Fatalf("sustained flood: %d alerts", c)
	}
}
