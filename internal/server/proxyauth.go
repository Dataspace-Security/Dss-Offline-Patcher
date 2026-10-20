package server

import (
	"context"
	"net/http"
	"path"
	"strconv"
	"sync"
	"time"
)

// Sign-in limits on the console_proxy listener (security review S-10).
// Forwarded client addresses can be forged by a local process, so every
// sign-in step through the proxy is also counted against a listener-wide
// budget. The order matters, so that one client cannot lock everyone out:
//
//  1. the per-client limit (loginBurst / loginEvery, the same bucket as on
//     the main listener) is checked first; a client over it is refused and
//     costs the shared budget nothing. A single address therefore can never
//     drain the shared budget (it refills faster than one client may send).
//  2. only then the listener-wide budget (proxyAuthBurst / proxyAuthEvery).
//  3. when that is empty (many addresses at once, e.g. a forged
//     X-Forwarded-For flood), client addresses that signed in successfully
//     through the proxy within proxyKnownFor still get a reserved budget
//     (proxyReservedBurst / proxyReservedEvery) that unknown addresses
//     cannot touch, so the bank's admins keep signing in during a flood.
//  4. refusals by the listener-wide budget that go on for proxyAlertAfter
//     (no pause longer than proxyFloodQuiet) are logged as an error and
//     raise one alert per episode (auth.signin_flood).

const (
	// proxyAuthBurst sign-in steps through the console proxy in total (all
	// clients together), then one more every proxyAuthEvery.
	proxyAuthBurst = 30
	proxyAuthEvery = time.Second
	// proxyReservedBurst / proxyReservedEvery: the budget kept for client
	// addresses with a recent successful sign-in.
	proxyReservedBurst = 10
	proxyReservedEvery = 3 * time.Second
	// proxyKnownFor: how long a successful sign-in makes an address "known".
	proxyKnownFor = 24 * time.Hour
	// proxyAlertAfter: listener-wide refusals this long raise the alert;
	// a pause of proxyFloodQuiet without one ends the episode.
	proxyAlertAfter = time.Minute
	proxyFloodQuiet = 10 * time.Second
	// alertSignInFlood: alert kind for sustained exhaustion.
	alertSignInFlood = "auth.signin_flood"
)

// proxyAuthPaths: the sign-in steps that get the listener-wide limit.
var proxyAuthPaths = map[string]bool{"/api/auth/login": true, "/api/auth/mfa": true, "/api/auth/password": true,
	"/api/auth/mfa/disable": true, "/api/auth/mfa/enroll/confirm": true}

// proxyAuthGate: the listener-wide budget, the reserved budget and the
// addresses that may use it.
type proxyAuthGate struct {
	shared   *ipLimiter
	reserved *ipLimiter

	mu          sync.Mutex
	known       map[string]time.Time // loginKey → last successful sign-in
	floodSince  time.Time            // first refusal of the current episode
	lastRefused time.Time            // latest refusal by the shared budget
	alerted     bool                 // the current episode was reported
	now         func() time.Time
}

func newProxyAuthGate() *proxyAuthGate {
	return &proxyAuthGate{shared: newIPLimiter(proxyAuthBurst, proxyAuthEvery), reserved: newIPLimiter(proxyReservedBurst, proxyReservedEvery),
		known: map[string]time.Time{}, now: time.Now}
}

// markKnown: key (a loginKey) just signed in successfully.
func (g *proxyAuthGate) markKnown(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if _, ok := g.known[key]; !ok && len(g.known) >= maxBuckets {
		for k, at := range g.known {
			if now.Sub(at) >= proxyKnownFor {
				delete(g.known, k)
			}
		}
		if len(g.known) >= maxBuckets {
			return // full of recent sign-ins: this one uses the shared budget only
		}
	}
	g.known[key] = now
}

func (g *proxyAuthGate) isKnown(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	at, ok := g.known[key]
	return ok && g.now().Sub(at) < proxyKnownFor
}

// take charges one sign-in step of key (which already passed its own
// limit). reserved: it was let in on the reserved budget. alert: the shared
// budget has now been refusing for proxyAlertAfter (once per episode).
func (g *proxyAuthGate) take(key string) (ok, reserved, alert bool, wait time.Duration) {
	ok, wait = g.shared.allow("console_proxy")
	if !ok {
		g.mu.Lock()
		now := g.now()
		if g.floodSince.IsZero() || now.Sub(g.lastRefused) > proxyFloodQuiet {
			g.floodSince, g.alerted = now, false
		}
		g.lastRefused = now
		if !g.alerted && now.Sub(g.floodSince) >= proxyAlertAfter {
			g.alerted, alert = true, true
		}
		g.mu.Unlock()
	}
	if ok {
		return true, false, alert, 0
	}
	if g.isKnown(key) {
		if rok, _ := g.reserved.allow("reserved"); rok {
			return true, true, alert, 0
		}
	}
	return false, false, alert, wait
}

// proxyAuthLimited applies the sign-in limits of the proxy listener to a
// sign-in step (429 with Retry-After): per client first, then the
// listener-wide budget (see the top of this file). info.loginCharged tells
// the handler that the per-client bucket was already charged.
func (s *Server) proxyAuthLimited(w http.ResponseWriter, r *http.Request, info *proxied) bool {
	if r.Method != http.MethodPost || !proxyAuthPaths[path.Clean("/"+r.URL.Path)] {
		return false
	}
	key := loginKey(info.ClientIP)
	if ok, wait := s.loginLimit.allow(key); !ok {
		s.log.Warn("sign-in rate limited", "ip", info.ClientIP, "via", "console_proxy")
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts from this address; retry later")
		return true
	}
	info.loginCharged = true
	ok, reserved, alert, wait := s.proxyAuth.take(key)
	if alert {
		s.log.Error("console proxy: the sign-in limit for all clients has been exhausted for a minute or more (many client addresses at once: a sign-in flood?); clients with a recent sign-in still get a reserved share",
			"last_ip", info.ClientIP)
		if err := s.store.RaiseAlert(context.WithoutCancel(r.Context()), "warning", alertSignInFlood, "listener", "console_proxy",
			"Sign-ins through the console reverse proxy hit the limit for all clients for over a minute (possible sign-in flood). Addresses with a recent successful sign-in keep a reserved share; check the reverse proxy logs."); err != nil {
			s.log.Warn("could not raise the sign-in flood alert", "err", err)
		}
	}
	if reserved {
		s.log.Info("console proxy: sign-in step let in on the reserved budget (recently signed-in address)", "ip", info.ClientIP)
	}
	if !ok {
		s.log.Warn("console proxy: sign-in limit for all clients reached", "ip", info.ClientIP, "path", r.URL.Path)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts right now; retry in a moment")
		return true
	}
	return false
}
