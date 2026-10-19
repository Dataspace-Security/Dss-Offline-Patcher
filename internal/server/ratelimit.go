package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ipLimiter is an in-memory token bucket per client IP, for unauthenticated
// endpoints (enrollment). Each IP may burst `burst` requests and then gets
// one more every `every`.
type ipLimiter struct {
	mu      sync.Mutex
	burst   float64
	every   time.Duration
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

// maxBuckets bounds memory; idle full buckets are dropped past this.
const maxBuckets = 10000

func newIPLimiter(burst int, every time.Duration) *ipLimiter {
	return &ipLimiter{burst: float64(burst), every: every, buckets: map[string]*bucket{}, now: time.Now}
}

// allow takes a token for ip; it returns false (and how long until the next
// token) when the bucket is empty.
func (l *ipLimiter) allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.prune(now)
		}
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[ip] = b
	}
	b.tokens += float64(now.Sub(b.at)) / float64(l.every)
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.at = now
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) * float64(l.every))
	}
	b.tokens--
	return true, 0
}

// prune drops buckets that would be full again (their IP is idle).
func (l *ipLimiter) prune(now time.Time) {
	for ip, b := range l.buckets {
		if b.tokens+float64(now.Sub(b.at))/float64(l.every) >= l.burst {
			delete(l.buckets, ip)
		}
	}
}

// clientIP is the TCP peer address (the management server is reached
// directly inside the isolated zone; no proxy headers are trusted), except
// on the console_proxy listener, where a trusted reverse proxy names the
// browser's address (X-Forwarded-For / X-Real-IP; consoleproxy.go).
func clientIP(r *http.Request) string {
	if p := proxiedInfo(r); p != nil {
		return p.ClientIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// enrollAllowed applies the enrollment limit. Requests from the server host
// itself are exempt (local scripts and tests; an attacker there already has
// the database).
func (s *Server) enrollAllowed(ip string) (bool, time.Duration) {
	if a := net.ParseIP(ip); a != nil && a.IsLoopback() {
		return true, 0
	}
	return s.enrollLimit.allow(ip)
}
