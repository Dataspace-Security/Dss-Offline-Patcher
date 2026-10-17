package server

import (
	"context"
	"sync"
	"time"

	"offpatch/internal/store"
)

// genCache holds one derived view for at most ttl and only while the store's
// Generation is the one it was built at. Concurrent callers that find it
// stale wait for a single rebuild instead of rebuilding in parallel. The
// cached value is shared: callers must treat it as read only.
type genCache[T any] struct {
	build sync.Mutex // one rebuild at a time
	mu    sync.Mutex // guards the fields below
	ok    bool
	gen   uint64
	at    time.Time
	v     T
}

func (c *genCache[T]) fresh(gen uint64, ttl time.Duration) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok && c.gen == gen && time.Since(c.at) < ttl {
		return c.v, true
	}
	var zero T
	return zero, false
}

// get returns the cached value or rebuilds it with f. gen reports the
// current generation; it is read before f runs, so a change committed while
// f runs leaves the result already stale.
func (c *genCache[T]) get(gen func() uint64, ttl time.Duration, f func() (T, error)) (T, error) {
	if v, ok := c.fresh(gen(), ttl); ok {
		return v, nil
	}
	c.build.Lock()
	defer c.build.Unlock()
	g := gen()
	if v, ok := c.fresh(g, ttl); ok {
		return v, nil
	}
	v, err := f()
	if err != nil {
		return v, err
	}
	c.mu.Lock()
	c.ok, c.gen, c.at, c.v = true, g, time.Now(), v
	c.mu.Unlock()
	return v, nil
}

// needsView is the cached GET /api/packages-needs result plus, per
// endpoint, how many approved catalog packages it needs (Endpoint.missing.ready).
type needsView struct {
	needs map[string]store.PackageNeed
	ready map[string]int
}

// fleetNeeds returns the cached package needs of the whole fleet (fleetTTL,
// invalidated by store changes).
func (s *Server) fleetNeeds(ctx context.Context) (needsView, error) {
	return s.needsCache.get(s.store.Generation, fleetTTL, func() (needsView, error) {
		needs, err := s.store.Needs(ctx)
		if err != nil {
			return needsView{}, err
		}
		ready := map[string]int{}
		for _, n := range needs {
			if !n.Approved() {
				continue
			}
			for _, id := range n.Endpoints {
				ready[id]++
			}
		}
		return needsView{needs: needs, ready: ready}, nil
	})
}

// acqRefs returns the cached store.AcqRequestRefs (fleetTTL, invalidated by
// store changes such as bundle intake, acquisition reports and new requests).
func (s *Server) acqRefs(ctx context.Context) (map[string]store.AcqRequestRef, error) {
	return s.refsCache.get(s.store.Generation, fleetTTL, func() (map[string]store.AcqRequestRef, error) {
		return s.store.AcqRequestRefs(ctx)
	})
}
