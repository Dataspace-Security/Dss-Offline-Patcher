package server

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenCache(t *testing.T) {
	var c genCache[int]
	var gen atomic.Uint64
	var builds atomic.Int32
	release := make(chan struct{})
	build := func() (int, error) {
		builds.Add(1)
		<-release
		return int(gen.Load()), nil
	}
	// Concurrent callers on a cold cache: one build, everyone gets its result.
	var wg sync.WaitGroup
	got := make([]int, 8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := c.get(gen.Load, time.Minute, build)
			if err != nil {
				t.Error(err)
			}
			got[i] = v
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := builds.Load(); n != 1 {
		t.Fatalf("%d builds for concurrent callers, want 1", n)
	}
	if v, _ := c.get(gen.Load, time.Minute, build); v != 0 || builds.Load() != 1 {
		t.Fatalf("cached: %d (builds %d)", v, builds.Load())
	}
	gen.Add(1) // a store change
	if v, _ := c.get(gen.Load, time.Minute, build); v != 1 || builds.Load() != 2 {
		t.Fatalf("after a generation bump: %d (builds %d)", v, builds.Load())
	}
	if _, _ = c.get(gen.Load, 0, build); builds.Load() != 3 {
		t.Fatalf("expired TTL must rebuild (builds %d)", builds.Load())
	}
	// Errors are not cached.
	var c2 genCache[int]
	fail := errors.New("boom")
	if _, err := c2.get(gen.Load, time.Minute, func() (int, error) { return 0, fail }); !errors.Is(err, fail) {
		t.Fatalf("error: %v", err)
	}
	if v, err := c2.get(gen.Load, time.Minute, func() (int, error) { return 7, nil }); err != nil || v != 7 {
		t.Fatalf("after an error: %d %v", v, err)
	}
}
