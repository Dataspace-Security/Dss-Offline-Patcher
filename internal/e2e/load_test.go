package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// TestLoad measures check-in capacity. Run with:
//
//	LOAD_ENDPOINTS=5000 LOAD_CONCURRENCY=64 go test -run TestLoad -v ./internal/e2e/
//
// Each simulated endpoint reports ~150 installed KBs (a realistic Windows
// inventory) while an active deployment targets every endpoint.
func TestLoad(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("LOAD_ENDPOINTS"))
	if n == 0 {
		t.Skip("set LOAD_ENDPOINTS to run the capacity test")
	}
	conc, _ := strconv.Atoi(os.Getenv("LOAD_CONCURRENCY"))
	if conc == 0 {
		conc = 64
	}
	e := newEnv(t)
	pk := map[string]manifest.Package{"KB5009999-x64": msuPkg("KB5009999-x64", "KB5009999")}
	e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pk, map[string]string{"KB5009999-x64": e.payload("kb.msu", "load")}))
	e.approve("KB5009999-x64")
	e.deploy(store.NewDeployment{PackageID: "KB5009999-x64", Name: "load", Rings: []store.Ring{{Name: "all", Groups: []string{"all"}}}})

	inv := make([]store.InventoryItem, 150)
	for i := range inv {
		inv[i] = store.InventoryItem{Kind: "kb", ID: fmt.Sprintf("KB50%05d", i)}
	}
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: conc}}
	post := func(path, token string, body any, out any) (time.Duration, error) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return 0, fmt.Errorf("%s: %s", path, resp.Status)
		}
		if out != nil {
			json.NewDecoder(resp.Body).Decode(out)
		}
		return time.Since(start), nil
	}

	// Enroll.
	secrets := make([]string, n)
	enrollStart := time.Now()
	run := func(fn func(i int) (time.Duration, error)) []time.Duration {
		lat := make([]time.Duration, n)
		var wg sync.WaitGroup
		var errMu sync.Mutex
		var firstErr error
		jobs := make(chan int)
		for w := 0; w < conc; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					d, err := fn(i)
					if err != nil {
						errMu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						errMu.Unlock()
					}
					lat[i] = d
				}
			}()
		}
		for i := 0; i < n; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		if firstErr != nil {
			t.Fatal(firstErr)
		}
		return lat
	}
	run(func(i int) (time.Duration, error) {
		var tok store.EnrollmentToken
		if _, err := post("/api/enrollment-tokens", tokOperator, map[string]any{"groups": []string{"load"}, "site": "hq", "expires_in_hours": 1}, &tok); err != nil {
			return 0, err
		}
		var r struct {
			Secret string `json:"secret"`
		}
		d, err := post("/api/agent/enroll", "", store.EnrollRequest{Token: tok.Token, Hostname: fmt.Sprintf("load-%05d", i), OS: "windows", Build: 19045, Arch: "x64"}, &r)
		secrets[i] = r.Secret
		return d, err
	})
	enrollTook := time.Since(enrollStart)

	// One full check-in round (every endpoint gets its assignment).
	roundStart := time.Now()
	lat := run(func(i int) (time.Duration, error) {
		return post("/api/agent/checkin", secrets[i], store.CheckinRequest{Hostname: fmt.Sprintf("load-%05d", i), Build: 19045, Arch: "x64", Inventory: inv}, nil)
	})
	round := time.Since(roundStart)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p := func(q float64) time.Duration { return lat[int(float64(len(lat)-1)*q)] }
	rate := float64(n) / round.Seconds()

	// Summary query cost at this scale.
	sumStart := time.Now()
	var sm store.Summary
	e.api("GET", "/api/summary", tokViewer, nil, &sm)
	sumTook := time.Since(sumStart)
	report := fmt.Sprintf("endpoints=%d concurrency=%d\nenroll: %v total\ncheck-in round: %v (%.0f check-ins/s) p50=%v p95=%v p99=%v max=%v\nsummary API: %v\nsustainable fleet at 60s check-in interval ≈ %.0f endpoints (at 50%% utilisation)\n",
		n, conc, enrollTook.Round(time.Millisecond), round.Round(time.Millisecond), rate, p(0.5), p(0.95), p(0.99), lat[len(lat)-1], sumTook.Round(time.Millisecond), rate*60*0.5)
	t.Log("\n" + report)
	if out := os.Getenv("LOAD_REPORT"); out != "" {
		os.WriteFile(out, []byte(report), 0o644)
	}
	if sm.Endpoints.Total != n {
		t.Fatalf("summary counted %d endpoints, want %d", sm.Endpoints.Total, n)
	}
}
