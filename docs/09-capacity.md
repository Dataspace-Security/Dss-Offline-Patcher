# 09 — Capacity test results (D3)

Measured with `internal/e2e/load_test.go` against the real HTTP server and SQLite store, in-process, on a laptop: Apple M5, 10 cores, 16 GB. Each simulated endpoint reports about 150 installed KBs while an active deployment targets every endpoint. Concurrency was 64 simultaneous agents.

| Endpoints | Check-ins/s | p50 | p95 | p99 | Fleet summary API |
|---|---|---|---|---|---|
| 5,000 | 2,191 | 26 ms | 59 ms | 80 ms | 0.28 s |
| 20,000 | 2,082 | 28 ms | 64 ms | 84 ms | 1.17 s |

**Reading the numbers.** A check-in costs about the same whatever the fleet size. At the default 60-second check-in interval, one server at 50% utilisation sustains roughly **60,000 endpoints**. That is above the 5,000-endpoint planning figure in decision D4.

**Bug found by this test (fixed).** In the first run, per-check-in cost grew with fleet size: 20,000 endpoints managed only 175 check-ins/s, with p95 at 1 s. Two causes:

- Every check-in recounted all targets of every active deployment.
- Every agent report re-read the whole ring to evaluate auto-pause, which made a rollout quadratic.

Both are now constant-cost: internal paths skip the counts, and an indexed aggregate replaces reading the ring.

**Known limits.**

- The fleet summary and the compliance report are O(fleet). They take about 1.2 s at 20,000 endpoints, while the console polls the overview every 10 s. Above about 50,000 endpoints, cache these or move to PostgreSQL (roadmap E).
- SQLite has a single writer. Throughput is bounded by one CPU core of write work, not by the number of agents.
- Content downloads are served by the same process. Large cumulative updates (500 MB+) going to many endpoints at once are bounded by network and disk, not by this test. Use `max_concurrent` and `download_rate_kbps` (C2) to shape them.

**Re-run on target hardware before the pilot:**

```bash
LOAD_ENDPOINTS=20000 LOAD_CONCURRENCY=64 go test -run TestLoad -v -timeout 30m ./internal/e2e/
```
