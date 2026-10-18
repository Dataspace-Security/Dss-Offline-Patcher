package main

// The Library (update intelligence "resolved" section): for the configured
// apps, every app id ever requested from the console, and a curated list
// of common enterprise packages, pmctl looks up the newest version's winget
// installer and defaultLocale manifests so the console can show what can be
// imported, with a description and links, before anyone requests it.
//
// Lookups are cached by id@version in state.json (a new version is looked
// up once), at most libraryMaxLookups new ones per run (the rest follow on
// later runs), and every failure is a warning: the Library describes, it
// never decides what is deployed.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire"
	"offpatch/internal/intel"
)

const (
	libraryMaxLookups  = 300
	libraryWorkers     = 8
	libraryMaxWarnings = 10
)

type libraryID struct {
	id  string
	why string // configured | requested | common
}

type libraryResult struct {
	ran                  bool // the Library was resolved this run
	resolved             []intel.Resolved
	cache                map[string]intel.Resolved // id@version → entry (only current versions)
	lookedUp, deferred   int
	importable, notFound int
	warnings             []string
}

// libraryIDs lists what to resolve, most important first (the lookup
// budget is spent in this order): configured, requested (newest first),
// then the curated common packages.
func libraryIDs(configured []string, requested map[string]string, common []string) []libraryID {
	var out []libraryID
	seen := map[string]bool{}
	add := func(id, why string) {
		k := strings.ToLower(id)
		if !acqrequest.ValidWingetID(id) || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, libraryID{id: id, why: why})
	}
	for _, id := range configured {
		add(id, "configured")
	}
	req := make([]string, 0, len(requested))
	for id := range requested {
		req = append(req, id)
	}
	sort.Slice(req, func(i, j int) bool {
		if requested[req[i]] != requested[req[j]] {
			return requested[req[i]] > requested[req[j]]
		}
		return req[i] < req[j]
	})
	for _, id := range req {
		add(id, "requested")
	}
	for _, id := range common {
		add(id, "common")
	}
	return out
}

// resolveLibrary resolves ids at their newest version per the winget index
// (apps), reusing cache entries and looking up at most max new ones.
func resolveLibrary(ctx context.Context, hc *http.Client, base string, apps []intel.App, ids []libraryID,
	cache map[string]intel.Resolved, max int, now time.Time) libraryResult {
	res := libraryResult{ran: true, cache: map[string]intel.Resolved{}}
	latest := make(map[string]intel.App, len(apps))
	for _, a := range apps {
		latest[strings.ToLower(a.ID)] = a
	}
	var warns []string
	type job struct {
		id  libraryID
		app intel.App
	}
	var todo []job
	for _, li := range ids {
		a, ok := latest[strings.ToLower(li.id)]
		if !ok {
			if li.why != "common" {
				res.notFound++
				warns = append(warns, fmt.Sprintf("%s (%s): not in the winget index", li.id, li.why))
			}
			continue
		}
		if !acqrequest.ValidVersion(a.Version) {
			continue
		}
		key := a.ID + "@" + a.Version
		if r, ok := cache[key]; ok {
			res.cache[key] = r
			continue
		}
		if len(todo) >= max {
			res.deferred++
			continue
		}
		todo = append(todo, job{li, a})
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, libraryWorkers)
	for _, j := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer func() { <-sem; wg.Done() }()
			r, err := acquire.ResolveWinget(ctx, hc, base, j.app.ID, j.app.Version, now)
			mu.Lock()
			defer mu.Unlock()
			res.lookedUp++
			switch {
			case errors.Is(err, acquire.ErrWingetNotFound):
				warns = append(warns, fmt.Sprintf("%s %s (%s): no winget manifest yet", j.app.ID, j.app.Version, j.id.why))
			case err != nil:
				warns = append(warns, fmt.Sprintf("%s %s (%s): %v", j.app.ID, j.app.Version, j.id.why, err))
			default:
				res.cache[j.app.ID+"@"+j.app.Version] = r
			}
		}(j)
	}
	wg.Wait()
	for _, r := range res.cache {
		res.resolved = append(res.resolved, r)
		if ok, _ := acquire.LibraryImportable(r, nil); ok == "yes" {
			res.importable++
		}
	}
	sort.Slice(res.resolved, func(i, j int) bool { return res.resolved[i].ID < res.resolved[j].ID })
	sort.Strings(warns)
	if len(warns) > libraryMaxWarnings {
		warns = append(warns[:libraryMaxWarnings], fmt.Sprintf("+%d more", len(warns)-libraryMaxWarnings))
	}
	for _, w := range warns {
		res.warnings = append(res.warnings, "library: "+w)
	}
	return res
}

// summary is the Library part of the intel feed detail.
func (r libraryResult) summary() string {
	s := fmt.Sprintf("library: %d packages (%d importable), %d looked up", len(r.resolved), r.importable, r.lookedUp)
	if r.deferred > 0 {
		s += fmt.Sprintf(", %d left for the next run (at most %d lookups per run)", r.deferred, libraryMaxLookups)
	}
	return s
}

// recordRequested remembers every app id a request asked for (the Library
// keeps describing it after the request is done).
func recordRequested(st autoState, req *acqrequest.Request) {
	for _, a := range req.Apps {
		if cur := st.Requested[a.WingetID]; req.CreatedAt > cur {
			st.Requested[a.WingetID] = req.CreatedAt
		}
	}
}

// backfillRequested reads the archived requests once (state.json from
// before the Library has no requested ids yet).
func backfillRequested(st autoState, dir string) {
	if dir == "" || len(st.Requested) > 0 {
		return
	}
	files, _ := filepath.Glob(filepath.Join(dir, "done", "*.json"))
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		req, err := acqrequest.Parse(f)
		f.Close()
		if err == nil {
			recordRequested(st, req)
		}
	}
}

// configuredLibraryIDs: the intel "library" list and the winget_id of
// configured apps.
func configuredLibraryIDs(c *autoConfig) []string {
	var out []string
	if c.Intel != nil {
		out = append(out, c.Intel.Library...)
	}
	for _, a := range c.Apps {
		if a.WingetID != "" {
			out = append(out, a.WingetID)
		}
	}
	return out
}
