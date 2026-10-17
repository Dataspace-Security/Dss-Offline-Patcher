package main

// Microsoft security updates in pmctl auto: MSRC monthly releases select the
// KBs, the Update Catalog provides the files (with their checkpoint
// prerequisites on Windows 11 24H2 and later).

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"offpatch/internal/acqstatus"
	"offpatch/internal/acquire"
)

type msRun struct {
	ctx       context.Context
	c         *autoConfig
	hc        *http.Client
	downloads string
	spec      string
	st        autoState
	dry       bool
	rep       *autoReport
	fail      func(id string, err error)
	added     func(id string)

	cat *acquire.Catalog
	ms  *acquire.MSRC
}

type msCand struct {
	id, kb, severity string
	p                autoMSProd
}

func fetchMicrosoft(r *msRun) {
	r.ms = acquire.NewMSRC()
	r.ms.HTTP = r.hc
	if r.c.MSRCURL != "" {
		r.ms.BaseURL = r.c.MSRCURL
	}
	r.cat = acquire.NewCatalog()
	r.cat.HTTP = r.hc
	if r.c.CatalogURL != "" {
		r.cat.BaseURL = r.c.CatalogURL
	}
	cands, superseded, msrcErr := r.candidates()
	if msrcErr != "" {
		// An unread release must not look like "nothing new": the run is
		// partial and every Microsoft feed shows the error.
		r.rep.Failures["msrc"] = msrcErr
	}

	// Drop a KB that a newer candidate supersedes (last month's CU once this
	// month's is out), but only once that newer KB is actually available
	// (fetched now or sent earlier), and never a checkpoint prerequisite.
	// Superseding candidates are processed first.
	processed := map[string]bool{} // KB → some candidate with it was processed
	prereq := map[string]bool{}    // checkpoint KBs required by fetched updates
	available := func(kb string) bool {
		for _, cd := range cands {
			if !strings.EqualFold(cd.kb, kb) {
				continue
			}
			if _, done := r.st.Done[cd.id]; done || slices.Contains(r.rep.New, cd.id) {
				return true
			}
		}
		return false
	}
	process := func(cd msCand) {
		processed[strings.ToUpper(cd.kb)] = true
		if slices.Contains(r.rep.New, cd.id) {
			return // already fetched, e.g. as a checkpoint prerequisite
		}
		if by, ok := superseded[strings.ToUpper(cd.kb)]; ok {
			switch {
			case prereq[strings.ToUpper(cd.kb)]:
				autoWarn(fmt.Sprintf("%s is superseded by %s but is a checkpoint prerequisite; kept", cd.id, by))
			case available(by):
				r.rep.Superseded = append(r.rep.Superseded, cd.id+" (superseded by "+by+")")
				return
			default:
				autoWarn(fmt.Sprintf("%s is superseded by %s, which is not available (it failed); fetching %s meanwhile", cd.id, by, cd.kb))
			}
		}
		if _, done := r.st.Done[cd.id]; done {
			r.rep.Skipped++
			return
		}
		if r.dry {
			r.added(cd.id)
			return
		}
		r.fetch(cd, prereq)
	}
	var deferred []msCand
	for _, cd := range cands {
		if by, ok := superseded[strings.ToUpper(cd.kb)]; ok && !processed[strings.ToUpper(by)] {
			deferred = append(deferred, cd)
			continue
		}
		process(cd)
	}
	for _, cd := range deferred {
		process(cd)
	}
	r.feeds(cands, msrcErr)
}

// candidates reads the MSRC releases of the configured months. Only a 404
// for the newest month is expected (it is published on Patch Tuesday); any
// other failure, or no month read at all, is returned as msrcErr.
func (r *msRun) candidates() (cands []msCand, superseded map[string]string, msrcErr string) {
	m := r.c.Microsoft
	superseded = map[string]string{} // KB → superseding KB
	seen := map[string]bool{}
	var errs []string
	read := 0
	months := recentMonths(autoNow(), m.Months)
	for i, month := range months {
		updates, err := r.ms.Month(r.ctx, month)
		if err != nil {
			if i == 0 && acquire.IsNotFound(err) {
				r.rep.Warnings = append(r.rep.Warnings, fmt.Sprintf("MSRC %s: not published yet (%v)", month, err))
			} else {
				errs = append(errs, fmt.Sprintf("MSRC %s: %v", month, err))
			}
			continue
		}
		read++
		sort.Slice(updates, func(i, j int) bool { return updates[i].KB < updates[j].KB })
		for _, p := range m.Products {
			for _, u := range updates {
				fu, ok := u.ForProduct(p.MSRCProduct, p.Arch)
				if !ok || sevRank[fu.Severity] < sevRank[m.MinSeverity] {
					continue
				}
				for _, s := range fu.Supersedes {
					superseded[strings.ToUpper(s)] = fu.KB
				}
				id := fu.KB + "-" + p.Arch + p.PackageSuffix
				if seen[id] {
					continue
				}
				seen[id] = true
				cands = append(cands, msCand{id: id, kb: fu.KB, severity: fu.Severity, p: p})
			}
		}
	}
	if read == 0 && len(errs) == 0 {
		errs = append(errs, "no MSRC release could be read for "+strings.Join(months, ", "))
	}
	return cands, superseded, strings.Join(errs, "; ")
}

func (r *msRun) fetch(cd msCand, prereq map[string]bool) {
	p := cd.p
	catProd := p.CatalogProduct
	if catProd == "" {
		catProd = p.MSRCProduct
	}
	res, err := acquire.FetchKB(r.ctx, r.cat, r.ms, acquire.FetchKBOptions{KB: cd.kb, Product: catProd, Arch: p.Arch, Match: p.Match,
		MinBuild: p.MinBuild, MaxBuild: p.MaxBuild, Severity: cd.severity, PackageID: cd.id, OutDir: r.downloads, SpecPath: r.spec,
		SkipPrerequisite: r.delivered})
	if err != nil {
		r.fail(cd.id, err)
		return
	}
	for _, w := range res.Warnings {
		autoWarn(cd.kb + ": " + w)
	}
	for _, kb := range res.Entry.Prerequisites {
		prereq[strings.ToUpper(kb)] = true
	}
	for _, pe := range res.Prerequisites {
		r.added(pe.PackageID)
	}
	r.added(cd.id)
}

// delivered: a package that was sent earlier or is already in this run.
func (r *msRun) delivered(id string) bool {
	_, done := r.st.Done[id]
	return done || slices.Contains(r.rep.New, id)
}

func (r *msRun) feeds(cands []msCand, msrcErr string) {
	for _, p := range r.c.Microsoft.Products {
		name := p.MSRCProduct + " " + p.Arch + p.PackageSuffix
		var kbs, fresh, failed []string
		for _, cd := range cands {
			if cd.p != p {
				continue
			}
			kbs = append(kbs, cd.kb)
			if r.rep.Failures[cd.id] != "" {
				failed = append(failed, cd.kb+": "+r.rep.Failures[cd.id])
			} else if slices.Contains(r.rep.New, cd.id) {
				fresh = append(fresh, cd.kb)
			}
		}
		if msrcErr != "" {
			failed = append(failed, msrcErr)
		}
		f := acqstatus.Feed{Type: "microsoft", Name: name, LatestVersion: strings.Join(kbs, ", "), Status: "up_to_date"}
		switch {
		case len(failed) > 0:
			f.Status, f.Detail = "failed", strings.Join(failed, "; ")
		case len(fresh) > 0:
			f.Status, f.Detail = "new", strings.Join(fresh, ", ")
		case len(kbs) == 0:
			f.Detail = "no qualifying updates in the checked months"
		}
		r.rep.Feeds = append(r.rep.Feeds, f)
	}
}
