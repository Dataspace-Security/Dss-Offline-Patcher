package main

// Per-item results of acquisition requests (acqstatus.Report.Items): for
// every app and KB named in a request, what this run did with it, with a
// short reason the console shows on the row the operator clicked ("Can't
// import: no MSI installer for x86 in winget"). The full error stays in the
// run report's failures and warnings.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acqstatus"
	"offpatch/internal/acquire"
)

// maxReasonLen bounds a reason; the console shows it inline.
const maxReasonLen = 200

// itemError carries the short reason for the console next to the full
// error. Unwrap keeps acquire.UnsupportedError / ErrHashMismatch visible.
type itemError struct {
	result string // acqstatus.ItemUnsupported | acqstatus.ItemFailed
	reason string
	err    error
}

func (e *itemError) Error() string { return e.err.Error() }
func (e *itemError) Unwrap() error { return e.err }

// unsupportedItem: retrying will not help. The full text goes to the
// warnings, reason to the console.
func unsupportedItem(reason, full string) error {
	return &itemError{result: acqstatus.ItemUnsupported, reason: reason, err: &acquire.UnsupportedError{Reason: full}}
}

// itemOutcome is what happened to one package of a requested item (an app
// has one per requested architecture).
type itemOutcome struct {
	result string // acqstatus.Item*
	reason string
}

type itemPart struct {
	arch string // apps only
	id   string // package id
	out  itemOutcome
}

// requestItem is one app or KB of a request, as the console listed it.
type requestItem struct {
	kind, key, version string
	parts              []itemPart
}

// classify turns a fetch error into a result and a short reason.
func classify(err error) itemOutcome {
	var ie *itemError
	if errors.As(err, &ie) {
		return itemOutcome{result: ie.result, reason: shortReason(ie.reason)}
	}
	var un *acquire.UnsupportedError
	if errors.As(err, &un) {
		return itemOutcome{result: acqstatus.ItemUnsupported, reason: shortReason(un.Reason)}
	}
	return itemOutcome{result: acqstatus.ItemFailed, reason: failureReason(err)}
}

// failureReason is the short reason for a transient failure.
func failureReason(err error) string {
	msg := err.Error()
	switch {
	case errors.Is(err, acquire.ErrHashMismatch):
		switch {
		case strings.Contains(msg, "SHA-256"):
			return "SHA-256 mismatch: the download does not match the published hash"
		case strings.Contains(msg, "SHA-1"):
			return "SHA-1 mismatch: the download does not match the published hash"
		default:
			return "size mismatch: the download does not match the published size"
		}
	case errors.Is(err, context.DeadlineExceeded):
		return "the run reached its time limit before this finished; retried next run"
	case errors.Is(err, context.Canceled):
		return "the run was stopped before this finished; retried next run"
	}
	return shortReason(msg)
}

// shortReason keeps the first line of s, at most maxReasonLen characters.
func shortReason(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxReasonLen {
		s = string(r[:maxReasonLen-3]) + "..."
	}
	return s
}

// pickMSIReason shortens acquire.PickMSI's UnsupportedError for the console.
func pickMSIReason(full, arch string) string {
	switch {
	case strings.Contains(full, "is not https"):
		return "the winget installer URL is not HTTPS"
	case strings.Contains(full, "InstallerSha256"):
		return "the winget manifest has no valid SHA-256 for the installer"
	}
	// An EXE installer exists but cannot be deployed (acquire.PickEXE):
	// "EXE installer (inno) for x64 is not importable: installs per user only".
	if pre, why, ok := strings.Cut(full, " is not importable: "); ok {
		if i := strings.Index(pre, "EXE installer ("); i >= 0 {
			return why + " (winget " + strings.TrimSpace(pre[i:]) + ")"
		}
		return why
	}
	kind := "MSI"
	switch {
	case strings.Contains(full, "no supported installer"):
		kind = "supported"
	case strings.Contains(full, "no MSI or EXE installer"):
		kind = "MSI or EXE"
	}
	if _, rest, ok := strings.Cut(full, "(only "); ok {
		if only, _, ok := strings.Cut(rest, ")"); ok {
			return fmt.Sprintf("no %s installer for %s in winget (only %s)", kind, arch, only)
		}
	}
	if strings.Contains(full, "no MSI") {
		return fmt.Sprintf("no %s installer for %s in winget", kind, arch)
	}
	return fmt.Sprintf("no installer for %s in winget", arch)
}

// kbCatalogError classifies a FetchKB error: a KB the catalog does not list
// for this product/arch (or lists ambiguously) can never be fetched this
// way; anything else is transient.
func kbCatalogError(k acqrequest.KB, err error) error {
	msg := err.Error()
	where := k.Arch
	if k.Build > 0 {
		where = fmt.Sprintf("build %d %s", k.Build, k.Arch)
	}
	switch {
	case strings.HasPrefix(msg, "catalog has no results for"), strings.HasPrefix(msg, "no catalog row matches"):
		return &itemError{result: acqstatus.ItemUnsupported, reason: fmt.Sprintf("%s not in the Microsoft Update Catalog for %s", k.KB, where),
			err: &acquire.UnsupportedError{Reason: msg}}
	case strings.Contains(msg, "catalog rows match; narrow"):
		return &itemError{result: acqstatus.ItemUnsupported, reason: fmt.Sprintf("several Microsoft Update Catalog entries match %s for %s; fetch it by hand with pmctl fetch -match", k.KB, where),
			err: &acquire.UnsupportedError{Reason: msg}}
	}
	return err
}

// finishItems settles every requested item once delivery is over and
// returns the per-item results for the status report. A package fetched
// this run counts as fetched only if one of this run's bundles carried it;
// otherwise it failed. Unless dry, packages sent for a request are recorded
// in st.RequestSent (so a retried request does not send them again), and
// the record of every request that is finished or no longer present is
// dropped.
func finishItems(reqs []*loadedRequest, st autoState, rep *autoReport, dry bool, runErr error, requestsDone bool) []acqstatus.ItemResult {
	var out []acqstatus.ItemResult
	present := map[string]bool{}
	for _, lr := range reqs {
		rid := lr.req.RequestID
		present[rid] = true
		for _, it := range lr.items {
			for i := range it.parts {
				p := &it.parts[i]
				p.out = settle(p, st, rep, dry, runErr)
				if !dry && p.out.result == acqstatus.ItemFetched {
					if st.RequestSent[rid] == nil {
						st.RequestSent[rid] = map[string]string{}
					}
					st.RequestSent[rid][p.id] = st.Done[p.id].BundleID
				}
			}
			out = append(out, mergeParts(rid, it))
		}
		if !dry && requestsDone && !requestHasFailure(lr, rep) {
			delete(st.RequestSent, rid)
		}
	}
	if !dry && reqs != nil {
		for rid := range st.RequestSent {
			if !present[rid] {
				delete(st.RequestSent, rid)
			}
		}
	}
	return out
}

func settle(p *itemPart, st autoState, rep *autoReport, dry bool, runErr error) itemOutcome {
	if p.out.result != acqstatus.ItemFetched || dry {
		return p.out
	}
	if f := rep.Failures[p.id]; f != "" {
		return itemOutcome{result: acqstatus.ItemFailed, reason: shortReason(f)}
	}
	if d, ok := st.Done[p.id]; ok && slices.Contains(rep.Bundles, d.BundleID) {
		return p.out
	}
	if runErr != nil {
		return itemOutcome{result: acqstatus.ItemFailed, reason: shortReason("downloaded but not sent: " + runErr.Error())}
	}
	return itemOutcome{result: acqstatus.ItemFailed, reason: "downloaded but not sent; retried next run"}
}

// mergeParts folds an app's per-architecture outcomes into one result (the
// console lists the app once): any failure makes it failed (a retry may
// help), else anything fetched makes it fetched, else already_sent, else
// unsupported. Reasons name the architecture when there are several.
func mergeParts(rid string, it requestItem) acqstatus.ItemResult {
	r := acqstatus.ItemResult{RequestID: rid, Kind: it.kind, Key: it.key, Version: it.version}
	has := map[string]bool{}
	for _, p := range it.parts {
		has[p.out.result] = true
	}
	for _, res := range []string{acqstatus.ItemFailed, acqstatus.ItemFetched, acqstatus.ItemAlreadySent, acqstatus.ItemUnsupported} {
		if has[res] {
			r.Result = res
			break
		}
	}
	var reasons []string
	for _, p := range it.parts {
		if r.PackageID == "" && (p.out.result == acqstatus.ItemFetched || p.out.result == acqstatus.ItemAlreadySent) {
			r.PackageID = p.id
		}
		if p.out.reason == "" || (p.out.result != r.Result && p.out.result != acqstatus.ItemUnsupported && p.out.result != acqstatus.ItemFailed) {
			continue
		}
		if len(it.parts) > 1 {
			reasons = append(reasons, p.arch+": "+p.out.reason)
		} else {
			reasons = append(reasons, p.out.reason)
		}
	}
	r.Reason = shortReason(strings.Join(reasons, "; "))
	return r
}

func requestHasFailure(lr *loadedRequest, rep *autoReport) bool {
	return slices.ContainsFunc(lr.ids, func(id string) bool { return rep.Failures[id] != "" })
}
