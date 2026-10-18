package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Acquisition request tracking: every exported request is stored with what
// it listed. Whether the acquisition zone has seen it (a `request` feed in a
// status report) and whether each item has arrived (a package in a validated
// bundle) is computed on read.

// AcqRequestItem is one requested app or KB. For kind "app", key is the
// winget id and version the requested version; for kind "kb", key is the KB
// and version the architecture (one item per KB and architecture).
type AcqRequestItem struct {
	Kind    string `json:"kind"` // app | kb
	Key     string `json:"key"`
	Version string `json:"version"`
	// Status: requested | seen | stale | unsupported | failed | fulfilled.
	// unsupported and failed come from the newest acquisition status report
	// with a per-item result for it (unsupported: can never be fetched this
	// way; failed: transient, the next run may work); fulfilled (the package
	// arrived) wins over both. stale: still requested or seen, but the
	// newest acquisition run (finished more than StaleRequestGrace after the
	// request was created) did not pick the request up, so it will not
	// arrive by itself ("Not picked up"; ask again).
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"` // why unsupported / failed
	FulfilledAt string `json:"fulfilled_at"`
	PackageID   string `json:"package_id"`
}

// AcqRequestRecord is a tracked acquisition request.
type AcqRequestRecord struct {
	RequestID        string           `json:"request_id"`
	CreatedAt        string           `json:"created_at"`
	CreatedBy        string           `json:"created_by"`
	IntelGeneratedAt string           `json:"intel_generated_at"`
	SeenAt           string           `json:"seen_at"` // first status report listing it ("" if none)
	Items            []AcqRequestItem `json:"items"`
}

// AcqRequestRef points from an update to the latest request listing it.
type AcqRequestRef struct {
	RequestID string `json:"request_id"`
	At        string `json:"at"`
	Status    string `json:"status"`           // the item's status
	Reason    string `json:"reason,omitempty"` // for unsupported / failed
}

// RecordAcqRequest stores an exported request and its audit event in one
// transaction (no audit record, no export).
func (s *Store) RecordAcqRequest(ctx context.Context, r AcqRequestRecord, ev Ev) error {
	items := make([]AcqRequestItem, 0, len(r.Items))
	for _, it := range r.Items {
		items = append(items, AcqRequestItem{Kind: it.Kind, Key: it.Key, Version: it.Version})
	}
	return s.txChanged(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO acq_requests(request_id,created_at,created_by,intel_generated_at,items) VALUES(?,?,?,?,?)`,
			r.RequestID, r.CreatedAt, r.CreatedBy, r.IntelGeneratedAt, mustJSON(items)); err != nil {
			return err
		}
		return s.audit(tx, ev)
	})
}

// MaxAcqRequests is how many requests GET /api/acquisition-requests lists.
const MaxAcqRequests = 100

// ListAcqRequests returns the newest requests first (limit <= 0 or above
// 1000: MaxAcqRequests) with seen / fulfilled computed now.
func (s *Store) ListAcqRequests(ctx context.Context, limit int) ([]AcqRequestRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = MaxAcqRequests
	}
	rows, err := s.db.QueryContext(ctx, `SELECT request_id,created_at,created_by,intel_generated_at,items FROM acq_requests
		ORDER BY created_at DESC, request_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	out := []AcqRequestRecord{}
	for rows.Next() {
		var r AcqRequestRecord
		var items string
		if err := rows.Scan(&r.RequestID, &r.CreatedAt, &r.CreatedBy, &r.IntelGeneratedAt, &items); err != nil {
			rows.Close()
			return nil, err
		}
		json.Unmarshal([]byte(items), &r.Items)
		if r.Items == nil {
			r.Items = []AcqRequestItem{}
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	seen, err := s.requestsSeen(ctx)
	if err != nil {
		return nil, err
	}
	pkgs, err := s.arrivedPackages(ctx)
	if err != nil {
		return nil, err
	}
	results, err := s.itemResults(ctx)
	if err != nil {
		return nil, err
	}
	last, err := s.lastAcqRun(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		r := &out[i]
		r.SeenAt = seen[r.RequestID]
		for j := range r.Items {
			it := &r.Items[j]
			it.Status = "requested"
			if r.SeenAt != "" {
				it.Status = "seen"
			}
			onItsWay := false
			if res, ok := results[itemResultKey(r.RequestID, it.Kind, it.Key, it.Version)]; ok {
				switch res.result {
				case "unsupported", "failed":
					it.Status, it.Reason = res.result, res.reason
				default: // fetched / already_sent: on its way (or here)
					it.Status, onItsWay = "seen", true
				}
			}
			if (it.Status == "requested" || it.Status == "seen") && !onItsWay && last.missed(r.RequestID, r.CreatedAt) {
				it.Status, it.Reason = "stale", "the acquisition run at "+last.finishedAt+" did not pick this request up"
			}
			if pid, at := pkgs.find(*it, r.CreatedAt); pid != "" {
				it.Status, it.PackageID, it.FulfilledAt, it.Reason = "fulfilled", pid, at, ""
			}
		}
	}
	return out, nil
}

// requestsSeen: request id -> received_at of the first acquisition status
// report with a `request` feed naming it.
func (s *Store) requestsSeen(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT json_extract(f.value,'$.name'), MIN(r.received_at)
		FROM acquisition_reports r, json_each(r.report,'$.feeds') f
		WHERE json_valid(r.report) AND json_extract(f.value,'$.type')='request' GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name sql.NullString
		var at string
		if err := rows.Scan(&name, &at); err != nil {
			return nil, err
		}
		if name.Valid {
			out[name.String] = at
		}
	}
	return out, rows.Err()
}

// StaleRequestGrace: a request is "stale" only when an acquisition run that
// finished at least this long after the request was created did not list
// it (a run already under way when the request was queued may miss it).
const StaleRequestGrace = 10 * time.Minute

// acqRun is the newest acquisition status report (by finished_at): when it
// finished and the request ids it listed (in a request feed or an item
// result).
type acqRun struct {
	finishedAt string
	finished   time.Time
	listed     map[string]bool
}

// missed reports whether the run finished more than StaleRequestGrace after
// createdAt and did not list the request.
func (r acqRun) missed(requestID, createdAt string) bool {
	if r.finished.IsZero() || r.listed[requestID] {
		return false
	}
	return r.finished.After(parseTime(createdAt).Add(StaleRequestGrace))
}

// lastAcqRun loads the newest acquisition status report's finish time and
// listed request ids (zero acqRun when there is none).
func (s *Store) lastAcqRun(ctx context.Context) (acqRun, error) {
	var id int64
	var fin, rep string
	err := s.db.QueryRowContext(ctx, `SELECT id, finished_at, report FROM acquisition_reports ORDER BY finished_at DESC, id DESC LIMIT 1`).Scan(&id, &fin, &rep)
	if errors.Is(err, sql.ErrNoRows) {
		return acqRun{}, nil
	}
	if err != nil {
		return acqRun{}, err
	}
	run := acqRun{finishedAt: fin, finished: parseTime(fin), listed: map[string]bool{}}
	var doc struct {
		Feeds []struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"feeds"`
		Items []struct {
			RequestID string `json:"request_id"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(rep), &doc) != nil {
		return acqRun{}, nil // unreadable: say nothing rather than guess
	}
	for _, f := range doc.Feeds {
		if f.Type == "request" {
			run.listed[f.Name] = true
		}
	}
	for _, it := range doc.Items {
		run.listed[it.RequestID] = true
	}
	return run, nil
}

type itemResult struct{ result, reason string }

// itemResultKey identifies one requested item across status reports: app
// ids and KBs are case-insensitive, versions and architectures exact apart
// from case.
func itemResultKey(requestID, kind, key, version string) string {
	return requestID + "\x00" + kind + "\x00" + strings.ToLower(key) + "\x00" + strings.ToLower(version)
}

// itemResults: per-item results (acqstatus.ItemResult) from acquisition
// status reports, the newest report for each request item.
func (s *Store) itemResults(ctx context.Context) (map[string]itemResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT json_extract(i.value,'$.request_id'), json_extract(i.value,'$.kind'), json_extract(i.value,'$.key'),
		json_extract(i.value,'$.version'), json_extract(i.value,'$.result'), json_extract(i.value,'$.reason')
		FROM acquisition_reports r, json_each(r.report,'$.items') i
		WHERE json_valid(r.report) AND json_type(r.report,'$.items')='array' ORDER BY r.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]itemResult{}
	for rows.Next() {
		var rid, kind, key, version, result, reason sql.NullString
		if err := rows.Scan(&rid, &kind, &key, &version, &result, &reason); err != nil {
			return nil, err
		}
		if !rid.Valid || !kind.Valid || !key.Valid || !result.Valid {
			continue
		}
		k := itemResultKey(rid.String, kind.String, key.String, version.String)
		if _, newer := out[k]; !newer {
			out[k] = itemResult{result: result.String, reason: truncate(reason.String, 300)}
		}
	}
	return out, rows.Err()
}

// truncate bounds report text shown in the console (untrusted input).
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type arrivedPkg struct{ id, at string }

// arrived: catalog packages and every validated bundle that delivered them
// (with the bundle's received_at): the bundle that first imported the
// package, and later bundles that carried it again as an identical
// duplicate (listed in their signed manifest).
type arrived []arrivedPkg

func (s *Store) arrivedPackages(ctx context.Context) (arrived, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.package_id, b.received_at FROM packages p
		JOIN bundles b ON b.bundle_id=p.bundle_id AND b.state='validated'
		UNION
		SELECT p.package_id, b.received_at FROM bundles b, json_each(CAST(b.manifest AS TEXT),'$.packages') m
		JOIN packages p ON p.package_id=json_extract(m.value,'$.package_id')
		WHERE b.state='validated' AND b.manifest IS NOT NULL AND json_valid(CAST(b.manifest AS TEXT))
		ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := arrived{}
	for rows.Next() {
		var a arrivedPkg
		if err := rows.Scan(&a.id, &a.at); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// unsafeIDChars as in pmctl's package ids (cmd/pmctl/requests.go).
var unsafeIDChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// wingetPackageID mirrors pmctl's package id for a winget app:
// <winget id>-<version>[-<arch>], with a hash suffix when characters were
// replaced or the id is longer than 64 characters.
func wingetPackageID(id, version, arch string) string {
	s := id + "-" + version
	if arch != "x64" {
		s += "-" + arch
	}
	clean := unsafeIDChars.ReplaceAllString(s, "-")
	if clean != s || len(clean) > 64 {
		h := sha256.Sum256([]byte(s))
		clean = clean[:min(len(clean), 55)] + "-" + hex.EncodeToString(h[:4])
	}
	return clean
}

// WingetPackageID is the catalog package id pmctl gives a winget app
// version for one architecture.
func WingetPackageID(id, version, arch string) string { return wingetPackageID(id, version, arch) }

// find returns the package that fulfils the item: <KB>-<arch> for a KB, the
// pmctl package id of the app version for any architecture for an app,
// delivered by a bundle received at or after the request was created
// (since); the earliest such delivery wins. A package that arrived before
// the request does not fulfil it.
func (a arrived) find(it AcqRequestItem, since string) (string, string) {
	want := map[string]bool{}
	norm := func(id string) string { return id }
	if it.Kind == "kb" {
		norm = strings.ToLower // KB5044280-x64, whatever the case
		want[norm(it.Key+"-"+it.Version)] = true
	} else {
		for _, arch := range []string{"x64", "x86", "arm64"} {
			want[wingetPackageID(it.Key, it.Version, arch)] = true
		}
	}
	// created_at has whole seconds: compare at that precision.
	from := parseTime(since).Truncate(time.Second)
	best, bestAt := arrivedPkg{}, time.Time{}
	for _, p := range a {
		if !want[norm(p.id)] {
			continue
		}
		at := parseTime(p.at)
		if at.Truncate(time.Second).Before(from) {
			continue
		}
		if best.id == "" || at.Before(bestAt) {
			best, bestAt = p, at
		}
	}
	return best.id, best.at
}

// AcqRefKey is the AcqRequestRefs key for an app (winget id) or a KB (kind
// "kb" or "os").
func AcqRefKey(kind, key string) string {
	if kind == "kb" || kind == "os" {
		return "kb\x00" + strings.ToUpper(key)
	}
	return "app\x00" + strings.ToLower(key)
}

// AcqRequestRefs maps AcqRefKey to the latest tracked request listing it,
// with that item's status. A KB requested for several architectures takes
// the least advanced status (fulfilled only once every architecture arrived).
func (s *Store) AcqRequestRefs(ctx context.Context) (map[string]AcqRequestRef, error) {
	reqs, err := s.ListAcqRequests(ctx, 1000)
	if err != nil {
		return nil, err
	}
	rank := map[string]int{"requested": 0, "stale": 0, "seen": 1, "failed": 1, "unsupported": 1, "fulfilled": 2}
	out := map[string]AcqRequestRef{}
	for _, r := range reqs { // newest first
		mine := map[string]AcqRequestRef{}
		for _, it := range r.Items {
			k := AcqRefKey(it.Kind, it.Key)
			if _, newer := out[k]; newer {
				continue // a newer request lists it
			}
			// Least advanced wins; on a tie the one with a reason, so "Can't
			// import: <reason>" for one architecture is not hidden by another.
			if ref, ok := mine[k]; !ok || rank[it.Status] < rank[ref.Status] || (rank[it.Status] == rank[ref.Status] && ref.Reason == "" && it.Reason != "") {
				mine[k] = AcqRequestRef{RequestID: r.RequestID, At: r.CreatedAt, Status: it.Status, Reason: it.Reason}
			}
		}
		for k, v := range mine {
			out[k] = v
		}
	}
	return out, nil
}
