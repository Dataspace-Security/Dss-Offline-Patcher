package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	Kind        string `json:"kind"` // app | kb
	Key         string `json:"key"`
	Version     string `json:"version"`
	Status      string `json:"status"` // requested | seen | fulfilled
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
	Status    string `json:"status"` // the item's status
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
	for i := range out {
		r := &out[i]
		r.SeenAt = seen[r.RequestID]
		for j := range r.Items {
			it := &r.Items[j]
			it.Status = "requested"
			if r.SeenAt != "" {
				it.Status = "seen"
			}
			if pid, at := pkgs.find(*it, r.CreatedAt); pid != "" {
				it.Status, it.PackageID, it.FulfilledAt = "fulfilled", pid, at
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
	rank := map[string]int{"requested": 0, "seen": 1, "fulfilled": 2}
	out := map[string]AcqRequestRef{}
	for _, r := range reqs { // newest first
		mine := map[string]AcqRequestRef{}
		for _, it := range r.Items {
			k := AcqRefKey(it.Kind, it.Key)
			if _, newer := out[k]; newer {
				continue // a newer request lists it
			}
			if ref, ok := mine[k]; !ok || rank[it.Status] < rank[ref.Status] {
				mine[k] = AcqRequestRef{RequestID: r.RequestID, At: r.CreatedAt, Status: it.Status}
			}
		}
		for k, v := range mine {
			out[k] = v
		}
	}
	return out, nil
}
