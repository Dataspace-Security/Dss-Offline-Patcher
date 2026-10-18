package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"offpatch/internal/manifest"
)

// ---- bundles ----

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type Bundle struct {
	ID           int64   `json:"id"`
	BundleID     string  `json:"bundle_id"`
	Source       string  `json:"source"`
	Sequence     int64   `json:"sequence"`
	KeyID        string  `json:"key_id"`
	State        string  `json:"state"`
	Filename     string  `json:"filename"`
	FileSHA256   string  `json:"file_sha256"`
	FileSize     int64   `json:"file_size"`
	ReceivedAt   string  `json:"received_at"`
	PackageCount int     `json:"package_count"`
	Checks       []Check `json:"checks"`
	Error        string  `json:"error"`
}

const bundleCols = `id,bundle_id,source,sequence,key_id,state,filename,file_sha256,file_size,received_at,package_count,checks,error`

func scanBundle(sc interface{ Scan(...any) error }) (Bundle, error) {
	var b Bundle
	var checks string
	err := sc.Scan(&b.ID, &b.BundleID, &b.Source, &b.Sequence, &b.KeyID, &b.State, &b.Filename, &b.FileSHA256, &b.FileSize, &b.ReceivedAt, &b.PackageCount, &checks, &b.Error)
	if err != nil {
		return b, err
	}
	b.Checks = []Check{}
	json.Unmarshal([]byte(checks), &b.Checks)
	return b, nil
}

// Intake is everything the intake service learned about one received file.
type Intake struct {
	Bundle        Bundle // filename, file hash/size, checks so far; bundle_id etc. if parsed
	Manifest      *manifest.Manifest
	ManifestBytes []byte
	Signature     string
	QuarantineDir string // contains payload/<base>
}

// IngestBundle runs the stateful checks (replay, duplicate, catalog conflict)
// and atomically records the bundle and its quarantined packages. If any
// earlier check failed (in.Manifest == nil or a check is !OK) the bundle is
// recorded as rejected. Packages are NEVER auto-approved.
func (s *Store) IngestBundle(ctx context.Context, in Intake) (Bundle, error) {
	b := in.Bundle
	b.ReceivedAt = s.now()
	failed := in.Manifest == nil
	for _, c := range b.Checks {
		if !c.OK {
			failed = true
		}
	}
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
		var newPkgs []manifest.Package
		var again []reimport // rejected packages delivered again: new review
		if !failed {
			m := in.Manifest
			// Replay: sequence must strictly increase per source.
			var last int64
			err := tx.QueryRow(`SELECT last_sequence FROM source_sequences WHERE source=?`, m.Source).Scan(&last)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if m.Sequence <= last {
				b.Checks = append(b.Checks, Check{"replay", false, fmt.Sprintf("sequence %d not greater than last accepted %d for source %s", m.Sequence, last, m.Source)})
				failed = true
			} else {
				b.Checks = append(b.Checks, Check{"replay", true, fmt.Sprintf("sequence %d > %d", m.Sequence, last)})
			}
			var n int
			tx.QueryRow(`SELECT COUNT(*) FROM bundles WHERE bundle_id=? AND state='validated'`, m.BundleID).Scan(&n)
			if n > 0 {
				b.Checks = append(b.Checks, Check{"duplicate_bundle", false, "bundle_id already accepted"})
				failed = true
			} else {
				b.Checks = append(b.Checks, Check{"duplicate_bundle", true, "new bundle_id"})
			}
			// Catalog conflicts: same package_id with different content is fatal;
			// identical content is a harmless duplicate. Two exceptions by state:
			//  - rejected: "Import again" (an operator asked for it explicitly in
			//    a request). The package goes back to quarantined for a new
			//    review, with this bundle's content and signed manifest; if the
			//    content changed, the new content replaces the old. Safe because
			//    a rejected package was never published or deployed, and the
			//    new review starts from scratch (earlier approvals are cleared).
			//  - revoked: a security decision, never undone by a delivery. The
			//    package is skipped as a duplicate (whatever the content) and
			//    stays revoked.
			conflict := false
			var dups []string
			for _, p := range m.Packages {
				var sha, state, oldBundle string
				err := tx.QueryRow(`SELECT sha256, state, bundle_id FROM packages WHERE package_id=?`, p.PackageID).Scan(&sha, &state, &oldBundle)
				switch {
				case errors.Is(err, sql.ErrNoRows):
					newPkgs = append(newPkgs, p)
				case err != nil:
					return err
				case state == "rejected":
					again = append(again, reimport{p: p, prevSHA: sha, prevBundle: oldBundle})
				case state == "revoked":
					dups = append(dups, p.PackageID+" (revoked; not imported again)")
				case sha == p.File.SHA256:
					dups = append(dups, p.PackageID)
				default:
					conflict = true
					b.Checks = append(b.Checks, Check{"catalog_conflict", false, fmt.Sprintf("package %s already in catalog with different sha256", p.PackageID)})
				}
			}
			if conflict {
				failed = true
			} else {
				d := "no conflicts"
				if len(dups) > 0 {
					d = fmt.Sprintf("identical duplicates skipped: %v", dups)
				}
				if len(again) > 0 {
					ids := make([]string, 0, len(again))
					for _, r := range again {
						ids = append(ids, r.p.PackageID)
					}
					d += fmt.Sprintf("; rejected packages imported again for a new review: %v", ids)
				}
				b.Checks = append(b.Checks, Check{"catalog_conflict", true, d})
			}
		}

		if failed {
			b.State = "rejected"
			if b.Error == "" {
				for _, c := range b.Checks {
					if !c.OK {
						b.Error = c.Name + ": " + c.Detail
						break
					}
				}
			}
		} else {
			b.State = "validated"
			b.PackageCount = len(in.Manifest.Packages)
		}
		res, err := tx.Exec(`INSERT INTO bundles(bundle_id,source,sequence,key_id,state,filename,file_sha256,file_size,received_at,package_count,checks,error,manifest,signature) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			b.BundleID, b.Source, b.Sequence, b.KeyID, b.State, b.Filename, b.FileSHA256, b.FileSize, b.ReceivedAt, b.PackageCount, mustJSON(b.Checks), b.Error, in.ManifestBytes, in.Signature)
		if err != nil {
			return err
		}
		b.ID, _ = res.LastInsertId()
		details := map[string]any{"intake_id": b.ID, "filename": b.Filename, "file_sha256": b.FileSHA256, "file_size": b.FileSize, "source": b.Source, "sequence": b.Sequence, "key_id": b.KeyID, "adapter": "dropdir"}
		if failed {
			details["error"] = b.Error
			if err := s.raiseAlert(tx, "warning", "bundle_rejected", "bundle", b.FileSHA256, "bundle "+b.Filename+" rejected at intake: "+b.Error); err != nil {
				return err
			}
			return s.audit(tx, Ev{Actor: "system:intake", Action: "bundle.rejected", ObjectType: "bundle", ObjectID: b.BundleID, Failure: true, Details: details})
		}
		m := in.Manifest
		if _, err := tx.Exec(`INSERT INTO source_sequences(source,last_sequence) VALUES(?,?) ON CONFLICT(source) DO UPDATE SET last_sequence=excluded.last_sequence`, m.Source, m.Sequence); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: "system:intake", Action: "bundle.validated", ObjectType: "bundle", ObjectID: b.BundleID, Details: details}); err != nil {
			return err
		}
		now := s.now()
		for _, p := range newPkgs {
			qpath := filepath.Join(in.QuarantineDir, "payload", filepath.Base(p.File.Name))
			_, err := tx.Exec(`INSERT INTO packages(package_id,bundle_id,title,vendor,kind,version,kb,product_code,severity,release_date,supersedes,applicability,file_name,size,sha256,source_url,vendor_signature,quarantine_path,state,state_by,state_at,created_at,package_name,prerequisites,expected_ubr) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'quarantined','system:intake',?,?,?,?,?)`,
				p.PackageID, m.BundleID, p.Title, p.Vendor, p.Kind, p.Version, p.KB, p.ProductCode, p.Severity, p.ReleaseDate,
				mustJSON(nonNil(p.Supersedes)), mustJSON(p.Applicability), filepath.Base(p.File.Name), p.File.Size, p.File.SHA256,
				p.SourceURL, mustJSON(p.VendorSignature), qpath, now, now, p.PackageName, mustJSON(nonNil(p.Prerequisites)), p.ExpectedUBR)
			if err != nil {
				return err
			}
			if err := s.audit(tx, Ev{Actor: "system:intake", Action: "package.quarantined", ObjectType: "package", ObjectID: p.PackageID, PackageID: p.PackageID,
				Details: map[string]any{"bundle_id": m.BundleID, "sha256": p.File.SHA256, "size": p.File.Size, "kb": p.KB, "product_code": p.ProductCode, "vendor_signature": p.VendorSignature.Status}}); err != nil {
				return err
			}
		}
		for _, r := range again {
			if err := s.reimportRejected(tx, m.BundleID, in.QuarantineDir, r); err != nil {
				return err
			}
		}
		return nil
	})
	return b, err
}

// reimport is a rejected package delivered again in a validated bundle.
type reimport struct {
	p                   manifest.Package
	prevSHA, prevBundle string
}

// reimportRejected puts a rejected package back in quarantine for a new
// review: every field comes from the new bundle (its signed manifest is the
// one endpoints verify against, so bundle_id must point at it), earlier
// approvals are cleared, and the audit event records what changed.
func (s *Store) reimportRejected(tx *sql.Tx, bundleID, quarantineDir string, r reimport) error {
	p, now := r.p, s.now()
	qpath := filepath.Join(quarantineDir, "payload", filepath.Base(p.File.Name))
	if _, err := tx.Exec(`UPDATE packages SET bundle_id=?,title=?,vendor=?,kind=?,version=?,kb=?,product_code=?,severity=?,release_date=?,supersedes=?,applicability=?,
		file_name=?,size=?,sha256=?,source_url=?,vendor_signature=?,quarantine_path=?,state='quarantined',state_reason='',state_by='system:intake',state_at=?,
		package_name=?,prerequisites=?,expected_ubr=? WHERE package_id=? AND state='rejected'`,
		bundleID, p.Title, p.Vendor, p.Kind, p.Version, p.KB, p.ProductCode, p.Severity, p.ReleaseDate, mustJSON(nonNil(p.Supersedes)), mustJSON(p.Applicability),
		filepath.Base(p.File.Name), p.File.Size, p.File.SHA256, p.SourceURL, mustJSON(p.VendorSignature), qpath, now,
		p.PackageName, mustJSON(nonNil(p.Prerequisites)), p.ExpectedUBR, p.PackageID); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM package_approvals WHERE package_id=?`, p.PackageID)
	if err != nil {
		return err
	}
	cleared, _ := res.RowsAffected()
	return s.audit(tx, Ev{Actor: "system:intake", Action: "package.reimported", ObjectType: "package", ObjectID: p.PackageID, PackageID: p.PackageID,
		Details: map[string]any{"bundle_id": bundleID, "previous_bundle_id": r.prevBundle, "sha256": p.File.SHA256, "previous_sha256": r.prevSHA,
			"content_changed": r.prevSHA != p.File.SHA256, "approvals_cleared": cleared, "from": "rejected", "to": "quarantined",
			"size": p.File.Size, "vendor_signature": p.VendorSignature.Status}})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// BundleFileRecorded reports whether a received file (by SHA-256) has an
// intake record; intake re-ingests evidence files that do not.
func (s *Store) BundleFileRecorded(ctx context.Context, fileSHA256 string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bundles WHERE file_sha256=?`, fileSHA256).Scan(&n)
	return n > 0, err
}

func (s *Store) ListBundles(ctx context.Context) ([]Bundle, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+bundleCols+` FROM bundles ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bundle{}
	for rows.Next() {
		b, err := scanBundle(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) GetBundle(ctx context.Context, id int64) (Bundle, error) {
	b, err := scanBundle(s.db.QueryRowContext(ctx, `SELECT `+bundleCols+` FROM bundles WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return b, ErrNotFound
	}
	return b, err
}

func (s *Store) GetValidatedBundleByBundleID(ctx context.Context, bundleID string) (Bundle, error) {
	b, err := scanBundle(s.db.QueryRowContext(ctx, `SELECT `+bundleCols+` FROM bundles WHERE bundle_id=? AND state='validated'`, bundleID))
	if errors.Is(err, sql.ErrNoRows) {
		return b, ErrNotFound
	}
	return b, err
}

// SignedManifest returns the original signed bytes of the bundle that
// delivered packageID, for end-to-end verification on the endpoint.
func (s *Store) SignedManifest(ctx context.Context, packageID string) (manifestBytes []byte, sig, keyID string, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT b.manifest, b.signature, b.key_id FROM packages p JOIN bundles b ON b.bundle_id=p.bundle_id AND b.state='validated' WHERE p.package_id=?`, packageID).Scan(&manifestBytes, &sig, &keyID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

// ---- packages ----

type Package struct {
	PackageID         string                   `json:"package_id"`
	BundleID          string                   `json:"bundle_id"`
	Title             string                   `json:"title"`
	Vendor            string                   `json:"vendor"`
	Kind              string                   `json:"kind"`
	Version           string                   `json:"version"`
	KB                string                   `json:"kb"`
	ProductCode       string                   `json:"product_code"`
	Severity          string                   `json:"severity"`
	ReleaseDate       string                   `json:"release_date"`
	Supersedes        []string                 `json:"supersedes"`
	Applicability     manifest.Applicability   `json:"applicability"`
	FileName          string                   `json:"file_name"`
	Size              int64                    `json:"size"`
	SHA256            string                   `json:"sha256"`
	SourceURL         string                   `json:"source_url"`
	VendorSignature   manifest.VendorSignature `json:"vendor_signature"`
	State             string                   `json:"state"`
	StateReason       string                   `json:"state_reason"`
	StateBy           string                   `json:"state_by"`
	StateAt           string                   `json:"state_at"`
	CreatedAt         string                   `json:"created_at"`
	QuarantinePath    string                   `json:"-"`
	PackageName       string                   `json:"package_name"`
	Prerequisites     []string                 `json:"prerequisites"`
	SupersededBy      string                   `json:"superseded_by"`
	Approvals         []Approval               `json:"approvals"`
	ApprovalsRequired int                      `json:"approvals_required"`
	// RollbackUnsupported says why a rollback deployment is impossible ("" = supported).
	RollbackUnsupported string `json:"rollback_unsupported"`
	// ExpectedUBR (msu): the build revision once installed (0 = unknown);
	// targets also verify by revision (presentOn).
	ExpectedUBR int `json:"expected_ubr,omitempty"`
}

const packageCols = `package_id,bundle_id,title,vendor,kind,version,kb,product_code,severity,release_date,supersedes,applicability,file_name,size,sha256,source_url,vendor_signature,quarantine_path,state,state_reason,state_by,state_at,created_at,package_name,prerequisites,superseded_by,expected_ubr`

func scanPackage(sc interface{ Scan(...any) error }) (Package, error) {
	var p Package
	var sup, app, vs, prq string
	err := sc.Scan(&p.PackageID, &p.BundleID, &p.Title, &p.Vendor, &p.Kind, &p.Version, &p.KB, &p.ProductCode, &p.Severity, &p.ReleaseDate,
		&sup, &app, &p.FileName, &p.Size, &p.SHA256, &p.SourceURL, &vs, &p.QuarantinePath, &p.State, &p.StateReason, &p.StateBy, &p.StateAt, &p.CreatedAt, &p.PackageName, &prq, &p.SupersededBy, &p.ExpectedUBR)
	if err != nil {
		return p, err
	}
	json.Unmarshal([]byte(sup), &p.Supersedes)
	json.Unmarshal([]byte(app), &p.Applicability)
	json.Unmarshal([]byte(vs), &p.VendorSignature)
	p.Supersedes = nonNil(p.Supersedes)
	json.Unmarshal([]byte(prq), &p.Prerequisites)
	p.Prerequisites = nonNil(p.Prerequisites)
	p.RollbackUnsupported = RollbackUnsupported(p)
	return p, nil
}

func (s *Store) ListPackages(ctx context.Context, state string) ([]Package, error) {
	q := `SELECT ` + packageCols + ` FROM packages`
	var args []any
	if state != "" {
		q += ` WHERE state=?`
		args = append(args, state)
	}
	q += ` ORDER BY created_at DESC, package_id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Package{}
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	ap, err := loadApprovals(ctx, s.db, "")
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Approvals = ap[out[i].PackageID]
		if out[i].Approvals == nil {
			out[i].Approvals = []Approval{}
		}
		out[i].ApprovalsRequired = s.Policy.required(out[i].Severity)
	}
	return out, nil
}

func (s *Store) GetPackage(ctx context.Context, id string) (Package, error) {
	p, err := getPackage(ctx, s.db, id)
	p.ApprovalsRequired = s.Policy.required(p.Severity)
	return p, err
}

type querier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}

func getPackage(ctx context.Context, q querier, id string) (Package, error) {
	p, err := scanPackage(q.QueryRowContext(ctx, `SELECT `+packageCols+` FROM packages WHERE package_id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, Errf(ErrNotFound, "package %s", id)
	}
	if err != nil {
		return p, err
	}
	ap, err := loadApprovals(ctx, q, id)
	p.Approvals = ap[id]
	if p.Approvals == nil {
		p.Approvals = []Approval{}
	}
	return p, err
}

type Approval struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
	At     string `json:"at"`
}

// loadApprovals returns approvals by package (all packages when id is "").
func loadApprovals(ctx context.Context, q querier, id string) (map[string][]Approval, error) {
	sqlq := `SELECT package_id, approver, reason, at FROM package_approvals`
	var args []any
	if id != "" {
		sqlq += ` WHERE package_id=?`
		args = append(args, id)
	}
	rows, err := q.QueryContext(ctx, sqlq+` ORDER BY at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Approval{}
	for rows.Next() {
		var pid string
		var a Approval
		if err := rows.Scan(&pid, &a.By, &a.Reason, &a.At); err != nil {
			return nil, err
		}
		out[pid] = append(out[pid], a)
	}
	return out, rows.Err()
}

// SetPackageState applies approve/reject/revoke. For the approval that
// completes the policy, publish runs BEFORE the transaction (copying and
// hashing a large file must not hold the single database connection); it is
// content-addressed and idempotent, so publishing and then losing a race is
// harmless. The DB only says "approved" if the content is in the repository.
func (s *Store) SetPackageState(ctx context.Context, actor, id, action, reason string, publish func(Package) error) (Package, error) {
	if err := requireReason(reason); err != nil {
		return Package{}, err
	}
	var from, to string
	switch action {
	case "approve":
		from, to = "quarantined", "approved"
	case "reject":
		from, to = "quarantined", "rejected"
	case "revoke":
		from, to = "approved", "revoked"
	default:
		return Package{}, Errf(ErrInvalid, "unknown action %s", action)
	}
	published := false
	if action == "approve" && publish != nil {
		if p, err := s.GetPackage(ctx, id); err == nil && p.State == from && !approvedBy(p, actor) && len(p.Approvals)+1 >= p.ApprovalsRequired {
			if err := publish(p); err != nil {
				return Package{}, fmt.Errorf("publish to repository: %w", err)
			}
			published = true
		}
	}
	var out Package
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
		p, err := getPackage(ctx, tx, id)
		if err != nil {
			return err
		}
		p.ApprovalsRequired = s.Policy.required(p.Severity)
		if p.State != from {
			return Errf(ErrConflict, "package is %s; %s requires %s", p.State, action, from)
		}
		if action == "approve" {
			if approvedBy(p, actor) {
				return Errf(ErrConflict, "%s already approved this package; a different approver is required", actor)
			}
			if _, err := tx.Exec(`INSERT INTO package_approvals(package_id,approver,reason,at) VALUES(?,?,?,?)`, id, actor, reason, s.now()); err != nil {
				return err
			}
			have := len(p.Approvals) + 1
			if have < p.ApprovalsRequired {
				if err := s.audit(tx, Ev{Actor: actor, Action: "package.approval_recorded", ObjectType: "package", ObjectID: id, PackageID: id,
					Details: map[string]any{"reason": reason, "approvals": have, "required": p.ApprovalsRequired, "severity": p.Severity}}); err != nil {
					return err
				}
				out, err = getPackage(ctx, tx, id)
				return err
			}
		}
		if action == "approve" && publish != nil && !published {
			// Another approval landed between the check above and this
			// transaction, so this one now completes the policy unpublished.
			return Errf(ErrConflict, "approvals changed while publishing; retry the approval")
		}
		now := s.now()
		if _, err := tx.Exec(`UPDATE packages SET state=?, state_reason=?, state_by=?, state_at=? WHERE package_id=?`, to, reason, actor, now, id); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "package." + to, ObjectType: "package", ObjectID: id, PackageID: id,
			Details: map[string]any{"from": from, "to": to, "reason": reason, "sha256": p.SHA256}}); err != nil {
			return err
		}
		if action == "revoke" {
			// No new installs of revoked content. Rollbacks keep running: removing
			// a bad package is often why it was revoked.
			rows, err := tx.Query(`SELECT deployment_id FROM deployments WHERE package_id=? AND state IN ('active','paused') AND operation='install'`, id)
			if err != nil {
				return err
			}
			var ids []string
			for rows.Next() {
				var d string
				rows.Scan(&d)
				ids = append(ids, d)
			}
			rows.Close()
			for _, d := range ids {
				if _, err := tx.Exec(`UPDATE deployments SET state='cancelled', state_reason=?, updated_at=? WHERE deployment_id=?`, "package revoked: "+reason, now, d); err != nil {
					return err
				}
				if err := s.audit(tx, Ev{Actor: actor, Action: "deployment.cancelled", ObjectType: "deployment", ObjectID: d, PackageID: id,
					Details: map[string]any{"reason": "package revoked: " + reason}}); err != nil {
					return err
				}
			}
		}
		out, err = getPackage(ctx, tx, id)
		return err
	})
	out.ApprovalsRequired = s.Policy.required(out.Severity)
	return out, err
}

func approvedBy(p Package, actor string) bool {
	for _, a := range p.Approvals {
		if a.By == actor {
			return true
		}
	}
	return false
}
