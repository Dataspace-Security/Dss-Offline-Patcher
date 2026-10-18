// Package store owns all persistent state (SQLite) and enforces the state
// machines in docs/03-state-model.md. Every state-changing method writes its
// audit event in the same transaction as the change.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid")
	// ErrForbidden: the actor's role does not allow this (HTTP 403).
	ErrForbidden = errors.New("forbidden")
)

// Errf wraps a sentinel with detail so callers can errors.Is() it.
func Errf(sentinel error, format string, a ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, a...))
}

type Store struct {
	db     *sql.DB
	Policy Policy
	// AcqStaleAfter: an acquisition source with no status report for this
	// long is stale (0 = DefaultAcqStaleAfter).
	AcqStaleAfter time.Duration
	// Now is overridable in tests.
	Now func() time.Time

	chain        chainCache
	enrollDenied deniedAudits
	mfaKey       mfaCipher
	gen          atomic.Uint64 // Generation
}

const schema = `
CREATE TABLE IF NOT EXISTS bundles(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bundle_id TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', sequence INTEGER NOT NULL DEFAULT 0,
  key_id TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, filename TEXT NOT NULL, file_sha256 TEXT NOT NULL,
  file_size INTEGER NOT NULL, received_at TEXT NOT NULL, package_count INTEGER NOT NULL DEFAULT 0,
  checks TEXT NOT NULL DEFAULT '[]', error TEXT NOT NULL DEFAULT '',
  manifest BLOB, signature TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX IF NOT EXISTS bundles_validated_id ON bundles(bundle_id) WHERE state='validated';
CREATE INDEX IF NOT EXISTS bundles_file_sha ON bundles(file_sha256);
CREATE TABLE IF NOT EXISTS source_sequences(source TEXT PRIMARY KEY, last_sequence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS packages(
  package_id TEXT PRIMARY KEY, bundle_id TEXT NOT NULL, title TEXT NOT NULL, vendor TEXT NOT NULL,
  kind TEXT NOT NULL, version TEXT NOT NULL, kb TEXT NOT NULL, product_code TEXT NOT NULL,
  severity TEXT NOT NULL, release_date TEXT NOT NULL, supersedes TEXT NOT NULL, applicability TEXT NOT NULL,
  file_name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, source_url TEXT NOT NULL,
  vendor_signature TEXT NOT NULL, quarantine_path TEXT NOT NULL,
  state TEXT NOT NULL, state_reason TEXT NOT NULL DEFAULT '', state_by TEXT NOT NULL DEFAULT '',
  state_at TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS endpoints(
  endpoint_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, os TEXT NOT NULL, os_version TEXT NOT NULL,
  build INTEGER NOT NULL, arch TEXT NOT NULL, groups TEXT NOT NULL, site TEXT NOT NULL,
  owner TEXT NOT NULL DEFAULT '', criticality TEXT NOT NULL DEFAULT '',
  last_seen TEXT NOT NULL, inventory_at TEXT NOT NULL DEFAULT '', reboot_pending INTEGER NOT NULL DEFAULT 0,
  agent_version TEXT NOT NULL, enrolled_at TEXT NOT NULL, secret_hash TEXT NOT NULL UNIQUE,
  inventory TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS enrollment_tokens(
  token_hash TEXT PRIMARY KEY, groups TEXT NOT NULL, site TEXT NOT NULL, expires_at TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, used_at TEXT NOT NULL DEFAULT '', used_by TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS deployments(
  deployment_id TEXT PRIMARY KEY, package_id TEXT NOT NULL, name TEXT NOT NULL, state TEXT NOT NULL,
  emergency INTEGER NOT NULL, justification TEXT NOT NULL, rings TEXT NOT NULL, current_ring INTEGER NOT NULL,
  max_failure_pct INTEGER NOT NULL, max_retries INTEGER NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, state_reason TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS targets(
  deployment_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, package_id TEXT NOT NULL, ring INTEGER NOT NULL,
  state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '',
  exit_code INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL,
  PRIMARY KEY(deployment_id, endpoint_id));
CREATE INDEX IF NOT EXISTS targets_endpoint ON targets(endpoint_id);
CREATE INDEX IF NOT EXISTS targets_ring ON targets(deployment_id, ring, state);
CREATE TABLE IF NOT EXISTS exceptions(
  exception_id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL, package_id TEXT NOT NULL, owner TEXT NOT NULL,
  reason TEXT NOT NULL, compensating_controls TEXT NOT NULL, expires_at TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, revoked_reason TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  object_type TEXT NOT NULL, object_id TEXT NOT NULL, outcome TEXT NOT NULL, package_id TEXT NOT NULL,
  details TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_object ON audit(object_id);
CREATE INDEX IF NOT EXISTS audit_package ON audit(package_id);
-- Append-only: the audit table refuses updates and deletes.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
-- Deletes only during retention pruning of already-exported, checkpointed events.
DROP TRIGGER IF EXISTS audit_no_delete;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit WHEN (SELECT v FROM meta WHERE k='audit_prune') IS NOT '1' BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
`

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite is single-writer; one connection serialises everything and makes
	// the audit hash chain trivially consistent.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema + usersSchema + windowsSchema + transferSchema + alertsSchema + acquisitionSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, Now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) now() string { return s.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- helpers ----

func NewID(prefix string) string {
	b := make([]byte, 6)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func RandomSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func HashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func requireReason(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return Errf(ErrInvalid, "a reason is required")
	}
	return nil
}

// Policy holds organisation rules the store enforces.
type Policy struct {
	// ApprovalsRequired by package severity (default 1). E.g. critical: 2
	// means two different approvers must approve before publication.
	ApprovalsRequired map[string]int
	// SeparationOfDuties: whoever approved a package may not deploy it.
	SeparationOfDuties bool
	// Deadlines from vendor release to required install, by severity
	// (defaults: critical 7d, important 30d, moderate 60d, low 90d).
	Deadlines map[string]time.Duration
	// DeploymentApprovals: distinct approvers (bank user or admin, not the
	// creator) a deployment or rollback needs before it starts. 0 = 2.
	DeploymentApprovals int
	// RequireMFA (config require_mfa): authenticator MFA is required for
	// every local user, super admins included (bank roles always need it).
	RequireMFA bool
}

// DefaultDeploymentApprovals is the approval count when none is configured.
const DefaultDeploymentApprovals = 2

// RequiredDeploymentApprovals is the configured count (default 2).
func (p Policy) RequiredDeploymentApprovals() int {
	if p.DeploymentApprovals > 0 {
		return p.DeploymentApprovals
	}
	return DefaultDeploymentApprovals
}

func (p Policy) required(severity string) int {
	if n := p.ApprovalsRequired[severity]; n > 1 {
		return n
	}
	return 1
}

// BackupTo writes a consistent snapshot of the database (safe while the
// server is running).
func (s *Store) BackupTo(ctx context.Context, path string) error {
	_, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}
