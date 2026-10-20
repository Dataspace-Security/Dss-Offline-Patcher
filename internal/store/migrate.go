package store

import (
	"database/sql"
	"fmt"
)

// Additive column migrations for databases created by earlier versions.
// New tables are created by the schema (CREATE TABLE IF NOT EXISTS).
var columnMigrations = []struct{ table, column, ddl string }{
	{"endpoints", "cert_serial", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "cert_not_after", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "prev_cert_serial", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "retired_at", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "retired_reason", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "edition", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "reboot_requested_at", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "hardware", "TEXT NOT NULL DEFAULT '{}'"},
	{"deployments", "deadline", "TEXT NOT NULL DEFAULT ''"},
	{"deployments", "max_concurrent", "INTEGER NOT NULL DEFAULT 0"},
	{"deployments", "reboot_policy", "TEXT NOT NULL DEFAULT 'never'"},
	{"deployments", "ignore_windows", "INTEGER NOT NULL DEFAULT 0"},
	{"deployments", "health_checks", "TEXT NOT NULL DEFAULT '[]'"},
	{"deployments", "operation", "TEXT NOT NULL DEFAULT 'install'"},
	{"deployments", "auto_advance", "INTEGER NOT NULL DEFAULT 0"},
	{"targets", "leased_until", "TEXT NOT NULL DEFAULT ''"},
	{"targets", "health", "TEXT NOT NULL DEFAULT ''"},
	{"targets", "health_detail", "TEXT NOT NULL DEFAULT ''"},
	// Consecutive "installer busy" results (not counted as attempts at first).
	{"targets", "busy_tries", "INTEGER NOT NULL DEFAULT 0"},
	{"packages", "superseded_by", "TEXT NOT NULL DEFAULT ''"},
	{"packages", "package_name", "TEXT NOT NULL DEFAULT ''"},
	{"packages", "prerequisites", "TEXT NOT NULL DEFAULT '[]'"},
	{"enrollment_tokens", "max_uses", "INTEGER NOT NULL DEFAULT 1"},
	{"enrollment_tokens", "uses", "INTEGER NOT NULL DEFAULT 0"},
	// Condition alerts: structured details (endpoint_ids) and when the
	// condition cleared (the alert closed itself).
	{"alerts", "details", "TEXT NOT NULL DEFAULT '{}'"},
	{"alerts", "resolved_at", "TEXT NOT NULL DEFAULT ''"},
	// Windows cumulative updates: the build revision once installed.
	{"packages", "expected_ubr", "INTEGER NOT NULL DEFAULT 0"},
	// Verified targets: the inventory line (or OS revision) that proved it.
	{"targets", "evidence", "TEXT NOT NULL DEFAULT ''"},
	// Sessions: oidc (SSO) or password (local users). Older sessions are SSO.
	{"sessions", "source", "TEXT NOT NULL DEFAULT 'oidc'"},
	// Two-person deployment approval: the count required when created (0 =
	// created before approvals existed), the rejection, and activation time.
	{"deployments", "approvals_required", "INTEGER NOT NULL DEFAULT 0"},
	{"deployments", "rejected_by", "TEXT NOT NULL DEFAULT ''"},
	{"deployments", "rejected_at", "TEXT NOT NULL DEFAULT ''"},
	{"deployments", "activated_at", "TEXT NOT NULL DEFAULT ''"},
	// Sessions limited to MFA enrolment (MFA required, not enrolled yet).
	{"sessions", "mfa_enroll_only", "INTEGER NOT NULL DEFAULT 0"},
	// EXE packages (kind exe): the manifest's exe block as JSON ("" = none).
	{"packages", "exe", "TEXT NOT NULL DEFAULT ''"},
	// Sign-in protection (authlimits.go): the account-wide wrong-password
	// window, and the authenticator step's own failure counter and lock.
	{"local_users", "failed_window_start", "TEXT NOT NULL DEFAULT ''"},
	{"mfa", "failed_attempts", "INTEGER NOT NULL DEFAULT 0"},
	{"mfa", "locked_until", "TEXT NOT NULL DEFAULT ''"},
	{"mfa", "lockouts", "INTEGER NOT NULL DEFAULT 0"},
	// Credential steward of a local user: who last set its credentials
	// (created it, reset its password or MFA, changed its role) and when.
	// Approvals from accounts the deployment's creator controls, or from two
	// accounts freshly set up by one person, are refused (deploy_approval.go).
	{"local_users", "cred_set_by", "TEXT NOT NULL DEFAULT ''"},
	{"local_users", "cred_set_at", "TEXT NOT NULL DEFAULT ''"},
	// When a deployment's approved endpoint set was fixed (deployment_scope;
	// "" = not yet, still waiting for approval).
	{"deployments", "scope_at", "TEXT NOT NULL DEFAULT ''"},
}

func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Additive tables added after the base schema (idempotent).
var tableMigrations = []string{
	// Exported acquisition requests (tracked: seen / fulfilled are computed on read).
	`CREATE TABLE IF NOT EXISTS acq_requests(
	  request_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
	  intel_generated_at TEXT NOT NULL DEFAULT '', items TEXT NOT NULL DEFAULT '[]')`,
	`CREATE INDEX IF NOT EXISTS acq_requests_created ON acq_requests(created_at)`,
	// Local (email + password) users.
	localUsersSchema,
	// Deployment and rollback approvals (two different people by default).
	`CREATE TABLE IF NOT EXISTS deployment_approvals(
	  deployment_id TEXT NOT NULL, approver TEXT NOT NULL, reason TEXT NOT NULL, at TEXT NOT NULL,
	  PRIMARY KEY(deployment_id, approver))`,
	// Auditor compliance report profile, one row per saved version.
	reportProfileSchema,
	// Authenticator-app (TOTP) MFA of local users.
	mfaSchema,
	// Auto-download policy (acquisition), one row per saved version.
	acqPolicySchema,
	// Wrong passwords per (account, client address) (authlimits.go).
	loginFailuresSchema,
	// Approved endpoint set of each deployment (deploy_scope.go).
	deploymentScopeSchema,
}

// The role names operator and approver were removed: stored users and
// sessions of earlier versions become user (the role they meant).
var roleRenames = []string{
	`UPDATE users SET role='user' WHERE role IN ('operator','approver')`,
	`UPDATE sessions SET role='user' WHERE role IN ('operator','approver')`,
	`UPDATE local_users SET role='user' WHERE role IN ('operator','approver')`,
}

func migrate(db *sql.DB) error {
	for _, ddl := range tableMigrations {
		if _, err := db.Exec(ddl); err != nil {
			return fmt.Errorf("table migration: %w", err)
		}
	}
	for _, m := range columnMigrations {
		ok, err := hasColumn(db, m.table, m.column)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", m.table, m.column, m.ddl)); err != nil {
				return fmt.Errorf("%s.%s: %w", m.table, m.column, err)
			}
		}
	}
	for _, q := range roleRenames {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("role rename: %w", err)
		}
	}
	// Accounts from before credential stewards: their creator set them up.
	if _, err := db.Exec(`UPDATE local_users SET cred_set_by=created_by, cred_set_at=created_at WHERE cred_set_by=''`); err != nil {
		return fmt.Errorf("credential stewards: %w", err)
	}
	if err := migrateDeploymentScopes(db); err != nil {
		return fmt.Errorf("deployment scopes: %w", err)
	}
	return nil
}
