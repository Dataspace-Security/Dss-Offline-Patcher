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
	{"endpoints", "retired_at", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "retired_reason", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "edition", "TEXT NOT NULL DEFAULT ''"},
	{"endpoints", "reboot_requested_at", "TEXT NOT NULL DEFAULT ''"},
	{"deployments", "deadline", "TEXT NOT NULL DEFAULT ''"},
	{"deployments", "max_concurrent", "INTEGER NOT NULL DEFAULT 0"},
	{"deployments", "reboot_policy", "TEXT NOT NULL DEFAULT 'never'"},
	{"deployments", "ignore_windows", "INTEGER NOT NULL DEFAULT 0"},
	{"deployments", "health_checks", "TEXT NOT NULL DEFAULT '[]'"},
	{"targets", "leased_until", "TEXT NOT NULL DEFAULT ''"},
	{"targets", "health", "TEXT NOT NULL DEFAULT ''"},
	{"targets", "health_detail", "TEXT NOT NULL DEFAULT ''"},
	{"packages", "superseded_by", "TEXT NOT NULL DEFAULT ''"},
	{"packages", "package_name", "TEXT NOT NULL DEFAULT ''"},
	{"packages", "prerequisites", "TEXT NOT NULL DEFAULT '[]'"},
	{"enrollment_tokens", "max_uses", "INTEGER NOT NULL DEFAULT 1"},
	{"enrollment_tokens", "uses", "INTEGER NOT NULL DEFAULT 0"},
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

func migrate(db *sql.DB) error {
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
	return nil
}
