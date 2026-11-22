package main

import (
	"database/sql"
	"fmt"
)

const (
	peerEnrollmentRepairVersion = 25
	peerEnrollmentRepairName    = "0025_reconcile_peer_enrollment"
)

type migrationColumn struct {
	name        string
	declaration string
}

func ensureActionBodyState(tx *sql.Tx) error {
	return addMissingMigrationColumns(tx, "actions", []migrationColumn{
		{"req_body_state", "TEXT"},
		{"resp_body_state", "TEXT"},
	})
}

func ensureDeviceNodeID(tx *sql.Tx) error {
	return addMissingMigrationColumns(tx, "devices", []migrationColumn{
		{"ts_node_id", "TEXT"},
	})
}

// Fork releases used version 20 and later 24 for enrollment. Upstream
// used those versions for action body state and Tailscale device identity.
// Inspect the tables since the version marker cannot distinguish those histories.
func repairPeerEnrollmentSchema(tx *sql.Tx) error {
	if err := ensureActionBodyState(tx); err != nil {
		return err
	}
	if err := ensureDeviceNodeID(tx); err != nil {
		return err
	}
	if err := addMissingMigrationColumns(tx, "wg_peers", []migrationColumn{
		{"enrolled", "INTEGER NOT NULL DEFAULT 0"},
		{"subject_key", "TEXT"},
		{"replacement_key", "TEXT"},
		{"display_name", "TEXT"},
		{"owner", "TEXT"},
		{"profile", "TEXT"},
		{"authorizer_type", "TEXT"},
		{"authorizer_name", "TEXT"},
		{"metadata_json", "TEXT NOT NULL DEFAULT '{}'"},
	}); err != nil {
		return err
	}
	_, err := tx.Exec(`
CREATE INDEX IF NOT EXISTS wg_peers_subject ON wg_peers(subject_key);
CREATE INDEX IF NOT EXISTS wg_peers_replacement ON wg_peers(replacement_key);
`)
	return err
}

func addMissingMigrationColumns(tx *sql.Tx, table string, columns []migrationColumn) error {
	rows, err := tx.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", table, err)
	}
	have := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inspect %s: %w", table, err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect %s: %w", table, err)
	}

	for _, col := range columns {
		if have[col.name] {
			continue
		}
		// Table names and declarations come only from the migration above.
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, col.name, col.declaration)
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("add %s.%s: %w", table, col.name, err)
		}
	}
	return nil
}
