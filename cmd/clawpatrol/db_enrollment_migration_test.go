package main

import (
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOpenDBRepairsEnrollmentMigration(t *testing.T) {
	legacyEnrollment, err := os.ReadFile("testdata/sqlite/0020_wg_peer_enrollment.sql")
	if err != nil {
		t.Fatal(err)
	}
	const addDeviceNode = "ALTER TABLE devices ADD COLUMN ts_node_id TEXT"
	const addRequestBodyState = "ALTER TABLE actions ADD COLUMN req_body_state TEXT"
	tests := []struct {
		name     string
		through  int
		stamp    int
		legacy   string
		enrolled bool
		body     bool
		node     bool
	}{
		{name: "fresh"},
		{name: "deployed version 20", through: 19, stamp: 20, legacy: string(legacyEnrollment), enrolled: true},
		{name: "upstream version 24", through: 23, stamp: 24, legacy: addDeviceNode, body: true, node: true},
		{name: "fork version 24", through: 23, stamp: 24, legacy: string(legacyEnrollment), enrolled: true, body: true},
		{name: "interrupted version 20", through: 19, stamp: 19, legacy: addRequestBodyState, body: true},
		{name: "interrupted version 24", through: 23, stamp: 23, legacy: addDeviceNode, body: true, node: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "clawpatrol.db")
			if tt.through != 0 {
				legacy := openMigrationFixture(t, path, tt.through)
				execMigrationFixture(t, legacy, tt.legacy)
				if tt.stamp != tt.through {
					execMigrationFixture(t, legacy, "INSERT INTO _schema (version) VALUES (?)", tt.stamp)
				}
				execMigrationFixture(t, legacy, "INSERT INTO actions (ts_ns, path) VALUES (1, '/preserved')")
				execMigrationFixture(t, legacy, "INSERT INTO devices (id, name, created_ns) VALUES ('192.0.2.1', 'existing', 1)")
				execMigrationFixture(t, legacy, "INSERT INTO wg_peers (pubkey, ip, added_ns) VALUES ('durable', '192.0.2.1', 1)")
				if tt.enrolled {
					execMigrationFixture(t, legacy, `
INSERT INTO wg_peers (pubkey, ip, added_ns, enrolled, subject_key, metadata_json)
VALUES ('enrolled', '192.0.2.2', 2, 1, 'sandbox-subject', '{"source":"fixture"}')`)
				}
				if tt.body {
					execMigrationFixture(t, legacy, "UPDATE actions SET req_body_state = 'stored' WHERE path = '/preserved'")
				}
				if tt.node {
					execMigrationFixture(t, legacy, "UPDATE devices SET ts_node_id = 'node-1' WHERE id = '192.0.2.1'")
				}
				if err := legacy.Close(); err != nil {
					t.Fatal(err)
				}
			}

			for startup := 1; startup <= 2; startup++ {
				db, err := OpenDB(path)
				if err != nil {
					t.Fatalf("startup %d: %v", startup, err)
				}
				t.Cleanup(func() { _ = db.Close() })
				checkMigrationValue(t, db, "1",
					"SELECT COUNT(*) FROM _schema WHERE version = ?", peerEnrollmentRepairVersion)
				for index, column := range map[string]string{
					"wg_peers_subject":     "subject_key",
					"wg_peers_replacement": "replacement_key",
				} {
					checkMigrationValue(t, db, column, "SELECT name FROM pragma_index_info(?)", index)
				}
				checkMigrationValue(t, db, "9", `
SELECT COUNT(*) FROM pragma_table_info('wg_peers')
WHERE name IN ('enrolled', 'subject_key', 'replacement_key', 'display_name', 'owner',
               'profile', 'authorizer_type', 'authorizer_name', 'metadata_json')`)
				checkMigrationValue(t, db, "2", `
SELECT COUNT(*) FROM pragma_table_info('actions') WHERE name IN ('req_body_state', 'resp_body_state')`)
				checkMigrationValue(t, db, "1", `
SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = 'ts_node_id'`)
				if tt.through != 0 {
					wantBody, wantNode := "<null>", "<null>"
					if tt.body {
						wantBody = "stored"
					}
					if tt.node {
						wantNode = "node-1"
					}
					checkMigrationValue(t, db, wantBody+"/<null>", `
SELECT COALESCE(req_body_state, '<null>') || '/' || COALESCE(resp_body_state, '<null>')
FROM actions WHERE path = '/preserved'`)
					checkMigrationValue(t, db, "existing/"+wantNode, `
SELECT name || '/' || COALESCE(ts_node_id, '<null>') FROM devices WHERE id = '192.0.2.1'`)
					checkMigrationValue(t, db, "192.0.2.1/0/{}", `
SELECT ip || '/' || enrolled || '/' || metadata_json FROM wg_peers WHERE pubkey = 'durable'`)
					if tt.enrolled {
						checkMigrationValue(t, db, `1/sandbox-subject/{"source":"fixture"}`, `
SELECT enrolled || '/' || subject_key || '/' || metadata_json FROM wg_peers WHERE pubkey = 'enrolled'`)
					}
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestOpenDBRollsBackEnrollmentMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clawpatrol.db")
	db := openMigrationFixture(t, path, 19)
	// The conflicting table makes the index DDL fail after adding columns.
	execMigrationFixture(t, db, "CREATE TABLE wg_peers_replacement (conflict TEXT)")
	if upgraded, err := OpenDB(path); err == nil {
		_ = upgraded.Close()
		t.Fatal("expected the index name collision to abort the upgrade")
	} else if !strings.Contains(err.Error(), peerEnrollmentRepairName) {
		t.Fatalf("expected failure in enrollment repair, got %v", err)
	}
	checkMigrationValue(t, db, "19", "SELECT MAX(version) FROM _schema")
	checkMigrationValue(t, db, "0", "SELECT COUNT(*) FROM pragma_table_info('actions') WHERE name = 'req_body_state'")
	checkMigrationValue(t, db, "0", "SELECT COUNT(*) FROM pragma_table_info('wg_peers') WHERE name = 'enrolled'")
	checkMigrationValue(t, db, "0", "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'wg_peers_subject'")

	execMigrationFixture(t, db, "DROP TABLE wg_peers_replacement")
	upgraded, err := OpenDB(path)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	checkMigrationValue(t, upgraded, "1",
		"SELECT COUNT(*) FROM _schema WHERE version = ?", peerEnrollmentRepairVersion)
}

func openMigrationFixture(t *testing.T, path string, through int) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	execMigrationFixture(t, db, "CREATE TABLE _schema (version INTEGER NOT NULL)")
	files, err := fs.ReadDir(migrationsFS, "migrations/sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		prefix, _, _ := strings.Cut(file.Name(), "_")
		number, err := strconv.Atoi(prefix)
		if err != nil || number > through {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/sqlite/"+file.Name())
		if err != nil {
			t.Fatal(err)
		}
		execMigrationFixture(t, db, string(body))
		execMigrationFixture(t, db, `
INSERT INTO _schema (version) SELECT ? WHERE ? > COALESCE((SELECT MAX(version) FROM _schema), 0)`,
			number, number)
	}
	return db
}

func execMigrationFixture(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("apply fixture %q: %v", query, err)
	}
}

func checkMigrationValue(t *testing.T, db *sql.DB, want, query string, args ...any) {
	t.Helper()
	var got string
	if err := db.QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	if got != want {
		t.Fatalf("query %q returned %q, want %q", query, got, want)
	}
}
