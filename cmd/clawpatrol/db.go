package main

// SQLite-backed persistent state. Replaces the per-blob JSON files
// (oauth-*.json, onboarded.json, wg-peers.json, gateway.log JSONL)
// with a single ${state_dir}/clawpatrol.db.
//
// Schema migrations run in numbered order on every boot. Most are SQL
// files in migrations/sqlite/. The _schema table tracks the highest version applied;
// migrations <= that number are skipped. Pattern mirrors
// ../unclaw/src/migrations.ts.
//
// Driver: modernc.org/sqlite — pure Go, keeps CGO_ENABLED=0 builds
// working so cross-compilation + the `-trimpath -ldflags='-s -w'`
// release recipe stay unchanged.

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/sqlite/*.sql
var migrationsFS embed.FS

// OpenDB opens (or creates) the SQLite store at path, applies any
// pending migrations, and returns a *sql.DB ready for shared use
// across modules. WAL mode + a generous busy_timeout let many readers
// + a single writer coexist without the Sink goroutine and the
// dashboard editor stepping on each other.
func OpenDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}
	// Tighten file modes after the sqlite driver creates them. The
	// driver creates files at process-umask (commonly 0644), but the
	// DB holds the CA private key, OAuth tokens, and audit log —
	// owner-only is the only correct mode. Idempotent: catches both
	// fresh creates and existing files inherited from older installs.
	// Mitigates security-review F-24.
	tightenDBPerms(path)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// tightenDBPerms chmods the sqlite db file plus its WAL/SHM
// sidecars to 0600. Called after sql.Open + db.Ping. Missing files
// are skipped (the WAL/SHM may not exist yet on fresh boots). Any
// chmod failure is logged but doesn't block startup — the
// warnIfStateLooselyPermissioned tripwire in main.go logs a follow-
// up warning if the mode doesn't stick.
func tightenDBPerms(dbPath string) {
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		err := os.Chmod(p, 0o600)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		log.Printf("warning: chmod %s 0600: %v", p, err)
	}
}

// migrate applies pending SQL and schema repair migrations atomically.
// File names must start with a zero-padded number (0001_*, 0002_*),
// applied in ascending order.
func migrate(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("migrate: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS _schema (version INTEGER NOT NULL)"); err != nil {
		return fmt.Errorf("migrate: create _schema: %w", err)
	}
	current := 0
	if err := tx.QueryRow("SELECT COALESCE(MAX(version), 0) FROM _schema").Scan(&current); err != nil {
		return fmt.Errorf("migrate: read current version: %w", err)
	}
	files, err := fs.ReadDir(migrationsFS, "migrations/sqlite")
	if err != nil {
		return fmt.Errorf("migrate: list migration files: %w", err)
	}
	type m struct {
		num  int
		name string
	}
	var pending []m
	used := map[int]string{peerEnrollmentRepairVersion: peerEnrollmentRepairName}
	if current < peerEnrollmentRepairVersion {
		pending = append(pending, m{num: peerEnrollmentRepairVersion, name: peerEnrollmentRepairName})
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		i := strings.IndexAny(f.Name(), "_-")
		if i <= 0 {
			continue
		}
		n, err := strconv.Atoi(f.Name()[:i])
		if err != nil {
			continue
		}
		if prior, ok := used[n]; ok {
			return fmt.Errorf("migrate: duplicate version %d: %s and %s", n, prior, f.Name())
		}
		used[n] = f.Name()
		if n <= current {
			continue
		}
		pending = append(pending, m{num: n, name: f.Name()})
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].num < pending[j].num })
	for _, p := range pending {
		if err := applySQLiteMigration(tx, p.name); err != nil {
			return fmt.Errorf("migrate %s: apply: %w", p.name, err)
		}
		// Migration files MAY insert their own _schema row (0001
		// does, since it's the first to run). Catch-all here for
		// later migrations that don't.
		var have int
		if err := tx.QueryRow("SELECT COALESCE(MAX(version), 0) FROM _schema").Scan(&have); err != nil {
			return fmt.Errorf("migrate %s: recheck version: %w", p.name, err)
		}
		if have < p.num {
			if _, err := tx.Exec("INSERT INTO _schema (version) VALUES (?)", p.num); err != nil {
				return fmt.Errorf("migrate %s: record version: %w", p.name, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate: commit: %w", err)
	}
	for _, p := range pending {
		log.Printf("[migrate] applied %s", p.name)
	}
	return nil
}

func applySQLiteMigration(tx *sql.Tx, name string) error {
	switch name {
	case peerEnrollmentRepairName:
		return repairPeerEnrollmentSchema(tx)
	// Earlier releases committed their DDL separately from the version
	// marker, so these steps must tolerate a column from a previous attempt.
	case "0020_action_body_state.sql":
		return ensureActionBodyState(tx)
	case "0024_device_node_id.sql":
		return ensureDeviceNodeID(tx)
	}
	body, err := fs.ReadFile(migrationsFS, "migrations/sqlite/"+name)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	_, err = tx.Exec(string(body))
	return err
}
