package test

import (
	"path/filepath"
	"testing"

	"cpa-usage-keeper/internal/auth"
	"cpa-usage-keeper/internal/repository/migration"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const authSessionViewerPrincipalMigrationVersion = "20260907_add_auth_session_viewer_principal"

func TestViewerPrincipalMigrationPreservesLegacyCPAAPIKeySession(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "legacy-auth-sessions.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open existing database: %v", err)
	}
	closeMigrationTestDatabase(t, db)

	if err := db.Exec(`CREATE TABLE auth_sessions (
		token_hash TEXT PRIMARY KEY,
		role TEXT NOT NULL,
		source TEXT NOT NULL,
		alias TEXT NOT NULL DEFAULT '',
		cpa_api_key_id INTEGER,
		login_ip TEXT,
		last_seen_ip TEXT,
		user_agent TEXT,
		last_seen_at DATETIME,
		expires_at DATETIME NOT NULL,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create legacy auth_sessions table: %v", err)
	}
	const token = "legacy-cpa-viewer-token"
	if err := db.Exec(`INSERT INTO auth_sessions
		(token_hash, role, source, cpa_api_key_id, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		auth.SessionTokenHash(token), string(auth.RoleAPIKeyViewer), string(auth.SessionSourceStandard), 42,
		"2030-01-01 00:00:00", "2026-09-07 00:00:00", "2026-09-07 00:00:00",
	).Error; err != nil {
		t.Fatalf("seed legacy CPA viewer session: %v", err)
	}
	if err := migration.MarkAllAsApplied(db); err != nil {
		t.Fatalf("mark migrations applied: %v", err)
	}
	if err := db.Table("schema_migrations").Where("version = ?", authSessionViewerPrincipalMigrationVersion).Delete(nil).Error; err != nil {
		t.Fatalf("make viewer principal migration pending: %v", err)
	}

	if err := migration.Run(db); err != nil {
		t.Fatalf("run viewer principal migration: %v", err)
	}
	for _, column := range []string{"viewer_source_system", "viewer_api_group_key", "viewer_display_name"} {
		if !db.Migrator().HasColumn("auth_sessions", column) {
			t.Fatalf("expected auth_sessions.%s column", column)
		}
	}

	legacy, found, err := auth.NewGormSessionStore(db).Get(token)
	if err != nil {
		t.Fatalf("load legacy CPA viewer session: %v", err)
	}
	if !found || legacy.CPAAPIKeyID != 42 {
		t.Fatalf("expected legacy CPA key ID to remain usable, got found=%t session=%+v", found, legacy)
	}
}
