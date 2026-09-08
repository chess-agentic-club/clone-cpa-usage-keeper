package test

import (
	"path/filepath"
	"testing"
	"time"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository/migration"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const authSessionExternalIdentityMigrationVersion = "20260908_auth_session_external_identity"

func TestAuthSessionExternalIdentityMigrationPreservesLegacySessions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "legacy.db")+"?_foreign_keys=on"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	closeMigrationTestDatabase(t, db)
	if err := migration.MarkAllAsApplied(db); err != nil {
		t.Fatalf("mark migrations applied: %v", err)
	}
	if err := db.Table("schema_migrations").Where("version = ?", authSessionExternalIdentityMigrationVersion).Delete(nil).Error; err != nil {
		t.Fatalf("make external identity migration pending: %v", err)
	}
	now := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	if err := db.Exec(`CREATE TABLE auth_sessions (
		token_hash TEXT PRIMARY KEY,
		role TEXT NOT NULL,
		source TEXT NOT NULL DEFAULT 'standard',
		expires_at DATETIME NOT NULL,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create legacy auth sessions: %v", err)
	}
	if err := db.Exec("INSERT INTO auth_sessions (token_hash, role, source, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", "legacy-hash", "admin", "standard", now.Add(time.Hour), now, now).Error; err != nil {
		t.Fatalf("seed legacy auth session: %v", err)
	}

	if err := migration.Run(db); err != nil {
		t.Fatalf("run external identity migration: %v", err)
	}
	if !db.Migrator().HasColumn(&entities.AuthSession{}, "ExternalIdentityID") {
		t.Fatal("expected auth_sessions.external_identity_id column")
	}
	var row struct {
		TokenHash          string
		ExternalIdentityID string
	}
	if err := db.Table("auth_sessions").Where("token_hash = ?", "legacy-hash").Take(&row).Error; err != nil {
		t.Fatalf("reload legacy auth session: %v", err)
	}
	if row.TokenHash != "legacy-hash" || row.ExternalIdentityID != "" {
		t.Fatalf("legacy session was not preserved benignly: %+v", row)
	}
}
