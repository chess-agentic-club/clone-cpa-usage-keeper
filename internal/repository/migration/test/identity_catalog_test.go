package test

import (
	"path/filepath"
	"testing"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository/migration"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const identityCatalogMigrationVersion = "20260908_create_identity_catalog"
const identityCatalogHardeningMigrationVersion = "20260908_harden_identity_catalog"
const identityCatalogInvariantMigrationVersion = "20260908_enforce_identity_catalog_invariants"

func TestIdentityCatalogMigrationCreatesSchemaWithForeignKeys(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "legacy.db")+"?_foreign_keys=on"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open existing database: %v", err)
	}
	closeMigrationTestDatabase(t, db)
	if err := db.AutoMigrate(&entities.UsageEvent{}); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := migration.MarkAllAsApplied(db); err != nil {
		t.Fatalf("mark historical migrations applied: %v", err)
	}
	if err := db.Table("schema_migrations").Where("version = ?", identityCatalogMigrationVersion).Delete(nil).Error; err != nil {
		t.Fatalf("make catalog migration pending: %v", err)
	}
	if err := db.Table("schema_migrations").Where("version = ?", identityCatalogHardeningMigrationVersion).Delete(nil).Error; err != nil {
		t.Fatalf("make catalog hardening migration pending: %v", err)
	}

	if err := migration.Run(db); err != nil {
		t.Fatalf("run identity catalog migration: %v", err)
	}
	for _, table := range []string{"external_identities", "source_users", "source_api_keys", "identity_source_links", "source_catalog_sync_states"} {
		if !db.Migrator().HasTable(table) {
			t.Fatalf("expected identity catalog table %s", table)
		}
	}
	if err := db.Create(&entities.SourceAPIKey{ID: "key-id", SourceSystem: "litellm", SourceKeyRef: "key-ref", SourceUserID: "missing-user", UsageGroupRef: "group", Active: true}).Error; err == nil {
		t.Fatal("expected source API key foreign key constraint to reject a missing source user")
	}
	otherUser := entities.SourceUser{ID: "other-user", SourceSystem: "other", SourceUserRef: "user-ref", Active: true}
	if err := db.Create(&otherUser).Error; err != nil {
		t.Fatalf("create other-source user: %v", err)
	}
	if err := db.Create(&entities.SourceAPIKey{ID: "cross-source-key", SourceSystem: "litellm", SourceKeyRef: "key-ref", SourceUserID: otherUser.ID, UsageGroupRef: "group", Active: true}).Error; err == nil {
		t.Fatal("expected source API key cross-source owner to be rejected")
	}
	identity := entities.ExternalIdentity{ID: "identity", Issuer: "issuer", Subject: "subject"}
	if err := db.Create(&identity).Error; err != nil {
		t.Fatalf("create external identity: %v", err)
	}
	if err := db.Create(&entities.IdentitySourceLink{ID: "cross-source-link", ExternalIdentityID: identity.ID, SourceSystem: "litellm", SourceUserID: otherUser.ID, MatchMethod: "manual"}).Error; err == nil {
		t.Fatal("expected identity link cross-source owner to be rejected")
	}
}

func TestIdentityCatalogInvariantMigrationRejectsLegacyParentSourceChanges(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "legacy-catalog.db")+"?_foreign_keys=on"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open legacy catalog database: %v", err)
	}
	closeMigrationTestDatabase(t, db)
	for _, statement := range []string{
		`CREATE TABLE source_users (id TEXT PRIMARY KEY, source_system TEXT NOT NULL, source_user_ref TEXT NOT NULL)`,
		`CREATE TABLE source_api_keys (id TEXT PRIMARY KEY, source_system TEXT NOT NULL, source_key_ref TEXT NOT NULL, source_user_id TEXT NOT NULL, usage_group_ref TEXT NOT NULL)`,
		`CREATE TABLE identity_source_links (id TEXT PRIMARY KEY, external_identity_id TEXT NOT NULL, source_system TEXT NOT NULL, source_user_id TEXT NOT NULL, match_method TEXT NOT NULL)`,
		`INSERT INTO source_users (id, source_system, source_user_ref) VALUES ('user-a', 'litellm', 'user-ref')`,
		`INSERT INTO source_api_keys (id, source_system, source_key_ref, source_user_id, usage_group_ref) VALUES ('key-a', 'litellm', 'key-ref', 'user-a', 'group-ref')`,
		`INSERT INTO identity_source_links (id, external_identity_id, source_system, source_user_id, match_method) VALUES ('link-a', 'identity-a', 'litellm', 'user-a', 'manual')`,
	} {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatalf("seed legacy catalog: %v", err)
		}
	}
	if err := migration.MarkAllAsApplied(db); err != nil {
		t.Fatalf("mark migrations applied: %v", err)
	}
	if err := db.Table("schema_migrations").Where("version = ?", identityCatalogInvariantMigrationVersion).Delete(nil).Error; err != nil {
		t.Fatalf("make invariant migration pending: %v", err)
	}
	if err := migration.Run(db); err != nil {
		t.Fatalf("run invariant migration: %v", err)
	}
	if err := db.Exec(`UPDATE source_users SET source_system = 'other' WHERE id = 'user-a'`).Error; err == nil {
		t.Fatal("expected legacy parent source-system update with dependents to fail")
	}
	var sourceSystem string
	if err := db.Table("source_users").Select("source_system").Where("id = ?", "user-a").Scan(&sourceSystem).Error; err != nil {
		t.Fatalf("read legacy source user: %v", err)
	}
	if sourceSystem != "litellm" {
		t.Fatalf("failed parent update must preserve source scope, got %q", sourceSystem)
	}
	if err := db.Exec(`INSERT INTO source_api_keys (id, source_system, source_key_ref, source_user_id, usage_group_ref) VALUES ('key-b', 'litellm', 'key-ref', 'user-a', 'sk-live-example-credential')`).Error; err == nil {
		t.Fatal("expected legacy direct SQL write with credential-shaped usage group to fail")
	}
}
