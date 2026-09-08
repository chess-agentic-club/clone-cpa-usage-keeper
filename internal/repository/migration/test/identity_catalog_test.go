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
