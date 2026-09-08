package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cpa-usage-keeper/internal/config"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"gorm.io/gorm"
)

func TestCLIProxyCatalogSyncerCreatesSyntheticUsersAndOpaqueReferences(t *testing.T) {
	db := cliProxyCatalogTestDB(t)
	if err := repository.SyncCPAAPIKeys(db, []string{"sk-one", "sk-two"}, time.Now()); err != nil {
		t.Fatalf("SyncCPAAPIKeys() error = %v", err)
	}
	rows, err := repository.ListActiveCPAAPIKeys(db)
	if err != nil {
		t.Fatalf("ListActiveCPAAPIKeys() error = %v", err)
	}
	if err := repository.UpdateCPAAPIKeyAlias(db, rows[0].ID, "team@example.com"); err != nil {
		t.Fatalf("UpdateCPAAPIKeyAlias() error = %v", err)
	}

	catalog := repository.NewCatalogRepository(db)
	syncer := NewCLIProxyCatalogSyncer(db, catalog, time.Minute)
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce() error = %v", err)
	}
	users, err := catalog.ListActiveSourceUsers(context.Background(), cliProxySourceSystem)
	if err != nil {
		t.Fatalf("ListActiveSourceUsers() error = %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("synthetic users = %d, want 2", len(users))
	}
	for _, user := range users {
		if user.Email != "" || user.NormalizedEmail != "" {
			t.Fatal("CPA alias was persisted as a verified email")
		}
	}
	keys, err := catalog.ListActiveSourceAPIKeys(context.Background(), cliProxySourceSystem)
	if err != nil {
		t.Fatalf("ListActiveSourceAPIKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("catalog keys = %d, want 2", len(keys))
	}
	resolved, err := (CLIProxyUsageKeyResolver{DB: db}).ResolveAPIGroupKeys(context.Background(), cliProxySourceSystem, keys[:1])
	if err != nil {
		t.Fatalf("ResolveAPIGroupKeys() error = %v", err)
	}
	if len(resolved) != 1 || resolved[0] != rows[0].APIKey {
		t.Fatal("resolver did not return the active CPA credential in request memory")
	}
}

func TestCLIProxyUsageKeyResolverRejectsMissingOrInactiveRow(t *testing.T) {
	db := cliProxyCatalogTestDB(t)
	resolver := CLIProxyUsageKeyResolver{DB: db}
	_, err := resolver.ResolveAPIGroupKeys(context.Background(), cliProxySourceSystem, []entities.SourceAPIKey{{UsageGroupRef: "cliproxy:999"}})
	if err == nil {
		t.Fatal("resolver accepted a missing CPA row")
	}
}

func cliProxyCatalogTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := repository.OpenDatabase(config.Config{SQLitePath: filepath.Join(t.TempDir(), "cliproxy-catalog.db")})
	if err != nil {
		t.Fatalf("OpenDatabase() error = %v", err)
	}
	t.Cleanup(func() { closeServiceDB(t, db) })
	return db
}

func closeServiceDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("DB() error = %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
