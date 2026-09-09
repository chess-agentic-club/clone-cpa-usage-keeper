package migration

import (
	"testing"
	"time"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestBackfillCLIProxyUsageSourceSystemIsIdempotentAndExcludesLiteLLM(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&entities.UsageEvent{}, &entities.UsageEventArchive{}); err != nil {
		t.Fatalf("migrate usage event tables: %v", err)
	}
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	hotRows := []entities.UsageEvent{
		{ID: 1, EventKey: "cli-hot", APIGroupKey: "sk-cli-hot", Source: "alice@example.com", Timestamp: now},
		{ID: 2, EventKey: "litellm-hot-source", APIGroupKey: "legacy-key", Source: "litellm", Timestamp: now},
		{ID: 3, EventKey: "litellm-hot-key", APIGroupKey: "litellm:key-ref", Timestamp: now},
		{ID: 4, EventKey: "known-hot", APIGroupKey: "future-key", SourceSystem: "future", Timestamp: now},
	}
	archiveRows := []entities.UsageEventArchive{
		{ID: 11, EventKey: "cli-archive", APIGroupKey: "sk-cli-archive", Source: "provider", Timestamp: now},
		{ID: 12, EventKey: "litellm-archive-source", APIGroupKey: "legacy-key", Source: "litellm", Timestamp: now},
		{ID: 13, EventKey: "litellm-archive-key", APIGroupKey: "litellm:key-ref", Timestamp: now},
		{ID: 14, EventKey: "known-archive", APIGroupKey: "future-key", SourceSystem: "future", Timestamp: now},
	}
	if err := db.Create(&hotRows).Error; err != nil {
		t.Fatalf("seed hot usage events: %v", err)
	}
	if err := db.Create(&archiveRows).Error; err != nil {
		t.Fatalf("seed archived usage events: %v", err)
	}
	if err := db.Table("usage_events").Where("id = ?", 1).UpdateColumn("source_system", nil).Error; err != nil {
		t.Fatalf("seed NULL hot source system: %v", err)
	}

	if err := backfillCLIProxyUsageSourceSystemMigration(db); err != nil {
		t.Fatalf("backfill CLIProxy usage source system: %v", err)
	}
	if err := backfillCLIProxyUsageSourceSystemMigration(db); err != nil {
		t.Fatalf("repeat CLIProxy usage source-system backfill: %v", err)
	}

	assertUsageSourceSystems(t, db, "usage_events", map[int64]string{
		1: "cliproxy", 2: "", 3: "", 4: "future",
	})
	assertUsageSourceSystems(t, db, "usage_events_archive", map[int64]string{
		11: "cliproxy", 12: "", 13: "", 14: "future",
	})
}

func assertUsageSourceSystems(t *testing.T, db *gorm.DB, table string, expected map[int64]string) {
	t.Helper()
	type row struct {
		ID           int64
		SourceSystem string
	}
	var rows []row
	if err := db.Table(table).Select("id, source_system").Order("id ASC").Scan(&rows).Error; err != nil {
		t.Fatalf("load %s source systems: %v", table, err)
	}
	if len(rows) != len(expected) {
		t.Fatalf("%s row count = %d, want %d", table, len(rows), len(expected))
	}
	for _, row := range rows {
		want, ok := expected[row.ID]
		if !ok {
			t.Fatalf("%s returned unexpected id %d", table, row.ID)
		}
		if row.SourceSystem != want {
			t.Fatalf("%s id %d source_system = %q, want %q", table, row.ID, row.SourceSystem, want)
		}
	}
}
