package migration

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// This is the schema emitted for UsageEventArchive before external usage
// receipts introduced source_system and source-cost fields. Keep it explicit
// so upgrades exercise a real deployed pre-feature database, not AutoMigrate's
// current model.
const legacyUsageEventArchiveSchema = `CREATE TABLE usage_events_archive (
	id integer PRIMARY KEY,
	event_key text,
	api_group_key text,
	provider text,
	endpoint text,
	auth_type text,
	request_id text,
	client_ip text,
	x_forwarded_for text,
	user_agent text,
	model text,
	model_alias text,
	reasoning_effort text NOT NULL DEFAULT '',
	service_tier text NOT NULL DEFAULT '',
	response_service_tier text NOT NULL DEFAULT '',
	executor_type text NOT NULL DEFAULT '',
	timestamp datetime,
	source text,
	auth_index text,
	failed numeric,
	generate numeric NOT NULL DEFAULT true,
	latency_ms integer,
	ttft_ms integer,
	input_tokens integer,
	output_tokens integer,
	reasoning_tokens integer,
	cached_tokens integer,
	cache_read_tokens integer NOT NULL DEFAULT 0,
	cache_creation_tokens integer NOT NULL DEFAULT 0,
	total_tokens integer,
	created_at datetime
)`

func TestArchiveExternalFieldsMigrationUpgradesLegacyArchiveForBackfillAndReplay(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(testSQLiteDSN(filepath.Join(t.TempDir(), "legacy-archive.db"))), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer closeOpenedDatabase(t, db)

	if err := db.AutoMigrate(&entities.UsageEvent{}); err != nil {
		t.Fatalf("create current hot usage_events schema: %v", err)
	}
	if err := db.Exec(legacyUsageEventArchiveSchema).Error; err != nil {
		t.Fatalf("create pre-feature usage_events_archive schema: %v", err)
	}
	for _, column := range []string{"source_system", "cost_usd", "cost_source"} {
		if db.Migrator().HasColumn("usage_events_archive", column) {
			t.Fatalf("pre-feature archive unexpectedly has %s", column)
		}
	}

	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	if err := db.Exec(`INSERT INTO usage_events_archive
		(id, event_key, api_group_key, provider, endpoint, auth_type, request_id, model, timestamp, source, auth_index, failed, input_tokens, output_tokens, total_tokens, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(1), "legacy-archive", "legacy-key", "legacy-provider", "/v1/chat/completions", "apikey", "legacy-request", "legacy-model", now, "legacy-source", "legacy-auth", false, int64(10), int64(20), int64(30), now).Error; err != nil {
		t.Fatalf("seed legacy archive row: %v", err)
	}
	if err := db.Create(&entities.UsageEvent{
		ID:          2,
		EventKey:    "hot-event",
		APIGroupKey: "hot-key",
		Source:      "hot-source",
		RequestID:   "hot-request",
		Model:       "hot-model",
		Timestamp:   now,
		TotalTokens: 40,
	}).Error; err != nil {
		t.Fatalf("seed hot usage event: %v", err)
	}

	if err := MarkAllAsApplied(db); err != nil {
		t.Fatalf("mark existing migrations applied: %v", err)
	}
	if err := db.Table("schema_migrations").Where("version IN ?", []string{
		migrationAddUsageEventArchiveExternalFields,
		migrationBackfillCLIProxyUsageSourceSystem,
	}).Delete(nil).Error; err != nil {
		t.Fatalf("make archive upgrade and source backfill pending: %v", err)
	}
	if err := Run(db); err != nil {
		t.Fatalf("run pending archive upgrade and source backfill: %v", err)
	}
	if err := Run(db); err != nil {
		t.Fatalf("repeat archive upgrade and source backfill: %v", err)
	}
	for _, column := range []string{"source_system", "cost_usd", "cost_source"} {
		if !db.Migrator().HasColumn("usage_events_archive", column) {
			t.Fatalf("expected upgraded archive to have %s", column)
		}
	}

	var legacy struct {
		EventKey     string
		Source       string
		APIGroupKey  string
		SourceSystem string
		CostUSD      sql.NullFloat64
		CostSource   string
		TotalTokens  int64
		Generate     bool
	}
	if err := db.Raw(`SELECT event_key, source, api_group_key, source_system, cost_usd, cost_source, total_tokens, generate
		FROM usage_events_archive WHERE id = ?`, int64(1)).Scan(&legacy).Error; err != nil {
		t.Fatalf("load upgraded archive row: %v", err)
	}
	if legacy.EventKey != "legacy-archive" || legacy.Source != "legacy-source" || legacy.APIGroupKey != "legacy-key" || legacy.TotalTokens != 30 || !legacy.Generate {
		t.Fatalf("legacy archive values changed during upgrade: %+v", legacy)
	}
	if legacy.SourceSystem != "cliproxy" || legacy.CostUSD.Valid || legacy.CostSource != "" {
		t.Fatalf("new archive fields did not preserve defaults/backfill behavior: %+v", legacy)
	}

	if err := backfillCLIProxyUsageSourceSystemMigration(db); err != nil {
		t.Fatalf("backfill upgraded archive source system: %v", err)
	}
	assertUsageSourceSystems(t, db, "usage_events_archive", map[int64]string{1: "cliproxy"})

	targetID, err := LoadUsageAggregationReplayTargetEventID(db)
	if err != nil {
		t.Fatalf("load replay target: %v", err)
	}
	if targetID != 2 {
		t.Fatalf("replay target = %d, want 2", targetID)
	}
	page, err := LoadUsageAggregationReplayEventPage(db, 0, targetID, 10)
	if err != nil {
		t.Fatalf("replay upgraded archive and hot events: %v", err)
	}
	if len(page) != 2 || page[0].ID != 1 || page[1].ID != 2 {
		t.Fatalf("replay rows = %v, want globally ordered ids [1 2]", replayIDs(page))
	}
	if page[0].SourceSystem != "cliproxy" || page[0].EventKey != "legacy-archive" || page[0].TotalTokens != 30 {
		t.Fatalf("archive replay event lost upgraded/backfilled fields: %+v", page[0])
	}
}

func replayIDs(events []entities.UsageEvent) []int64 {
	ids := make([]int64, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.ID)
	}
	return ids
}
