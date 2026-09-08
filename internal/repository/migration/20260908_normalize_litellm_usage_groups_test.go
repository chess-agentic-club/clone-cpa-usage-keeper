package migration

import (
	"strings"
	"testing"
	"time"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNormalizeLegacyLiteLLMUsageGroupsMigratesAllPersistedProjections(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(entities.All()...); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	legacy := "litellm:" + strings.Repeat("a", 64)
	now := time.Now()
	if err := db.Create(&entities.UsageEvent{APIGroupKey: legacy, SourceSystem: "litellm", Timestamp: now}).Error; err != nil {
		t.Fatalf("seed usage event: %v", err)
	}
	if err := db.Create(&entities.UsageEvent{APIGroupKey: "litellm:", SourceSystem: "litellm", Timestamp: now}).Error; err != nil {
		t.Fatalf("seed unattributed usage event: %v", err)
	}
	if err := db.Create(&entities.UsageEventArchive{ID: 1, APIGroupKey: legacy, SourceSystem: "litellm", Timestamp: now}).Error; err != nil {
		t.Fatalf("seed usage archive: %v", err)
	}
	if err := db.Create(&entities.UsageAPIKeyIdentity{SourceSystem: "litellm", APIGroupKey: legacy}).Error; err != nil {
		t.Fatalf("seed API key identity: %v", err)
	}
	if err := db.Create(&entities.AuthSession{TokenHash: "session", Role: "viewer", Source: "api-key", ViewerSourceSystem: "litellm", ViewerAPIGroupKey: legacy, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := db.Create(&entities.UsageOverviewHourlyStat{BucketStart: now, APIGroupKey: legacy, Model: "model", RequestCount: 1, TotalTokens: 1}).Error; err != nil {
		t.Fatalf("seed hourly rollup: %v", err)
	}
	if err := db.Create(&entities.UsageOverviewDailyStat{BucketStart: now, APIGroupKey: legacy, Model: "model", RequestCount: 1, TotalTokens: 1}).Error; err != nil {
		t.Fatalf("seed daily rollup: %v", err)
	}
	if err := db.Create(&entities.UsageActivityStat{Grain: entities.UsageActivityGrainDaily, BucketStart: now, BucketEnd: now.Add(time.Hour), APIGroupKey: legacy}).Error; err != nil {
		t.Fatalf("seed activity rollup: %v", err)
	}
	if err := db.Create(&entities.UsageLatencyStat{BucketType: entities.UsageLatencyBucketHour, BucketStart: now, APIGroupKey: legacy, TTFTSketch: []byte{}, LatencySketch: []byte{}, SamplePoints: []byte{}}).Error; err != nil {
		t.Fatalf("seed latency rollup: %v", err)
	}
	canonical, err := normalizedLiteLLMUsageGroup(legacy)
	if err != nil {
		t.Fatalf("calculate canonical group: %v", err)
	}
	if err := db.Create(&entities.UsageOverviewHourlyStat{BucketStart: now, APIGroupKey: canonical, Model: "model", RequestCount: 2}).Error; err != nil {
		t.Fatalf("seed colliding hourly rollup: %v", err)
	}
	if err := db.Create(&entities.UsageOverviewDailyStat{BucketStart: now, APIGroupKey: canonical, Model: "model", RequestCount: 2}).Error; err != nil {
		t.Fatalf("seed colliding daily rollup: %v", err)
	}
	if err := db.Create(&entities.UsageActivityStat{Grain: entities.UsageActivityGrainDaily, BucketStart: now, BucketEnd: now.Add(time.Hour), APIGroupKey: canonical, TotalTokens: 2}).Error; err != nil {
		t.Fatalf("seed colliding activity rollup: %v", err)
	}

	if err := normalizeLegacyLiteLLMUsageGroupsMigration(db); err != nil {
		t.Fatalf("normalize migration: %v", err)
	}
	if err := normalizeLegacyLiteLLMUsageGroupsMigration(db); err != nil {
		t.Fatalf("idempotent normalize migration: %v", err)
	}
	for _, table := range []string{"usage_events", "usage_events_archive", "usage_api_key_identities", "usage_overview_hourly_stats", "usage_overview_daily_stats", "usage_activity_stats", "usage_latency_stats"} {
		var count int64
		if err := db.Table(table).Where("api_group_key = ?", canonical).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("%s canonical group count = %d, error=%v", table, count, err)
		}
	}
	var hourly entities.UsageOverviewHourlyStat
	if err := db.Where("api_group_key = ?", canonical).First(&hourly).Error; err != nil || hourly.RequestCount != 3 || hourly.TotalTokens != 1 {
		t.Fatal("hourly collision was not reconciled")
	}
	var unattributed int64
	if err := db.Model(&entities.UsageEvent{}).Where("api_group_key = ?", "litellm:unattributed").Count(&unattributed).Error; err != nil || unattributed != 1 {
		t.Fatalf("unattributed usage event count = %d, error=%v", unattributed, err)
	}
	var sessions int64
	if err := db.Model(&entities.AuthSession{}).Where("viewer_api_group_key = ?", canonical).Count(&sessions).Error; err != nil || sessions != 1 {
		t.Fatalf("canonical session count = %d, error=%v", sessions, err)
	}
	for _, table := range []string{"usage_events", "usage_events_archive", "usage_api_key_identities", "usage_overview_hourly_stats", "usage_overview_daily_stats", "usage_activity_stats", "usage_latency_stats"} {
		var count int64
		if err := db.Table(table).Where("api_group_key = ?", legacy).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("%s retained legacy group", table)
		}
	}
}
