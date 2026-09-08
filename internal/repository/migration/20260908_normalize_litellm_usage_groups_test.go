package migration

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/latency"
	"cpa-usage-keeper/internal/timeutil"
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
	latencyRow := newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, now, legacy, latencyTestSample{eventID: 1, ttftMS: 100, latencyMS: 500})
	if err := db.Create(&latencyRow).Error; err != nil {
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

func TestNormalizeLegacyLiteLLMUsageGroupsMatchesRollupCollisionsByBucketStart(t *testing.T) {
	db := openNormalizeLiteLLMMigrationTestDB(t)
	legacy := "litellm:legacy-bucket-ref"
	canonical, err := normalizedLiteLLMUsageGroup(legacy)
	if err != nil {
		t.Fatalf("calculate canonical group: %v", err)
	}
	matchingBucket := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	otherBucket := matchingBucket.Add(time.Hour)

	for _, row := range []entities.UsageOverviewHourlyStat{
		{BucketStart: otherBucket, APIGroupKey: canonical, Model: "model", RequestCount: 11},
		{BucketStart: matchingBucket, APIGroupKey: canonical, Model: "model", RequestCount: 2},
		{BucketStart: matchingBucket, APIGroupKey: legacy, Model: "model", RequestCount: 3},
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed hourly rollup: %v", err)
		}
	}
	for _, row := range []entities.UsageOverviewDailyStat{
		{BucketStart: otherBucket, APIGroupKey: canonical, Model: "model", RequestCount: 13},
		{BucketStart: matchingBucket, APIGroupKey: canonical, Model: "model", RequestCount: 5},
		{BucketStart: matchingBucket, APIGroupKey: legacy, Model: "model", RequestCount: 7},
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed daily rollup: %v", err)
		}
	}
	for _, row := range []entities.UsageActivityStat{
		{Grain: entities.UsageActivityGrainDaily, BucketStart: otherBucket, BucketEnd: otherBucket.Add(time.Hour), APIGroupKey: canonical, SuccessCount: 17},
		{Grain: entities.UsageActivityGrainDaily, BucketStart: matchingBucket, BucketEnd: matchingBucket.Add(time.Hour), APIGroupKey: canonical, SuccessCount: 11},
		{Grain: entities.UsageActivityGrainDaily, BucketStart: matchingBucket, BucketEnd: matchingBucket.Add(time.Hour), APIGroupKey: legacy, SuccessCount: 12},
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed activity rollup: %v", err)
		}
	}
	for _, row := range []entities.UsageLatencyStat{
		newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, otherBucket, canonical, latencyTestSample{eventID: 10, ttftMS: 101, latencyMS: 501}),
		newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, matchingBucket, canonical, latencyTestSample{eventID: 11, ttftMS: 102, latencyMS: 502}),
		newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, matchingBucket, legacy, latencyTestSample{eventID: 12, ttftMS: 103, latencyMS: 503}),
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed latency rollup: %v", err)
		}
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		return normalizeLegacyLiteLLMUsageGroupsMigration(tx)
	}); err != nil {
		t.Fatalf("normalize migration: %v", err)
	}

	assertOverviewHourlyRequestCount(t, db, canonical, matchingBucket, 5)
	assertOverviewHourlyRequestCount(t, db, canonical, otherBucket, 11)
	assertOverviewDailyRequestCount(t, db, canonical, matchingBucket, 12)
	assertOverviewDailyRequestCount(t, db, canonical, otherBucket, 13)
	assertActivitySuccessCount(t, db, canonical, matchingBucket, 23)
	assertActivitySuccessCount(t, db, canonical, otherBucket, 17)
	assertLatencySampleCount(t, db, canonical, matchingBucket, 2)
	assertLatencySampleCount(t, db, canonical, otherBucket, 1)
}

func TestNormalizeLegacyLiteLLMUsageGroupsPreservesEveryAggregateField(t *testing.T) {
	db := openNormalizeLiteLLMMigrationTestDB(t)
	legacy := "litellm:legacy-aggregate-ref"
	canonical, err := normalizedLiteLLMUsageGroup(legacy)
	if err != nil {
		t.Fatalf("calculate canonical group: %v", err)
	}
	bucket := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	hourlyTarget := entities.UsageOverviewHourlyStat{BucketStart: bucket, APIGroupKey: canonical, Model: "hourly-model", RequestCount: 1, SuccessCount: 2, FailureCount: 3, InputTokens: 4, OutputTokens: 5, ReasoningTokens: 6, CachedTokens: 7, CacheReadTokens: 8, CacheCreationTokens: 9, TotalTokens: 10, ProviderCostUSD: 1.25, ProviderCostCount: 11}
	hourlyLegacy := entities.UsageOverviewHourlyStat{BucketStart: bucket, APIGroupKey: legacy, Model: "hourly-model", RequestCount: 20, SuccessCount: 21, FailureCount: 22, InputTokens: 23, OutputTokens: 24, ReasoningTokens: 25, CachedTokens: 26, CacheReadTokens: 27, CacheCreationTokens: 28, TotalTokens: 29, ProviderCostUSD: 2.5, ProviderCostCount: 30}
	for _, row := range []entities.UsageOverviewHourlyStat{hourlyTarget, hourlyLegacy} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed hourly rollup: %v", err)
		}
	}

	dailyTarget := entities.UsageOverviewDailyStat{BucketStart: bucket, APIGroupKey: canonical, Model: "daily-model", RequestCount: 2, SuccessCount: 3, FailureCount: 4, InputTokens: 5, OutputTokens: 6, ReasoningTokens: 7, CachedTokens: 8, CacheReadTokens: 9, CacheCreationTokens: 10, TotalTokens: 11, ProviderCostUSD: 1.5, ProviderCostCount: 12}
	dailyLegacy := entities.UsageOverviewDailyStat{BucketStart: bucket, APIGroupKey: legacy, Model: "daily-model", RequestCount: 40, SuccessCount: 41, FailureCount: 42, InputTokens: 43, OutputTokens: 44, ReasoningTokens: 45, CachedTokens: 46, CacheReadTokens: 47, CacheCreationTokens: 48, TotalTokens: 49, ProviderCostUSD: 2.25, ProviderCostCount: 50}
	for _, row := range []entities.UsageOverviewDailyStat{dailyTarget, dailyLegacy} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed daily rollup: %v", err)
		}
	}

	activityTarget := entities.UsageActivityStat{Grain: entities.UsageActivityGrainDaily, BucketStart: bucket, BucketEnd: bucket.Add(24 * time.Hour), APIGroupKey: canonical, SuccessCount: 1, FailureCount: 2, InputTokens: 3, OutputTokens: 4, ReasoningTokens: 5, CacheReadTokens: 6, CacheCreationTokens: 7, TotalTokens: 8}
	activityLegacy := entities.UsageActivityStat{Grain: entities.UsageActivityGrainDaily, BucketStart: bucket, BucketEnd: bucket.Add(24 * time.Hour), APIGroupKey: legacy, SuccessCount: 10, FailureCount: 11, InputTokens: 12, OutputTokens: 13, ReasoningTokens: 14, CacheReadTokens: 15, CacheCreationTokens: 16, TotalTokens: 17}
	for _, row := range []entities.UsageActivityStat{activityTarget, activityLegacy} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed activity rollup: %v", err)
		}
	}

	for _, row := range []entities.UsageLatencyStat{
		newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, bucket, canonical, latencyTestSample{eventID: 20, ttftMS: 100, latencyMS: 800}),
		newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, bucket, legacy,
			latencyTestSample{eventID: 21, ttftMS: 250, latencyMS: 900},
			latencyTestSample{eventID: 22, ttftMS: 400, latencyMS: 1_200}),
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed latency rollup: %v", err)
		}
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		return normalizeLegacyLiteLLMUsageGroupsMigration(tx)
	}); err != nil {
		t.Fatalf("normalize migration: %v", err)
	}

	var hourly entities.UsageOverviewHourlyStat
	if err := db.Where("api_group_key = ? AND model = ?", canonical, "hourly-model").First(&hourly).Error; err != nil {
		t.Fatalf("load hourly rollup: %v", err)
	}
	if hourly.RequestCount != 21 || hourly.SuccessCount != 23 || hourly.FailureCount != 25 || hourly.InputTokens != 27 || hourly.OutputTokens != 29 || hourly.ReasoningTokens != 31 || hourly.CachedTokens != 33 || hourly.CacheReadTokens != 35 || hourly.CacheCreationTokens != 37 || hourly.TotalTokens != 39 || hourly.ProviderCostUSD != 3.75 || hourly.ProviderCostCount != 41 {
		t.Fatalf("hourly aggregate fields were not preserved: %+v", hourly)
	}

	var daily entities.UsageOverviewDailyStat
	if err := db.Where("api_group_key = ? AND model = ?", canonical, "daily-model").First(&daily).Error; err != nil {
		t.Fatalf("load daily rollup: %v", err)
	}
	if daily.RequestCount != 42 || daily.SuccessCount != 44 || daily.FailureCount != 46 || daily.InputTokens != 48 || daily.OutputTokens != 50 || daily.ReasoningTokens != 52 || daily.CachedTokens != 54 || daily.CacheReadTokens != 56 || daily.CacheCreationTokens != 58 || daily.TotalTokens != 60 || daily.ProviderCostUSD != 3.75 || daily.ProviderCostCount != 62 {
		t.Fatalf("daily aggregate fields were not preserved: %+v", daily)
	}

	var activity entities.UsageActivityStat
	if err := db.Where("api_group_key = ?", canonical).First(&activity).Error; err != nil {
		t.Fatalf("load activity rollup: %v", err)
	}
	if activity.SuccessCount != 11 || activity.FailureCount != 13 || activity.InputTokens != 15 || activity.OutputTokens != 17 || activity.ReasoningTokens != 19 || activity.CacheReadTokens != 21 || activity.CacheCreationTokens != 23 || activity.TotalTokens != 25 {
		t.Fatalf("activity aggregate fields were not preserved: %+v", activity)
	}

	var latencyRow entities.UsageLatencyStat
	if err := db.Where("api_group_key = ?", canonical).First(&latencyRow).Error; err != nil {
		t.Fatalf("load latency rollup: %v", err)
	}
	if latencyRow.SampleCount != 3 || latencyRow.MaxTTFTMS != 400 || latencyRow.MaxLatencyMS != 1_200 || latencyRow.FormatVersion != latency.FormatVersion {
		t.Fatalf("latency scalar fields were not preserved: %+v", latencyRow)
	}
	ttftSketch, err := latency.UnmarshalSketch(latencyRow.TTFTSketch)
	if err != nil || ttftSketch.Count() != 3 {
		t.Fatalf("merged TTFT sketch count = %d, error=%v", ttftSketch.Count(), err)
	}
	latencySketch, err := latency.UnmarshalSketch(latencyRow.LatencySketch)
	if err != nil || latencySketch.Count() != 3 {
		t.Fatalf("merged latency sketch count = %d, error=%v", latencySketch.Count(), err)
	}
	points, err := latency.UnmarshalSampleSet(latencyRow.SamplePoints)
	if err != nil {
		t.Fatalf("decode merged sample points: %v", err)
	}
	gotPoints := points.Points()
	if len(gotPoints) != 3 {
		t.Fatalf("merged sample point count = %d, want 3", len(gotPoints))
	}
	pointValues := make(map[int64][2]int64, len(gotPoints))
	for _, point := range gotPoints {
		pointValues[point.EventID] = [2]int64{point.TTFTMS, point.LatencyMS}
	}
	for eventID, want := range map[int64][2]int64{20: {100, 800}, 21: {250, 900}, 22: {400, 1_200}} {
		if got, exists := pointValues[eventID]; !exists || got != want {
			t.Fatalf("merged sample %d = %v, exists=%t, want %v", eventID, got, exists, want)
		}
	}
}

func TestNormalizeLegacyLiteLLMUsageGroupsRejectsInvalidLatencyRowsAtomically(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*entities.UsageLatencyStat)
	}{
		{name: "format version", mutate: func(row *entities.UsageLatencyStat) { row.FormatVersion = latency.FormatVersion + 1 }},
		{name: "negative sample count", mutate: func(row *entities.UsageLatencyStat) { row.SampleCount = -1 }},
		{name: "nonpositive TTFT maximum", mutate: func(row *entities.UsageLatencyStat) { row.MaxTTFTMS = 0 }},
		{name: "nonpositive latency maximum", mutate: func(row *entities.UsageLatencyStat) { row.MaxLatencyMS = 0 }},
		{name: "TTFT encoding", mutate: func(row *entities.UsageLatencyStat) { row.TTFTSketch = []byte{} }},
		{name: "latency encoding", mutate: func(row *entities.UsageLatencyStat) { row.LatencySketch = []byte{} }},
		{name: "sample encoding", mutate: func(row *entities.UsageLatencyStat) { row.SamplePoints = []byte{} }},
		{name: "sketch count consistency", mutate: func(row *entities.UsageLatencyStat) { row.SampleCount = 2 }},
		{name: "sample cardinality", mutate: func(row *entities.UsageLatencyStat) {
			samples := latency.NewSampleSet()
			if err := samples.Add(31, 100, 500); err != nil {
				t.Fatalf("add first excess sample: %v", err)
			}
			if err := samples.Add(32, 110, 510); err != nil {
				t.Fatalf("add second excess sample: %v", err)
			}
			encoded, err := samples.MarshalBinary()
			if err != nil {
				t.Fatalf("encode excess samples: %v", err)
			}
			row.SamplePoints = encoded
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := openNormalizeLiteLLMMigrationTestDB(t)
			legacy := "litellm:legacy-invalid-ref"
			canonical, err := normalizedLiteLLMUsageGroup(legacy)
			if err != nil {
				t.Fatalf("calculate canonical group: %v", err)
			}
			bucket := time.Date(2026, 9, 8, 15, 0, 0, 0, time.UTC)
			if err := db.Create(&entities.UsageEvent{APIGroupKey: legacy, SourceSystem: "litellm", Timestamp: bucket}).Error; err != nil {
				t.Fatalf("seed usage event: %v", err)
			}
			for _, row := range []entities.UsageOverviewHourlyStat{
				{BucketStart: bucket, APIGroupKey: canonical, Model: "model", RequestCount: 2},
				{BucketStart: bucket, APIGroupKey: legacy, Model: "model", RequestCount: 3},
			} {
				if err := db.Create(&row).Error; err != nil {
					t.Fatalf("seed hourly rollup: %v", err)
				}
			}
			invalid := newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, bucket, legacy, latencyTestSample{eventID: 30, ttftMS: 100, latencyMS: 500})
			test.mutate(&invalid)
			if err := db.Create(&invalid).Error; err != nil {
				t.Fatalf("seed invalid latency rollup: %v", err)
			}

			err = db.Transaction(func(tx *gorm.DB) error {
				return normalizeLegacyLiteLLMUsageGroupsMigration(tx)
			})
			if err == nil {
				t.Fatal("expected invalid latency row to abort migration")
			}

			assertNormalizeLiteLLMMigrationRolledBack(t, db, legacy, canonical, bucket)
			assertLatencySampleCount(t, db, legacy, bucket, invalid.SampleCount)
			assertLatencyRowCount(t, db, canonical, bucket, 0)
		})
	}
}

func TestNormalizeLegacyLiteLLMUsageGroupsRejectsInvalidCanonicalLatencyCollisionAtomically(t *testing.T) {
	db := openNormalizeLiteLLMMigrationTestDB(t)
	legacy := "litellm:legacy-invalid-target-ref"
	canonical, err := normalizedLiteLLMUsageGroup(legacy)
	if err != nil {
		t.Fatalf("calculate canonical group: %v", err)
	}
	bucket := time.Date(2026, 9, 8, 15, 30, 0, 0, time.UTC)
	if err := db.Create(&entities.UsageEvent{APIGroupKey: legacy, SourceSystem: "litellm", Timestamp: bucket}).Error; err != nil {
		t.Fatalf("seed usage event: %v", err)
	}
	for _, row := range []entities.UsageOverviewHourlyStat{
		{BucketStart: bucket, APIGroupKey: canonical, Model: "model", RequestCount: 2},
		{BucketStart: bucket, APIGroupKey: legacy, Model: "model", RequestCount: 3},
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed hourly rollup: %v", err)
		}
	}
	invalidTarget := newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, bucket, canonical, latencyTestSample{eventID: 35, ttftMS: 100, latencyMS: 500})
	invalidTarget.FormatVersion = latency.FormatVersion + 1
	legacyRow := newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, bucket, legacy, latencyTestSample{eventID: 36, ttftMS: 110, latencyMS: 510})
	for _, row := range []entities.UsageLatencyStat{invalidTarget, legacyRow} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed latency rollup: %v", err)
		}
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		return normalizeLegacyLiteLLMUsageGroupsMigration(tx)
	})
	if err == nil {
		t.Fatal("expected invalid canonical latency row to abort migration")
	}

	assertNormalizeLiteLLMMigrationRolledBack(t, db, legacy, canonical, bucket)
	assertLatencySampleCount(t, db, canonical, bucket, 1)
	assertLatencySampleCount(t, db, legacy, bucket, 1)
}

func TestNormalizeLegacyLiteLLMUsageGroupsRejectsLatencySampleCountOverflowAtomically(t *testing.T) {
	db := openNormalizeLiteLLMMigrationTestDB(t)
	legacy := "litellm:legacy-overflow-ref"
	canonical, err := normalizedLiteLLMUsageGroup(legacy)
	if err != nil {
		t.Fatalf("calculate canonical group: %v", err)
	}
	bucket := time.Date(2026, 9, 8, 16, 0, 0, 0, time.UTC)
	if err := db.Create(&entities.UsageEvent{APIGroupKey: legacy, SourceSystem: "litellm", Timestamp: bucket}).Error; err != nil {
		t.Fatalf("seed usage event: %v", err)
	}
	for _, row := range []entities.UsageOverviewHourlyStat{
		{BucketStart: bucket, APIGroupKey: canonical, Model: "model", RequestCount: 2},
		{BucketStart: bucket, APIGroupKey: legacy, Model: "model", RequestCount: 3},
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed hourly rollup: %v", err)
		}
	}
	emptySamples, err := latency.NewSampleSet().MarshalBinary()
	if err != nil {
		t.Fatalf("encode empty sample set: %v", err)
	}
	for _, row := range []entities.UsageLatencyStat{
		{BucketType: entities.UsageLatencyBucketHour, BucketStart: bucket, APIGroupKey: canonical, SampleCount: math.MaxInt64, MaxTTFTMS: 100, MaxLatencyMS: 500, FormatVersion: latency.FormatVersion, TTFTSketch: migrationTestSketchWithCount(math.MaxInt64), LatencySketch: migrationTestSketchWithCount(math.MaxInt64), SamplePoints: emptySamples},
		newMigrationTestLatencyRow(t, entities.UsageLatencyBucketHour, bucket, legacy, latencyTestSample{eventID: 40, ttftMS: 110, latencyMS: 510}),
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed latency rollup: %v", err)
		}
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		return normalizeLegacyLiteLLMUsageGroupsMigration(tx)
	})
	if err == nil {
		t.Fatal("expected latency sample count overflow to abort migration")
	}

	assertNormalizeLiteLLMMigrationRolledBack(t, db, legacy, canonical, bucket)
	assertLatencySampleCount(t, db, canonical, bucket, math.MaxInt64)
	assertLatencySampleCount(t, db, legacy, bucket, 1)
}

type latencyTestSample struct {
	eventID   int64
	ttftMS    int64
	latencyMS int64
}

func openNormalizeLiteLLMMigrationTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(entities.All()...); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	return db
}

func newMigrationTestLatencyRow(t *testing.T, bucketType entities.UsageLatencyBucketType, bucketStart time.Time, apiGroupKey string, samples ...latencyTestSample) entities.UsageLatencyStat {
	t.Helper()
	ttftSketch := latency.NewSketch()
	latencySketch := latency.NewSketch()
	samplePoints := latency.NewSampleSet()
	var maxTTFTMS int64
	var maxLatencyMS int64
	for _, sample := range samples {
		if err := ttftSketch.Add(sample.ttftMS); err != nil {
			t.Fatalf("add TTFT sample: %v", err)
		}
		if err := latencySketch.Add(sample.latencyMS); err != nil {
			t.Fatalf("add latency sample: %v", err)
		}
		if err := samplePoints.Add(sample.eventID, sample.ttftMS, sample.latencyMS); err != nil {
			t.Fatalf("add paired latency sample: %v", err)
		}
		maxTTFTMS = max(maxTTFTMS, sample.ttftMS)
		maxLatencyMS = max(maxLatencyMS, sample.latencyMS)
	}
	ttftEncoded, err := ttftSketch.MarshalBinary()
	if err != nil {
		t.Fatalf("encode TTFT sketch: %v", err)
	}
	latencyEncoded, err := latencySketch.MarshalBinary()
	if err != nil {
		t.Fatalf("encode latency sketch: %v", err)
	}
	samplesEncoded, err := samplePoints.MarshalBinary()
	if err != nil {
		t.Fatalf("encode sample points: %v", err)
	}
	return entities.UsageLatencyStat{BucketType: bucketType, BucketStart: bucketStart, APIGroupKey: apiGroupKey, SampleCount: int64(len(samples)), MaxTTFTMS: maxTTFTMS, MaxLatencyMS: maxLatencyMS, FormatVersion: latency.FormatVersion, TTFTSketch: ttftEncoded, LatencySketch: latencyEncoded, SamplePoints: samplesEncoded}
}

func migrationTestSketchWithCount(count int64) []byte {
	encoded := []byte{latency.FormatVersion}
	encoded = binary.AppendUvarint(encoded, 1)
	encoded = binary.AppendUvarint(encoded, 0)
	return binary.AppendUvarint(encoded, uint64(count))
}

func assertOverviewHourlyRequestCount(t *testing.T, db *gorm.DB, group string, bucket time.Time, want int64) {
	t.Helper()
	var row entities.UsageOverviewHourlyStat
	if err := db.Where("api_group_key = ? AND bucket_start = ?", group, timeutil.FormatStorageTime(bucket)).First(&row).Error; err != nil {
		t.Fatalf("load hourly rollup: %v", err)
	}
	if row.RequestCount != want {
		t.Fatalf("hourly request count for %v = %d, want %d", bucket, row.RequestCount, want)
	}
}

func assertOverviewDailyRequestCount(t *testing.T, db *gorm.DB, group string, bucket time.Time, want int64) {
	t.Helper()
	var row entities.UsageOverviewDailyStat
	if err := db.Where("api_group_key = ? AND bucket_start = ?", group, timeutil.FormatStorageTime(bucket)).First(&row).Error; err != nil {
		t.Fatalf("load daily rollup: %v", err)
	}
	if row.RequestCount != want {
		t.Fatalf("daily request count for %v = %d, want %d", bucket, row.RequestCount, want)
	}
}

func assertActivitySuccessCount(t *testing.T, db *gorm.DB, group string, bucket time.Time, want int64) {
	t.Helper()
	var row entities.UsageActivityStat
	if err := db.Where("api_group_key = ? AND bucket_start = ?", group, timeutil.FormatSortableStorageTime(bucket)).First(&row).Error; err != nil {
		t.Fatalf("load activity rollup: %v", err)
	}
	if row.SuccessCount != want {
		t.Fatalf("activity success count for %v = %d, want %d", bucket, row.SuccessCount, want)
	}
}

func assertLatencySampleCount(t *testing.T, db *gorm.DB, group string, bucket time.Time, want int64) {
	t.Helper()
	var row entities.UsageLatencyStat
	if err := db.Where("api_group_key = ? AND bucket_start = ?", group, timeutil.FormatStorageTime(bucket)).First(&row).Error; err != nil {
		t.Fatalf("load latency rollup: %v", err)
	}
	if row.SampleCount != want {
		t.Fatalf("latency sample count for %v = %d, want %d", bucket, row.SampleCount, want)
	}
}

func assertLatencyRowCount(t *testing.T, db *gorm.DB, group string, bucket time.Time, want int64) {
	t.Helper()
	var count int64
	if err := db.Model(&entities.UsageLatencyStat{}).Where("api_group_key = ? AND bucket_start = ?", group, timeutil.FormatStorageTime(bucket)).Count(&count).Error; err != nil {
		t.Fatalf("count latency rollups: %v", err)
	}
	if count != want {
		t.Fatalf("latency rollup count for %v = %d, want %d", bucket, count, want)
	}
}

func assertNormalizeLiteLLMMigrationRolledBack(t *testing.T, db *gorm.DB, legacy, canonical string, bucket time.Time) {
	t.Helper()
	var legacyEvents int64
	if err := db.Model(&entities.UsageEvent{}).Where("api_group_key = ?", legacy).Count(&legacyEvents).Error; err != nil || legacyEvents != 1 {
		t.Fatalf("legacy event count after rollback = %d, error=%v", legacyEvents, err)
	}
	assertOverviewHourlyRequestCount(t, db, canonical, bucket, 2)
	assertOverviewHourlyRequestCount(t, db, legacy, bucket, 3)
}
