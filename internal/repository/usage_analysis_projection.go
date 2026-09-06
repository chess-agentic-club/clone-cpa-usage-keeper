package repository

import (
	"fmt"
	"strings"
	"time"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/helper"
	"cpa-usage-keeper/internal/pricing"
	"cpa-usage-keeper/internal/repository/dto"
	"cpa-usage-keeper/internal/timeutil"

	"gorm.io/gorm"
)

// analysisOverviewStatProjection 同时承接 hourly 与 daily 聚合表的 Analysis 窄投影。
type analysisOverviewStatProjection struct {
	BucketStart         time.Time
	APIGroupKey         string
	Model               string
	AuthIndex           string
	ModelAlias          string
	ServiceTier         string
	ResponseServiceTier string
	ReasoningEffort     string
	Endpoint            string
	ExecutorType        string
	RequestCount        int64
	InputTokens         int64
	OutputTokens        int64
	ReasoningTokens     int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	TotalTokens         int64
	ProviderCostUSD     float64
	ProviderCostCount   int64
}

var analysisOverviewProjectionFixedColumns = [...]string{
	"bucket_start",
	"api_group_key",
	"model",
	"auth_index",
	"model_alias",
	"request_count",
	"input_tokens",
	"output_tokens",
	"reasoning_tokens",
	"cache_read_tokens",
	"cache_creation_tokens",
	"total_tokens",
	"provider_cost_usd",
	"provider_cost_count",
}

func analysisOverviewProjectionColumns(activeFields pricing.ActiveFields) string {
	columns := make([]string, 0, len(analysisOverviewProjectionFixedColumns)+activeFields.Len())
	seen := make(map[string]struct{}, len(analysisOverviewProjectionFixedColumns)+activeFields.Len())
	for _, column := range analysisOverviewProjectionFixedColumns {
		columns = append(columns, column)
		seen[column] = struct{}{}
	}
	// 价格维度只能来自编译后的固定枚举；展示必需列已固定读取，这里只追加实际启用且未重复的条件列。
	for _, column := range UsagePricingDimensionColumns(activeFields) {
		if _, ok := seen[column]; ok {
			continue
		}
		columns = append(columns, column)
		seen[column] = struct{}{}
	}
	return strings.Join(columns, ", ")
}

func loadAnalysisOverviewHourlyStatsWithFilter(db *gorm.DB, filter dto.UsageQueryFilter, start, end time.Time, activeFields pricing.ActiveFields) ([]analysisOverviewStatProjection, error) {
	query := queryActiveUsageAPIKeyStats(db.Model(&entities.UsageOverviewHourlyStat{}), "usage_overview_hourly_stats")
	return loadAnalysisOverviewStatProjection(query, filter, start, end, "hourly", activeFields)
}

func loadAnalysisOverviewDailyStatsWithFilter(db *gorm.DB, filter dto.UsageQueryFilter, start, end time.Time, activeFields pricing.ActiveFields) ([]analysisOverviewStatProjection, error) {
	query := queryActiveUsageAPIKeyStats(db.Model(&entities.UsageOverviewDailyStat{}), "usage_overview_daily_stats")
	return loadAnalysisOverviewStatProjection(query, filter, start, end, "daily", activeFields)
}

func queryActiveUsageAPIKeyStats(query *gorm.DB, table string) *gorm.DB {
	// Correlated EXISTS preserves the narrow rollup projection while accepting
	// either an active CPA key or a source-owned non-secret analytics identity.
	return query.Where(
		"EXISTS (SELECT 1 FROM cpa_api_keys WHERE cpa_api_keys.api_key = "+table+".api_group_key AND cpa_api_keys.is_deleted = ?) OR EXISTS (SELECT 1 FROM usage_api_key_identities WHERE usage_api_key_identities.api_group_key = "+table+".api_group_key AND usage_api_key_identities.is_deleted = ?)",
		false,
		false,
	)
}

func loadAnalysisOverviewStatProjection(query *gorm.DB, filter dto.UsageQueryFilter, start, end time.Time, grain string, activeFields pricing.ActiveFields) ([]analysisOverviewStatProjection, error) {
	rows := make([]analysisOverviewStatProjection, 0)
	query = query.
		Select(analysisOverviewProjectionColumns(activeFields)).
		Where("bucket_start >= ? AND bucket_start < ?", timeutil.FormatStorageTime(start), timeutil.FormatStorageTime(end)).
		Order("bucket_start asc")
	if apiGroupKey := strings.TrimSpace(filter.APIGroupKey); apiGroupKey != "" {
		query = query.Where("api_group_key = ?", apiGroupKey)
	}
	if err := query.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("load usage overview %s stats: %w", grain, err)
	}
	return rows, nil
}

func calculateAnalysisOverviewProjectionCost(costResolver pricing.Resolver, row analysisOverviewStatProjection) pricing.CostResult {
	if row.ProviderCostCount == row.RequestCount && row.RequestCount > 0 {
		return pricing.CostResult{Available: true, Cost: helper.UsageTokenCostBreakdown{TotalCostUSD: row.ProviderCostUSD}, PricingStyle: "provider_reported"}
	}
	return costResolver.Calculate(newUsagePricingCostSubject(
		row.APIGroupKey,
		row.Model,
		row.AuthIndex,
		row.ModelAlias,
		row.ServiceTier,
		row.ResponseServiceTier,
		row.ReasoningEffort,
		row.Endpoint,
		row.ExecutorType,
		row.InputTokens,
		row.OutputTokens,
		row.CacheReadTokens,
		row.CacheCreationTokens,
	))
}
