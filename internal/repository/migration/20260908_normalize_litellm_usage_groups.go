package migration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"gorm.io/gorm"
)

// normalizeLegacyLiteLLMUsageGroupsMigration upgrades legacy LiteLLM usage
// identities to the short opaque group used by the catalog. It deliberately
// transforms the historical value in place rather than re-ingesting it, since
// external receipts correctly prevent duplicate event import.
func normalizeLegacyLiteLLMUsageGroupsMigration(tx *gorm.DB) error {
	if tx == nil {
		return fmt.Errorf("normalize LiteLLM usage groups: database is nil")
	}
	groups, err := legacyLiteLLMUsageGroups(tx)
	if err != nil {
		return err
	}
	for _, legacy := range groups {
		canonical, err := normalizedLiteLLMUsageGroup(legacy)
		if err != nil {
			// A malformed legacy value cannot safely identify an owner. Retain its
			// usage only as unattributed data, never as a persisted credential.
			canonical = "litellm:unattributed"
		}
		if canonical == legacy {
			continue
		}
		if err := replaceLegacyLiteLLMUsageGroup(tx, legacy, canonical); err != nil {
			return err
		}
	}
	return nil
}

func legacyLiteLLMUsageGroups(tx *gorm.DB) ([]string, error) {
	tables := []struct {
		name   string
		column string
	}{
		{"usage_events", "api_group_key"},
		{"usage_events_archive", "api_group_key"},
		{"usage_api_key_identities", "api_group_key"},
		{"usage_overview_hourly_stats", "api_group_key"},
		{"usage_overview_daily_stats", "api_group_key"},
		{"usage_activity_stats", "api_group_key"},
		{"usage_latency_stats", "api_group_key"},
		{"auth_sessions", "viewer_api_group_key"},
	}
	seen := map[string]struct{}{}
	for _, table := range tables {
		if !tx.Migrator().HasTable(table.name) || !tx.Migrator().HasColumn(table.name, table.column) {
			continue
		}
		var values []string
		if err := tx.Table(table.name).Distinct(table.column).Where(table.column+" LIKE ?", "litellm:%").Pluck(table.column, &values).Error; err != nil {
			return nil, fmt.Errorf("list legacy LiteLLM usage groups: %w", err)
		}
		for _, value := range values {
			seen[value] = struct{}{}
		}
	}
	groups := make([]string, 0, len(seen))
	for value := range seen {
		groups = append(groups, value)
	}
	return groups, nil
}

func replaceLegacyLiteLLMUsageGroup(tx *gorm.DB, legacy, canonical string) error {
	if err := discardDuplicateLiteLLMRollups(tx, legacy, canonical); err != nil {
		return err
	}
	updates := []struct {
		table  string
		column string
	}{
		{"usage_events", "api_group_key"},
		{"usage_events_archive", "api_group_key"},
		{"usage_overview_hourly_stats", "api_group_key"},
		{"usage_overview_daily_stats", "api_group_key"},
		{"usage_activity_stats", "api_group_key"},
		{"usage_latency_stats", "api_group_key"},
		{"auth_sessions", "viewer_api_group_key"},
	}
	for _, update := range updates {
		if !tx.Migrator().HasTable(update.table) || !tx.Migrator().HasColumn(update.table, update.column) {
			continue
		}
		if err := tx.Table(update.table).Where(update.column+" = ?", legacy).Update(update.column, canonical).Error; err != nil {
			return fmt.Errorf("normalize LiteLLM usage group: %w", err)
		}
	}
	if tx.Migrator().HasTable("usage_api_key_identities") {
		// The projection has a source/key uniqueness constraint. Retain the
		// canonical row if it already exists; raw events remain authoritative.
		if err := tx.Exec(`DELETE FROM usage_api_key_identities
			WHERE source_system = 'litellm' AND api_group_key = ?
			AND EXISTS (SELECT 1 FROM usage_api_key_identities AS canonical WHERE canonical.source_system = 'litellm' AND canonical.api_group_key = ?)`, legacy, canonical).Error; err != nil {
			return fmt.Errorf("deduplicate LiteLLM API key identity: %w", err)
		}
		if err := tx.Table("usage_api_key_identities").Where("source_system = ? AND api_group_key = ?", "litellm", legacy).Update("api_group_key", canonical).Error; err != nil {
			return fmt.Errorf("normalize LiteLLM API key identity: %w", err)
		}
	}
	return nil
}

func discardDuplicateLiteLLMRollups(tx *gorm.DB, legacy, canonical string) error {
	queries := []string{
		`UPDATE usage_overview_hourly_stats AS current_row SET request_count=request_count+(SELECT legacy_row.request_count FROM usage_overview_hourly_stats AS legacy_row WHERE legacy_row.api_group_key=? AND legacy_row.bucket_start=current_row.bucket_start AND legacy_row.model=current_row.model AND legacy_row.auth_index=current_row.auth_index AND legacy_row.model_alias=current_row.model_alias AND legacy_row.service_tier=current_row.service_tier AND legacy_row.response_service_tier=current_row.response_service_tier AND legacy_row.reasoning_effort=current_row.reasoning_effort AND legacy_row.endpoint=current_row.endpoint AND legacy_row.executor_type=current_row.executor_type), total_tokens=total_tokens+(SELECT legacy_row.total_tokens FROM usage_overview_hourly_stats AS legacy_row WHERE legacy_row.api_group_key=? AND legacy_row.bucket_start=current_row.bucket_start AND legacy_row.model=current_row.model AND legacy_row.auth_index=current_row.auth_index AND legacy_row.model_alias=current_row.model_alias AND legacy_row.service_tier=current_row.service_tier AND legacy_row.response_service_tier=current_row.response_service_tier AND legacy_row.reasoning_effort=current_row.reasoning_effort AND legacy_row.endpoint=current_row.endpoint AND legacy_row.executor_type=current_row.executor_type) WHERE current_row.api_group_key=?`,
		`UPDATE usage_overview_daily_stats AS current_row SET request_count=request_count+(SELECT legacy_row.request_count FROM usage_overview_daily_stats AS legacy_row WHERE legacy_row.api_group_key=? AND legacy_row.bucket_start=current_row.bucket_start AND legacy_row.model=current_row.model AND legacy_row.auth_index=current_row.auth_index AND legacy_row.model_alias=current_row.model_alias AND legacy_row.service_tier=current_row.service_tier AND legacy_row.response_service_tier=current_row.response_service_tier AND legacy_row.reasoning_effort=current_row.reasoning_effort AND legacy_row.endpoint=current_row.endpoint AND legacy_row.executor_type=current_row.executor_type), total_tokens=total_tokens+(SELECT legacy_row.total_tokens FROM usage_overview_daily_stats AS legacy_row WHERE legacy_row.api_group_key=? AND legacy_row.bucket_start=current_row.bucket_start AND legacy_row.model=current_row.model AND legacy_row.auth_index=current_row.auth_index AND legacy_row.model_alias=current_row.model_alias AND legacy_row.service_tier=current_row.service_tier AND legacy_row.response_service_tier=current_row.response_service_tier AND legacy_row.reasoning_effort=current_row.reasoning_effort AND legacy_row.endpoint=current_row.endpoint AND legacy_row.executor_type=current_row.executor_type) WHERE current_row.api_group_key=?`,
		`UPDATE usage_activity_stats AS current_row SET total_tokens=total_tokens+(SELECT legacy_row.total_tokens FROM usage_activity_stats AS legacy_row WHERE legacy_row.api_group_key=? AND legacy_row.grain=current_row.grain AND legacy_row.bucket_start=current_row.bucket_start) WHERE current_row.api_group_key=?`,
		`DELETE FROM usage_overview_hourly_stats AS legacy_row WHERE api_group_key = ? AND EXISTS (SELECT 1 FROM usage_overview_hourly_stats AS current_row WHERE current_row.api_group_key = ? AND current_row.bucket_start = legacy_row.bucket_start AND current_row.model = legacy_row.model AND current_row.auth_index = legacy_row.auth_index AND current_row.model_alias = legacy_row.model_alias AND current_row.service_tier = legacy_row.service_tier AND current_row.response_service_tier = legacy_row.response_service_tier AND current_row.reasoning_effort = legacy_row.reasoning_effort AND current_row.endpoint = legacy_row.endpoint AND current_row.executor_type = legacy_row.executor_type)`,
		`DELETE FROM usage_overview_daily_stats AS legacy_row WHERE api_group_key = ? AND EXISTS (SELECT 1 FROM usage_overview_daily_stats AS current_row WHERE current_row.api_group_key = ? AND current_row.bucket_start = legacy_row.bucket_start AND current_row.model = legacy_row.model AND current_row.auth_index = legacy_row.auth_index AND current_row.model_alias = legacy_row.model_alias AND current_row.service_tier = legacy_row.service_tier AND current_row.response_service_tier = legacy_row.response_service_tier AND current_row.reasoning_effort = legacy_row.reasoning_effort AND current_row.endpoint = legacy_row.endpoint AND current_row.executor_type = legacy_row.executor_type)`,
		`DELETE FROM usage_activity_stats AS legacy_row WHERE api_group_key = ? AND EXISTS (SELECT 1 FROM usage_activity_stats AS current_row WHERE current_row.api_group_key = ? AND current_row.grain = legacy_row.grain AND current_row.bucket_start = legacy_row.bucket_start)`,
		`DELETE FROM usage_latency_stats AS legacy_row WHERE api_group_key = ? AND EXISTS (SELECT 1 FROM usage_latency_stats AS current_row WHERE current_row.api_group_key = ? AND current_row.bucket_type = legacy_row.bucket_type AND current_row.bucket_start = legacy_row.bucket_start)`,
	}
	for index, query := range queries {
		args := []any{legacy, canonical}
		if index < 2 {
			args = []any{legacy, legacy, canonical}
		}
		if err := tx.Exec(query, args...).Error; err != nil {
			return fmt.Errorf("reconcile duplicate LiteLLM rollup: %w", err)
		}
	}
	return nil
}

func normalizedLiteLLMUsageGroup(value string) (string, error) {
	value = strings.TrimSpace(value)
	token, found := strings.CutPrefix(value, "litellm:")
	if !found {
		return "", fmt.Errorf("invalid legacy LiteLLM usage group")
	}
	if token == "" || token == "unattributed" {
		return "litellm:unattributed", nil
	}
	if strings.HasPrefix(token, "lkey-") && len(token) == len("lkey-")+base64.RawURLEncoding.EncodedLen(16) {
		if decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "lkey-")); err == nil && len(decoded) == 16 {
			return "litellm:" + token, nil
		}
	}
	canonical, err := canonicalLegacyLiteLLMToken(token)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return "litellm:lkey-" + base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

func canonicalLegacyLiteLLMToken(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("invalid legacy LiteLLM usage group")
	}
	if strings.HasPrefix(value, "sk-") {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:]), nil
	}
	if len(value) == 64 && strings.Trim(value, "0123456789abcdefABCDEF") == "" {
		return strings.ToLower(value), nil
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return "", fmt.Errorf("invalid legacy LiteLLM usage group")
		}
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:]), nil
}
