package migration

import (
	"fmt"

	"gorm.io/gorm"
)

const cliProxyUsageSourceSystem = "cliproxy"

func backfillCLIProxyUsageSourceSystemMigration(tx *gorm.DB) error {
	for _, table := range []string{"usage_events", "usage_events_archive"} {
		if !tx.Migrator().HasTable(table) || !tx.Migrator().HasColumn(table, "source_system") {
			continue
		}
		result := tx.Table(table).
			Where("COALESCE(TRIM(source_system), '') = ''").
			Where("LOWER(TRIM(COALESCE(source, ''))) <> ?", "litellm").
			Where("LOWER(TRIM(COALESCE(api_group_key, ''))) NOT LIKE ?", "litellm:%").
			Update("source_system", cliProxyUsageSourceSystem)
		if result.Error != nil {
			return fmt.Errorf("backfill CLIProxy source system in %s: %w", table, result.Error)
		}
	}
	return nil
}
