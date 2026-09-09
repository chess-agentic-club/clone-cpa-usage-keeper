package migration

import (
	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

// addUsageEventArchiveExternalFieldsMigration upgrades archives created before
// external usage receipts. It runs as a new version because existing databases
// already recorded the original 20260906 migration.
func addUsageEventArchiveExternalFieldsMigration(tx *gorm.DB) error {
	return addExternalUsageEventFieldsMigration(tx, &entities.UsageEventArchive{})
}
