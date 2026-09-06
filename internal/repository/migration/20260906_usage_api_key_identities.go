package migration

import (
	"fmt"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

func createUsageAPIKeyIdentitiesMigration(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&entities.UsageAPIKeyIdentity{}); err != nil {
		return fmt.Errorf("create usage API key identities: %w", err)
	}
	if tx.Migrator().HasTable(&entities.UsageEvent{}) {
		if err := tx.Exec(`INSERT OR IGNORE INTO usage_api_key_identities (source_system, api_group_key, is_deleted, created_at, updated_at)
			SELECT source_system, api_group_key, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
			FROM usage_events
			WHERE TRIM(source_system) <> '' AND TRIM(api_group_key) <> ''`).Error; err != nil {
			return fmt.Errorf("backfill usage API key identities: %w", err)
		}
	}
	return nil
}
