package migration

import (
	"fmt"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

func createExternalUsageReceiptsMigration(tx *gorm.DB) error {
	if err := addExternalUsageEventFieldsMigration(tx, &entities.UsageEvent{}, &entities.UsageEventArchive{}); err != nil {
		return err
	}
	migrator := tx.Migrator()
	if migrator.HasTable(&entities.UsageEvent{}) {
		if !migrator.HasIndex(&entities.UsageEvent{}, "idx_usage_events_source_system_request_id") {
			if err := migrator.CreateIndex(&entities.UsageEvent{}, "idx_usage_events_source_system_request_id"); err != nil {
				return fmt.Errorf("create external usage event index: %w", err)
			}
		}
	}
	if err := tx.AutoMigrate(&entities.ExternalUsageReceipt{}, &entities.LiteLLMSyncCheckpoint{}); err != nil {
		return fmt.Errorf("create external usage receipts: %w", err)
	}
	return nil
}

func addExternalUsageEventFieldsMigration(tx *gorm.DB, models ...any) error {
	migrator := tx.Migrator()
	for _, model := range models {
		if !migrator.HasTable(model) {
			continue
		}
		for _, field := range []string{"SourceSystem", "CostUSD", "CostSource"} {
			if !migrator.HasColumn(model, field) {
				if err := migrator.AddColumn(model, field); err != nil {
					return fmt.Errorf("add external usage event %s: %w", field, err)
				}
			}
		}
	}
	return nil
}
