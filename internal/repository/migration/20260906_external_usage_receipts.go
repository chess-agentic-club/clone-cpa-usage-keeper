package migration

import (
	"fmt"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

func createExternalUsageReceiptsMigration(tx *gorm.DB) error {
	migrator := tx.Migrator()
	if migrator.HasTable(&entities.UsageEvent{}) {
		for _, field := range []string{"SourceSystem", "CostUSD", "CostSource"} {
			if !migrator.HasColumn(&entities.UsageEvent{}, field) {
				if err := migrator.AddColumn(&entities.UsageEvent{}, field); err != nil {
					return fmt.Errorf("add usage event %s: %w", field, err)
				}
			}
		}
		if !migrator.HasIndex(&entities.UsageEvent{}, "idx_usage_events_source_system_request_id") {
			if err := migrator.CreateIndex(&entities.UsageEvent{}, "idx_usage_events_source_system_request_id"); err != nil {
				return fmt.Errorf("create external usage event index: %w", err)
			}
		}
	}
	if err := tx.AutoMigrate(&entities.ExternalUsageReceipt{}); err != nil {
		return fmt.Errorf("create external usage receipts: %w", err)
	}
	return nil
}
