package repository

import (
	"fmt"
	"strings"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/timeutil"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// InsertExternalUsageEvents atomically persists polling-source events once per source/request ID.
func InsertExternalUsageEvents(db *gorm.DB, source string, events []entities.UsageEvent) ([]entities.UsageEvent, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, fmt.Errorf("source system is required")
	}
	inserted := make([]entities.UsageEvent, 0, len(events))
	err := db.Transaction(func(tx *gorm.DB) error {
		for _, event := range events {
			requestID := strings.TrimSpace(event.RequestID)
			if requestID == "" {
				return fmt.Errorf("external request ID is required")
			}
			receipt := entities.ExternalUsageReceipt{SourceSystem: source, ExternalRequestID: requestID}
			result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&receipt)
			if result.Error != nil {
				return fmt.Errorf("insert external receipt: %w", result.Error)
			}
			if result.RowsAffected == 0 {
				continue
			}
			event.SourceSystem = source
			if err := upsertExternalUsageAPIKeyIdentity(tx, source, event.APIGroupKey); err != nil {
				return err
			}
			event.Timestamp = timeutil.NormalizeStorageTime(event.Timestamp)
			if err := tx.Create(&event).Error; err != nil {
				return fmt.Errorf("insert external usage event: %w", err)
			}
			inserted = append(inserted, event)
		}
		return nil
	})
	return inserted, err
}
