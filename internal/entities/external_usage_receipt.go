package entities

import "time"

// ExternalUsageReceipt makes polling sources idempotent independently of legacy CPA ingestion.
type ExternalUsageReceipt struct {
	ID                int64     `gorm:"primaryKey"`
	SourceSystem      string    `gorm:"not null;uniqueIndex:uniq_external_usage_receipts_source_request,priority:1"`
	ExternalRequestID string    `gorm:"not null;uniqueIndex:uniq_external_usage_receipts_source_request,priority:2"`
	CreatedAt         time.Time `gorm:"serializer:storageTime"`
}
