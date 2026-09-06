package entities

import "time"

// UsageAPIKeyIdentity is a source-owned, non-secret API-key identity used only
// for analytics selection and presentation. CPA authentication keys remain in
// CPAAPIKey and are never copied into this catalog.
type UsageAPIKeyIdentity struct {
	ID           int64     `gorm:"primaryKey"`
	SourceSystem string    `gorm:"not null;uniqueIndex:uniq_usage_api_key_identities_source_key,priority:1;index:idx_usage_api_key_identities_source_deleted_key,priority:1"`
	APIGroupKey  string    `gorm:"not null;uniqueIndex:uniq_usage_api_key_identities_source_key,priority:2;index:idx_usage_api_key_identities_source_deleted_key,priority:3"`
	IsDeleted    bool      `gorm:"not null;default:false;index:idx_usage_api_key_identities_source_deleted_key,priority:2"`
	CreatedAt    time.Time `gorm:"serializer:storageTime"`
	UpdatedAt    time.Time `gorm:"serializer:storageTime"`
}
