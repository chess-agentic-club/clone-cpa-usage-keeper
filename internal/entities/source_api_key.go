package entities

import "time"

// SourceAPIKey describes source-owned, validated non-secret references. It
// deliberately has no credential material.
type SourceAPIKey struct {
	ID            string     `gorm:"primaryKey"`
	SourceSystem  string     `gorm:"not null;uniqueIndex:uniq_source_api_keys_system_ref,priority:1;index:idx_source_api_keys_system_active,priority:1"`
	SourceKeyRef  string     `gorm:"not null;uniqueIndex:uniq_source_api_keys_system_ref,priority:2"`
	SourceUserID  string     `gorm:"not null;index"`
	SourceUser    SourceUser `gorm:"foreignKey:SourceSystem,SourceUserID;references:SourceSystem,ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	UsageGroupRef string     `gorm:"not null"`
	DisplayName   string
	Active        bool      `gorm:"not null;default:false;index:idx_source_api_keys_system_active,priority:2"`
	CreatedAt     time.Time `gorm:"serializer:storageTime"`
	UpdatedAt     time.Time `gorm:"serializer:storageTime"`
}
