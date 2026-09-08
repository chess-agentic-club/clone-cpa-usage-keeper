package entities

import "time"

// SourceAPIKey describes source-owned, validated non-secret references. It
// deliberately has no credential material.
type SourceAPIKey struct {
	ID            string     `gorm:"primaryKey"`
	SourceSystem  string     `gorm:"not null;uniqueIndex:uniq_source_api_keys_system_ref,priority:1;index:idx_source_api_keys_system_active,priority:1"`
	SourceKeyRef  string     `gorm:"not null;uniqueIndex:uniq_source_api_keys_system_ref,priority:2;check:chk_source_api_keys_safe_key_ref,length(source_key_ref) BETWEEN 1 AND 31 AND source_key_ref NOT GLOB '*[^A-Za-z0-9._:-]*' AND lower(source_key_ref) NOT LIKE '%authorization%' AND lower(source_key_ref) NOT LIKE '%bearer%' AND lower(source_key_ref) NOT LIKE '%token%' AND lower(source_key_ref) NOT LIKE '%secret%' AND lower(source_key_ref) NOT LIKE '%master%' AND lower(source_key_ref) NOT LIKE '%api_key%' AND lower(source_key_ref) NOT LIKE '%apikey%' AND lower(source_key_ref) NOT LIKE 'sk-%' AND length(source_key_ref) - length(replace(source_key_ref, '.', '')) < 2"`
	SourceUserID  string     `gorm:"not null;index"`
	SourceUser    SourceUser `gorm:"foreignKey:SourceSystem,SourceUserID;references:SourceSystem,ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	UsageGroupRef string     `gorm:"not null;check:chk_source_api_keys_safe_group_ref,length(usage_group_ref) BETWEEN 1 AND 31 AND usage_group_ref NOT GLOB '*[^A-Za-z0-9._:-]*' AND lower(usage_group_ref) NOT LIKE '%authorization%' AND lower(usage_group_ref) NOT LIKE '%bearer%' AND lower(usage_group_ref) NOT LIKE '%token%' AND lower(usage_group_ref) NOT LIKE '%secret%' AND lower(usage_group_ref) NOT LIKE '%master%' AND lower(usage_group_ref) NOT LIKE '%api_key%' AND lower(usage_group_ref) NOT LIKE '%apikey%' AND lower(usage_group_ref) NOT LIKE 'sk-%' AND length(usage_group_ref) - length(replace(usage_group_ref, '.', '')) < 2"`
	DisplayName   string
	Active        bool      `gorm:"not null;default:false;index:idx_source_api_keys_system_active,priority:2"`
	CreatedAt     time.Time `gorm:"serializer:storageTime"`
	UpdatedAt     time.Time `gorm:"serializer:storageTime"`
}
