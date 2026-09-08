package entities

import "time"

// SourceUser is a user from one source system. SourceUserRef is a source
// entity reference, never an authentication credential.
type SourceUser struct {
	ID              string `gorm:"primaryKey;uniqueIndex:uniq_source_users_system_id,priority:2"`
	SourceSystem    string `gorm:"not null;uniqueIndex:uniq_source_users_system_ref,priority:1;uniqueIndex:uniq_source_users_system_id,priority:1;index:idx_source_users_system_email_active,priority:1"`
	SourceUserRef   string `gorm:"not null;uniqueIndex:uniq_source_users_system_ref,priority:2"`
	Email           string
	NormalizedEmail string `gorm:"index:idx_source_users_system_email_active,priority:2"`
	DisplayName     string
	Active          bool      `gorm:"not null;default:false;index:idx_source_users_system_email_active,priority:3"`
	CreatedAt       time.Time `gorm:"serializer:storageTime"`
	UpdatedAt       time.Time `gorm:"serializer:storageTime"`
}
