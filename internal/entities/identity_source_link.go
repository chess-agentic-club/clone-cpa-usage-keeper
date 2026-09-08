package entities

import "time"

// IdentitySourceLink associates one external identity with at most one source
// user per source system.
type IdentitySourceLink struct {
	ID                 string           `gorm:"primaryKey"`
	ExternalIdentityID string           `gorm:"not null;uniqueIndex:uniq_identity_source_links_identity_system,priority:1"`
	ExternalIdentity   ExternalIdentity `gorm:"foreignKey:ExternalIdentityID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	SourceSystem       string           `gorm:"not null;uniqueIndex:uniq_identity_source_links_identity_system,priority:2;index"`
	SourceUserID       string           `gorm:"not null;index"`
	SourceUser         SourceUser       `gorm:"foreignKey:SourceUserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	MatchMethod        string           `gorm:"not null"`
	Confirmed          bool             `gorm:"not null;default:false"`
	CreatedAt          time.Time        `gorm:"serializer:storageTime"`
	UpdatedAt          time.Time        `gorm:"serializer:storageTime"`
}
