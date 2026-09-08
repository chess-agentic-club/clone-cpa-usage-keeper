package entities

import "time"

// ExternalIdentity is an authenticated external principal. Issuer and subject
// are the stable identity coordinates; ID is an internal opaque identifier.
type ExternalIdentity struct {
	ID              string `gorm:"primaryKey"`
	Issuer          string `gorm:"not null;uniqueIndex:uniq_external_identities_issuer_subject,priority:1"`
	Subject         string `gorm:"not null;uniqueIndex:uniq_external_identities_issuer_subject,priority:2"`
	Email           string
	NormalizedEmail string `gorm:"index:idx_external_identities_normalized_email"`
	DisplayName     string
	CreatedAt       time.Time `gorm:"serializer:storageTime"`
	UpdatedAt       time.Time `gorm:"serializer:storageTime"`
}
