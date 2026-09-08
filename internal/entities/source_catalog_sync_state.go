package entities

import "time"

// SourceCatalogSyncState records only a successfully committed source snapshot.
type SourceCatalogSyncState struct {
	SourceSystem  string    `gorm:"primaryKey"`
	LastSuccessAt time.Time `gorm:"not null;serializer:storageTime"`
	UserCount     int       `gorm:"not null"`
	KeyCount      int       `gorm:"not null"`
}
