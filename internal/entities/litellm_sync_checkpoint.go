package entities

import "time"

// LiteLLMSyncCheckpoint records the last fully committed LiteLLM window.
type LiteLLMSyncCheckpoint struct {
	ID        int64     `gorm:"primaryKey"`
	Cursor    time.Time `gorm:"serializer:storageTime;not null"`
	UpdatedAt time.Time `gorm:"serializer:storageTime"`
}
