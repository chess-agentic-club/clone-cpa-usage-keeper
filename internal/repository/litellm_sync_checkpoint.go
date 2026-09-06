package repository

import (
	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

func LoadLiteLLMSyncCheckpoint(db *gorm.DB) (entities.LiteLLMSyncCheckpoint, error) {
	var checkpoint entities.LiteLLMSyncCheckpoint
	err := db.First(&checkpoint, 1).Error
	if err == gorm.ErrRecordNotFound {
		return entities.LiteLLMSyncCheckpoint{ID: 1}, nil
	}
	return checkpoint, err
}

func SaveLiteLLMSyncCheckpoint(db *gorm.DB, checkpoint entities.LiteLLMSyncCheckpoint) error {
	checkpoint.ID = 1
	return db.Save(&checkpoint).Error
}
