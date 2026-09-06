package repository

import (
	"context"
	"fmt"
	"strings"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ListActiveUsageAPIKeyIdentities returns only source-owned analytics keys.
// Unlike CPAAPIKey, these values are never authentication credentials.
func ListActiveUsageAPIKeyIdentities(ctx context.Context, db *gorm.DB) ([]entities.UsageAPIKeyIdentity, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	var identities []entities.UsageAPIKeyIdentity
	if err := db.WithContext(ctx).
		Where("is_deleted = ?", false).
		Order("source_system ASC, api_group_key ASC, id ASC").
		Find(&identities).Error; err != nil {
		return nil, fmt.Errorf("list active usage API key identities: %w", err)
	}
	return identities, nil
}

// FindActiveUsageAPIKeyIdentityByID resolves an opaque external filter ID.
func FindActiveUsageAPIKeyIdentityByID(ctx context.Context, db *gorm.DB, id int64) (entities.UsageAPIKeyIdentity, error) {
	if db == nil {
		return entities.UsageAPIKeyIdentity{}, fmt.Errorf("database is nil")
	}
	if id <= 0 {
		return entities.UsageAPIKeyIdentity{}, gorm.ErrRecordNotFound
	}
	var identity entities.UsageAPIKeyIdentity
	if err := db.WithContext(ctx).Where("id = ? AND is_deleted = ?", id, false).First(&identity).Error; err != nil {
		return entities.UsageAPIKeyIdentity{}, err
	}
	return identity, nil
}

func upsertExternalUsageAPIKeyIdentity(tx *gorm.DB, sourceSystem, apiGroupKey string) error {
	sourceSystem = strings.TrimSpace(sourceSystem)
	apiGroupKey = strings.TrimSpace(apiGroupKey)
	if sourceSystem == "" || apiGroupKey == "" {
		return nil
	}
	identity := entities.UsageAPIKeyIdentity{SourceSystem: sourceSystem, APIGroupKey: apiGroupKey}
	if err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "source_system"}, {Name: "api_group_key"}},
		DoUpdates: clause.Assignments(map[string]any{"is_deleted": false}),
	}).Create(&identity).Error; err != nil {
		return fmt.Errorf("upsert external usage API key identity: %w", err)
	}
	return nil
}
