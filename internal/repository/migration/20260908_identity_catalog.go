package migration

import (
	"fmt"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

func createIdentityCatalogMigration(tx *gorm.DB) error {
	if err := tx.AutoMigrate(
		&entities.ExternalIdentity{},
		&entities.SourceUser{},
		&entities.SourceAPIKey{},
		&entities.IdentitySourceLink{},
		&entities.SourceCatalogSyncState{},
	); err != nil {
		return fmt.Errorf("create identity catalog: %w", err)
	}
	return nil
}
