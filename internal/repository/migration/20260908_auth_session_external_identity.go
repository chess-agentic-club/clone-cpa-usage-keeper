package migration

import (
	"fmt"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

func addAuthSessionExternalIdentityMigration(tx *gorm.DB) error {
	if !tx.Migrator().HasTable(&entities.AuthSession{}) || tx.Migrator().HasColumn(&entities.AuthSession{}, "ExternalIdentityID") {
		return nil
	}
	if err := tx.Migrator().AddColumn(&entities.AuthSession{}, "ExternalIdentityID"); err != nil {
		return fmt.Errorf("add auth_sessions.external_identity_id column: %w", err)
	}
	return nil
}
