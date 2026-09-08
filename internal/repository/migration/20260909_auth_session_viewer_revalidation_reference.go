package migration

import (
	"fmt"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

func addAuthSessionViewerRevalidationReferenceMigration(tx *gorm.DB) error {
	if !tx.Migrator().HasTable(&entities.AuthSession{}) || tx.Migrator().HasColumn(&entities.AuthSession{}, "ViewerRevalidationRef") {
		return nil
	}
	if err := tx.Migrator().AddColumn(&entities.AuthSession{}, "ViewerRevalidationRef"); err != nil {
		return fmt.Errorf("add auth_sessions.viewer_revalidation_ref column: %w", err)
	}
	return nil
}
