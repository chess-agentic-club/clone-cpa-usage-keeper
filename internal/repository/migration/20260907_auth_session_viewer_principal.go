package migration

import (
	"fmt"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

func addAuthSessionViewerPrincipalMigration(tx *gorm.DB) error {
	if !tx.Migrator().HasTable(&entities.AuthSession{}) {
		return nil
	}
	columns := []struct {
		name  string
		field string
	}{
		{name: "viewer_source_system", field: "ViewerSourceSystem"},
		{name: "viewer_api_group_key", field: "ViewerAPIGroupKey"},
		{name: "viewer_display_name", field: "ViewerDisplayName"},
	}
	for _, column := range columns {
		if tx.Migrator().HasColumn(&entities.AuthSession{}, column.name) {
			continue
		}
		if err := tx.Migrator().AddColumn(&entities.AuthSession{}, column.field); err != nil {
			return fmt.Errorf("add auth_sessions.%s column: %w", column.name, err)
		}
	}
	return nil
}
