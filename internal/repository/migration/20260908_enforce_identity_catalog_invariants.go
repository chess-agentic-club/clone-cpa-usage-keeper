package migration

import (
	"fmt"

	"gorm.io/gorm"
)

const safeSourceReferenceSQL = `length(%s) BETWEEN 1 AND 31 AND %s NOT GLOB '*[^A-Za-z0-9._:-]*' AND lower(%s) NOT LIKE '%%authorization%%' AND lower(%s) NOT LIKE '%%bearer%%' AND lower(%s) NOT LIKE '%%token%%' AND lower(%s) NOT LIKE '%%secret%%' AND lower(%s) NOT LIKE '%%master%%' AND lower(%s) NOT LIKE '%%api_key%%' AND lower(%s) NOT LIKE '%%apikey%%' AND lower(%s) NOT LIKE 'sk-%%' AND length(%s) - length(replace(%s, '.', '')) < 2`

// enforceIdentityCatalogInvariantsMigration adds the database checks that a
// fresh AutoMigrate schema receives through SourceAPIKey. It also blocks legacy
// parent source changes that would otherwise descope dependent rows.
func enforceIdentityCatalogInvariantsMigration(tx *gorm.DB) error {
	keyRefSafe := sourceReferenceCheck("NEW.source_key_ref")
	groupRefSafe := sourceReferenceCheck("NEW.usage_group_ref")
	statements := []string{
		fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS enforce_source_api_key_reference_insert
		BEFORE INSERT ON source_api_keys FOR EACH ROW WHEN NOT (%s AND %s)
		BEGIN SELECT RAISE(ABORT, 'unsafe source API key reference'); END`, keyRefSafe, groupRefSafe),
		fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS enforce_source_api_key_reference_update
		BEFORE UPDATE OF source_key_ref, usage_group_ref ON source_api_keys FOR EACH ROW WHEN NOT (%s AND %s)
		BEGIN SELECT RAISE(ABORT, 'unsafe source API key reference'); END`, keyRefSafe, groupRefSafe),
		`CREATE TRIGGER IF NOT EXISTS enforce_source_user_source_system_update
		BEFORE UPDATE OF source_system ON source_users
		FOR EACH ROW WHEN NEW.source_system <> OLD.source_system AND (
			EXISTS (SELECT 1 FROM source_api_keys WHERE source_user_id = OLD.id) OR
			EXISTS (SELECT 1 FROM identity_source_links WHERE source_user_id = OLD.id)
		)
		BEGIN SELECT RAISE(ABORT, 'source user has source-scoped dependents'); END`,
	}
	for _, statement := range statements {
		if err := tx.Exec(statement).Error; err != nil {
			return fmt.Errorf("create identity catalog invariant trigger: %w", err)
		}
	}
	return nil
}

func sourceReferenceCheck(column string) string {
	return fmt.Sprintf(safeSourceReferenceSQL,
		column, column, column, column, column, column,
		column, column, column, column, column, column,
	)
}
