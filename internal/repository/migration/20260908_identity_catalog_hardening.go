package migration

import (
	"fmt"

	"gorm.io/gorm"
)

// hardenIdentityCatalogMigration protects databases created by the initial
// identity-catalog migration. Fresh schemas also receive composite foreign
// keys from the entity definitions.
func hardenIdentityCatalogMigration(tx *gorm.DB) error {
	statements := []string{
		`CREATE TRIGGER IF NOT EXISTS enforce_source_api_key_owner_insert
		BEFORE INSERT ON source_api_keys
		FOR EACH ROW WHEN NOT EXISTS (
			SELECT 1 FROM source_users WHERE id = NEW.source_user_id AND source_system = NEW.source_system
		)
		BEGIN SELECT RAISE(ABORT, 'source API key owner is outside its source system'); END`,
		`CREATE TRIGGER IF NOT EXISTS enforce_source_api_key_owner_update
		BEFORE UPDATE OF source_system, source_user_id ON source_api_keys
		FOR EACH ROW WHEN NOT EXISTS (
			SELECT 1 FROM source_users WHERE id = NEW.source_user_id AND source_system = NEW.source_system
		)
		BEGIN SELECT RAISE(ABORT, 'source API key owner is outside its source system'); END`,
		`CREATE TRIGGER IF NOT EXISTS enforce_identity_source_link_owner_insert
		BEFORE INSERT ON identity_source_links
		FOR EACH ROW WHEN NOT EXISTS (
			SELECT 1 FROM source_users WHERE id = NEW.source_user_id AND source_system = NEW.source_system
		)
		BEGIN SELECT RAISE(ABORT, 'identity link owner is outside its source system'); END`,
		`CREATE TRIGGER IF NOT EXISTS enforce_identity_source_link_owner_update
		BEFORE UPDATE OF source_system, source_user_id ON identity_source_links
		FOR EACH ROW WHEN NOT EXISTS (
			SELECT 1 FROM source_users WHERE id = NEW.source_user_id AND source_system = NEW.source_system
		)
		BEGIN SELECT RAISE(ABORT, 'identity link owner is outside its source system'); END`,
	}
	for _, statement := range statements {
		if err := tx.Exec(statement).Error; err != nil {
			return fmt.Errorf("create identity catalog ownership trigger: %w", err)
		}
	}
	return nil
}
