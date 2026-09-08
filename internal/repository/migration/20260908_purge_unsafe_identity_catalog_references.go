package migration

import (
	"fmt"

	"gorm.io/gorm"
)

// purgeUnsafeIdentityCatalogReferencesMigration removes legacy rows that could
// have stored credential-like material before database safety checks existed.
// Deletion, rather than deactivation, ensures the material is not retained.
func purgeUnsafeIdentityCatalogReferencesMigration(tx *gorm.DB) error {
	keySafe := sourceReferenceCheck("source_key_ref")
	groupSafe := sourceReferenceCheck("usage_group_ref")
	if err := tx.Exec(fmt.Sprintf(`DELETE FROM source_api_keys WHERE NOT (%s AND %s)`, keySafe, groupSafe)).Error; err != nil {
		return fmt.Errorf("purge unsafe source API key references: %w", err)
	}
	return nil
}
