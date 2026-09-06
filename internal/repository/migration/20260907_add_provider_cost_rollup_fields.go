package migration

import "gorm.io/gorm"

func addProviderCostRollupFieldsMigration(db *gorm.DB) error {
	for _, table := range []string{"usage_overview_hourly_stats", "usage_overview_daily_stats"} {
		if !db.Migrator().HasColumn(table, "provider_cost_usd") {
			if err := db.Exec("ALTER TABLE " + table + " ADD COLUMN provider_cost_usd REAL NOT NULL DEFAULT 0").Error; err != nil {
				return err
			}
		}
		if !db.Migrator().HasColumn(table, "provider_cost_count") {
			if err := db.Exec("ALTER TABLE " + table + " ADD COLUMN provider_cost_count INTEGER NOT NULL DEFAULT 0").Error; err != nil {
				return err
			}
		}
	}
	return nil
}
