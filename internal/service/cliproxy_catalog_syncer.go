package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"gorm.io/gorm"
)

const cliProxySourceSystem = "cliproxy"

// CLIProxyCatalogSyncer projects active local CPA credentials into catalog rows
// without copying the credential into the catalog. Each credential has a
// synthetic, email-less user so aliases never become verified identities.
type CLIProxyCatalogSyncer struct {
	db       *gorm.DB
	catalog  *repository.CatalogRepository
	interval time.Duration
	now      func() time.Time
	mu       sync.Mutex
}

func NewCLIProxyCatalogSyncer(db *gorm.DB, catalog *repository.CatalogRepository, interval time.Duration) *CLIProxyCatalogSyncer {
	return &CLIProxyCatalogSyncer{db: db, catalog: catalog, interval: interval, now: time.Now}
}

func (s *CLIProxyCatalogSyncer) Run(ctx context.Context) error {
	if s == nil || s.interval <= 0 {
		return fmt.Errorf("CLIProxy catalog sync interval must be positive")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// ApplySourceSnapshot is atomic: an unsuccessful cycle preserves the
			// last completed catalog.
			_ = s.SyncOnce(ctx)
		}
	}
}

func (s *CLIProxyCatalogSyncer) SyncOnce(ctx context.Context) error {
	if s == nil || s.db == nil || s.catalog == nil {
		return fmt.Errorf("CLIProxy catalog syncer is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := repository.ListActiveCPAAPIKeys(s.db)
	if err != nil {
		return fmt.Errorf("list active CPA API keys: %w", err)
	}
	users := make([]repository.SourceUserInput, 0, len(rows))
	keys := make([]repository.SourceAPIKeyInput, 0, len(rows))
	userRefs := make([]string, 0, len(rows))
	keyRefs := make([]string, 0, len(rows))
	for _, row := range rows {
		userRef, keyRef := cliProxyCatalogReferences(row.ID)
		userRefs, keyRefs = append(userRefs, userRef), append(keyRefs, keyRef)
		displayName := cliProxyCatalogDisplayName(row.KeyAlias, row.APIKey)
		users = append(users, repository.SourceUserInput{SourceUserRef: userRef, DisplayName: displayName, Active: true})
		keys = append(keys, repository.SourceAPIKeyInput{SourceKeyRef: keyRef, SourceUserRef: userRef, UsageGroupRef: keyRef, DisplayName: displayName, Active: true})
	}
	if err := scrubAbsentCLIProxyCatalogLabels(s.db, userRefs, keyRefs); err != nil {
		return fmt.Errorf("scrub inactive CLIProxy catalog labels: %w", err)
	}
	return s.catalog.ApplySourceSnapshot(ctx, repository.SourceCatalogSnapshot{SourceSystem: cliProxySourceSystem, Users: users, Keys: keys, SyncedAt: s.now()})
}

func scrubAbsentCLIProxyCatalogLabels(db *gorm.DB, userRefs, keyRefs []string) error {
	users := db.Model(&entities.SourceUser{}).Where("source_system = ?", cliProxySourceSystem)
	keys := db.Model(&entities.SourceAPIKey{}).Where("source_system = ?", cliProxySourceSystem)
	if len(userRefs) > 0 {
		users = users.Where("source_user_ref NOT IN ?", userRefs)
	}
	if len(keyRefs) > 0 {
		keys = keys.Where("source_key_ref NOT IN ?", keyRefs)
	}
	if err := users.Update("display_name", "CLIProxy key").Error; err != nil {
		return err
	}
	return keys.Update("display_name", "CLIProxy key").Error
}

func cliProxyCatalogDisplayName(alias, credential string) string {
	alias = strings.TrimSpace(alias)
	credential = strings.TrimSpace(credential)
	if alias == "" || credential == "" {
		return "CLIProxy key"
	}
	if strings.Contains(alias, credential) || strings.HasPrefix(strings.ToLower(alias), "sk-") || looksLikeCPAKeyHash(alias) {
		return "CLIProxy key"
	}
	encoded := []string{
		base64.StdEncoding.EncodeToString([]byte(credential)),
		base64.RawStdEncoding.EncodeToString([]byte(credential)),
		base64.URLEncoding.EncodeToString([]byte(credential)),
		base64.RawURLEncoding.EncodeToString([]byte(credential)),
	}
	for _, value := range encoded {
		if value != "" && strings.Contains(alias, value) {
			return "CLIProxy key"
		}
	}
	return alias
}

func looksLikeCPAKeyHash(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F') || (character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func cliProxyCatalogReferences(id int64) (string, string) {
	rowID := strconv.FormatInt(id, 10)
	return "cliproxy-user:" + rowID, "cliproxy:" + rowID
}

// CLIProxyUsageKeyResolver retrieves the original CPA credential only while a
// trusted server-side usage query is being assembled. It never writes the
// credential into catalog rows or returns it to a browser-facing caller.
type CLIProxyUsageKeyResolver struct{ DB *gorm.DB }

func (r CLIProxyUsageKeyResolver) ResolveAPIGroupKeys(_ context.Context, sourceSystem string, keys []entities.SourceAPIKey) ([]string, error) {
	if r.DB == nil || strings.TrimSpace(sourceSystem) != cliProxySourceSystem {
		return nil, fmt.Errorf("CLIProxy source mismatch")
	}
	resolved := make([]string, 0, len(keys))
	for _, key := range keys {
		if key.SourceSystem != "" && key.SourceSystem != cliProxySourceSystem {
			return nil, fmt.Errorf("CLIProxy catalog key source mismatch")
		}
		rowID, err := cliProxyCatalogRowID(key.UsageGroupRef)
		if err != nil {
			return nil, err
		}
		row, err := repository.FindActiveCPAAPIKeyByID(r.DB, rowID)
		if err != nil || strings.TrimSpace(row.APIKey) == "" {
			return nil, fmt.Errorf("active CLIProxy key is unavailable")
		}
		resolved = append(resolved, row.APIKey)
	}
	return resolved, nil
}

func cliProxyCatalogRowID(ref string) (int64, error) {
	rowID, found := strings.CutPrefix(strings.TrimSpace(ref), "cliproxy:")
	if !found || rowID == "" {
		return 0, fmt.Errorf("invalid CLIProxy catalog reference")
	}
	id, err := strconv.ParseInt(rowID, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid CLIProxy catalog reference")
	}
	return id, nil
}
