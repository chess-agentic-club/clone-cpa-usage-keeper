package poller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
)

const (
	liteLLMCatalogMaxPages = 10000
	liteLLMUnownedUserRef  = "unowned"
	liteLLMOpaqueKeyPrefix = "lkey-"
)

var ErrInvalidLiteLLMKeyRef = errors.New("invalid LiteLLM key reference")

// LiteLLMCatalogClient is the restricted master-key HTTP surface used for a
// complete catalog refresh. It deliberately exposes no filtered user lookup.
type LiteLLMCatalogClient interface {
	ListUsers(context.Context, int, int) (LiteLLMUserPage, error)
	ListKeys(context.Context, int, int) (LiteLLMKeyPage, error)
}

// LiteLLMCatalogRunner fetches both paginated LiteLLM catalogs before applying
// their single atomic source snapshot.
type LiteLLMCatalogRunner struct {
	client   LiteLLMCatalogClient
	catalog  *repository.CatalogRepository
	interval time.Duration
	pageSize int
	now      func() time.Time
	mu       sync.Mutex
}

func NewLiteLLMCatalogRunner(client LiteLLMCatalogClient, catalog *repository.CatalogRepository, interval time.Duration, pageSize int) *LiteLLMCatalogRunner {
	return &LiteLLMCatalogRunner{client: client, catalog: catalog, interval: interval, pageSize: pageSize, now: time.Now}
}

func (r *LiteLLMCatalogRunner) Run(ctx context.Context) error {
	if r == nil || r.interval <= 0 {
		return fmt.Errorf("LiteLLM catalog sync interval must be positive")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// A failed refresh leaves the prior atomic snapshot intact. The next
			// interval retries without disrupting the serving process.
			_ = r.SyncOnce(ctx)
		}
	}
}

func (r *LiteLLMCatalogRunner) SyncOnce(ctx context.Context) error {
	if r == nil || r.client == nil || r.catalog == nil {
		return fmt.Errorf("LiteLLM catalog runner is not initialized")
	}
	if r.pageSize <= 0 || r.pageSize > liteLLMMaxCatalogPageSize {
		return fmt.Errorf("LiteLLM catalog page size is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	users, err := r.listUsers(ctx)
	if err != nil {
		return err
	}
	keys, needsUnownedUser, err := r.listKeys(ctx, users)
	if err != nil {
		return err
	}
	if needsUnownedUser {
		users = append(users, repository.SourceUserInput{SourceUserRef: liteLLMUnownedUserRef, DisplayName: "Unowned LiteLLM keys", Active: false})
	}
	return r.catalog.ApplySourceSnapshot(ctx, repository.SourceCatalogSnapshot{
		SourceSystem: liteLLMSourceSystem,
		Users:        users,
		Keys:         keys,
		SyncedAt:     r.now(),
	})
}

func (r *LiteLLMCatalogRunner) listUsers(ctx context.Context) ([]repository.SourceUserInput, error) {
	var users []repository.SourceUserInput
	seen := make(map[string]struct{})
	for page := 1; ; page++ {
		if page > liteLLMCatalogMaxPages {
			return nil, fmt.Errorf("LiteLLM user catalog exceeds page limit")
		}
		result, err := r.client.ListUsers(ctx, page, r.pageSize)
		if err != nil {
			return nil, fmt.Errorf("list LiteLLM users: %w", err)
		}
		if result.TotalPages < page || result.TotalPages > liteLLMCatalogMaxPages {
			return nil, fmt.Errorf("invalid LiteLLM user catalog pagination")
		}
		for _, user := range result.Users {
			ref := strings.TrimSpace(user.UserID)
			if ref == "" {
				continue
			}
			if _, duplicate := seen[ref]; duplicate {
				return nil, fmt.Errorf("duplicate LiteLLM user reference")
			}
			seen[ref] = struct{}{}
			users = append(users, repository.SourceUserInput{SourceUserRef: ref, Email: strings.TrimSpace(user.Email), DisplayName: strings.TrimSpace(user.DisplayName), Active: true})
		}
		if page == result.TotalPages {
			return users, nil
		}
	}
}

func (r *LiteLLMCatalogRunner) listKeys(ctx context.Context, users []repository.SourceUserInput) ([]repository.SourceAPIKeyInput, bool, error) {
	knownUsers := make(map[string]struct{}, len(users))
	for _, user := range users {
		knownUsers[user.SourceUserRef] = struct{}{}
	}
	var keys []repository.SourceAPIKeyInput
	seen := make(map[string]struct{})
	needsUnownedUser := false
	for page := 1; ; page++ {
		if page > liteLLMCatalogMaxPages {
			return nil, false, fmt.Errorf("LiteLLM key catalog exceeds page limit")
		}
		result, err := r.client.ListKeys(ctx, page, r.pageSize)
		if err != nil {
			return nil, false, fmt.Errorf("list LiteLLM keys: %w", err)
		}
		if result.TotalPages < page || result.TotalPages > liteLLMCatalogMaxPages {
			return nil, false, fmt.Errorf("invalid LiteLLM key catalog pagination")
		}
		for _, key := range result.Keys {
			ref, err := opaqueLiteLLMKeyRef(key.Token)
			if err != nil {
				return nil, false, ErrInvalidLiteLLMKeyRef
			}
			if _, duplicate := seen[ref]; duplicate {
				return nil, false, fmt.Errorf("duplicate LiteLLM key reference")
			}
			seen[ref] = struct{}{}
			owner := strings.TrimSpace(key.UserID)
			if _, exists := knownUsers[owner]; owner == "" || !exists {
				owner = liteLLMUnownedUserRef
				needsUnownedUser = true
			}
			keys = append(keys, repository.SourceAPIKeyInput{
				SourceKeyRef:  ref,
				SourceUserRef: owner,
				UsageGroupRef: ref,
				DisplayName:   liteLLMKeyDisplayName(key),
				Active:        !key.Blocked && (key.Expires == nil || key.Expires.After(r.now())),
			})
		}
		if page == result.TotalPages {
			return keys, needsUnownedUser, nil
		}
	}
}

func canonicalLiteLLMKeyRef(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "sk-") {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:]), nil
	}
	if len(value) == 64 && strings.Trim(value, "0123456789abcdefABCDEF") == "" {
		return strings.ToLower(value), nil
	}
	if value == "" {
		return "", ErrInvalidLiteLLMKeyRef
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", ErrInvalidLiteLLMKeyRef
		}
	}
	// Some LiteLLM versions return opaque token identifiers instead of a
	// virtual key or 64-character hash. Canonicalize those values too so they
	// can join usage events without ever being persisted themselves.
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:]), nil
}

// opaqueLiteLLMKeyRef converts a canonical identity into a short opaque
// identifier. The canonical hash is intentionally never written to storage.
func opaqueLiteLLMKeyRef(value string) (string, error) {
	canonical, err := canonicalLiteLLMKeyRef(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return liteLLMOpaqueKeyPrefix + base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

func liteLLMAPIGroupKeyFromRef(ref string) string { return liteLLMSourceSystem + ":" + ref }

func isLiteLLMOpaqueKeyRef(ref string) bool {
	if !strings.HasPrefix(ref, liteLLMOpaqueKeyPrefix) || len(ref) != len(liteLLMOpaqueKeyPrefix)+base64.RawURLEncoding.EncodedLen(16) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ref, liteLLMOpaqueKeyPrefix))
	return err == nil && len(decoded) == 16
}

func liteLLMKeyDisplayName(key LiteLLMKey) string {
	alias := strings.TrimSpace(key.Alias)
	if alias == "" || strings.EqualFold(alias, strings.TrimSpace(key.Token)) || strings.HasPrefix(strings.ToLower(alias), "sk-") || isLiteLLMHash(alias) {
		return "LiteLLM key"
	}
	canonicalAlias, aliasErr := canonicalLiteLLMKeyRef(alias)
	canonicalToken, tokenErr := canonicalLiteLLMKeyRef(key.Token)
	if aliasErr == nil && (tokenErr == nil && canonicalAlias == canonicalToken || strings.HasPrefix(strings.ToLower(alias), "sk-")) {
		return "LiteLLM key"
	}
	return alias
}

func isLiteLLMHash(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdefABCDEF") == ""
}

// LiteLLMUsageKeyResolver resolves only opaque catalog references. It never
// recreates a raw key or full hash from persisted catalog data.
type LiteLLMUsageKeyResolver struct{}

func (LiteLLMUsageKeyResolver) ResolveAPIGroupKeys(_ context.Context, sourceSystem string, keys []entities.SourceAPIKey) ([]string, error) {
	if strings.TrimSpace(sourceSystem) != liteLLMSourceSystem {
		return nil, fmt.Errorf("LiteLLM source mismatch")
	}
	groups := make([]string, 0, len(keys))
	for _, key := range keys {
		ref := strings.TrimSpace(key.UsageGroupRef)
		if key.SourceSystem != "" && key.SourceSystem != liteLLMSourceSystem || !isLiteLLMOpaqueKeyRef(ref) {
			return nil, fmt.Errorf("invalid LiteLLM catalog key reference")
		}
		groups = append(groups, liteLLMAPIGroupKeyFromRef(ref))
	}
	return groups, nil
}
