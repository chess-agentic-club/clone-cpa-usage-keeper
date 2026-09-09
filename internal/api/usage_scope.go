package api

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/service"
	servicedto "cpa-usage-keeper/internal/service/dto"
	"github.com/gin-gonic/gin"
)

const usageScopeCatalogStaleAfter = 2 * time.Minute

type usageScopeOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type usageScopeUsersResponse struct {
	SourceSystem string             `json:"source_system"`
	SyncedAt     time.Time          `json:"synced_at"`
	Stale        bool               `json:"stale"`
	Users        []usageScopeOption `json:"users"`
}

type usageScopeKeysResponse struct {
	SourceSystem string             `json:"source_system"`
	SyncedAt     time.Time          `json:"synced_at"`
	Stale        bool               `json:"stale"`
	Keys         []usageScopeOption `json:"keys"`
}

type usageScopeSyncMetadata struct {
	SourceSystem string
	SyncedAt     time.Time
	Stale        bool
}

func registerUsageScopeUserRoute(router gin.IRoutes, access service.UsageAccessProvider, catalogState CatalogStateProvider) {
	router.GET("/usage/scope/users", func(c *gin.Context) {
		principal, ok := embeddedAccessPrincipalFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		users, err := access.ListScopeUsers(c.Request.Context(), principal)
		if err != nil {
			writeUsageScopeError(c, err)
			return
		}
		metadata, ok := loadUsageScopeSyncMetadata(c, catalogState, principal.SourceSystem)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, usageScopeUsersResponse{
			SourceSystem: metadata.SourceSystem,
			SyncedAt:     metadata.SyncedAt,
			Stale:        metadata.Stale,
			Users:        buildUsageScopeUserOptions(users),
		})
	})
}

func registerUsageScopeKeyRoute(router gin.IRoutes, access service.UsageAccessProvider, catalogState CatalogStateProvider) {
	router.GET("/usage/scope/keys", func(c *gin.Context) {
		principal, ok := embeddedAccessPrincipalFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		keys, err := access.ListScopeKeys(c.Request.Context(), principal, c.Query("user_catalog_id"))
		if err != nil {
			writeUsageScopeError(c, err)
			return
		}
		metadata, ok := loadUsageScopeSyncMetadata(c, catalogState, principal.SourceSystem)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, usageScopeKeysResponse{
			SourceSystem: metadata.SourceSystem,
			SyncedAt:     metadata.SyncedAt,
			Stale:        metadata.Stale,
			Keys:         buildUsageScopeKeyOptions(keys),
		})
	})
}

func applyResolvedUsageScope(c *gin.Context, access service.UsageAccessProvider, filter *servicedto.UsageFilter) bool {
	principal, ok := embeddedAccessPrincipalFromContext(c)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return false
	}
	if access == nil || filter == nil {
		writeUsageScopeError(c, service.ErrUsageScopeUnavailable)
		return false
	}
	scope, err := access.ResolveScope(c.Request.Context(), principal, service.ScopeSelection{
		UserCatalogID: c.Query("user_catalog_id"),
		KeyCatalogID:  c.Query("key_catalog_id"),
	})
	if err != nil {
		writeUsageScopeError(c, err)
		return false
	}
	filter.Scope = &scope
	filter.APIKeyID = ""
	filter.APIGroupKey = ""
	return true
}

func resolvedUsageScopeAPIKeyInfos(c *gin.Context, access service.UsageAccessProvider) (map[string]analysisAPIKeyInfo, bool) {
	principal, ok := embeddedAccessPrincipalFromContext(c)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return nil, false
	}
	keys, err := access.ListScopeKeys(c.Request.Context(), principal, c.Query("user_catalog_id"))
	if err != nil {
		writeUsageScopeError(c, err)
		return nil, false
	}
	infos := make(map[string]analysisAPIKeyInfo, len(keys))
	for _, key := range keys {
		selection := service.ScopeSelection{KeyCatalogID: key.ID}
		if principal.IsAdministrator && strings.TrimSpace(c.Query("user_catalog_id")) != "" {
			selection.UserCatalogID = c.Query("user_catalog_id")
		}
		scope, err := access.ResolveScope(c.Request.Context(), principal, selection)
		if err != nil {
			writeUsageScopeError(c, err)
			return nil, false
		}
		label := safeUsageScopeKeyLabel(key)
		for _, groupKey := range scope.APIGroupKeys {
			infos[groupKey] = analysisAPIKeyInfo{ID: key.ID, Label: label}
		}
	}
	return infos, true
}

func loadUsageScopeSyncMetadata(c *gin.Context, catalogState CatalogStateProvider, sourceSystem string) (usageScopeSyncMetadata, bool) {
	if catalogState == nil {
		writeUsageScopeError(c, service.ErrUsageScopeUnavailable)
		return usageScopeSyncMetadata{}, false
	}
	state, err := catalogState.CatalogSyncState(c.Request.Context(), sourceSystem)
	if err != nil || state.LastSuccessAt.IsZero() {
		writeUsageScopeError(c, service.ErrUsageScopeUnavailable)
		return usageScopeSyncMetadata{}, false
	}
	now := time.Now()
	return usageScopeSyncMetadata{
		SourceSystem: sourceSystem,
		SyncedAt:     state.LastSuccessAt,
		Stale:        now.Sub(state.LastSuccessAt) > usageScopeCatalogStaleAfter,
	}, true
}

func buildUsageScopeUserOptions(users []entities.SourceUser) []usageScopeOption {
	options := make([]usageScopeOption, 0, len(users))
	for _, user := range users {
		label := safeUsageScopeLabel(user.DisplayName, "User")
		if strings.EqualFold(strings.TrimSpace(label), strings.TrimSpace(user.SourceUserRef)) {
			label = "User"
		}
		options = append(options, usageScopeOption{ID: user.ID, Label: label})
	}
	return options
}

func buildUsageScopeKeyOptions(keys []entities.SourceAPIKey) []usageScopeOption {
	options := make([]usageScopeOption, 0, len(keys))
	for _, key := range keys {
		options = append(options, usageScopeOption{ID: key.ID, Label: safeUsageScopeKeyLabel(key)})
	}
	return options
}

func safeUsageScopeKeyLabel(key entities.SourceAPIKey) string {
	label := safeUsageScopeLabel(key.DisplayName, "API key")
	if strings.EqualFold(strings.TrimSpace(label), strings.TrimSpace(key.SourceKeyRef)) || strings.EqualFold(strings.TrimSpace(label), strings.TrimSpace(key.UsageGroupRef)) {
		return "API key"
	}
	return label
}

func safeUsageScopeLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || looksLikeCredentialValue(value) {
		return fallback
	}
	return value
}

func looksLikeCredentialValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "sk-") || strings.Contains(lower, "authorization") || strings.Contains(lower, "bearer") || strings.Contains(lower, "secret") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") {
		return true
	}
	for _, part := range strings.FieldsFunc(trimmed, func(r rune) bool { return r == ':' || r == '/' }) {
		if len(part) >= 40 && allHex(part) {
			return true
		}
	}
	return strings.Count(trimmed, ".") >= 2 && len(trimmed) > 40
}

func allHex(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) && (unicode.ToLower(r) < 'a' || unicode.ToLower(r) > 'f') {
			return false
		}
	}
	return true
}

func writeUsageScopeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrUsageScopeForbidden):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	case errors.Is(err, service.ErrUsageScopeUnavailable):
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "catalog unavailable"})
	default:
		writeInternalError(c, "resolve usage scope failed", err)
	}
}
