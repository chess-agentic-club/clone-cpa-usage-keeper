package service

import (
	"context"
	"errors"
	"sort"
	"strings"

	"cpa-usage-keeper/internal/auth"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	servicedto "cpa-usage-keeper/internal/service/dto"
)

var (
	// ErrUsageScopeForbidden intentionally does not reveal whether a requested
	// catalog ID exists, is inactive, or belongs to somebody else.
	ErrUsageScopeForbidden   = errors.New("usage scope is forbidden")
	ErrUsageScopeUnavailable = errors.New("usage scope is unavailable")
)

// ScopeSelection contains only opaque catalog IDs supplied by a browser.
// It never carries a source API key or a resolved analytics group key.
type ScopeSelection struct {
	UserCatalogID string
	KeyCatalogID  string
}

// AccessPrincipal is the server-side outcome of authenticating an external
// identity for one source. A non-administrator has exactly one linked source
// user before a scope can be resolved.
type AccessPrincipal struct {
	ExternalIdentityID string
	SourceSystem       string
	SourceUserID       string
	IsAdministrator    bool
	authorized         bool
}

// SourceUsageKeyResolver turns source-safe catalog references into the exact
// internal group keys understood by a trusted usage source.
type SourceUsageKeyResolver interface {
	ResolveAPIGroupKeys(context.Context, string, []entities.SourceAPIKey) ([]string, error)
}

type UsageAccessProvider interface {
	ResolveIdentity(context.Context, auth.ExternalPrincipal, string) (AccessPrincipal, error)
	ResolveScope(context.Context, AccessPrincipal, ScopeSelection) (servicedto.UsageScope, error)
	ListScopeUsers(context.Context, AccessPrincipal) ([]entities.SourceUser, error)
	ListScopeKeys(context.Context, AccessPrincipal, string) ([]entities.SourceAPIKey, error)
	ListIdentityMappings(context.Context, AccessPrincipal) ([]repository.IdentityMappingRecord, error)
	ReplaceIdentityMapping(context.Context, AccessPrincipal, string, string) error
}

// IdentityAccessService is the policy boundary between an authenticated
// external principal and trusted source usage queries.
type IdentityAccessService struct {
	catalog   *repository.CatalogRepository
	resolvers map[string]SourceUsageKeyResolver
}

func NewIdentityAccessService(catalog *repository.CatalogRepository, resolvers map[string]SourceUsageKeyResolver) *IdentityAccessService {
	copyOfResolvers := make(map[string]SourceUsageKeyResolver, len(resolvers))
	for sourceSystem, resolver := range resolvers {
		copyOfResolvers[strings.TrimSpace(sourceSystem)] = resolver
	}
	return &IdentityAccessService{catalog: catalog, resolvers: copyOfResolvers}
}

func (s *IdentityAccessService) ResolveIdentity(ctx context.Context, principal auth.ExternalPrincipal, sourceSystem string) (AccessPrincipal, error) {
	sourceSystem = strings.TrimSpace(sourceSystem)
	if !s.supportsSource(sourceSystem) {
		return AccessPrincipal{}, ErrUsageScopeForbidden
	}
	identity, err := s.catalog.UpsertExternalIdentity(ctx, principal.Issuer, principal.Subject, principal.Email, principal.DisplayName)
	if err != nil {
		return AccessPrincipal{}, ErrUsageScopeUnavailable
	}
	access := AccessPrincipal{ExternalIdentityID: identity.ID, SourceSystem: sourceSystem, IsAdministrator: principal.IsAdministrator, authorized: true}
	if access.IsAdministrator {
		return access, nil
	}

	link, found, err := s.catalog.FindIdentityLink(ctx, identity.ID, sourceSystem)
	if err != nil {
		return AccessPrincipal{}, ErrUsageScopeUnavailable
	}
	if found {
		if s.isActiveSourceUser(ctx, sourceSystem, link.SourceUserID) {
			access.SourceUserID = link.SourceUserID
			return access, nil
		}
		return AccessPrincipal{}, ErrUsageScopeForbidden
	}

	if strings.TrimSpace(principal.Email) == "" {
		return AccessPrincipal{}, ErrUsageScopeForbidden
	}
	users, err := s.catalog.FindActiveSourceUsersByEmail(ctx, sourceSystem, principal.Email)
	if err != nil {
		return AccessPrincipal{}, ErrUsageScopeUnavailable
	}
	if len(users) != 1 {
		return AccessPrincipal{}, ErrUsageScopeForbidden
	}
	if err := s.catalog.ReplaceIdentityLink(ctx, identity.ID, sourceSystem, users[0].ID, "email", false); err != nil {
		return AccessPrincipal{}, ErrUsageScopeUnavailable
	}
	access.SourceUserID = users[0].ID
	return access, nil
}

func (s *IdentityAccessService) ResolveScope(ctx context.Context, principal AccessPrincipal, selection ScopeSelection) (servicedto.UsageScope, error) {
	if !s.acceptsPrincipal(principal) || (strings.TrimSpace(selection.UserCatalogID) != "" && strings.TrimSpace(selection.KeyCatalogID) != "") {
		return servicedto.UsageScope{}, ErrUsageScopeForbidden
	}
	if principal.IsAdministrator && strings.TrimSpace(selection.UserCatalogID) == "" && strings.TrimSpace(selection.KeyCatalogID) == "" {
		return servicedto.UsageScope{Mode: servicedto.UsageScopeAllSource, SourceSystem: principal.SourceSystem}, nil
	}

	var keys []entities.SourceAPIKey
	if principal.IsAdministrator {
		var err error
		if keyID := strings.TrimSpace(selection.KeyCatalogID); keyID != "" {
			key, findErr := s.catalog.FindActiveSourceAPIKeyByID(ctx, principal.SourceSystem, keyID)
			if findErr != nil {
				return servicedto.UsageScope{}, ErrUsageScopeForbidden
			}
			keys = []entities.SourceAPIKey{key}
		} else {
			keys, err = s.keysForActiveUser(ctx, principal.SourceSystem, selection.UserCatalogID)
			if err != nil {
				return servicedto.UsageScope{}, err
			}
		}
	} else {
		if strings.TrimSpace(selection.UserCatalogID) != "" {
			return servicedto.UsageScope{}, ErrUsageScopeForbidden
		}
		if keyID := strings.TrimSpace(selection.KeyCatalogID); keyID != "" {
			key, findErr := s.catalog.FindActiveSourceAPIKeyByID(ctx, principal.SourceSystem, keyID)
			if findErr != nil || key.SourceUserID != principal.SourceUserID {
				return servicedto.UsageScope{}, ErrUsageScopeForbidden
			}
			keys = []entities.SourceAPIKey{key}
		} else {
			allKeys, listErr := s.catalog.ListActiveSourceAPIKeys(ctx, principal.SourceSystem)
			if listErr != nil {
				return servicedto.UsageScope{}, ErrUsageScopeUnavailable
			}
			for _, key := range allKeys {
				if key.SourceUserID == principal.SourceUserID {
					keys = append(keys, key)
				}
			}
		}
	}
	return s.resolveKeySet(ctx, principal.SourceSystem, keys)
}

func (s *IdentityAccessService) ListScopeUsers(ctx context.Context, principal AccessPrincipal) ([]entities.SourceUser, error) {
	if !s.acceptsPrincipal(principal) {
		return nil, ErrUsageScopeForbidden
	}
	users, err := s.catalog.ListActiveSourceUsers(ctx, principal.SourceSystem)
	if err != nil {
		return nil, ErrUsageScopeUnavailable
	}
	if principal.IsAdministrator {
		return users, nil
	}
	for _, user := range users {
		if user.ID == principal.SourceUserID {
			return []entities.SourceUser{user}, nil
		}
	}
	return nil, ErrUsageScopeForbidden
}

func (s *IdentityAccessService) ListScopeKeys(ctx context.Context, principal AccessPrincipal, userCatalogID string) ([]entities.SourceAPIKey, error) {
	if !s.acceptsPrincipal(principal) {
		return nil, ErrUsageScopeForbidden
	}
	if !principal.IsAdministrator && strings.TrimSpace(userCatalogID) != "" && strings.TrimSpace(userCatalogID) != principal.SourceUserID {
		return nil, ErrUsageScopeForbidden
	}
	if principal.IsAdministrator && strings.TrimSpace(userCatalogID) != "" && !s.isActiveSourceUser(ctx, principal.SourceSystem, strings.TrimSpace(userCatalogID)) {
		return nil, ErrUsageScopeForbidden
	}
	keys, err := s.catalog.ListActiveSourceAPIKeys(ctx, principal.SourceSystem)
	if err != nil {
		return nil, ErrUsageScopeUnavailable
	}
	ownerID := strings.TrimSpace(userCatalogID)
	if !principal.IsAdministrator {
		ownerID = principal.SourceUserID
	}
	if ownerID == "" {
		return keys, nil
	}
	filtered := make([]entities.SourceAPIKey, 0, len(keys))
	for _, key := range keys {
		if key.SourceUserID == ownerID {
			filtered = append(filtered, key)
		}
	}
	return filtered, nil
}

func (s *IdentityAccessService) ListIdentityMappings(ctx context.Context, principal AccessPrincipal) ([]repository.IdentityMappingRecord, error) {
	if !s.acceptsPrincipal(principal) || !principal.IsAdministrator {
		return nil, ErrUsageScopeForbidden
	}
	mappings, err := s.catalog.ListIdentityMappings(ctx, principal.SourceSystem)
	if err != nil {
		return nil, ErrUsageScopeUnavailable
	}
	return mappings, nil
}

func (s *IdentityAccessService) ReplaceIdentityMapping(ctx context.Context, principal AccessPrincipal, externalIdentityID, sourceUserID string) error {
	if !s.acceptsPrincipal(principal) || !principal.IsAdministrator || !s.isActiveSourceUser(ctx, principal.SourceSystem, strings.TrimSpace(sourceUserID)) {
		return ErrUsageScopeForbidden
	}
	if err := s.catalog.ReplaceIdentityLink(ctx, strings.TrimSpace(externalIdentityID), principal.SourceSystem, strings.TrimSpace(sourceUserID), "manual", true); err != nil {
		return ErrUsageScopeForbidden
	}
	return nil
}

func (s *IdentityAccessService) resolveKeySet(ctx context.Context, sourceSystem string, keys []entities.SourceAPIKey) (servicedto.UsageScope, error) {
	resolver := s.resolver(sourceSystem)
	if resolver == nil {
		return servicedto.UsageScope{}, ErrUsageScopeForbidden
	}
	resolved, err := resolver.ResolveAPIGroupKeys(ctx, sourceSystem, keys)
	if err != nil {
		return servicedto.UsageScope{}, ErrUsageScopeUnavailable
	}
	return servicedto.UsageScope{Mode: servicedto.UsageScopeKeySet, SourceSystem: sourceSystem, APIGroupKeys: sortedUniqueNonEmpty(resolved)}, nil
}

func (s *IdentityAccessService) keysForActiveUser(ctx context.Context, sourceSystem, userCatalogID string) ([]entities.SourceAPIKey, error) {
	userCatalogID = strings.TrimSpace(userCatalogID)
	if !s.isActiveSourceUser(ctx, sourceSystem, userCatalogID) {
		return nil, ErrUsageScopeForbidden
	}
	keys, err := s.catalog.ListActiveSourceAPIKeys(ctx, sourceSystem)
	if err != nil {
		return nil, ErrUsageScopeUnavailable
	}
	filtered := make([]entities.SourceAPIKey, 0, len(keys))
	for _, key := range keys {
		if key.SourceUserID == userCatalogID {
			filtered = append(filtered, key)
		}
	}
	return filtered, nil
}

func (s *IdentityAccessService) isActiveSourceUser(ctx context.Context, sourceSystem, userID string) bool {
	users, err := s.catalog.ListActiveSourceUsers(ctx, sourceSystem)
	if err != nil {
		return false
	}
	for _, user := range users {
		if user.ID == userID {
			return true
		}
	}
	return false
}

func (s *IdentityAccessService) acceptsPrincipal(principal AccessPrincipal) bool {
	return s != nil && s.catalog != nil && principal.authorized && strings.TrimSpace(principal.SourceSystem) != "" && s.supportsSource(principal.SourceSystem) && (principal.IsAdministrator || strings.TrimSpace(principal.SourceUserID) != "")
}

func (s *IdentityAccessService) supportsSource(sourceSystem string) bool {
	return s != nil && s.catalog != nil && s.resolver(sourceSystem) != nil
}

func (s *IdentityAccessService) resolver(sourceSystem string) SourceUsageKeyResolver {
	if s == nil {
		return nil
	}
	return s.resolvers[strings.TrimSpace(sourceSystem)]
}

func sortedUniqueNonEmpty(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
