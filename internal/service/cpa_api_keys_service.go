package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"cpa-usage-keeper/internal/auth"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/helper"
	"cpa-usage-keeper/internal/repository"

	"gorm.io/gorm"
	"gorm.io/plugin/dbresolver"
)

var ErrInvalidID = errors.New("invalid id")

const CLIProxyViewerSourceSystem = "cliproxy"

func cliProxyViewerAPIGroupKey(id int64) string {
	return fmt.Sprintf("%s:%d", CLIProxyViewerSourceSystem, id)
}

type CPAAPIKeyProvider interface {
	ListCPAAPIKeys(ctx context.Context) ([]entities.CPAAPIKey, error)
	FindActiveCPAAPIKeyByValue(ctx context.Context, apiKey string) (entities.CPAAPIKey, error)
	FindActiveCPAAPIKeyByID(ctx context.Context, id int64) (entities.CPAAPIKey, error)
	UpdateCPAAPIKeyAlias(ctx context.Context, id int64, keyAlias string) (entities.CPAAPIKey, error)
}

type cpaAPIKeyService struct {
	db *gorm.DB
}

func NewCPAAPIKeyService(db *gorm.DB) CPAAPIKeyProvider {
	return &cpaAPIKeyService{db: db}
}

type cpaAPIKeyViewerAdapter struct {
	provider CPAAPIKeyProvider
}

// NewCPAAPIKeyViewerAdapter exposes existing active CPA API keys through the
// source-neutral viewer authentication contract.
func NewCPAAPIKeyViewerAdapter(provider CPAAPIKeyProvider) interface {
	auth.ViewerKeyAuthenticator
	auth.ViewerPrincipalValidator
	auth.ViewerPrincipalResolver
} {
	return &cpaAPIKeyViewerAdapter{provider: provider}
}

func (a *cpaAPIKeyViewerAdapter) AuthenticateViewerKey(ctx context.Context, rawKey string) (auth.ViewerPrincipal, error) {
	if a == nil || a.provider == nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	row, err := a.provider.FindActiveCPAAPIKeyByValue(ctx, rawKey)
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	principal, err := auth.NormalizeViewerPrincipal(auth.ViewerPrincipal{
		SourceSystem: CLIProxyViewerSourceSystem,
		APIGroupKey:  cliProxyViewerAPIGroupKey(row.ID),
		DisplayName:  helper.CPAAPIKeyDisplayName(row),
	})
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	return principal, nil
}

func (a *cpaAPIKeyViewerAdapter) ValidateViewerPrincipal(ctx context.Context, principal auth.ViewerPrincipal) error {
	_, err := a.ResolveViewerPrincipal(ctx, principal)
	return err
}

func (a *cpaAPIKeyViewerAdapter) ResolveViewerPrincipal(ctx context.Context, principal auth.ViewerPrincipal) (auth.ViewerPrincipal, error) {
	principal, err := auth.NormalizeViewerPrincipal(principal)
	if err != nil || principal.SourceSystem != CLIProxyViewerSourceSystem || a == nil || a.provider == nil {
		return auth.ViewerPrincipal{}, auth.ErrViewerPrincipalUnavailable
	}
	idValue := strings.TrimPrefix(principal.APIGroupKey, CLIProxyViewerSourceSystem+":")
	id, parseErr := strconv.ParseInt(idValue, 10, 64)
	if !strings.HasPrefix(principal.APIGroupKey, CLIProxyViewerSourceSystem+":") || parseErr != nil || id <= 0 || principal.APIGroupKey != cliProxyViewerAPIGroupKey(id) {
		return auth.ViewerPrincipal{}, auth.ErrViewerPrincipalUnavailable
	}
	row, err := a.provider.FindActiveCPAAPIKeyByID(ctx, id)
	if err != nil || strings.TrimSpace(row.APIKey) == "" {
		return auth.ViewerPrincipal{}, auth.ErrViewerPrincipalUnavailable
	}
	principal.APIGroupKey = row.APIKey
	return principal, nil
}

func (s *cpaAPIKeyService) ListCPAAPIKeys(context.Context) ([]entities.CPAAPIKey, error) {
	return repository.ListActiveCPAAPIKeys(s.db)
}

func (s *cpaAPIKeyService) FindActiveCPAAPIKeyByValue(_ context.Context, apiKey string) (entities.CPAAPIKey, error) {
	trimmed := strings.TrimSpace(apiKey)
	if trimmed == "" {
		return entities.CPAAPIKey{}, gorm.ErrRecordNotFound
	}
	return repository.FindActiveCPAAPIKeyByValue(s.db, trimmed)
}

func (s *cpaAPIKeyService) FindActiveCPAAPIKeyByID(_ context.Context, id int64) (entities.CPAAPIKey, error) {
	if id <= 0 {
		return entities.CPAAPIKey{}, gorm.ErrRecordNotFound
	}
	return repository.FindActiveCPAAPIKeyByID(s.db, id)
}

func (s *cpaAPIKeyService) UpdateCPAAPIKeyAlias(_ context.Context, id int64, keyAlias string) (entities.CPAAPIKey, error) {
	if id <= 0 {
		return entities.CPAAPIKey{}, ErrInvalidID
	}
	// UPDATE 由 dbresolver 自动路由 writer；结果回读再用官方 Write clause 固定到同一物理池。
	if err := repository.UpdateCPAAPIKeyAlias(s.db, id, keyAlias); err != nil {
		return entities.CPAAPIKey{}, err
	}
	return repository.FindActiveCPAAPIKeyByID(s.db.Clauses(dbresolver.Write), id)
}
