package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"gorm.io/gorm"
)

// ExternalUsageAPIKeyFilterIDPrefix distinguishes catalog IDs from CPA API key IDs.
const ExternalUsageAPIKeyFilterIDPrefix = "external:"

// UsageAPIKeyIdentityProvider supplies non-secret, source-owned API-key options
// for analytics UIs. CPA authentication key options use CPAAPIKeyProvider.
type UsageAPIKeyIdentityProvider interface {
	ListUsageAPIKeyIdentities(context.Context) ([]entities.UsageAPIKeyIdentity, error)
}

type usageAPIKeyIdentityService struct {
	db *gorm.DB
}

func NewUsageAPIKeyIdentityService(db *gorm.DB) UsageAPIKeyIdentityProvider {
	return &usageAPIKeyIdentityService{db: db}
}

func (s *usageAPIKeyIdentityService) ListUsageAPIKeyIdentities(ctx context.Context) ([]entities.UsageAPIKeyIdentity, error) {
	return repository.ListActiveUsageAPIKeyIdentities(ctx, s.db)
}

func UsageAPIKeyIdentityFilterID(id int64) string {
	return fmt.Sprintf("%s%d", ExternalUsageAPIKeyFilterIDPrefix, id)
}

func parseExternalUsageAPIKeyFilterID(value string) (int64, bool, error) {
	if !strings.HasPrefix(value, ExternalUsageAPIKeyFilterIDPrefix) {
		return 0, false, nil
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(value, ExternalUsageAPIKeyFilterIDPrefix), 10, 64)
	if err != nil || id <= 0 {
		return 0, true, ErrInvalidID
	}
	return id, true, nil
}
