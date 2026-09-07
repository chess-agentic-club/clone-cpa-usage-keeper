package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidViewerCredentials   = errors.New("invalid viewer credentials")
	ErrViewerPrincipalUnavailable = errors.New("viewer principal unavailable")
)

// ViewerPrincipal identifies one source-owned API key without retaining the
// request credential that authenticated it.
type ViewerPrincipal struct {
	SourceSystem string
	APIGroupKey  string
	DisplayName  string
}

type ViewerKeyAuthenticator interface {
	AuthenticateViewerKey(context.Context, string) (ViewerPrincipal, error)
}

type ViewerPrincipalValidator interface {
	ValidateViewerPrincipal(context.Context, ViewerPrincipal) error
}

// NormalizeViewerPrincipal removes presentation whitespace and rejects an
// incomplete principal before it can be persisted or used as a cache entry.
func NormalizeViewerPrincipal(principal ViewerPrincipal) (ViewerPrincipal, error) {
	principal.SourceSystem = strings.TrimSpace(principal.SourceSystem)
	principal.APIGroupKey = strings.TrimSpace(principal.APIGroupKey)
	principal.DisplayName = strings.TrimSpace(principal.DisplayName)
	if principal.SourceSystem == "" || principal.APIGroupKey == "" || principal.DisplayName == "" {
		return ViewerPrincipal{}, ErrViewerPrincipalUnavailable
	}
	return principal, nil
}

type viewerPrincipalCacheKey struct {
	sourceSystem string
	apiGroupKey  string
}

// ViewerPrincipalValidationCache caches only successful validation of the
// non-secret source and canonical group identity.
type ViewerPrincipalValidationCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[viewerPrincipalCacheKey]time.Time
}

func NewViewerPrincipalValidationCache(ttl time.Duration) *ViewerPrincipalValidationCache {
	return &ViewerPrincipalValidationCache{ttl: ttl, entries: make(map[viewerPrincipalCacheKey]time.Time)}
}

func (c *ViewerPrincipalValidationCache) Validate(ctx context.Context, validator ViewerPrincipalValidator, principal ViewerPrincipal) error {
	principal, err := NormalizeViewerPrincipal(principal)
	if err != nil {
		return err
	}
	if validator == nil {
		return ErrViewerPrincipalUnavailable
	}

	key := viewerPrincipalCacheKey{sourceSystem: principal.SourceSystem, apiGroupKey: principal.APIGroupKey}
	now := time.Now()
	if c != nil && c.ttl > 0 {
		c.mu.Lock()
		expiresAt, ok := c.entries[key]
		c.mu.Unlock()
		if ok && now.Before(expiresAt) {
			return nil
		}
	}

	if err := validator.ValidateViewerPrincipal(ctx, principal); err != nil {
		return err
	}
	if c != nil && c.ttl > 0 {
		c.mu.Lock()
		c.entries[key] = now.Add(c.ttl)
		c.mu.Unlock()
	}
	return nil
}
