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

// ViewerPrincipalReferenceProvider creates a durable, server-only reference
// that allows a source-owned principal to be revalidated after a restart.
// Implementations must not return raw credentials or plaintext provider IDs.
type ViewerPrincipalReferenceProvider interface {
	CreateViewerPrincipalReference(ViewerPrincipal) (string, error)
}

// ViewerPrincipalReferenceValidator validates a persisted server-only
// reference for a source-owned principal.
type ViewerPrincipalReferenceValidator interface {
	ValidateViewerPrincipalWithReference(context.Context, ViewerPrincipal, string) error
}

// ViewerPrincipalResolver converts a persisted source-owned principal into
// the canonical analytics group identity used by trusted server queries.
type ViewerPrincipalResolver interface {
	ResolveViewerPrincipal(context.Context, ViewerPrincipal) (ViewerPrincipal, error)
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
	sourceSystem    string
	apiGroupKey     string
	revalidationRef string
}

// ViewerPrincipalValidationCache caches only successful viewer-principal
// validation. Reference-aware entries are bound to their persisted reference.
type ViewerPrincipalValidationCache struct {
	mu       sync.Mutex
	ttl      time.Duration
	entries  map[viewerPrincipalCacheKey]time.Time
	inFlight map[viewerPrincipalCacheKey]*viewerPrincipalValidationCall
}

type viewerPrincipalValidationCall struct {
	done chan struct{}
	err  error
}

func NewViewerPrincipalValidationCache(ttl time.Duration) *ViewerPrincipalValidationCache {
	return &ViewerPrincipalValidationCache{
		ttl:      ttl,
		entries:  make(map[viewerPrincipalCacheKey]time.Time),
		inFlight: make(map[viewerPrincipalCacheKey]*viewerPrincipalValidationCall),
	}
}

func (c *ViewerPrincipalValidationCache) Validate(ctx context.Context, validator ViewerPrincipalValidator, principal ViewerPrincipal) error {
	principal, err := NormalizeViewerPrincipal(principal)
	if err != nil {
		return err
	}
	if validator == nil {
		return ErrViewerPrincipalUnavailable
	}

	return c.validate(ctx, viewerPrincipalCacheKey{sourceSystem: principal.SourceSystem, apiGroupKey: principal.APIGroupKey}, func() error {
		return validator.ValidateViewerPrincipal(ctx, principal)
	})
}

// ValidateWithReference is the cache-aware counterpart for validators that
// can use a durable server-only revalidation reference.
func (c *ViewerPrincipalValidationCache) ValidateWithReference(ctx context.Context, validator ViewerPrincipalReferenceValidator, principal ViewerPrincipal, reference string) error {
	principal, err := NormalizeViewerPrincipal(principal)
	if err != nil {
		return err
	}
	reference = strings.TrimSpace(reference)
	if validator == nil || reference == "" {
		return ErrViewerPrincipalUnavailable
	}
	return c.validate(ctx, viewerPrincipalCacheKey{
		sourceSystem:    principal.SourceSystem,
		apiGroupKey:     principal.APIGroupKey,
		revalidationRef: strings.TrimSpace(reference),
	}, func() error {
		return validator.ValidateViewerPrincipalWithReference(ctx, principal, reference)
	})
}

func (c *ViewerPrincipalValidationCache) validate(ctx context.Context, key viewerPrincipalCacheKey, validate func() error) error {
	if c == nil || c.ttl <= 0 {
		return validate()
	}

	c.mu.Lock()
	if expiresAt, ok := c.entries[key]; ok && time.Now().Before(expiresAt) {
		c.mu.Unlock()
		return nil
	}
	if call, ok := c.inFlight[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	call := &viewerPrincipalValidationCall{done: make(chan struct{})}
	c.inFlight[key] = call
	c.mu.Unlock()

	call.err = validate()
	c.mu.Lock()
	if call.err == nil {
		c.entries[key] = time.Now().Add(c.ttl)
	}
	delete(c.inFlight, key)
	close(call.done)
	c.mu.Unlock()
	return call.err
}
