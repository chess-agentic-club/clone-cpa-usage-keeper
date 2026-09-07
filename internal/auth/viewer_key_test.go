package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeViewerAdapter struct {
	principal     ViewerPrincipal
	validateCalls int
	validateErr   error
}

func (f *fakeViewerAdapter) AuthenticateViewerKey(context.Context, string) (ViewerPrincipal, error) {
	return f.principal, nil
}

func (f *fakeViewerAdapter) ValidateViewerPrincipal(context.Context, ViewerPrincipal) error {
	f.validateCalls++
	return f.validateErr
}

func TestViewerPrincipalValidationRejectsMissingSourceOrGroup(t *testing.T) {
	adapter := &fakeViewerAdapter{principal: ViewerPrincipal{SourceSystem: "source-a", APIGroupKey: "key-1", DisplayName: "Key 1"}}
	cache := NewViewerPrincipalValidationCache(time.Minute)

	for _, principal := range []ViewerPrincipal{
		{APIGroupKey: "key-1", DisplayName: "Key 1"},
		{SourceSystem: "source-a", DisplayName: "Key 1"},
	} {
		if err := cache.Validate(context.Background(), adapter, principal); !errors.Is(err, ErrViewerPrincipalUnavailable) {
			t.Fatalf("missing source or group error = %v, want unavailable principal", err)
		}
	}
	if adapter.validateCalls != 0 {
		t.Fatalf("validator called %d times for unavailable principals, want 0", adapter.validateCalls)
	}
}

func TestViewerPrincipalValidationCachesCanonicalPrincipalBeforeTTLExpiry(t *testing.T) {
	adapter := &fakeViewerAdapter{principal: ViewerPrincipal{SourceSystem: "source-a", APIGroupKey: "key-1", DisplayName: "Key 1"}}
	cache := NewViewerPrincipalValidationCache(time.Minute)
	principal := ViewerPrincipal{SourceSystem: " source-a ", APIGroupKey: " key-1 ", DisplayName: " Key 1 "}

	for range 2 {
		if err := cache.Validate(context.Background(), adapter, principal); err != nil {
			t.Fatalf("Validate returned error: %v", err)
		}
	}
	if adapter.validateCalls != 1 {
		t.Fatalf("validator called %d times before cache TTL expiry, want 1", adapter.validateCalls)
	}
}
