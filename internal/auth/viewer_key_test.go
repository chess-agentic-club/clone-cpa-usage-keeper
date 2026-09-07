package auth

import (
	"context"
	"errors"
	"sync"
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

type blockingViewerValidator struct {
	mu            sync.Mutex
	validateCalls int
	firstStarted  chan struct{}
	secondStarted chan struct{}
	releaseFirst  chan struct{}
}

func (v *blockingViewerValidator) ValidateViewerPrincipal(context.Context, ViewerPrincipal) error {
	v.mu.Lock()
	v.validateCalls++
	call := v.validateCalls
	v.mu.Unlock()
	if call == 1 {
		close(v.firstStarted)
		<-v.releaseFirst
		return nil
	}
	close(v.secondStarted)
	return nil
}

func TestViewerPrincipalValidationCacheCoalescesConcurrentMisses(t *testing.T) {
	validator := &blockingViewerValidator{
		firstStarted:  make(chan struct{}),
		secondStarted: make(chan struct{}),
		releaseFirst:  make(chan struct{}),
	}
	cache := NewViewerPrincipalValidationCache(time.Minute)
	principal := ViewerPrincipal{SourceSystem: "source-a", APIGroupKey: "key-1", DisplayName: "Key 1"}
	results := make(chan error, 2)
	defer func() {
		select {
		case <-validator.releaseFirst:
		default:
			close(validator.releaseFirst)
		}
	}()

	go func() { results <- cache.Validate(context.Background(), validator, principal) }()
	<-validator.firstStarted
	go func() { results <- cache.Validate(context.Background(), validator, principal) }()

	select {
	case <-validator.secondStarted:
		t.Fatal("concurrent cache miss started a second validation")
	case <-time.After(25 * time.Millisecond):
	}
	close(validator.releaseFirst)
	if err := <-results; err != nil {
		t.Fatalf("first Validate returned error: %v", err)
	}
	if err := <-results; err != nil {
		t.Fatalf("second Validate returned error: %v", err)
	}
	if validator.validateCalls != 1 {
		t.Fatalf("validator called %d times, want 1", validator.validateCalls)
	}
}
