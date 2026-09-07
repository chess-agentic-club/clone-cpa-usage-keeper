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
	return nil
}

func (v *blockingViewerValidator) calls() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.validateCalls
}

func TestViewerPrincipalValidationCacheCancelsConcurrentFollowerWithoutSecondValidation(t *testing.T) {
	validator := &blockingViewerValidator{
		firstStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	cache := NewViewerPrincipalValidationCache(time.Minute)
	principal := ViewerPrincipal{SourceSystem: "source-a", APIGroupKey: "key-1", DisplayName: "Key 1"}
	leaderResult := make(chan error, 1)
	defer func() {
		select {
		case <-validator.releaseFirst:
		default:
			close(validator.releaseFirst)
		}
	}()

	go func() { leaderResult <- cache.Validate(context.Background(), validator, principal) }()
	<-validator.firstStarted
	followerContext, cancelFollower := context.WithCancel(context.Background())
	defer cancelFollower()
	followerResult := make(chan error, 1)
	go func() { followerResult <- cache.Validate(followerContext, validator, principal) }()
	cancelFollower()

	select {
	case err := <-followerResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled follower error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled follower did not return while leader validation was blocked")
	}
	if calls := validator.calls(); calls != 1 {
		t.Fatalf("validator called %d times after follower reached in-flight wait, want 1", calls)
	}
	close(validator.releaseFirst)
	if err := <-leaderResult; err != nil {
		t.Fatalf("leader Validate returned error: %v", err)
	}
}
