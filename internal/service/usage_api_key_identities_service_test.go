package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cpa-usage-keeper/internal/config"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
)

func TestUsageAPIKeyIdentityServiceListsExternalAnalyticsKeys(t *testing.T) {
	db, err := repository.OpenDatabase(config.Config{SQLitePath: filepath.Join(t.TempDir(), "usage-api-key-identities.db")})
	if err != nil {
		t.Fatalf("OpenDatabase returned error: %v", err)
	}
	closeTestDatabase(t, db)
	if _, err := repository.InsertExternalUsageEvents(db, "litellm", []entities.UsageEvent{
		{RequestID: "request-1", APIGroupKey: "litellm:key-hash", Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("insert external usage event: %v", err)
	}

	identities, err := NewUsageAPIKeyIdentityService(db).ListUsageAPIKeyIdentities(context.Background())
	if err != nil {
		t.Fatalf("list usage API key identities: %v", err)
	}
	if len(identities) != 1 || identities[0].APIGroupKey != "litellm:key-hash" || UsageAPIKeyIdentityFilterID(identities[0].ID) != "external:1" {
		t.Fatalf("expected an opaque external filter option, got %+v", identities)
	}
}
