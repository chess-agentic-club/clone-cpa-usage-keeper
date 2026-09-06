package repository

import (
	"context"
	"testing"
	"time"

	"cpa-usage-keeper/internal/entities"
)

func TestInsertExternalUsageEventsSkipsReplay(t *testing.T) {
	db := openUsageTestDatabase(t)
	event := entities.UsageEvent{SourceSystem: "litellm", RequestID: "req-1", EventKey: "req-1", APIGroupKey: "litellm:hash", Timestamp: time.Now()}

	inserted, err := InsertExternalUsageEvents(db, "litellm", []entities.UsageEvent{event})
	if err != nil || len(inserted) != 1 {
		t.Fatalf("first insert = %d, %v; want 1, nil", len(inserted), err)
	}
	inserted, err = InsertExternalUsageEvents(db, "litellm", []entities.UsageEvent{event})
	if err != nil || len(inserted) != 0 {
		t.Fatalf("replay insert = %d, %v; want 0, nil", len(inserted), err)
	}
}

func TestInsertExternalUsageEventsRegistersNonSecretAPIKeyIdentity(t *testing.T) {
	db := openUsageTestDatabase(t)
	_, err := InsertExternalUsageEvents(db, "litellm", []entities.UsageEvent{{
		RequestID:   "req-1",
		APIGroupKey: "litellm:key-hash",
		Timestamp:   time.Now(),
	}})
	if err != nil {
		t.Fatalf("insert external event: %v", err)
	}

	identities, err := ListActiveUsageAPIKeyIdentities(context.Background(), db)
	if err != nil {
		t.Fatalf("list usage API key identities: %v", err)
	}
	if len(identities) != 1 || identities[0].SourceSystem != "litellm" || identities[0].APIGroupKey != "litellm:key-hash" {
		t.Fatalf("expected LiteLLM virtual-key identity, got %+v", identities)
	}
}
