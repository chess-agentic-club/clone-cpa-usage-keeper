package repository

import (
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
