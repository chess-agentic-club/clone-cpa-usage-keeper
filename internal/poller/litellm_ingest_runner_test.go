package poller

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"cpa-usage-keeper/internal/config"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"gorm.io/gorm"
)

func TestLiteLLMRunnerContract(t *testing.T) {
	// The concrete sync-cycle tests are added with the runner implementation;
	// this compilation contract prevents wiring an incompatible source runtime.
	var _ interface{ Status() Status } = (*LiteLLMIngestRunner)(nil)
}

func TestLiteLLMRunnerDoesNotAdvanceCheckpointAfterPageTwoFailure(t *testing.T) {
	db := openLiteLLMRunnerDB(t)
	priorCursor := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	if err := repository.SaveLiteLLMSyncCheckpoint(db, entities.LiteLLMSyncCheckpoint{Cursor: priorCursor}); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}
	client := &fakeLiteLLMSpendLogsClient{
		pages: map[int]LiteLLMSpendLogPage{
			1: {Data: []LiteLLMSpendLog{{RequestID: "req-page-1", StartTime: priorCursor}}, TotalPages: 2},
		},
		errors: map[int]error{2: errors.New("page two unavailable")},
	}
	runner := newLiteLLMRunnerForTest(db, client)

	if err := runner.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce succeeded after page two failed")
	}
	checkpoint, err := repository.LoadLiteLLMSyncCheckpoint(db)
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if !checkpoint.Cursor.Equal(priorCursor) {
		t.Fatalf("checkpoint cursor = %s, want unchanged %s", checkpoint.Cursor, priorCursor)
	}
	if runner.Status().LastError == "" {
		t.Fatal("runner status did not record the page failure")
	}
}

func TestLiteLLMRunnerUsesOverlapWithoutDuplicateEvents(t *testing.T) {
	db := openLiteLLMRunnerDB(t)
	client := &fakeLiteLLMSpendLogsClient{pages: map[int]LiteLLMSpendLogPage{
		1: {Data: []LiteLLMSpendLog{{RequestID: "req-overlap", APIKey: "hash", StartTime: time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)}}, TotalPages: 1},
	}}
	runner := newLiteLLMRunnerForTest(db, client)

	if err := runner.SyncOnce(context.Background()); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if err := runner.SyncOnce(context.Background()); err != nil {
		t.Fatalf("overlap sync: %v", err)
	}
	var count int64
	if err := db.Model(&entities.UsageEvent{}).Count(&count).Error; err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 1 {
		t.Fatalf("overlap persisted %d events, want 1", count)
	}
}

func TestLiteLLMRunnerRetriesRetryableFailuresWithCappedExponentialBackoff(t *testing.T) {
	db := openLiteLLMRunnerDB(t)
	client := &fakeLiteLLMSpendLogsClient{
		failuresBeforeSuccess: 2,
		pages: map[int]LiteLLMSpendLogPage{
			1: {Data: []LiteLLMSpendLog{{RequestID: "req-retried", StartTime: time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)}}, TotalPages: 1},
		},
	}
	var delays []time.Duration
	runner := NewLiteLLMIngestRunnerWithOptions(client, db, LiteLLMIngestRunnerOptions{
		Interval:    time.Minute,
		Overlap:     time.Minute,
		PageSize:    100,
		RetryDelays: []time.Duration{time.Millisecond, 2 * time.Millisecond, 2 * time.Millisecond},
		Sleep: func(_ context.Context, delay time.Duration) bool {
			delays = append(delays, delay)
			return true
		},
	})

	if err := runner.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce returned %v after retryable failures", err)
	}
	if client.calls != 3 {
		t.Fatalf("ListSpendLogs calls = %d, want 3", client.calls)
	}
	if len(delays) != 2 || delays[0] != time.Millisecond || delays[1] != 2*time.Millisecond {
		t.Fatalf("retry delays = %v, want [1ms 2ms]", delays)
	}
}

func TestLiteLLMBackfillImportsSpecifiedRangeThroughDedupePath(t *testing.T) {
	db := openLiteLLMRunnerDB(t)
	client := &fakeLiteLLMSpendLogsClient{pages: map[int]LiteLLMSpendLogPage{
		1: {Data: []LiteLLMSpendLog{{RequestID: "req-backfill", APIKey: "hash", StartTime: time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)}}, TotalPages: 1},
	}}
	runner := newLiteLLMRunnerForTest(db, client)
	start := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	if err := runner.Backfill(context.Background(), start, end); err != nil {
		t.Fatalf("first backfill: %v", err)
	}
	if err := runner.Backfill(context.Background(), start, end); err != nil {
		t.Fatalf("replayed backfill: %v", err)
	}
	if len(client.windows) != 2 || !client.windows[0].start.Equal(start) || !client.windows[0].end.Equal(end) {
		t.Fatalf("backfill windows = %+v, want [%s, %s]", client.windows, start, end)
	}
	var count int64
	if err := db.Model(&entities.UsageEvent{}).Count(&count).Error; err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 1 {
		t.Fatalf("backfill persisted %d events, want 1", count)
	}
	checkpoint, err := repository.LoadLiteLLMSyncCheckpoint(db)
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if !checkpoint.Cursor.IsZero() {
		t.Fatalf("backfill advanced scheduled checkpoint to %s", checkpoint.Cursor)
	}
}

type liteLLMWindow struct{ start, end time.Time }

type fakeLiteLLMSpendLogsClient struct {
	pages                 map[int]LiteLLMSpendLogPage
	errors                map[int]error
	failuresBeforeSuccess int
	calls                 int
	windows               []liteLLMWindow
}

func (c *fakeLiteLLMSpendLogsClient) ListSpendLogs(_ context.Context, start, end time.Time, page, _ int) (LiteLLMSpendLogPage, error) {
	c.calls++
	c.windows = append(c.windows, liteLLMWindow{start: start, end: end})
	if c.failuresBeforeSuccess > 0 {
		c.failuresBeforeSuccess--
		return LiteLLMSpendLogPage{}, &LiteLLMHTTPError{StatusCode: 503}
	}
	if err := c.errors[page]; err != nil {
		return LiteLLMSpendLogPage{}, err
	}
	return c.pages[page], nil
}

func newLiteLLMRunnerForTest(db *gorm.DB, client *fakeLiteLLMSpendLogsClient) *LiteLLMIngestRunner {
	return NewLiteLLMIngestRunnerWithOptions(client, db, LiteLLMIngestRunnerOptions{
		Interval: time.Minute,
		Overlap:  time.Minute,
		PageSize: 100,
		Now:      func() time.Time { return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC) },
		Sleep:    func(context.Context, time.Duration) bool { return true },
	})
}

func openLiteLLMRunnerDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := repository.OpenDatabase(config.Config{SQLitePath: filepath.Join(t.TempDir(), "litellm-runner.db")})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql database: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}
