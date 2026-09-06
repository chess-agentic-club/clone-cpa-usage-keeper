package poller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"gorm.io/gorm"
)

const (
	liteLLMDefaultInitialLookback = 24 * time.Hour
	liteLLMDefaultMaxBackfill     = 31 * 24 * time.Hour
	liteLLMDefaultMaxPages        = 10000
)

var liteLLMDefaultRetryDelays = []time.Duration{
	time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	30 * time.Second,
}

// LiteLLMSpendLogsClient is the narrow HTTP contract the poller needs.
// Keeping it separate from the CPA transport avoids a synthetic shared source API.
type LiteLLMSpendLogsClient interface {
	ListSpendLogs(context.Context, time.Time, time.Time, int, int) (LiteLLMSpendLogPage, error)
}

// LiteLLMUsageEventsNotifier wakes shared rollups only after external events commit.
type LiteLLMUsageEventsNotifier interface {
	NotifyUsageEventsCommitted([]entities.UsageEvent)
}

// LiteLLMIngestRunnerOptions exposes timing dependencies for tests while keeping
// production defaults bounded and conservative.
type LiteLLMIngestRunnerOptions struct {
	Interval         time.Duration
	Overlap          time.Duration
	PageSize         int
	InitialLookback  time.Duration
	MaxBackfillRange time.Duration
	MaxPages         int
	RetryDelays      []time.Duration
	Now              func() time.Time
	Sleep            func(context.Context, time.Duration) bool
	Notifier         LiteLLMUsageEventsNotifier
}

type LiteLLMIngestRunner struct {
	client            LiteLLMSpendLogsClient
	db                *gorm.DB
	interval, overlap time.Duration
	pageSize          int
	initialLookback   time.Duration
	maxBackfillRange  time.Duration
	maxPages          int
	retryDelays       []time.Duration
	now               func() time.Time
	sleep             func(context.Context, time.Duration) bool
	notifier          LiteLLMUsageEventsNotifier
	mu                sync.RWMutex
	status            Status
}

func NewLiteLLMIngestRunner(client *LiteLLMClient, db *gorm.DB, interval, overlap time.Duration, pageSize int) *LiteLLMIngestRunner {
	return NewLiteLLMIngestRunnerWithOptions(client, db, LiteLLMIngestRunnerOptions{
		Interval: interval,
		Overlap:  overlap,
		PageSize: pageSize,
	})
}

func NewLiteLLMIngestRunnerWithOptions(client LiteLLMSpendLogsClient, db *gorm.DB, options LiteLLMIngestRunnerOptions) *LiteLLMIngestRunner {
	initialLookback := options.InitialLookback
	if initialLookback <= 0 {
		initialLookback = liteLLMDefaultInitialLookback
	}
	maxBackfillRange := options.MaxBackfillRange
	if maxBackfillRange <= 0 {
		maxBackfillRange = liteLLMDefaultMaxBackfill
	}
	maxPages := options.MaxPages
	if maxPages <= 0 {
		maxPages = liteLLMDefaultMaxPages
	}
	retryDelays := options.RetryDelays
	if retryDelays == nil {
		retryDelays = append([]time.Duration(nil), liteLLMDefaultRetryDelays...)
	} else {
		retryDelays = append([]time.Duration(nil), retryDelays...)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	sleep := options.Sleep
	if sleep == nil {
		sleep = liteLLMSleepContext
	}
	return &LiteLLMIngestRunner{
		client:           client,
		db:               db,
		interval:         options.Interval,
		overlap:          options.Overlap,
		pageSize:         options.PageSize,
		initialLookback:  initialLookback,
		maxBackfillRange: maxBackfillRange,
		maxPages:         maxPages,
		retryDelays:      retryDelays,
		now:              now,
		sleep:            sleep,
		notifier:         options.Notifier,
	}
}
func (r *LiteLLMIngestRunner) Status() Status { r.mu.RLock(); defer r.mu.RUnlock(); return r.status }
func (r *LiteLLMIngestRunner) Run(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("LiteLLM ingest runner is nil")
	}
	if r.interval <= 0 {
		return fmt.Errorf("LiteLLM sync interval must be positive")
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		_ = r.SyncOnce(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (r *LiteLLMIngestRunner) SyncOnce(ctx context.Context) (err error) {
	if r == nil || r.client == nil {
		return fmt.Errorf("LiteLLM client is nil")
	}
	if r.db == nil {
		return fmt.Errorf("database is nil")
	}
	if r.pageSize <= 0 {
		return fmt.Errorf("LiteLLM page size must be positive")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	r.status.Running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.status.Running = false
		r.status.LastRunAt = r.now()
		if err != nil {
			r.status.LastError = err.Error()
			r.status.LastStatus = "error"
			return
		}
		r.status.LastError = ""
		r.status.LastStatus = "success"
	}()
	checkpoint, err := repository.LoadLiteLLMSyncCheckpoint(r.db)
	if err != nil {
		return err
	}
	end := r.now()
	start := checkpoint.Cursor.Add(-r.overlap)
	if checkpoint.Cursor.IsZero() {
		start = end.Add(-r.initialLookback)
	}
	if err = r.syncRange(ctx, start, end); err != nil {
		return err
	}
	checkpoint.Cursor = end
	return repository.SaveLiteLLMSyncCheckpoint(r.db, checkpoint)
}

// Backfill imports a bounded historical range with the same mapper and durable
// receipt path as scheduled polling. It intentionally does not move the live
// checkpoint, so an operator cannot skip the normal overlap window.
func (r *LiteLLMIngestRunner) Backfill(ctx context.Context, start, end time.Time) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("LiteLLM client is nil")
	}
	if r.db == nil {
		return fmt.Errorf("database is nil")
	}
	if r.pageSize <= 0 {
		return fmt.Errorf("LiteLLM page size must be positive")
	}
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return fmt.Errorf("LiteLLM backfill requires an increasing start and end time")
	}
	if end.Sub(start) > r.maxBackfillRange {
		return fmt.Errorf("LiteLLM backfill range exceeds %s", r.maxBackfillRange)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return r.syncRange(ctx, start, end)
}

func (r *LiteLLMIngestRunner) syncRange(ctx context.Context, start, end time.Time) error {
	for page := 1; ; page++ {
		if page > r.maxPages {
			return fmt.Errorf("LiteLLM spend logs exceeded page limit %d", r.maxPages)
		}
		result, err := r.listSpendLogsWithRetry(ctx, start, end, page)
		if err != nil {
			return err
		}
		if result.TotalPages < page || result.TotalPages > r.maxPages {
			return fmt.Errorf("invalid LiteLLM total_pages %d on page %d", result.TotalPages, page)
		}
		events := make([]entities.UsageEvent, 0, len(result.Data))
		for _, log := range result.Data {
			event, err := MapLiteLLMSpendLog(log)
			if err != nil {
				return err
			}
			events = append(events, event)
		}
		inserted, err := repository.InsertExternalUsageEvents(r.db, "litellm", events)
		if err != nil {
			return err
		}
		if len(inserted) > 0 && r.notifier != nil {
			r.notifier.NotifyUsageEventsCommitted(inserted)
		}
		if page == result.TotalPages {
			return nil
		}
	}
}

func (r *LiteLLMIngestRunner) listSpendLogsWithRetry(ctx context.Context, start, end time.Time, page int) (LiteLLMSpendLogPage, error) {
	for attempt := 0; ; attempt++ {
		result, err := r.client.ListSpendLogs(ctx, start, end, page, r.pageSize)
		if err == nil {
			return result, nil
		}
		if !isRetryableLiteLLMError(err) || attempt >= len(r.retryDelays) {
			return LiteLLMSpendLogPage{}, err
		}
		if !r.sleep(ctx, r.retryDelays[attempt]) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return LiteLLMSpendLogPage{}, ctxErr
			}
			return LiteLLMSpendLogPage{}, err
		}
	}
}

func isRetryableLiteLLMError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var httpErr *LiteLLMHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == 408 || httpErr.StatusCode == 429 || httpErr.StatusCode >= 500
	}
	var syntaxErr *json.SyntaxError
	return !errors.As(err, &syntaxErr)
}

func liteLLMSleepContext(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
