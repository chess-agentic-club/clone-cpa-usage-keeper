package poller

import (
	"context"
	"sync"
	"time"

	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"gorm.io/gorm"
)

type LiteLLMIngestRunner struct {
	client            *LiteLLMClient
	db                *gorm.DB
	interval, overlap time.Duration
	pageSize          int
	mu                sync.RWMutex
	status            Status
}

func NewLiteLLMIngestRunner(client *LiteLLMClient, db *gorm.DB, interval, overlap time.Duration, pageSize int) *LiteLLMIngestRunner {
	return &LiteLLMIngestRunner{client: client, db: db, interval: interval, overlap: overlap, pageSize: pageSize}
}
func (r *LiteLLMIngestRunner) Status() Status { r.mu.RLock(); defer r.mu.RUnlock(); return r.status }
func (r *LiteLLMIngestRunner) Run(ctx context.Context) error {
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
func (r *LiteLLMIngestRunner) SyncOnce(ctx context.Context) error {
	r.mu.Lock()
	r.status.Running = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.status.Running = false; r.status.LastRunAt = time.Now(); r.mu.Unlock() }()
	checkpoint, err := repository.LoadLiteLLMSyncCheckpoint(r.db)
	if err != nil {
		return err
	}
	end := time.Now()
	start := checkpoint.Cursor.Add(-r.overlap)
	for page := 1; ; page++ {
		result, err := r.client.ListSpendLogs(ctx, start, end, page, r.pageSize)
		if err != nil {
			return err
		}
		events := make([]entities.UsageEvent, 0, len(result.Data))
		for _, log := range result.Data {
			event, err := MapLiteLLMSpendLog(log)
			if err != nil {
				return err
			}
			events = append(events, event)
		}
		if _, err = repository.InsertExternalUsageEvents(r.db, "litellm", events); err != nil {
			return err
		}
		if result.TotalPages <= page {
			break
		}
	}
	checkpoint.Cursor = end
	return repository.SaveLiteLLMSyncCheckpoint(r.db, checkpoint)
}
