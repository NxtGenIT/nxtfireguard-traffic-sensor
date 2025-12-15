package arbiter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"go.uber.org/zap"
)

// QueuedItem represents something that needs to be retried
type QueuedItem struct {
	ItemType  string      // "alert" or "recommendation"
	Data      interface{} // the actual data to send
	Attempts  int
	NextRetry time.Time
}

type AlertData struct {
	IpType    string
	Ip        string
	RelatedIp string
	Source    types.Source
}

type RecommendationData struct {
	IP        string
	Decisions []types.Decision
}

// RetryQueue manages items that failed due to rate limiting
type RetryQueue struct {
	mu    sync.RWMutex
	items []QueuedItem
	cfg   *config.Config
}

var (
	globalRetryQueue *RetryQueue
	queueOnce        sync.Once
)

// GetRetryQueue returns the singleton retry queue
func GetRetryQueue(cfg *config.Config) *RetryQueue {
	queueOnce.Do(func() {
		globalRetryQueue = &RetryQueue{
			items: make([]QueuedItem, 0),
			cfg:   cfg,
		}
	})
	return globalRetryQueue
}

// Add adds an item to the retry queue
func (rq *RetryQueue) Add(itemType string, data interface{}) {
	rq.mu.Lock()
	defer rq.mu.Unlock()

	item := QueuedItem{
		ItemType:  itemType,
		Data:      data,
		Attempts:  0,
		NextRetry: time.Now().Add(5 * time.Second), // Initial retry after 5 seconds
	}

	rq.items = append(rq.items, item)
	zap.L().Info("Added item to retry queue",
		zap.String("type", itemType),
		zap.Int("queueSize", len(rq.items)),
	)
}

// ProcessQueue processes items ready for retry
func (rq *RetryQueue) ProcessQueue(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			zap.L().Info("Retry queue processor stopping")
			return
		case <-ticker.C:
			rq.processReadyItems()
		}
	}
}

func (rq *RetryQueue) processReadyItems() {
	rq.mu.Lock()
	defer rq.mu.Unlock()

	now := time.Now()
	var remaining []QueuedItem

	for _, item := range rq.items {
		if now.Before(item.NextRetry) {
			// Not ready yet, keep in queue
			remaining = append(remaining, item)
			continue
		}

		// Try to process the item
		success := false
		var err error

		switch item.ItemType {
		case "alert":
			if alertData, ok := item.Data.(AlertData); ok {
				err = sendAlertInternal(alertData.IpType, alertData.Ip, alertData.RelatedIp, alertData.Source, rq.cfg)
				success = (err == nil)
			}
		case "recommendation":
			if recData, ok := item.Data.(RecommendationData); ok {
				err = recommendInternal(rq.cfg, recData.IP, recData.Decisions)
				success = (err == nil)
			}
		}

		if success {
			zap.L().Info("Successfully retried queued item",
				zap.String("type", item.ItemType),
				zap.Int("attempts", item.Attempts+1),
			)
			// Item succeeded, don't add back to queue
			continue
		}

		// Check if we should give up
		item.Attempts++
		maxAttempts := 10
		if item.Attempts >= maxAttempts {
			zap.L().Warn("Dropping item after max retries",
				zap.String("type", item.ItemType),
				zap.Int("attempts", item.Attempts),
			)
			continue
		}

		// Calculate exponential backoff: 5s, 10s, 20s, 40s, ... up to 5 minutes
		backoff := time.Duration(5*(1<<item.Attempts)) * time.Second
		if backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
		item.NextRetry = now.Add(backoff)

		zap.L().Debug("Requeueing item",
			zap.String("type", item.ItemType),
			zap.Int("attempts", item.Attempts),
			zap.Duration("nextRetry", backoff),
			zap.Error(err),
		)

		remaining = append(remaining, item)
	}

	rq.items = remaining
	if len(rq.items) > 0 {
		zap.L().Debug("Retry queue status", zap.Int("itemsRemaining", len(rq.items)))
	}
}

// GetQueueSize returns the current queue size (for monitoring)
func (rq *RetryQueue) GetQueueSize() int {
	rq.mu.RLock()
	defer rq.mu.RUnlock()
	return len(rq.items)
}

// RateLimitError represents a 429 response
type RateLimitError struct {
	StatusCode int
	Message    string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded (429): %s", e.Message)
}

func isRateLimitError(err error) bool {
	_, ok := err.(*RateLimitError)
	return ok
}
