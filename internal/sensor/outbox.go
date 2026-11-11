package sensor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"go.uber.org/zap"
)

const (
	kindAlert          = "alert"
	kindRecommendation = "recommendation"
)

// Outbox delivers alerts and recommendations in the background. A message
// that fails temporarily (network, 5xx, 429) is retried with backoff; a 429
// also holds back every message of that kind until the backend accepts
// them again. A message equal to one still waiting is dropped, and so is
// everything once Capacity messages are waiting.
type Outbox struct {
	Capacity    int
	MaxAttempts int
	Backoff     time.Duration // first retry delay, doubled per attempt
	MaxBackoff  time.Duration
	Tick        time.Duration // how often due retries are released

	mu      sync.Mutex
	pending map[string]*job
	delayed []*job
	paused  map[string]time.Time
	ready   chan *job
	now     func() time.Time

	dropped atomic.Uint64
}

type job struct {
	kind, key string
	send      func(context.Context) error
	giveUp    func()
	attempts  int
	due       time.Time
}

func NewOutbox(capacity int) *Outbox {
	return &Outbox{
		Capacity:    capacity,
		MaxAttempts: 10,
		Backoff:     5 * time.Second,
		MaxBackoff:  5 * time.Minute,
		Tick:        time.Second,
		pending:     map[string]*job{},
		paused:      map[string]time.Time{},
		ready:       make(chan *job, capacity),
		now:         time.Now,
	}
}

// Add queues a message. giveUp, if set, runs when the message is dropped
// without being delivered. It reports whether the message was queued.
func (o *Outbox) Add(kind, key string, send func(context.Context) error, giveUp func()) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, dup := o.pending[key]; dup {
		return false
	}
	if len(o.pending) >= o.Capacity {
		o.dropped.Add(1)
		if giveUp != nil {
			giveUp()
		}
		return false
	}
	j := &job{kind: kind, key: key, send: send, giveUp: giveUp}
	o.pending[key] = j
	o.ready <- j // never blocks: ready holds at most len(pending) jobs
	return true
}

// Run delivers messages with the given number of concurrent senders until
// ctx ends. Messages still waiting then are lost.
func (o *Outbox) Run(ctx context.Context, senders int) {
	var wg sync.WaitGroup
	for range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-o.ready:
					o.deliver(ctx, j)
				}
			}
		}()
	}

	t := time.NewTicker(o.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-t.C:
			o.releaseDue()
			if n := o.dropped.Swap(0); n > 0 {
				zap.L().Warn("outbox full, messages dropped", zap.Uint64("count", n))
			}
		}
	}
}

func (o *Outbox) deliver(ctx context.Context, j *job) {
	if until, ok := o.pausedUntil(j.kind); ok {
		o.retryAt(j, until, false)
		return
	}
	err := j.send(ctx)
	if err == nil || ctx.Err() != nil {
		o.finish(j, false)
		return
	}

	var rl *nfg.RateLimitedError
	switch {
	case errors.As(err, &rl):
		wait := rl.RetryAfter
		if wait <= 0 {
			wait = o.backoff(j.attempts + 1)
		}
		until := o.now().Add(wait)
		o.mu.Lock()
		if until.After(o.paused[j.kind]) {
			o.paused[j.kind] = until
		}
		o.mu.Unlock()
		zap.L().Info("backend rate limit, holding messages", zap.String("kind", j.kind), zap.Duration("for", wait))
		o.retryAt(j, until, true)
	case nfg.Temporary(err):
		o.retryAt(j, o.now().Add(o.backoff(j.attempts+1)), true)
	default:
		zap.L().Warn("message rejected by backend", zap.String("kind", j.kind), zap.Error(err))
		o.finish(j, true)
	}
}

func (o *Outbox) retryAt(j *job, due time.Time, attempted bool) {
	if attempted {
		j.attempts++
		if j.attempts >= o.MaxAttempts {
			zap.L().Warn("message dropped after retries", zap.String("kind", j.kind), zap.Int("attempts", j.attempts))
			o.finish(j, true)
			return
		}
	}
	j.due = due
	o.mu.Lock()
	o.delayed = append(o.delayed, j)
	o.mu.Unlock()
}

func (o *Outbox) finish(j *job, failed bool) {
	o.mu.Lock()
	delete(o.pending, j.key)
	o.mu.Unlock()
	if failed && j.giveUp != nil {
		j.giveUp()
	}
}

func (o *Outbox) releaseDue() {
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	keep := o.delayed[:0]
	for _, j := range o.delayed {
		if now.Before(j.due) {
			keep = append(keep, j)
		} else {
			o.ready <- j
		}
	}
	clear(o.delayed[len(keep):])
	o.delayed = keep
}

func (o *Outbox) pausedUntil(kind string) (time.Time, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	until, ok := o.paused[kind]
	if ok && o.now().Before(until) {
		return until, true
	}
	return time.Time{}, false
}

func (o *Outbox) backoff(attempt int) time.Duration {
	d := o.Backoff
	for i := 1; i < attempt && d < o.MaxBackoff; i++ {
		d *= 2
	}
	return min(d, o.MaxBackoff)
}

// Len is the number of messages not yet delivered.
func (o *Outbox) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.pending)
}
