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

var kinds = []string{kindAlert, kindRecommendation}

// Outbox delivers alerts and recommendations in the background.
//
//   - Network errors and 5xx answers are retried with backoff, up to
//     MaxAttempts; then giveUp runs so the caller may try again later.
//   - A 429 holds back every message of that kind. score-proxy limits per
//     second and sends no Retry-After, so without one the pause starts at
//     MinPause and doubles while the backend keeps refusing (up to
//     MaxPause). A 429 is not a failed attempt: the message waits, it is
//     not dropped.
//   - Any other 4xx means the backend will never take the message; it is
//     dropped without giveUp, so the caller does not send it again.
//
// A message whose key is still waiting is dropped, and so is every new
// message of a kind once Capacity messages of that kind are waiting. Each
// kind has its own capacity so a flood of alerts cannot crowd out
// recommendations (which are what actually block traffic).
type Outbox struct {
	Capacity    int // per kind
	MaxAttempts int
	Backoff     time.Duration // first retry delay, doubled per attempt
	MaxBackoff  time.Duration
	MinPause    time.Duration // rate-limit pause without Retry-After
	MaxPause    time.Duration
	Tick        time.Duration // how often due retries are released

	mu      sync.Mutex
	pending map[string]*job
	perKind map[string]int
	delayed []*job
	paused  map[string]time.Time
	pause   map[string]time.Duration // current pause per kind, reset on success
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
		MinPause:    time.Second,
		MaxPause:    30 * time.Second,
		Tick:        time.Second,
		pending:     map[string]*job{},
		perKind:     map[string]int{},
		paused:      map[string]time.Time{},
		pause:       map[string]time.Duration{},
		// Every pending job is in ready, in delayed or being sent, so ready
		// never holds more than all kinds' capacity together.
		ready: make(chan *job, capacity*len(kinds)),
		now:   time.Now,
	}
}

// Add queues a message. giveUp, if set, runs when the message is dropped
// for lack of room or after MaxAttempts. It reports whether the message
// was queued.
func (o *Outbox) Add(kind, key string, send func(context.Context) error, giveUp func()) bool {
	o.mu.Lock()
	if _, dup := o.pending[key]; dup {
		o.mu.Unlock()
		return false
	}
	if o.perKind[kind] >= o.Capacity {
		o.mu.Unlock()
		o.dropped.Add(1)
		if giveUp != nil {
			giveUp()
		}
		return false
	}
	j := &job{kind: kind, key: key, send: send, giveUp: giveUp}
	o.pending[key] = j
	o.perKind[kind]++
	o.ready <- j // never blocks, see NewOutbox
	o.mu.Unlock()
	return true
}

// Run delivers messages with the given number of concurrent senders until
// ctx ends. Messages still waiting then are lost.
func (o *Outbox) Run(ctx context.Context, senders int) {
	var wg sync.WaitGroup
	for range senders {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-o.ready:
					o.deliver(ctx, j)
				}
			}
		})
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
		o.delay(j, until)
		return
	}
	err := j.send(ctx)
	if ctx.Err() != nil {
		return // shutting down; the message is lost either way
	}
	if err == nil {
		o.mu.Lock()
		delete(o.pause, j.kind)
		o.mu.Unlock()
		o.finish(j, false)
		return
	}

	var rl *nfg.RateLimitedError
	switch {
	case errors.As(err, &rl):
		until := o.holdKind(j.kind, rl.RetryAfter)
		o.delay(j, until)
	case nfg.Temporary(err):
		j.attempts++
		if j.attempts >= o.MaxAttempts {
			zap.L().Warn("message dropped after retries", zap.String("kind", j.kind), zap.Int("attempts", j.attempts), zap.Error(err))
			o.finish(j, true)
			return
		}
		o.delay(j, o.now().Add(o.backoff(j.attempts)))
	default:
		zap.L().Warn("message rejected by backend", zap.String("kind", j.kind), zap.Error(err))
		o.finish(j, false)
	}
}

// holdKind pauses kind after a 429 and returns when the pause ends.
func (o *Outbox) holdKind(kind string, retryAfter time.Duration) time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	wait := retryAfter
	if wait <= 0 {
		wait = o.pause[kind]
		if wait <= 0 {
			wait = o.MinPause
		} else {
			wait = min(wait*2, o.MaxPause)
		}
		o.pause[kind] = wait
	}
	wait = min(wait, o.MaxBackoff)
	until := o.now().Add(wait)
	if until.After(o.paused[kind]) {
		o.paused[kind] = until
		zap.L().Info("backend rate limit, holding messages", zap.String("kind", kind), zap.Duration("for", wait))
	}
	return o.paused[kind]
}

func (o *Outbox) delay(j *job, due time.Time) {
	j.due = due
	o.mu.Lock()
	o.delayed = append(o.delayed, j)
	o.mu.Unlock()
}

// finish forgets j; giveUp runs if undelivered is set.
func (o *Outbox) finish(j *job, undelivered bool) {
	o.mu.Lock()
	delete(o.pending, j.key)
	o.perKind[j.kind]--
	o.mu.Unlock()
	if undelivered && j.giveUp != nil {
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
