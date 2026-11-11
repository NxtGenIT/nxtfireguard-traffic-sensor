package sensor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
)

func runOutbox(t *testing.T, capacity int) *Outbox {
	t.Helper()
	o := NewOutbox(capacity)
	o.Backoff, o.MaxBackoff, o.Tick = time.Millisecond, 4*time.Millisecond, time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { o.Run(ctx, 2); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return o
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOutboxRetriesTemporaryErrors(t *testing.T) {
	o := runOutbox(t, 10)
	var calls atomic.Int32
	o.Add(kindAlert, "a", func(context.Context) error {
		if calls.Add(1) < 3 {
			return &nfg.StatusError{Code: 502}
		}
		return nil
	}, func() { t.Error("gave up on a message that succeeded") })
	eventually(t, "delivery", func() bool { return calls.Load() == 3 && o.Len() == 0 })
}

func TestOutboxDropsDuplicatesWhilePending(t *testing.T) {
	o := runOutbox(t, 10)
	release := make(chan struct{})
	var calls atomic.Int32
	send := func(context.Context) error { calls.Add(1); <-release; return nil }
	if !o.Add(kindAlert, "same", send, nil) || o.Add(kindAlert, "same", send, nil) {
		t.Fatal("duplicate accepted")
	}
	close(release)
	eventually(t, "delivery", func() bool { return o.Len() == 0 })
	if !o.Add(kindAlert, "same", func(context.Context) error { return nil }, nil) {
		t.Fatal("key must be free again after delivery")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
}

func TestOutboxRateLimitHoldsTheKind(t *testing.T) {
	o := runOutbox(t, 10)
	start := time.Now()
	var mu sync.Mutex
	var sentAt []time.Duration
	limited := atomic.Bool{}
	o.Add(kindRecommendation, "r1", func(context.Context) error {
		if !limited.Swap(true) {
			return &nfg.RateLimitedError{RetryAfter: 50 * time.Millisecond}
		}
		mu.Lock()
		sentAt = append(sentAt, time.Since(start))
		mu.Unlock()
		return nil
	}, nil)
	eventually(t, "rate limit hit", limited.Load)
	o.Add(kindRecommendation, "r2", func(context.Context) error {
		mu.Lock()
		sentAt = append(sentAt, time.Since(start))
		mu.Unlock()
		return nil
	}, nil)
	var alertSent atomic.Bool
	o.Add(kindAlert, "a", func(context.Context) error { alertSent.Store(true); return nil }, nil)

	eventually(t, "both recommendations", func() bool { mu.Lock(); defer mu.Unlock(); return len(sentAt) == 2 })
	if !alertSent.Load() {
		t.Error("other kinds must not be held")
	}
	for _, d := range sentAt {
		if d < 50*time.Millisecond {
			t.Errorf("recommendation sent %s after start, before Retry-After passed", d)
		}
	}
}

func TestOutboxGivesUp(t *testing.T) {
	o := runOutbox(t, 10)
	o.MaxAttempts = 3
	var permanent, exhausted atomic.Bool
	var calls atomic.Int32
	o.Add(kindAlert, "bad", func(context.Context) error { return &nfg.StatusError{Code: 400} }, func() { permanent.Store(true) })
	o.Add(kindAlert, "down", func(context.Context) error { calls.Add(1); return errors.New("connection refused") }, func() { exhausted.Store(true) })
	eventually(t, "give up", func() bool { return permanent.Load() && exhausted.Load() })
	if calls.Load() != 3 {
		t.Errorf("attempts %d, want 3", calls.Load())
	}
}

func TestOutboxCapacity(t *testing.T) {
	o := NewOutbox(2) // not running: nothing is delivered
	var dropped atomic.Int32
	for _, k := range []string{"a", "b", "c"} {
		o.Add(kindAlert, k, func(context.Context) error { return nil }, func() { dropped.Add(1) })
	}
	if o.Len() != 2 || dropped.Load() != 1 {
		t.Fatalf("len %d dropped %d", o.Len(), dropped.Load())
	}
}
