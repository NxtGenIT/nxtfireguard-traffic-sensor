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
	o.MinPause, o.MaxPause = 2*time.Millisecond, 8*time.Millisecond
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
	o.MaxBackoff = time.Second // Retry-After is capped at MaxBackoff
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

func TestOutboxGivesUpOnlyOnTemporaryErrors(t *testing.T) {
	o := runOutbox(t, 10)
	o.MaxAttempts = 3
	var rejectedGaveUp, exhausted atomic.Bool
	var rejected, calls atomic.Int32
	o.Add(kindAlert, "bad", func(context.Context) error { rejected.Add(1); return &nfg.StatusError{Code: 400} }, func() { rejectedGaveUp.Store(true) })
	o.Add(kindAlert, "down", func(context.Context) error { calls.Add(1); return errors.New("connection refused") }, func() { exhausted.Store(true) })
	eventually(t, "give up", func() bool { return exhausted.Load() && o.Len() == 0 })
	if calls.Load() != 3 {
		t.Errorf("attempts %d, want 3", calls.Load())
	}
	// A 4xx will never succeed: drop it once and do not ask for a resend.
	if rejected.Load() != 1 || rejectedGaveUp.Load() {
		t.Errorf("rejected message: %d sends, giveUp %v; want 1 send, no giveUp", rejected.Load(), rejectedGaveUp.Load())
	}
}

func TestOutboxRateLimitWithoutRetryAfterIsNotAnAttempt(t *testing.T) {
	o := runOutbox(t, 10)
	o.MaxAttempts = 2
	var calls atomic.Int32
	o.Add(kindRecommendation, "r", func(context.Context) error {
		if calls.Add(1) <= 5 {
			return &nfg.RateLimitedError{} // score-proxy sends no Retry-After
		}
		return nil
	}, func() { t.Error("a rate-limited message must not be given up") })
	eventually(t, "delivery after the limit lifts", func() bool { return calls.Load() == 6 && o.Len() == 0 })
}

func TestOutboxPauseGrowsAndResets(t *testing.T) {
	o := NewOutbox(1)
	o.MinPause, o.MaxPause, o.MaxBackoff = time.Second, 4*time.Second, time.Minute
	now := time.Unix(0, 0)
	o.now = func() time.Time { return now }
	var got []time.Duration
	for range 4 {
		got = append(got, o.holdKind(kindAlert, 0).Sub(now))
		now = now.Add(time.Hour)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pauses %v, want %v", got, want)
		}
	}
	if d := o.holdKind(kindAlert, 10*time.Second).Sub(now); d != 10*time.Second {
		t.Errorf("Retry-After ignored: %s", d)
	}
}

func TestOutboxCapacityIsPerKind(t *testing.T) {
	o := NewOutbox(2) // not running: nothing is delivered
	var dropped atomic.Int32
	for _, k := range []string{"a", "b", "c"} {
		o.Add(kindAlert, k, func(context.Context) error { return nil }, func() { dropped.Add(1) })
	}
	if o.Len() != 2 || dropped.Load() != 1 {
		t.Fatalf("len %d dropped %d", o.Len(), dropped.Load())
	}
	if !o.Add(kindRecommendation, "r", func(context.Context) error { return nil }, nil) {
		t.Fatal("a full alert queue must not block recommendations")
	}
}
