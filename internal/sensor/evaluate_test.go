package sensor

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/flow"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/policy"
)

type mapScores struct {
	mu sync.Mutex
	m  map[netip.Addr]int32
}

func (s *mapScores) Score(ip netip.Addr) (int32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[ip], nil
}

func (s *mapScores) set(ip netip.Addr, v int32) {
	s.mu.Lock()
	s.m[ip] = v
	s.mu.Unlock()
}

type gatedBackend struct {
	gate  chan struct{} // recommendations wait here
	recs  atomic.Int32
	calls atomic.Int32
}

func (b *gatedBackend) SendAlert(context.Context, nfg.Alert) error { return nil }
func (b *gatedBackend) SendRecommendation(ctx context.Context, _ nfg.Recommendation) error {
	b.calls.Add(1)
	select {
	case <-b.gate:
	case <-ctx.Done():
		return ctx.Err()
	}
	b.recs.Add(1)
	return nil
}

// A recommendation that waited in the outbox (rate limit, retries) is not
// sent once the score no longer meets any blocklist.
func TestQueuedRecommendationIsRecheckedBeforeSending(t *testing.T) {
	var p policy.State
	p.SetAlertThreshold(100)
	p.SetBlocklists([]nfg.Blocklist{{ID: 1, Name: "edge", ShouldIncludePublicIPs: true, NfgScoreThresholdPublicIPs: 70}})
	p.SetWhitelist(nil)

	bad := netip.MustParseAddr("203.0.113.7")
	scores := &mapScores{m: map[netip.Addr]int32{bad: 90}}
	o := NewOutbox(10) // not running yet: the job waits
	b := &gatedBackend{gate: make(chan struct{})}
	close(b.gate)
	e := NewEvaluator(&p, scores, b, o, 100)

	e.Evaluate(flow.New(bad, netip.MustParseAddr("198.51.100.1"), nfg.Source{Type: "traffic"}))
	if o.Len() != 1 {
		t.Fatalf("queued %d, want 1 recommendation", o.Len())
	}
	scores.set(bad, 20) // score-update arrives while it waits
	e.Forget(bad.String())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.Run(ctx, 1)
	eventually(t, "outbox drained", func() bool { return o.Len() == 0 })
	time.Sleep(10 * time.Millisecond)
	if b.calls.Load() != 0 {
		t.Fatalf("outdated recommendation sent (%d calls)", b.calls.Load())
	}

	// Still valid: sent.
	scores.set(bad, 95)
	e.Evaluate(flow.New(bad, netip.MustParseAddr("198.51.100.1"), nfg.Source{Type: "traffic"}))
	eventually(t, "valid recommendation sent", func() bool { return b.recs.Load() == 1 })
}
