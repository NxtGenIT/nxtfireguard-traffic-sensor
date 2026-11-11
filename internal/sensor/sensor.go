// Package sensor wires the traffic sources, the score store, the backend
// rules and the delivery of alerts and recommendations together.
package sensor

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/capture"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/flow"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/policy"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/scores"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/syslog"
	"go.uber.org/zap"
)

// Timings of the background work. Variables so tests can shorten them.
var (
	// resyncEvery re-fetches everything in case a websocket push was lost.
	resyncEvery = time.Hour
	// snapshotAfterReconnect: a websocket reconnect re-fetches the score
	// snapshot only if the last one started longer ago than this.
	snapshotAfterReconnect = 5 * time.Minute
	retryMin               = 10 * time.Second
	retryMax               = 5 * time.Minute
	heartbeatEvery         = time.Minute
)

// Saved under these keys, the last rules received let the sensor work
// while the backend is unreachable at startup.
const (
	stateConfig     = "sensor_config"
	stateBlocklists = "blocklists"
	stateWhitelist  = "whitelist"
)

// Backend is what the sensor needs from nfg.Client.
type Backend interface {
	backend
	SensorConfig(context.Context) (nfg.SensorConfig, error)
	Blocklists(context.Context) ([]nfg.Blocklist, error)
	Whitelist(context.Context) ([]string, error)
	ScoreSnapshot(context.Context, func(nfg.Score) error) error
	Heartbeat(context.Context) error
	Stream(ctx context.Context, connected func(), handle func(nfg.Update))
}

type Sensor struct {
	cfg     config.Config
	backend Backend
	store   *scores.Store

	policy policy.State
	eval   *Evaluator
	outbox *Outbox
	flows  chan flow.Flow
	sup    *Supervisor

	// Components run by the supervisor; replaceable in tests.
	capture Component
	syslog  Component

	refresh      map[string]chan struct{}
	scoreUpdates chan nfg.ScoreUpdate
	snapshotAt   atomic.Int64 // unix nanos of the last snapshot start
	droppedFlows atomic.Uint64

	configMu sync.Mutex
	config   *nfg.SensorConfig
}

func New(cfg config.Config, b Backend, store *scores.Store) *Sensor {
	s := &Sensor{
		cfg:          cfg,
		backend:      b,
		store:        store,
		outbox:       NewOutbox(cfg.QueueSize),
		flows:        make(chan flow.Flow, cfg.QueueSize),
		refresh:      map[string]chan struct{}{},
		scoreUpdates: make(chan nfg.ScoreUpdate, 4096),
		sup:          NewSupervisor(),
	}
	s.eval = NewEvaluator(&s.policy, store, b, s.outbox, cfg.RecommendCacheSize)
	s.capture = func(ctx context.Context, ready func()) error { return capture.Run(ctx, s.Submit, ready) }
	s.syslog = func(ctx context.Context, ready func()) error { return syslog.Run(ctx, cfg.SyslogAddr, s.Submit, ready) }
	for _, r := range []string{stateConfig, stateBlocklists, stateWhitelist, "scores"} {
		s.refresh[r] = make(chan struct{}, 1)
	}
	return s
}

// Submit hands a flow to the evaluation workers. It never blocks: when the
// workers fall behind, flows are dropped and counted.
func (s *Sensor) Submit(f flow.Flow) {
	select {
	case s.flows <- f:
	default:
		s.droppedFlows.Add(1)
	}
}

// Run works until ctx ends.
func (s *Sensor) Run(ctx context.Context) {
	s.restoreState()
	// The first snapshot starts right away; the first websocket connect
	// must not queue a second one.
	s.snapshotAt.Store(time.Now().UnixNano())

	var wg sync.WaitGroup
	start := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	for range s.cfg.Workers {
		start(func() { s.evaluate(ctx) })
	}
	start(func() { s.outbox.Run(ctx, 4) })
	start(func() { s.applyScoreUpdates(ctx) })
	start(func() { s.keepFresh(ctx, stateConfig, s.syncConfig) })
	start(func() { s.keepFresh(ctx, stateBlocklists, s.syncBlocklists) })
	start(func() { s.keepFresh(ctx, stateWhitelist, s.syncWhitelist) })
	start(func() { s.keepFresh(ctx, "scores", s.syncScores) })
	start(func() { s.backend.Stream(ctx, s.onConnect, s.onUpdate) })
	start(func() { s.heartbeat(ctx) })
	start(func() { s.reportDrops(ctx) })

	<-ctx.Done()
	s.sup.Stop()
	wg.Wait()
}

func (s *Sensor) evaluate(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-s.flows:
			s.eval.Evaluate(f)
		}
	}
}

// keepFresh runs sync now, on every trigger, every resyncEvery, and after
// a failure again with backoff.
func (s *Sensor) keepFresh(ctx context.Context, name string, sync func(context.Context) error) {
	wait := retryMin
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.refresh[name]:
		}
		if err := sync(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			zap.L().Warn("sync failed", zap.String("resource", name), zap.Error(err), zap.Duration("retry_in", wait))
			t.Reset(wait)
			wait = min(wait*2, retryMax)
			continue
		}
		wait = retryMin
		t.Reset(resyncEvery)
	}
}

func (s *Sensor) trigger(name string) {
	select {
	case s.refresh[name] <- struct{}{}:
	default: // a refresh is already pending
	}
}

func (s *Sensor) syncConfig(ctx context.Context) error {
	c, err := s.backend.SensorConfig(ctx)
	if err != nil {
		return err
	}
	s.applyConfig(c)
	s.save(stateConfig, c)
	return nil
}

func (s *Sensor) syncBlocklists(ctx context.Context) error {
	l, err := s.backend.Blocklists(ctx)
	if err != nil {
		return err
	}
	s.applyBlocklists(l)
	s.save(stateBlocklists, l)
	return nil
}

func (s *Sensor) syncWhitelist(ctx context.Context) error {
	w, err := s.backend.Whitelist(ctx)
	if err != nil {
		return err
	}
	s.applyWhitelist(w)
	s.save(stateWhitelist, w)
	return nil
}

func (s *Sensor) syncScores(ctx context.Context) error {
	s.snapshotAt.Store(time.Now().UnixNano())
	start := time.Now()
	n, err := s.store.ReplaceAll(ctx, func(add func(nfg.Score) error) error {
		return s.backend.ScoreSnapshot(ctx, add)
	})
	if err != nil {
		return err
	}
	zap.L().Info("score snapshot loaded", zap.Int("ips", n), zap.Duration("took", time.Since(start)))
	return nil
}

func (s *Sensor) applyConfig(c nfg.SensorConfig) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if s.config == nil || *s.config != c {
		zap.L().Info("sensor config", zap.Bool("sniff_traffic", c.SniffTraffic), zap.Bool("run_syslog", c.RunSyslog), zap.Int32("alert_threshold", c.AlertThreshold))
	}
	s.config = &c
	s.policy.SetAlertThreshold(c.AlertThreshold)
	s.sup.Set("capture", c.SniffTraffic, s.capture)
	s.sup.Set("syslog", c.RunSyslog, s.syslog)
}

func (s *Sensor) applyBlocklists(l []nfg.Blocklist) {
	if s.policy.SetBlocklists(l) {
		s.eval.ForgetAll()
		zap.L().Info("blocklists", zap.Int("count", len(l)))
	}
}

func (s *Sensor) applyWhitelist(cidrs []string) {
	if bad := s.policy.SetWhitelist(cidrs); len(bad) > 0 {
		zap.L().Warn("whitelist entries skipped, not CIDRs", zap.Strings("entries", bad))
	}
	zap.L().Debug("whitelist", zap.Int("cidrs", len(cidrs)))
}

// restoreState applies the rules saved by the last run, if any.
func (s *Sensor) restoreState() {
	var c nfg.SensorConfig
	if s.load(stateConfig, &c) {
		s.applyConfig(c)
	}
	var l []nfg.Blocklist
	if s.load(stateBlocklists, &l) {
		s.applyBlocklists(l)
	}
	var w []string
	if s.load(stateWhitelist, &w) {
		s.applyWhitelist(w)
	}
	if s.policy.Load() != nil {
		zap.L().Info("using saved backend rules until the backend answers")
	}
}

func (s *Sensor) load(key string, v any) bool {
	ok, err := s.store.LoadState(key, v)
	if err != nil {
		zap.L().Warn("saved state unreadable", zap.String("key", key), zap.Error(err))
	}
	return ok && err == nil
}

func (s *Sensor) save(key string, v any) {
	if err := s.store.SaveState(key, v); err != nil {
		zap.L().Warn("cannot save state", zap.String("key", key), zap.Error(err))
	}
}

// onConnect resyncs what may have changed while the websocket was down.
func (s *Sensor) onConnect() {
	s.trigger(stateConfig)
	s.trigger(stateBlocklists)
	s.trigger(stateWhitelist)
	if time.Since(time.Unix(0, s.snapshotAt.Load())) > snapshotAfterReconnect {
		s.trigger("scores")
	}
}

func (s *Sensor) onUpdate(u nfg.Update) {
	switch u.Type {
	case nfg.UpdateScore:
		var su nfg.ScoreUpdate
		if err := json.Unmarshal(u.Data, &su); err != nil {
			zap.L().Warn("bad score-update", zap.Error(err))
			return
		}
		select {
		case s.scoreUpdates <- su:
		default:
			// Too many to keep up with; the snapshot catches up on all.
			s.trigger("scores")
		}
	case nfg.UpdateBlocklist:
		s.trigger(stateBlocklists)
	case nfg.UpdateWhitelist:
		s.trigger(stateWhitelist)
	case nfg.UpdateConfig:
		s.trigger(stateConfig)
	default:
		zap.L().Debug("unknown update type", zap.String("type", u.Type))
	}
}

func (s *Sensor) applyScoreUpdates(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case su := <-s.scoreUpdates:
			if err := s.store.Put(nfg.Score{IP: su.IP, Score: su.Score, LastUpdated: su.Timestamp}); err != nil {
				zap.L().Warn("cannot store score-update", zap.String("ip", su.IP), zap.Error(err))
				continue
			}
			s.eval.Forget(su.IP)
		}
	}
}

// heartbeat tells the backend the sensor is alive, but only while every
// component the backend turned on is working.
func (s *Sensor) heartbeat(ctx context.Context) {
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if broken := s.sup.NotReady(); len(broken) > 0 {
			zap.L().Warn("heartbeat skipped, components not running", zap.Strings("components", broken))
			continue
		}
		if err := s.backend.Heartbeat(ctx); err != nil && !errors.Is(err, context.Canceled) {
			zap.L().Warn("heartbeat failed", zap.Error(err))
		}
	}
}

func (s *Sensor) reportDrops(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := s.droppedFlows.Swap(0); n > 0 {
				zap.L().Warn("evaluation queue full, flows dropped", zap.Uint64("count", n))
			}
		}
	}
}
