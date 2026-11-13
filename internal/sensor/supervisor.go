package sensor

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Component is a long-running part of the sensor that the backend can turn
// on and off. It calls ready once it works and returns when ctx ends or it
// fails.
type Component func(ctx context.Context, ready func()) error

// Supervisor runs the components the backend wants and restarts failed
// ones with backoff.
type Supervisor struct {
	ctx        context.Context
	stop       context.CancelFunc
	MinBackoff time.Duration
	MaxBackoff time.Duration

	mu      sync.Mutex
	running map[string]*instance
}

type instance struct {
	cancel context.CancelFunc
	done   chan struct{}
	ready  atomic.Bool
}

func NewSupervisor() *Supervisor {
	ctx, stop := context.WithCancel(context.Background())
	return &Supervisor{ctx: ctx, stop: stop, MinBackoff: time.Second, MaxBackoff: time.Minute, running: map[string]*instance{}}
}

// Set starts name if want and it is not running, or stops it if !want.
func (s *Supervisor) Set(name string, want bool, run Component) {
	s.mu.Lock()
	inst, isRunning := s.running[name]
	switch {
	case want && !isRunning:
		ctx, cancel := context.WithCancel(s.ctx)
		inst = &instance{cancel: cancel, done: make(chan struct{})}
		s.running[name] = inst
		s.mu.Unlock()
		zap.L().Info("component starting", zap.String("component", name))
		go s.loop(ctx, name, inst, run)
	case !want && isRunning:
		delete(s.running, name)
		s.mu.Unlock()
		inst.cancel()
		<-inst.done
		zap.L().Info("component stopped", zap.String("component", name))
	default:
		s.mu.Unlock()
	}
}

func (s *Supervisor) loop(ctx context.Context, name string, inst *instance, run Component) {
	defer close(inst.done)
	wait := s.MinBackoff
	for {
		start := time.Now()
		err := run(ctx, func() { inst.ready.Store(true) })
		inst.ready.Store(false)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > s.MaxBackoff {
			wait = s.MinBackoff
		}
		zap.L().Error("component failed, restarting", zap.String("component", name), zap.Error(err), zap.Duration("retry_in", wait))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, s.MaxBackoff)
	}
}

// NotReady lists the wanted components that are not working right now.
func (s *Supervisor) NotReady() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for name, inst := range s.running {
		if !inst.ready.Load() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Stop stops every component and waits for them.
func (s *Supervisor) Stop() {
	s.stop()
	s.mu.Lock()
	insts := make([]*instance, 0, len(s.running))
	for _, inst := range s.running {
		insts = append(insts, inst)
	}
	s.mu.Unlock()
	for _, inst := range insts {
		<-inst.done
	}
}
