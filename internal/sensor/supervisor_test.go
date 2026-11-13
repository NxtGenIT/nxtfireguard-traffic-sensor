package sensor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestSupervisorRestartsAndStops(t *testing.T) {
	s := NewSupervisor()
	defer s.Stop()
	s.MinBackoff, s.MaxBackoff = time.Millisecond, 2*time.Millisecond

	var starts atomic.Int32
	stopped := make(chan struct{})
	run := func(ctx context.Context, ready func()) error {
		if starts.Add(1) < 3 {
			return errors.New("bind: address in use")
		}
		ready()
		<-ctx.Done()
		close(stopped)
		return nil
	}
	s.Set("syslog", true, run)
	s.Set("syslog", true, run) // already running: no second instance
	eventually(t, "ready after restarts", func() bool { return len(s.NotReady()) == 0 && starts.Load() == 3 })

	s.Set("syslog", false, run)
	select {
	case <-stopped:
	default:
		t.Fatal("Set(false) must return after the component stopped")
	}
	if starts.Load() != 3 {
		t.Fatalf("starts %d", starts.Load())
	}
}

func TestSupervisorReportsNotReady(t *testing.T) {
	s := NewSupervisor()
	s.MinBackoff = time.Hour
	s.Set("capture", true, func(context.Context, func()) error { return errors.New("no interface") })
	eventually(t, "failure seen", func() bool { return len(s.NotReady()) == 1 && s.NotReady()[0] == "capture" })
	s.Stop()
}
