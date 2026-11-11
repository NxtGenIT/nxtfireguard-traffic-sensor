package capture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/flow"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

const (
	snapLen = 1600
	// readTimeout lets the read loop notice cancellation on idle links.
	readTimeout = 500 * time.Millisecond
)

// Eligible reports whether an interface is captured: it must have an
// address and must not be loopback or a Docker bridge or veth.
func Eligible(name string, hasAddress bool) bool {
	if !hasAddress {
		return false
	}
	for _, prefix := range []string{"lo", "docker", "br-", "veth"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

// Run captures on every eligible interface until ctx ends or one of them
// fails. ready is called once all interfaces are open.
func Run(ctx context.Context, emit func(flow.Flow), ready func()) error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	var handles []*pcap.Handle
	var names []string
	for _, d := range devs {
		if !Eligible(d.Name, len(d.Addresses) > 0) {
			continue
		}
		h, err := pcap.OpenLive(d.Name, snapLen, true, readTimeout)
		if err != nil {
			zap.L().Warn("capture: cannot open interface", zap.String("interface", d.Name), zap.Error(err))
			continue
		}
		if err := h.SetBPFFilter("ip or ip6"); err != nil {
			zap.L().Warn("capture: no BPF filter", zap.String("interface", d.Name), zap.Error(err))
		}
		handles = append(handles, h)
		names = append(names, d.Name)
	}
	if len(handles) == 0 {
		return errors.New("capture: no interface could be opened")
	}
	zap.L().Info("capture: started", zap.Strings("interfaces", names))
	ready()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(handles))
	var wg sync.WaitGroup
	for i, h := range handles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer h.Close()
			err := read(ctx, h, names[i], emit)
			if ctx.Err() == nil {
				errs <- fmt.Errorf("capture %s: %w", names[i], err)
				cancel()
			}
		}()
	}
	wg.Wait()
	close(errs)
	return <-errs // nil when ctx ended
}

func read(ctx context.Context, h *pcap.Handle, name string, emit func(flow.Flow)) error {
	c := NewClassifier()
	source := nfg.Source{Type: "interface", Name: name}
	decode := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	for ctx.Err() == nil {
		data, _, err := h.ZeroCopyReadPacketData()
		switch {
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			continue
		case err != nil:
			return err
		}
		p := gopacket.NewPacket(data, h.LinkType(), decode)
		if src, dst, isNew := c.Classify(p); isNew {
			emit(flow.New(src, dst, source))
		}
	}
	return nil
}
