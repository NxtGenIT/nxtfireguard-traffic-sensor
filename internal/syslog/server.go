// Package syslog receives firewall and IDS logs over syslog (UDP and TCP on
// the same port) and turns each line that names two addresses into a flow.
//
// Only the message parsers of go-syslog are used. Its server is not: Kill
// closes a channel its UDP reader may still send on, which panics.
package syslog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/flow"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"go.uber.org/zap"
	"gopkg.in/mcuadros/go-syslog.v2/format"
)

// maxMessage bounds one syslog message (UDP datagram or TCP frame).
const maxMessage = 64 * 1024

// Run listens on addr until ctx ends. ready is called once both listeners
// are bound.
func Run(ctx context.Context, addr string, emit func(flow.Flow), ready func()) error {
	var lc net.ListenConfig
	udp, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("syslog udp: %w", err)
	}
	tcp, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("syslog tcp: %w", err)
	}
	zap.L().Info("syslog: listening", zap.String("addr", addr))
	ready()

	r := &receiver{emit: emit, conns: map[net.Conn]struct{}{}}
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Go(func() { errs <- r.readUDP(udp) })
	wg.Go(func() { errs <- r.acceptTCP(tcp) })

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errs:
	}
	_ = udp.Close()
	_ = tcp.Close()
	r.closeConns()
	wg.Wait()
	return runErr
}

type receiver struct {
	emit   func(flow.Flow)
	format format.Automatic

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func (r *receiver) readUDP(c net.PacketConn) error {
	buf := make([]byte, maxMessage)
	split := r.format.GetSplitFunc()
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		// Trailing newlines and NULs are framing, not message.
		for n > 0 && buf[n-1] < 32 {
			n--
		}
		if n == 0 {
			continue
		}
		// One message per datagram; the split function strips octet
		// counting (RFC 6587) if the sender uses it.
		if _, tok, err := split(buf[:n], true); err == nil && tok != nil {
			r.handle(tok, from)
		}
	}
}

func (r *receiver) acceptTCP(l net.Listener) error {
	defer r.wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if !r.track(c) {
			_ = c.Close()
			return nil
		}
		r.wg.Go(func() {
			defer r.untrack(c)
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 4096), maxMessage)
			sc.Split(r.format.GetSplitFunc())
			for sc.Scan() {
				r.handle(sc.Bytes(), c.RemoteAddr())
			}
			if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
				zap.L().Debug("syslog: tcp connection ended", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
			}
		})
	}
}

func (r *receiver) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *receiver) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
	_ = c.Close()
}

func (r *receiver) closeConns() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for c := range r.conns {
		_ = c.Close()
	}
}

func (r *receiver) handle(line []byte, from net.Addr) {
	p := r.format.GetParser(line)
	_ = p.Parse() // a partial parse still yields the content
	msg := message(p.Dump())
	src, dst, ok := Extract(msg)
	if !ok {
		zap.L().Debug("syslog: no address pair", zap.String("message", msg))
		return
	}
	r.emit(flow.New(src, dst, nfg.Source{Type: "syslog", Name: host(from)}))
}

// message returns the free-text part. The RFC 3164 parser puts it in
// "content", the RFC 5424 parser in "message".
func message(parts format.LogParts) string {
	for _, k := range []string{"content", "message"} {
		if s, ok := parts[k].(string); ok {
			return s
		}
	}
	return ""
}

func host(a net.Addr) string {
	if a == nil {
		return "unknown"
	}
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}
