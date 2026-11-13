// Package syslog receives firewall and IDS logs over syslog (UDP and TCP on
// the same port) and turns each line that names two addresses into a flow.
//
// Only the RFC 3164/5424 parsers of go-syslog are used, behind a recover.
// Its server is not used (Kill closes a channel its UDP reader may still
// send on), nor its framing (negative or huge octet counts panic).
package syslog

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/flow"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"go.uber.org/zap"
	"gopkg.in/mcuadros/go-syslog.v2/format"
)

const (
	// maxMessage bounds one syslog message (UDP datagram or TCP frame).
	maxMessage = 64 * 1024
	// maxConns bounds concurrent TCP senders; idleTimeout closes silent ones.
	maxConns    = 512
	idleTimeout = 10 * time.Minute
)

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

	r := &receiver{emit: emit, conns: map[net.Conn]struct{}{}, slots: make(chan struct{}, maxConns)}
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
	emit  func(flow.Flow)
	slots chan struct{}

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func (r *receiver) readUDP(c net.PacketConn) error {
	buf := make([]byte, maxMessage)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		// One message per datagram, optionally octet-counted.
		if msg := datagram(buf[:n]); len(msg) > 0 {
			r.handle(msg, from)
		}
	}
}

func (r *receiver) acceptTCP(l net.Listener) error {
	defer r.wg.Wait()
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			// Out of file descriptors and the like: keep UDP running.
			zap.L().Warn("syslog: accept failed", zap.Error(err))
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case r.slots <- struct{}{}:
		default:
			zap.L().Warn("syslog: too many TCP senders, connection refused", zap.Stringer("client", c.RemoteAddr()))
			_ = c.Close()
			continue
		}
		if !r.track(c) {
			_ = c.Close()
			return nil
		}
		r.wg.Go(func() {
			defer func() { <-r.slots }()
			defer r.untrack(c)
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 4096), maxMessage+16)
			sc.Split(splitTCP)
			for {
				_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
				if !sc.Scan() {
					break
				}
				r.handle(sc.Bytes(), c.RemoteAddr())
			}
			if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
				zap.L().Debug("syslog: tcp connection ended", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
			}
		})
	}
}

var errFrame = errors.New("invalid octet count")

// octetCount reads an RFC 6587 octet-counting header ("LEN SP"). more is
// set when data could still turn into a header once more bytes arrive.
func octetCount(data []byte) (n, hdr int, ok, more bool) {
	i := 0
	for i < len(data) && i < 6 && data[i] >= '0' && data[i] <= '9' {
		i++
	}
	switch {
	case i == 0:
		return 0, 0, false, false
	case i == len(data):
		return 0, 0, false, i < 6
	case data[i] != ' ':
		return 0, 0, false, false
	}
	n, _ = strconv.Atoi(string(data[:i]))
	return n, i + 1, true, false
}

// splitTCP frames a TCP stream: octet counting when a frame starts with
// "LEN SP", otherwise one message per line (RFC 6587 3.4.1 and 3.4.2).
func splitTCP(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	n, hdr, ok, more := octetCount(data)
	if more && !atEOF {
		return 0, nil, nil
	}
	if !ok {
		return bufio.ScanLines(data, atEOF)
	}
	if n <= 0 || n > maxMessage {
		return 0, nil, errFrame
	}
	if len(data) < hdr+n {
		if atEOF {
			return len(data), data[hdr:], nil
		}
		return 0, nil, nil
	}
	return hdr + n, data[hdr : hdr+n], nil
}

// datagram strips trailing newlines/NULs and an octet-counting header.
func datagram(b []byte) []byte {
	b = bytes.TrimRightFunc(b, func(r rune) bool { return r < 32 })
	if n, hdr, ok, _ := octetCount(b); ok && n > 0 {
		b = b[hdr:]
		if n < len(b) {
			b = b[:n]
		}
	}
	return b
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
	msg, ok := content(line)
	if !ok {
		zap.L().Debug("syslog: unparsable message", zap.Int("bytes", len(line)), zap.ByteString("line", clip(line)))
		return
	}
	src, dst, ok := Extract(msg)
	if !ok {
		zap.L().Debug("syslog: no address pair", zap.Int("bytes", len(msg)), zap.ByteString("message", clip([]byte(msg))))
		return
	}
	r.emit(flow.New(src, dst, nfg.Source{Type: "syslog", Name: host(from)}))
}

// content parses an RFC 3164 or RFC 5424 message and returns its free text.
// go-syslog's parsers panic on some malformed input; that counts as unparsable.
func content(line []byte) (msg string, ok bool) {
	defer func() {
		if recover() != nil {
			msg, ok = "", false
		}
	}()
	var f format.Automatic
	p := f.GetParser(line)
	_ = p.Parse() // a partial parse still yields the content
	return message(p.Dump()), true
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

// logClip bounds how much of an untrusted message reaches the debug log.
const logClip = 256

func clip(b []byte) []byte {
	if len(b) > logClip {
		return b[:logClip]
	}
	return b
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
