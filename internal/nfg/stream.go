package nfg

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// Stream timings: a connection that delivers neither a message nor a pong
// for readTimeout is treated as dead.
var (
	pingEvery    = 30 * time.Second
	readTimeout  = 60 * time.Second
	writeTimeout = 10 * time.Second
	minReconnect = time.Second
	maxReconnect = 5 * time.Minute
	stableConn   = time.Minute
)

// Stream keeps the update websocket open until ctx ends, reconnecting with
// backoff. connected runs after every successful (re)connect, before the
// first message is read, so the caller can resync whatever it missed while
// disconnected. handle runs for each message on the reading goroutine and
// must not block.
func (c *Client) Stream(ctx context.Context, connected func(), handle func(Update)) {
	wait := minReconnect
	for ctx.Err() == nil {
		hdr := http.Header{}
		hdr.Set("X_AUTH_KEY", c.secret.Reveal())
		hdr.Set("X_SENSOR_NAME", c.name)
		hdr.Set("User-Agent", c.userAgent)

		conn, resp, err := c.dialer.DialContext(ctx, c.streamURL, hdr)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			zap.L().Warn("update stream: connect failed", zap.String("url", c.streamURL), zap.Error(err), zap.Duration("retry_in", wait))
		} else {
			zap.L().Info("update stream: connected", zap.String("url", c.streamURL))
			start := time.Now()
			connected()
			err = readUntilClosed(ctx, conn, handle)
			if ctx.Err() != nil {
				return
			}
			// A connection that held for a while was healthy; start over
			// with short waits instead of continuing the old backoff.
			if time.Since(start) > stableConn {
				wait = minReconnect
			}
			zap.L().Warn("update stream: disconnected", zap.Error(err), zap.Duration("retry_in", wait))
		}
		if sleep(ctx, jitter(wait)) != nil {
			return
		}
		wait = min(wait*2, maxReconnect)
	}
}

// readUntilClosed owns conn: it reads until an error or ctx ends, keeps the
// connection alive with pings, and closes it before returning.
func readUntilClosed(ctx context.Context, conn *websocket.Conn, handle func(Update)) error {
	connCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		_ = conn.Close()
		wg.Wait()
	}()

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readTimeout))
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(pingEvery)
		defer t.Stop()
		for {
			select {
			case <-connCtx.Done():
				// Unblocks ReadMessage when the caller is shutting down.
				_ = conn.Close()
				return
			case <-t.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)); err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		var u Update
		if err := json.Unmarshal(msg, &u); err != nil {
			zap.L().Warn("update stream: undecodable message", zap.Error(err), zap.Int("bytes", len(msg)))
			continue
		}
		handle(u)
	}
}

// jitter spreads reconnects of many sensors after a backend restart.
func jitter(d time.Duration) time.Duration {
	return d/2 + rand.N(d/2+1)
}
