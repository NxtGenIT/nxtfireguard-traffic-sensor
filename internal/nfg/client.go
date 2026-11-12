package nfg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/config"
	"github.com/gorilla/websocket"
)

// Client is the only code that talks to the backend.
type Client struct {
	baseURL      string
	streamURL    string
	heartbeatURL string
	heartbeatID  string
	name         string
	secret       config.Secret
	userAgent    string

	http     *http.Client
	snapshot *http.Client
	dialer   *websocket.Dialer

	// Retries is how often a GET is repeated after a network error or a 5xx
	// answer, waiting Backoff, 2*Backoff, ... in between. POSTs are not
	// repeated here; the caller's outbox retries them.
	Retries int
	Backoff time.Duration
	// Requests without their own deadline get this one.
	Timeout time.Duration
	// score-proxy builds the snapshot before it answers, which can take
	// minutes on a cache miss. SnapshotTimeout bounds the whole download,
	// SnapshotIdle a stall in the middle of it.
	SnapshotTimeout time.Duration
	SnapshotIdle    time.Duration
}

func New(cfg config.Config, version string) *Client {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.InsecureSkipVerifyTLS {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // explicit opt-in for test backends
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     true,
	}
	slow := transport.Clone()
	slow.ResponseHeaderTimeout = 0
	return &Client{
		baseURL:      cfg.ArbiterURL,
		streamURL:    cfg.StreamURL,
		heartbeatURL: cfg.HeartbeatURL,
		heartbeatID:  cfg.HeartbeatIdentifier,
		name:         cfg.SensorName,
		secret:       cfg.AuthSecret,
		userAgent:    "nfg-traffic-sensor/" + version,
		http:         &http.Client{Transport: transport},
		snapshot:     &http.Client{Transport: slow},
		dialer: &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 15 * time.Second,
			TLSClientConfig:  tlsConf,
		},
		Retries:         3,
		Backoff:         time.Second,
		Timeout:         30 * time.Second,
		SnapshotTimeout: 30 * time.Minute,
		SnapshotIdle:    5 * time.Minute,
	}
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Method, URL string
	Code        int
	Body        string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: status %d: %s", e.Method, e.URL, e.Code, e.Body)
}

// RateLimitedError is a 429 answer. It is not retried by the client so the
// caller can decide how long to hold the request back.
type RateLimitedError struct {
	URL        string
	RetryAfter time.Duration // zero if the server did not say
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("%s: rate limited (retry after %s)", e.URL, e.RetryAfter)
}

// Temporary reports whether repeating the request later can succeed: network
// failures, 5xx and 429 are temporary; other 4xx answers are not.
func Temporary(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code >= 500
	}
	return err != nil && !errors.Is(err, context.Canceled)
}

func (c *Client) SensorConfig(ctx context.Context) (SensorConfig, error) {
	var out SensorConfig
	return out, c.getJSON(ctx, "/sync", &out)
}

func (c *Client) Blocklists(ctx context.Context) ([]Blocklist, error) {
	var out blocklistsResponse
	if err := c.getJSON(ctx, "/sync/blocklist", &out); err != nil {
		return nil, err
	}
	if out.Blocklists == nil {
		out.Blocklists = []Blocklist{}
	}
	return out.Blocklists, nil
}

func (c *Client) Whitelist(ctx context.Context) ([]string, error) {
	var out whitelistResponse
	if err := c.getJSON(ctx, "/sync/whitelist", &out); err != nil {
		return nil, err
	}
	if out.CIDRs == nil {
		out.CIDRs = []string{}
	}
	return out.CIDRs, nil
}

// ScoreSnapshot streams GET /sync/score, a tar.gz of JSON arrays of Score,
// into fn. The snapshot holds every scored IP the license can see.
func (c *Client) ScoreSnapshot(ctx context.Context, fn func(Score) error) error {
	ctx, cancel := context.WithTimeout(ctx, c.SnapshotTimeout)
	defer cancel()
	// Not retried here: a retry would make score-proxy build it again.
	resp, err := c.send(ctx, c.snapshot, http.MethodGet, c.baseURL+"/sync/score", nil, c.sensorHeaders, 0)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body

	stall := time.AfterFunc(c.SnapshotIdle, cancel)
	defer stall.Stop()
	body := &idleReader{r: resp.Body, timer: stall, idle: c.SnapshotIdle}

	gz, err := gzip.NewReader(body)
	if err != nil {
		return fmt.Errorf("score snapshot: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("score snapshot: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := decodeScoreArray(tr, fn); err != nil {
			return fmt.Errorf("score snapshot %s: %w", hdr.Name, err)
		}
	}
}

func decodeScoreArray(r io.Reader, fn func(Score) error) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil // `null`: how a Go backend marshals an empty (nil) slice
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("expected a JSON array, got %v", tok)
	}
	for dec.More() {
		var s Score
		if err := dec.Decode(&s); err != nil {
			return err
		}
		if err := fn(s); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

func (c *Client) SendAlert(ctx context.Context, a Alert) error {
	return c.postJSON(ctx, "/alert", a)
}

func (c *Client) SendRecommendation(ctx context.Context, r Recommendation) error {
	return c.postJSON(ctx, "/recommend", r)
}

// Heartbeat pings the heartbeat server. It is a no-op without an identifier.
func (c *Client) Heartbeat(ctx context.Context) error {
	if c.heartbeatID == "" {
		return nil
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.send(ctx, c.http, http.MethodGet, c.heartbeatURL+"/ping/"+c.heartbeatID, nil, func(r *http.Request) {
		r.Header.Set("apikey", c.secret.Reveal())
	}, 1)
	if err != nil {
		return err
	}
	return drain(resp)
}

func (c *Client) sensorHeaders(r *http.Request) {
	r.Header.Set("X_AUTH_KEY", c.secret.Reveal())
	r.Header.Set("X_SENSOR_NAME", c.name)
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.send(ctx, c.http, http.MethodGet, c.baseURL+path, nil, c.sensorHeaders, c.Retries)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("GET %s: decode: %w", path, err)
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, path string, in any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.send(ctx, c.http, http.MethodPost, c.baseURL+path, body, func(r *http.Request) {
		c.sensorHeaders(r)
		r.Header.Set("Content-Type", "application/json")
	}, 0)
	if err != nil {
		return err
	}
	return drain(resp)
}

func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok || c.Timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.Timeout)
}

// send sends the request, repeating it up to retries times after network
// errors and 5xx answers. It returns the response only for 2xx; the caller
// closes its body.
func (c *Client) send(ctx context.Context, hc *http.Client, method, url string, body []byte, headers func(*http.Request), retries int) (*http.Response, error) {
	wait := c.Backoff
	var lastErr error
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			if attempt > retries {
				return nil, lastErr
			}
			if err := sleep(ctx, wait); err != nil {
				return nil, lastErr
			}
			wait *= 2
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.userAgent)
		headers(req)

		resp, err := hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("%s %s: %w", method, url, err)
			continue
		}
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return resp, nil
		case resp.StatusCode == http.StatusTooManyRequests:
			_ = drain(resp)
			return nil, &RateLimitedError{URL: url, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
		default:
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			lastErr = &StatusError{Method: method, URL: url, Code: resp.StatusCode, Body: string(bytes.TrimSpace(msg))}
			if resp.StatusCode < 500 {
				return nil, lastErr
			}
		}
	}
}

// idleReader restarts timer on every read, so the timer only fires when
// the body stalls for idle.
type idleReader struct {
	r     io.Reader
	timer *time.Timer
	idle  time.Duration
}

func (i *idleReader) Read(p []byte) (int, error) {
	n, err := i.r.Read(p)
	i.timer.Reset(i.idle)
	return n, err
}

func drain(resp *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.Body.Close()
}

// retryAfter parses a Retry-After header: delay-seconds or an HTTP date.
func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s > 0 {
		return time.Duration(min(s, 86400)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
