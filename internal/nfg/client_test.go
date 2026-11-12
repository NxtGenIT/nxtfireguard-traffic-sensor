package nfg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/config"
	"github.com/gorilla/websocket"
)

func newClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg, _, err := config.Load(func(k string) (string, bool) {
		v, ok := map[string]string{
			"TRAFFIC_SENSOR_NAME":  "sensor-1",
			"AUTH_SECRET":          "s3cret",
			"NFG_ARBITER_URL":      srv.URL,
			"HEARTBEAT_URL":        srv.URL + "/hb",
			"HEARTBEAT_IDENTIFIER": "abc",
		}[k]
		return v, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	c := New(cfg, "test")
	c.Backoff = time.Millisecond
	return c
}

func TestAuthHeadersAndDecoding(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X_AUTH_KEY") != "s3cret" || r.Header.Get("X_SENSOR_NAME") != "sensor-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/sync":
			_, _ = io.WriteString(w, `{"sniffTraffic":true,"runSyslog":false,"alertThreshold":42}`)
		case "/sync/blocklist":
			_, _ = io.WriteString(w, `{"blocklists":[{"id":3,"name":"bl","shouldIncludePublicIPs":true,"nfgScoreThresholdPublicIPs":70}]}`)
		case "/sync/whitelist":
			_, _ = io.WriteString(w, `{"cidrs":["10.0.0.0/8"]}`)
		}
	}))
	ctx := context.Background()
	sc, err := c.SensorConfig(ctx)
	if err != nil || sc != (SensorConfig{SniffTraffic: true, AlertThreshold: 42}) {
		t.Fatalf("config %+v %v", sc, err)
	}
	bl, err := c.Blocklists(ctx)
	if err != nil || len(bl) != 1 || bl[0].Name != "bl" || bl[0].NfgScoreThresholdPublicIPs != 70 {
		t.Fatalf("blocklists %+v %v", bl, err)
	}
	wl, err := c.Whitelist(ctx)
	if err != nil || len(wl) != 1 || wl[0] != "10.0.0.0/8" {
		t.Fatalf("whitelist %v %v", wl, err)
	}
}

func TestEmptyListsAreNotNil(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }))
	bl, err := c.Blocklists(context.Background())
	if err != nil || bl == nil {
		t.Fatalf("%v %v", bl, err)
	}
	wl, err := c.Whitelist(context.Background())
	if err != nil || wl == nil {
		t.Fatalf("%v %v", wl, err)
	}
}

func TestGetRetriesServerErrors(t *testing.T) {
	var calls atomic.Int32
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, `{"cidrs":["10.0.0.0/8"]}`)
	}))
	wl, err := c.Whitelist(context.Background())
	if err != nil || len(wl) != 1 || calls.Load() != 3 {
		t.Fatalf("%v, %v after %d calls", wl, err, calls.Load())
	}
}

func TestGetGivesUpAfterRetries(t *testing.T) {
	var calls atomic.Int32
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	_, err := c.SensorConfig(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 503 || !Temporary(err) || calls.Load() != 1+int32(c.Retries) {
		t.Fatalf("err %v, calls %d", err, calls.Load())
	}
}

// POSTs are sent once: the outbox retries them with its own backoff, and
// retrying here as well would multiply the load on a struggling backend.
func TestPostIsSentOnce(t *testing.T) {
	var calls atomic.Int32
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"ip":"1.2.3.4","decisions":[{"block":true,"reason":"r","blocklist":"b"}]}` {
			t.Errorf("body %s", body)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	err := c.SendRecommendation(context.Background(), Recommendation{IP: "1.2.3.4", Decisions: []Decision{{Block: true, Reason: "r", Blocklist: "b"}}})
	if !Temporary(err) || calls.Load() != 1 {
		t.Fatalf("err %v after %d calls", err, calls.Load())
	}
}

func TestRateLimitIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	err := c.SendAlert(context.Background(), Alert{IP: "1.2.3.4"})
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second || calls.Load() != 1 || !Temporary(err) {
		t.Fatalf("err %v, calls %d", err, calls.Load())
	}
}

func TestClientErrorIsPermanent(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "bad ip")
	}))
	err := c.SendAlert(context.Background(), Alert{})
	if err == nil || Temporary(err) || !strings.Contains(err.Error(), "bad ip") {
		t.Fatalf("err %v", err)
	}
}

func TestScoreSnapshot(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"public.json":  `[{"ip":"203.0.113.1","score":80,"last_updated":"2026-01-01T00:00:00Z"},{"ip":"203.0.113.2","score":10,"last_updated":"2026-01-02T00:00:00Z"}]`,
		"private.json": `[{"ip":"10.0.0.1","score":55,"last_updated":"2026-01-03T00:00:00Z"}]`,
	} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = io.WriteString(tw, body)
	}
	_ = tw.Close()
	_ = gz.Close()

	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sync/score" {
			_, _ = w.Write(buf.Bytes())
		}
	}))
	got := map[string]int32{}
	err := c.ScoreSnapshot(context.Background(), func(s Score) error {
		if s.LastUpdated.IsZero() {
			t.Errorf("%s: no timestamp", s.IP)
		}
		got[s.IP] = s.Score
		return nil
	})
	if err != nil || len(got) != 3 || got["203.0.113.1"] != 80 || got["10.0.0.1"] != 55 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestHeartbeat(t *testing.T) {
	var path, key, auth string
	c := newClient(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		path, key, auth = r.URL.Path, r.Header.Get("apikey"), r.Header.Get("X_AUTH_KEY")
	}))
	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if path != "/hb/ping/abc" || key != "s3cret" || auth != "" {
		t.Fatalf("path %q apikey %q x_auth_key %q", path, key, auth)
	}
}

func TestStreamReconnectsAndReportsEachConnect(t *testing.T) {
	minReconnect = time.Millisecond
	t.Cleanup(func() { minReconnect = time.Second })

	up := websocket.Upgrader{}
	var conns atomic.Int32
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sync/ws/updates" || r.Header.Get("X_AUTH_KEY") != "s3cret" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		n := conns.Add(1)
		msg, _ := json.Marshal(map[string]any{"type": "score-update", "data": map[string]any{"ip": "1.2.3.4", "score": n, "timestamp": "2026-01-01T00:00:00Z"}})
		_ = ws.WriteMessage(websocket.TextMessage, []byte("not json"))
		_ = ws.WriteMessage(websocket.TextMessage, msg)
		if n == 1 {
			return // drop the first connection
		}
		_, _, _ = ws.ReadMessage() // hold until the client goes away
	}))

	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var connects int
	var scores []int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Stream(ctx, func() { mu.Lock(); connects++; mu.Unlock() }, func(u Update) {
			var su ScoreUpdate
			if err := json.Unmarshal(u.Data, &su); err != nil || u.Type != UpdateScore {
				t.Errorf("update %+v: %v", u, err)
			}
			mu.Lock()
			scores = append(scores, su.Score)
			mu.Unlock()
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		ok := len(scores) == 2
		mu.Unlock()
		if ok || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stream did not return after cancel")
	}
	mu.Lock()
	defer mu.Unlock()
	if connects != 2 || len(scores) != 2 || scores[0] != 1 || scores[1] != 2 {
		t.Fatalf("connects %d scores %v", connects, scores)
	}
}

func TestScoreSnapshotStallIsAborted(t *testing.T) {
	release := make(chan struct{})
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x1f, 0x8b}) // start of a gzip stream, then nothing
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer close(release)
	c.SnapshotIdle = 50 * time.Millisecond
	start := time.Now()
	err := c.ScoreSnapshot(context.Background(), func(Score) error { return nil })
	if err == nil {
		t.Fatal("a stalled snapshot must fail")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("stall detected after %s", d)
	}
}
