package sensor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/scores"
	"github.com/gorilla/websocket"
)

// fakeBackend is score-proxy plus the heartbeat server.
type fakeBackend struct {
	t        *testing.T
	srv      *httptest.Server
	down     atomic.Bool // every /sync* answers 503
	mu       sync.Mutex
	config   string
	lists    string
	cidrs    string
	scores   []nfg.Score
	alerts   []nfg.Alert
	recs     []nfg.Recommendation
	beats    int
	hits     map[string]int
	wsConns  chan *websocket.Conn
	upgrader websocket.Upgrader
}

func newFakeBackend(t *testing.T) *fakeBackend {
	b := &fakeBackend{
		t:       t,
		config:  `{"sniffTraffic":true,"runSyslog":true,"alertThreshold":50}`,
		lists:   `{"blocklists":[{"id":1,"name":"edge","shouldIncludePublicIPs":true,"nfgScoreThresholdPublicIPs":70}]}`,
		cidrs:   `{"cidrs":["192.0.2.0/24"]}`,
		wsConns: make(chan *websocket.Conn, 4),
	}
	b.srv = httptest.NewServer(http.HandlerFunc(b.serve))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *fakeBackend) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ping/hb-1" {
		b.mu.Lock()
		b.beats++
		b.mu.Unlock()
		return
	}
	if r.Header.Get("X_AUTH_KEY") != "secret" || r.Header.Get("X_SENSOR_NAME") != "sensor-1" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if b.down.Load() && r.URL.Path != "/alert" && r.URL.Path != "/recommend" {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.hits == nil {
		b.hits = map[string]int{}
	}
	b.hits[r.URL.Path]++
	switch r.URL.Path {
	case "/sync":
		_, _ = io.WriteString(w, b.config)
	case "/sync/blocklist":
		_, _ = io.WriteString(w, b.lists)
	case "/sync/whitelist":
		_, _ = io.WriteString(w, b.cidrs)
	case "/sync/score":
		_, _ = w.Write(tarGz(b.t, b.scores))
	case "/alert":
		var a nfg.Alert
		_ = json.NewDecoder(r.Body).Decode(&a)
		b.alerts = append(b.alerts, a)
	case "/recommend":
		var rec nfg.Recommendation
		_ = json.NewDecoder(r.Body).Decode(&rec)
		b.recs = append(b.recs, rec)
	case "/sync/ws/updates":
		b.mu.Unlock()
		defer b.mu.Lock()
		c, err := b.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		b.wsConns <- c
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (b *fakeBackend) push(t *testing.T, conn *websocket.Conn, v any) {
	t.Helper()
	if err := conn.WriteJSON(v); err != nil {
		t.Fatal(err)
	}
}

func (b *fakeBackend) got() ([]nfg.Alert, []nfg.Recommendation, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]nfg.Alert(nil), b.alerts...), append([]nfg.Recommendation(nil), b.recs...), b.beats
}

func tarGz(t *testing.T, rows []nfg.Score) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body, _ := json.Marshal(rows)
	if err := tw.WriteHeader(&tar.Header{Name: "scores.json", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	for range 20 {
		u, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := u.LocalAddr().(*net.UDPAddr).Port
		_ = u.Close()
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			_ = l.Close()
			return fmt.Sprint(port)
		}
	}
	t.Fatal("no free port")
	return ""
}

type running struct {
	sensor *Sensor
	cancel context.CancelFunc
	done   chan struct{}
	addr   string
}

func startSensor(t *testing.T, b *fakeBackend, dbPath string) *running {
	t.Helper()
	return startSensorOn(t, b, dbPath, freeUDPPort(t))
}

func startSensorOn(t *testing.T, b *fakeBackend, dbPath, port string) *running {
	t.Helper()
	heartbeatEvery = 20 * time.Millisecond
	retryMin = 20 * time.Millisecond
	env := map[string]string{
		"TRAFFIC_SENSOR_NAME": "sensor-1", "AUTH_SECRET": "secret",
		"NFG_ARBITER_URL": b.srv.URL, "HEARTBEAT_URL": b.srv.URL, "HEARTBEAT_IDENTIFIER": "hb-1",
		"SQLITE_DB_PATH": dbPath, "SYSLOG_LISTEN_ADDR": "127.0.0.1", "SYSLOG_PORT": port,
	}
	cfg, _, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	store, err := scores.Open(cfg.DBPath, 100)
	if err != nil {
		t.Fatal(err)
	}
	client := nfg.New(cfg, "test")
	client.Backoff = time.Millisecond
	client.Retries = 0
	s := New(cfg, client, store)
	s.capture = func(ctx context.Context, ready func()) error { ready(); <-ctx.Done(); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{sensor: s, cancel: cancel, done: make(chan struct{}), addr: cfg.SyslogAddr}
	go func() { s.Run(ctx); _ = store.Close(); close(r.done) }()
	t.Cleanup(r.stop)
	return r
}

func (r *running) stop() {
	r.cancel()
	<-r.done
}

func (r *running) syslog(t *testing.T, msg string) {
	t.Helper()
	c, err := net.Dial("udp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := fmt.Fprintf(c, "<134>Jan  1 00:00:00 fw01 CEF: %s", msg); err != nil {
		t.Fatal(err)
	}
}

func TestEndToEnd(t *testing.T) {
	b := newFakeBackend(t)
	now := time.Now().UTC()
	b.scores = []nfg.Score{{IP: "203.0.113.7", Score: 90, LastUpdated: now}, {IP: "192.0.2.10", Score: 99, LastUpdated: now}}
	r := startSensor(t, b, filepath.Join(t.TempDir(), "s.db"))

	var ws *websocket.Conn
	select {
	case ws = <-b.wsConns:
	case <-time.After(5 * time.Second):
		t.Fatal("sensor did not open the update websocket")
	}
	defer func() { _ = ws.Close() }()

	// Syslog only works once the backend rules and the snapshot are in.
	eventually(t, "first alert", func() bool {
		r.syslog(t, "CEF:0|V|P|1|1|x|5|src=203.0.113.7 dst=198.51.100.20")
		alerts, _, _ := b.got()
		return len(alerts) > 0
	})
	alerts, recs, _ := b.got()
	want := nfg.Alert{IPType: "source", IP: "203.0.113.7", RelatedIP: "198.51.100.20", SourceType: "syslog", SourceName: "127.0.0.1"}
	if alerts[0] != want {
		t.Errorf("alert %+v, want %+v", alerts[0], want)
	}
	eventually(t, "recommendation", func() bool { _, recs, _ = b.got(); return len(recs) > 0 })
	if recs[0].IP != "203.0.113.7" || len(recs[0].Decisions) != 1 || recs[0].Decisions[0] != (nfg.Decision{Block: true, Reason: "Score 90 >= threshold 70", Blocklist: "edge"}) {
		t.Errorf("recommendation %+v", recs[0])
	}

	// A live score update makes the other end alert too, with full weight.
	b.push(t, ws, map[string]any{"type": "score-update", "data": map[string]any{"ip": "198.51.100.20", "score": 80, "timestamp": now}})
	eventually(t, "destination alert", func() bool {
		r.syslog(t, "CEF:0|V|P|1|1|x|5|src=203.0.113.7 dst=198.51.100.20")
		alerts, _, _ := b.got()
		for _, a := range alerts {
			if a.IP == "198.51.100.20" && a.IPType == "destination" && a.RelatedIP == "203.0.113.7" {
				return true
			}
		}
		return false
	})
	eventually(t, "destination recommendation", func() bool {
		_, recs, _ := b.got()
		return len(recs) == 2 && recs[1].IP == "198.51.100.20" && recs[1].Decisions[0].Reason == "Score 80 >= threshold 70"
	})

	// Whitelisted flows are ignored even when an end has a high score.
	r.syslog(t, "CEF:0|V|P|1|1|x|5|src=203.0.113.7 dst=192.0.2.10")
	time.Sleep(100 * time.Millisecond)
	alerts, recs, beats := b.got()
	for _, a := range alerts {
		if a.IP == "192.0.2.10" || a.RelatedIP == "192.0.2.10" {
			t.Errorf("whitelisted flow alerted: %+v", a)
		}
	}
	if len(recs) != 2 {
		t.Errorf("recommendations repeated: %d", len(recs))
	}
	if beats == 0 {
		t.Error("no heartbeat although all components run")
	}

	// A config push turning syslog off stops the listener.
	b.mu.Lock()
	b.config = `{"sniffTraffic":true,"runSyslog":false,"alertThreshold":50}`
	b.mu.Unlock()
	b.push(t, ws, map[string]any{"type": "config-update"})
	eventually(t, "syslog stopped", func() bool {
		l, err := net.ListenPacket("udp", r.addr)
		if err == nil {
			_ = l.Close()
		}
		return err == nil
	})
}

func TestStartsFromSavedStateWhenBackendIsDown(t *testing.T) {
	b := newFakeBackend(t)
	b.scores = []nfg.Score{{IP: "203.0.113.7", Score: 90, LastUpdated: time.Now()}}
	db := filepath.Join(t.TempDir(), "s.db")

	first := startSensor(t, b, db)
	eventually(t, "first run alerts", func() bool {
		first.syslog(t, "src=203.0.113.7 dst=198.51.100.20")
		alerts, _, _ := b.got()
		return len(alerts) > 0
	})
	first.stop()

	b.down.Store(true)
	b.mu.Lock()
	b.alerts = nil
	b.mu.Unlock()
	second := startSensor(t, b, db)
	eventually(t, "alert while the backend sync is down", func() bool {
		second.syslog(t, "src=203.0.113.7 dst=198.51.100.21")
		alerts, _, _ := b.got()
		return len(alerts) > 0
	})
}

func TestHeartbeatOnlyWhileComponentsRun(t *testing.T) {
	b := newFakeBackend(t)
	// Occupy the syslog port so the listener cannot start.
	port := freeUDPPort(t)
	l, err := net.ListenPacket("udp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	r := startSensorOn(t, b, filepath.Join(t.TempDir(), "s.db"), port)
	eventually(t, "syslog reported broken", func() bool {
		nr := r.sensor.sup.NotReady()
		return len(nr) == 1 && nr[0] == "syslog"
	})
	time.Sleep(10 * heartbeatEvery)
	if _, _, beats := b.got(); beats != 0 {
		t.Fatalf("%d heartbeats although syslog cannot bind", beats)
	}
	_ = l.Close()
	eventually(t, "heartbeat after syslog recovered", func() bool { _, _, beats := b.got(); return beats > 0 })
}

// The first websocket connect follows the initial sync within milliseconds;
// fetching everything again would only hit score-proxy's per-second limit.
func TestFirstConnectDoesNotRefetch(t *testing.T) {
	b := newFakeBackend(t)
	b.scores = []nfg.Score{{IP: "203.0.113.7", Score: 90, LastUpdated: time.Now()}}
	startSensor(t, b, filepath.Join(t.TempDir(), "s.db"))
	select {
	case <-b.wsConns:
	case <-time.After(5 * time.Second):
		t.Fatal("no websocket")
	}
	time.Sleep(200 * time.Millisecond)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range []string{"/sync", "/sync/blocklist", "/sync/whitelist", "/sync/score"} {
		if b.hits[p] != 1 {
			t.Errorf("%s fetched %d times on startup, want 1", p, b.hits[p])
		}
	}
}

// A fresh volume with the backend down has nothing to evaluate with: the
// inputs stay off and no heartbeat claims the sensor works. Once the
// backend answers, both start.
func TestFreshSensorWaitsForRulesAndScores(t *testing.T) {
	b := newFakeBackend(t)
	b.scores = []nfg.Score{{IP: "203.0.113.7", Score: 90, LastUpdated: time.Now()}}
	b.down.Store(true)
	r := startSensor(t, b, filepath.Join(t.TempDir(), "s.db"))
	running := func() int {
		r.sensor.sup.mu.Lock()
		defer r.sensor.sup.mu.Unlock()
		return len(r.sensor.sup.running)
	}
	time.Sleep(10 * heartbeatEvery)
	if _, _, beats := b.got(); beats != 0 || running() != 0 {
		t.Fatalf("backend down on a fresh volume: %d heartbeats, %d components", beats, running())
	}
	b.down.Store(false)
	eventually(t, "inputs started", func() bool { return running() == 2 })
	eventually(t, "heartbeat", func() bool { _, _, beats := b.got(); return beats > 0 })
}
