//go:build e2e

package e2e

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The wire format below is written out here on purpose instead of importing
// internal/nfg: the fake must keep the backend's shapes (score-proxy in the
// main repo) even if the sensor's own types drift.

const (
	sensorName  = "e2e-sensor"
	authSecret  = "e2e-secret-key"
	heartbeatID = "e2e-heartbeat"
)

type sensorConfig struct {
	SniffTraffic   bool  `json:"sniffTraffic"`
	RunSyslog      bool  `json:"runSyslog"`
	AlertThreshold int32 `json:"alertThreshold"`
}

type blocklist struct {
	ID                          int    `json:"id"`
	Name                        string `json:"name"`
	ShouldIncludePrivateIPs     bool   `json:"shouldIncludePrivateIPs"`
	ShouldIncludePublicIPs      bool   `json:"shouldIncludePublicIPs"`
	NfgScoreThresholdPrivateIPs int32  `json:"nfgScoreThresholdPrivateIPs"`
	NfgScoreThresholdPublicIPs  int32  `json:"nfgScoreThresholdPublicIPs"`
}

type score struct {
	IP    string
	Score int32
}

type alert struct {
	IPType     string `json:"ipType"`
	IP         string `json:"ip"`
	RelatedIP  string `json:"relatedIp"`
	SourceType string `json:"sourceType"`
	SourceName string `json:"sourceName"`
}

type decision struct {
	Block     bool   `json:"block"`
	Reason    string `json:"reason"`
	Blocklist string `json:"blocklist"`
}

type recommendation struct {
	IP        string     `json:"ip"`
	Decisions []decision `json:"decisions"`
}

// respondFunc scripts an answer: the status for the nth call (from 1) of a
// route with this body, or 0 to answer normally.
type respondFunc func(n int, body []byte) int

// backend is a scriptable fake of score-proxy and the heartbeat server. It
// records what the sensor sends; only messages answered with 2xx count as
// delivered.
type backend struct {
	t *testing.T

	mu           sync.Mutex
	config       sensorConfig
	blocklists   []blocklist
	whitelist    []string
	scores       []score
	snapshotGate chan struct{} // if set, /sync/score waits until it is closed
	gateOnce     *sync.Once
	respond      map[string]respondFunc

	hits         map[string]int
	unauthorized []string
	attempts     map[string]int // POST /recommend calls per IP
	alerts       []alert
	recs         []recommendation
	pings        int
	wsConnects   int
	conns        map[*websocket.Conn]struct{}

	srv *http.Server
}

func newBackend(t *testing.T) *backend {
	b := &backend{
		t:        t,
		respond:  map[string]respondFunc{},
		hits:     map[string]int{},
		attempts: map[string]int{},
		conns:    map[*websocket.Conn]struct{}{},
	}
	t.Cleanup(func() {
		b.stop()
		b.mu.Lock()
		defer b.mu.Unlock()
		if len(b.unauthorized) > 0 {
			t.Errorf("requests with wrong credentials: %v", b.unauthorized)
		}
	})
	return b
}

// start serves on addr (":0" for any port) and returns the port.
func (b *backend) start(addr string) int {
	b.t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		b.t.Fatalf("backend listen: %v", err)
	}
	b.mu.Lock()
	b.srv = &http.Server{Handler: b, ReadHeaderTimeout: 10 * time.Second}
	srv := b.srv
	b.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().(*net.TCPAddr).Port
}

func (b *backend) stop() {
	b.openGate()
	b.mu.Lock()
	srv := b.srv
	for c := range b.conns {
		_ = c.Close()
	}
	b.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// holdSnapshot makes /sync/score wait until openGate.
func (b *backend) holdSnapshot() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.snapshotGate = make(chan struct{})
	b.gateOnce = new(sync.Once)
}

func (b *backend) openGate() {
	b.mu.Lock()
	gate, once := b.snapshotGate, b.gateOnce
	b.mu.Unlock()
	if gate != nil {
		once.Do(func() { close(gate) })
	}
}

func (b *backend) set(f func(b *backend)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f(b)
}

// push sends an update to every connected sensor, as score-proxy does.
func (b *backend) push(typ string, data any) {
	b.t.Helper()
	msg := map[string]any{"type": typ}
	if data != nil {
		msg["data"] = data
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.conns) == 0 {
		b.t.Fatalf("push %s: no sensor connected", typ)
	}
	for c := range b.conns {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteJSON(msg); err != nil {
			b.t.Errorf("push %s: %v", typ, err)
		}
	}
}

func (b *backend) hit(route string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hits[route]
}

func (b *backend) pingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pings
}

func (b *backend) wsConnectCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.wsConnects
}

func (b *backend) attemptsFor(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempts[ip]
}

func (b *backend) alertsFor(ip string) []alert {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []alert
	for _, a := range b.alerts {
		if a.IP == ip {
			out = append(out, a)
		}
	}
	return out
}

func (b *backend) allAlerts() []alert {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]alert(nil), b.alerts...)
}

func (b *backend) recsFor(ip string) []recommendation {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []recommendation
	for _, r := range b.recs {
		if r.IP == ip {
			out = append(out, r)
		}
	}
	return out
}

// forget clears the recorded messages.
func (b *backend) forget() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.alerts, b.recs = nil, nil
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := r.Method + " " + r.URL.Path
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	b.mu.Lock()
	b.hits[route]++
	n := b.hits[route]
	respond := b.respond[route]
	b.mu.Unlock()

	if strings.HasPrefix(r.URL.Path, "/ping/") {
		if r.Method != http.MethodGet || r.URL.Path != "/ping/"+heartbeatID || r.Header.Get("apikey") != authSecret {
			b.deny(w, route)
			return
		}
		b.mu.Lock()
		b.pings++
		b.mu.Unlock()
		_, _ = io.WriteString(w, "OK")
		return
	}
	if r.Header.Get("X_AUTH_KEY") != authSecret || r.Header.Get("X_SENSOR_NAME") != sensorName {
		b.deny(w, route)
		return
	}
	if route == "POST /recommend" {
		var rec recommendation
		if json.Unmarshal(body, &rec) == nil {
			b.mu.Lock()
			b.attempts[rec.IP]++
			b.mu.Unlock()
		}
	}
	if respond != nil {
		if code := respond(n, body); code != 0 {
			http.Error(w, http.StatusText(code), code)
			return
		}
	}

	switch route {
	case "GET /sync":
		b.mu.Lock()
		c := b.config
		b.mu.Unlock()
		writeJSON(w, c)
	case "GET /sync/blocklist":
		b.mu.Lock()
		l := append([]blocklist(nil), b.blocklists...)
		b.mu.Unlock()
		writeJSON(w, map[string]any{"blocklists": l})
	case "GET /sync/whitelist":
		b.mu.Lock()
		cidrs := append([]string{}, b.whitelist...)
		b.mu.Unlock()
		writeJSON(w, map[string]any{"cidrs": cidrs})
	case "GET /sync/score":
		b.serveSnapshot(w, r)
	case "GET /sync/ws/updates":
		b.serveUpdates(w, r)
	case "POST /alert":
		var a alert
		if err := json.Unmarshal(body, &a); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.alerts = append(b.alerts, a)
		b.mu.Unlock()
		writeJSON(w, map[string]string{"status": "ok"})
	case "POST /recommend":
		var rec recommendation
		if err := json.Unmarshal(body, &rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.recs = append(b.recs, rec)
		b.mu.Unlock()
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.NotFound(w, r)
	}
}

func (b *backend) deny(w http.ResponseWriter, route string) {
	b.mu.Lock()
	b.unauthorized = append(b.unauthorized, route)
	b.mu.Unlock()
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// serveSnapshot writes the scores as score-proxy does: a tar.gz of
// batch_NNNN.json files, each an indented JSON array of {ip, score,
// last_updated} with the score as a float.
func (b *backend) serveSnapshot(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	gate := b.snapshotGate
	b.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
	}
	b.mu.Lock()
	scores := append([]score(nil), b.scores...)
	b.mu.Unlock()

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=ip-scores.tar.gz")
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	const batchSize = 2
	for i := 0; i < len(scores); i += batchSize {
		var docs []map[string]any
		for _, s := range scores[i:min(i+batchSize, len(scores))] {
			docs = append(docs, map[string]any{"ip": s.IP, "score": float64(s.Score), "last_updated": now})
		}
		data, _ := json.MarshalIndent(docs, "", "  ")
		hdr := &tar.Header{Name: fmt.Sprintf("batch_%04d.json", i/batchSize), Mode: 0o644, Size: int64(len(data)), ModTime: time.Now()}
		if tw.WriteHeader(hdr) != nil {
			return
		}
		if _, err := tw.Write(data); err != nil {
			return
		}
	}
	_ = tw.Close()
	_ = gz.Close()
}

func (b *backend) serveUpdates(w http.ResponseWriter, r *http.Request) {
	up := websocket.Upgrader{}
	c, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	b.mu.Lock()
	b.conns[c] = struct{}{}
	b.wsConnects++
	b.mu.Unlock()
	for {
		// Reading also answers the sensor's pings.
		if _, _, err := c.ReadMessage(); err != nil {
			break
		}
	}
	b.mu.Lock()
	delete(b.conns, c)
	b.mu.Unlock()
	_ = c.Close()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
