//go:build e2e

package e2e

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Generator hosts and their scores in standardRules.
const (
	hostBlocked     = 10 // score 95: alert and recommendation
	hostSuspicious  = 11 // score 60: alert only
	hostWhitelisted = 12 // score 99, but whitelisted: nothing
	hostLow         = 13 // score 20: nothing, until an update raises it
	hostRejected    = 14 // score 95; the backend refuses its recommendation
)

const (
	alertThreshold = 50
	blockThreshold = 80
	blockName      = "e2e-block"
)

// standardRules gives the backend one blocklist for public and private IPs
// at blockThreshold, alerts at alertThreshold, and scores for the hosts.
func (e *env) standardRules() {
	e.backend.set(func(b *backend) {
		b.config = sensorConfig{SniffTraffic: true, RunSyslog: false, AlertThreshold: alertThreshold}
		b.blocklists = []blocklist{{ID: 1, Name: blockName, ShouldIncludePrivateIPs: true, ShouldIncludePublicIPs: true,
			NfgScoreThresholdPrivateIPs: blockThreshold, NfgScoreThresholdPublicIPs: blockThreshold}}
		b.whitelist = []string{e.ip(hostWhitelisted) + "/32"}
		b.scores = []score{
			{e.ip(hostBlocked), 95},
			{e.ip(hostSuspicious), 60},
			{e.ip(hostWhitelisted), 99},
			{e.ip(hostLow), 20},
			{e.ip(hostRejected), 95},
		}
	})
}

func blockDecision(score, threshold int32, list string) []decision {
	return []decision{{Block: true, Reason: fmt.Sprintf("Score %d >= threshold %d", score, threshold), Blocklist: list}}
}

func (e *env) wantRecommendation(host int, want []decision) {
	e.t.Helper()
	ip := e.ip(host)
	eventually(e.t, 30*time.Second, "recommendation for "+ip, func() bool { return len(e.backend.recsFor(ip)) > 0 })
	got := e.backend.recsFor(ip)[0]
	if !slices.Equal(got.Decisions, want) {
		e.t.Errorf("recommendation for %s = %+v, want %+v", ip, got.Decisions, want)
	}
}

// 2: captured connections are scored, alerted, recommended and deduplicated.
func TestCapturedTraffic(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.standardRules()
	e.startBackend()
	s := e.startSensor(sensorImage, "")
	s.waitLog("capture: started", 2*time.Minute)

	e.connect(hostBlocked)
	e.wantRecommendation(hostBlocked, blockDecision(95, blockThreshold, blockName))
	eventually(t, 30*time.Second, "alert for the blocked host", func() bool { return len(e.backend.alertsFor(e.ip(hostBlocked))) == 1 })
	want := alert{IPType: "source", IP: e.ip(hostBlocked), RelatedIP: e.sensorIP(), SourceType: "interface", SourceName: "eth0"}
	if got := e.backend.alertsFor(e.ip(hostBlocked))[0]; got != want {
		t.Errorf("alert = %+v, want %+v", got, want)
	}

	e.connect(hostSuspicious)
	eventually(t, 30*time.Second, "alert for the suspicious host", func() bool { return len(e.backend.alertsFor(e.ip(hostSuspicious))) == 1 })

	// The whitelisted host first, then the blocked host again as a marker:
	// once its second alert is in, both connections were evaluated.
	e.connect(hostWhitelisted)
	e.connect(hostBlocked)
	eventually(t, 30*time.Second, "second alert for the blocked host", func() bool { return len(e.backend.alertsFor(e.ip(hostBlocked))) == 2 })
	time.Sleep(2 * time.Second) // let anything wrongly queued arrive

	if n := len(e.backend.recsFor(e.ip(hostBlocked))); n != 1 {
		t.Errorf("blocked host recommended %d times, want once (deduplicated)", n)
	}
	if n := len(e.backend.recsFor(e.ip(hostSuspicious))); n != 0 {
		t.Errorf("suspicious host (below the block threshold) recommended %d times", n)
	}
	if a, r := e.backend.alertsFor(e.ip(hostWhitelisted)), e.backend.recsFor(e.ip(hostWhitelisted)); len(a)+len(r) > 0 {
		t.Errorf("whitelisted host reported: alerts %+v, recommendations %+v", a, r)
	}
	// The sensor itself and the gateway have no score.
	for _, ip := range []string{e.sensorIP(), e.ip(1)} {
		if a := e.backend.alertsFor(ip); len(a) > 0 {
			t.Errorf("unscored %s alerted: %+v", ip, a)
		}
	}
}

// 1: no inputs and no heartbeat until rules and scores are loaded.
func TestStartupWaitsForScores(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.standardRules()
	e.backend.holdSnapshot()
	e.startBackend()
	start := time.Now()
	s := e.startSensor(sensorImage, "")

	eventually(t, time.Minute, "rules and snapshot requested", func() bool {
		return e.backend.hit("GET /sync") > 0 && e.backend.hit("GET /sync/blocklist") > 0 &&
			e.backend.hit("GET /sync/whitelist") > 0 && e.backend.hit("GET /sync/score") > 0
	})
	e.connect(hostBlocked)
	// The heartbeat ticks every minute; wait past the first tick.
	s.waitLog("heartbeat skipped, no backend rules or scores yet", 90*time.Second)
	e.connect(hostBlocked)
	time.Sleep(time.Until(start.Add(65 * time.Second)))
	if n := e.backend.pingCount(); n != 0 {
		t.Errorf("%d heartbeats before scores were loaded", n)
	}
	if strings.Contains(s.logs(), "capture: started") {
		t.Error("capture started before scores were loaded")
	}
	if r := e.backend.recsFor(e.ip(hostBlocked)); len(r) > 0 {
		t.Errorf("recommendation before scores were loaded: %+v", r)
	}

	e.backend.openGate()
	s.waitLog("score snapshot loaded", time.Minute)
	s.waitLog("capture: started", 30*time.Second)
	e.connect(hostBlocked)
	e.wantRecommendation(hostBlocked, blockDecision(95, blockThreshold, blockName))
	eventually(t, 90*time.Second, "heartbeat once initialized", func() bool { return e.backend.pingCount() > 0 })
}

// syslogCase is one line of internal/syslog/testdata/corpus.txt.
type syslogCase struct {
	msg      string
	src, dst netip.Addr
	flow     bool
	want     []string // alert keys, see alertKeys
}

func readCorpus(t *testing.T) []syslogCase {
	t.Helper()
	f, err := os.Open("../internal/syslog/testdata/corpus.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var cases []syslogCase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		want, msg, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("malformed corpus line %q", line)
		}
		c := syslogCase{msg: msg}
		if want != "-" {
			src, dst, _ := strings.Cut(want, "|")
			c.src, c.dst, c.flow = netip.MustParseAddr(src), netip.MustParseAddr(dst), true
		}
		cases = append(cases, c)
	}
	if len(cases) < 20 {
		t.Fatalf("corpus has only %d cases", len(cases))
	}
	return cases
}

// scorable mirrors which addresses the sensor scores: not loopback,
// unspecified, broadcast, multicast or link-local, except the cloud
// metadata address.
func scorable(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsMulticast():
		return false
	case a == netip.MustParseAddr("255.255.255.255"):
		return false
	case a == netip.MustParseAddr("169.254.169.254"):
		return true
	}
	return !a.IsLinkLocalUnicast()
}

func alertKeys(alerts []alert) []string {
	var keys []string
	seen := map[string]bool{}
	for _, a := range alerts {
		k := strings.Join([]string{a.IPType, a.IP, a.RelatedIP, a.SourceType, a.SourceName}, " ")
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// 3: syslog lines of every supported format, over UDP and TCP, become alerts.
// Each corpus line is checked on its own: several lines name the same
// addresses, so a combined check would let one line cover for another.
func TestSyslog(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	cases := readCorpus(t)

	// Every scorable address of the corpus scores above the alert threshold.
	scored := map[string]bool{}
	var flows, noFlows []syslogCase
	total := 0
	for _, c := range cases {
		if !c.flow {
			noFlows = append(noFlows, c)
			continue
		}
		ends := []struct {
			role      string
			ip, other netip.Addr
		}{{"source", c.src, c.dst}, {"destination", c.dst, c.src}}
		if c.src == c.dst {
			ends = ends[:1]
		}
		var want []alert
		for _, end := range ends {
			if !scorable(end.ip) {
				continue
			}
			scored[end.ip.String()] = true
			want = append(want, alert{IPType: end.role, IP: end.ip.String(), RelatedIP: end.other.String(), SourceType: "syslog", SourceName: e.ip(1)})
		}
		c.want = alertKeys(want)
		total += len(c.want)
		flows = append(flows, c)
	}
	if len(flows) < 15 || len(noFlows) < 3 || total < 30 {
		t.Fatalf("corpus too small: %d lines with a flow (%d alerts), %d without", len(flows), total, len(noFlows))
	}
	t.Logf("%d corpus lines with a flow (%d alerts), %d without", len(flows), total, len(noFlows))

	e.backend.set(func(b *backend) {
		b.config = sensorConfig{SniffTraffic: false, RunSyslog: true, AlertThreshold: alertThreshold}
		b.blocklists = []blocklist{}
		b.whitelist = []string{}
		for ip := range scored {
			b.scores = append(b.scores, score{ip, 60})
		}
	})
	e.startBackend()
	s := e.startSensor(sensorImage, "")
	s.waitLog("syslog: listening", 2*time.Minute)
	if strings.Contains(s.logs(), "capture: started") {
		t.Error("capture started although the backend turned it off")
	}
	addr := net.JoinHostPort(e.sensorIP(), fmt.Sprint(syslogPort))

	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	udp, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	frames := 0
	transports := []struct {
		name string
		send func(msg string)
		// resend: datagrams can be lost; a TCP line arrives or the test fails.
		resend time.Duration
	}{
		{"udp/rfc3164", func(msg string) {
			line := fmt.Sprintf("<134>%s fw01 nfgtest[42]: %s", time.Now().Format(time.Stamp), msg)
			if _, err := udp.Write([]byte(line)); err != nil {
				t.Fatal(err)
			}
		}, 3 * time.Second},
		{"tcp/rfc5424", func(msg string) {
			// Alternating octet-counted and newline framing on one connection.
			line := fmt.Sprintf("<134>1 %s fw01 nfgtest 42 - - %s", time.Now().UTC().Format(time.RFC3339), msg)
			frame := line + "\n"
			if frames++; frames%2 == 0 {
				frame = fmt.Sprintf("%d %s", len(line), line)
			}
			if _, err := tcp.Write([]byte(frame)); err != nil {
				t.Fatal(err)
			}
		}, 30 * time.Second},
	}

	for _, tr := range transports {
		var prev []string
		for _, c := range flows {
			e.backend.forget()
			retrying(t, 30*time.Second, tr.resend, fmt.Sprintf("%s: alerts %v for %q", tr.name, c.want, c.msg),
				func() { tr.send(c.msg) },
				func() bool { return subset(c.want, alertKeys(e.backend.allAlerts())) })
			time.Sleep(200 * time.Millisecond)
			// A late duplicate of the previous line is the only other thing
			// that may arrive.
			allowed := append(slices.Clone(c.want), prev...)
			if got := alertKeys(e.backend.allAlerts()); !subset(got, allowed) {
				t.Errorf("%s: %q gave alerts %v, want %v", tr.name, c.msg, got, c.want)
			}
			prev = c.want
		}

		// Lines without a usable address pair give nothing. The first flow
		// line goes last, as a marker that the others were processed.
		e.backend.forget()
		marker := flows[0]
		retrying(t, 30*time.Second, tr.resend, tr.name+": marker after the lines without a flow",
			func() {
				for _, c := range noFlows {
					tr.send(c.msg)
				}
				tr.send(marker.msg)
			},
			func() bool { return subset(marker.want, alertKeys(e.backend.allAlerts())) })
		time.Sleep(time.Second)
		if got := alertKeys(e.backend.allAlerts()); !subset(got, marker.want) {
			t.Errorf("%s: lines without a flow gave alerts: %v", tr.name, got)
		}
	}
}

// subset reports whether every element of a is in b.
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// 4: websocket pushes are applied, and changed decisions are recommended.
func TestWebsocketUpdates(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.standardRules()
	e.startBackend()
	s := e.startSensor(sensorImage, "")
	s.waitLog("capture: started", 2*time.Minute)
	eventually(t, time.Minute, "websocket connected", func() bool { return e.backend.wsConnectCount() > 0 })

	e.connect(hostBlocked)
	e.wantRecommendation(hostBlocked, blockDecision(95, blockThreshold, blockName))

	// A score-update raises the low host above the block threshold.
	e.connect(hostLow)
	e.connect(hostSuspicious)
	eventually(t, 30*time.Second, "marker alert", func() bool { return len(e.backend.alertsFor(e.ip(hostSuspicious))) > 0 })
	if r := e.backend.recsFor(e.ip(hostLow)); len(r) > 0 {
		t.Fatalf("low host recommended before the update: %+v", r)
	}
	e.backend.push("score-update", map[string]any{"ip": e.ip(hostLow), "score": 90, "timestamp": time.Now().UTC()})
	retrying(t, 30*time.Second, 2*time.Second, "recommendation after score-update", func() { e.connect(hostLow) },
		func() bool { return len(e.backend.recsFor(e.ip(hostLow))) > 0 })
	if got := e.backend.recsFor(e.ip(hostLow))[0].Decisions; !slices.Equal(got, blockDecision(90, blockThreshold, blockName)) {
		t.Errorf("after score-update: %+v", got)
	}

	// A blocklist-update: the sensor re-fetches, and the already recommended
	// host is recommended again for the new list.
	before := e.backend.hit("GET /sync/blocklist")
	e.backend.set(func(b *backend) {
		b.blocklists = []blocklist{{ID: 2, Name: "e2e-block-v2", ShouldIncludePrivateIPs: true, ShouldIncludePublicIPs: true,
			NfgScoreThresholdPrivateIPs: 70, NfgScoreThresholdPublicIPs: 70}}
	})
	e.backend.push("blocklist-update", nil)
	eventually(t, 30*time.Second, "blocklist re-fetched", func() bool { return e.backend.hit("GET /sync/blocklist") > before })
	retrying(t, 30*time.Second, 2*time.Second, "recommendation for the new blocklist", func() { e.connect(hostBlocked) },
		func() bool { return len(e.backend.recsFor(e.ip(hostBlocked))) >= 2 })
	if got := e.backend.recsFor(e.ip(hostBlocked))[1].Decisions; !slices.Equal(got, blockDecision(95, 70, "e2e-block-v2")) {
		t.Errorf("after blocklist-update: %+v", got)
	}

	// A config-update raises the alert threshold above the suspicious score.
	before = e.backend.hit("GET /sync")
	e.backend.set(func(b *backend) { b.config.AlertThreshold = 70 })
	e.backend.push("config-update", nil)
	eventually(t, 30*time.Second, "config re-fetched", func() bool { return e.backend.hit("GET /sync") > before })
	s.waitLog(`"alert_threshold":70`, 10*time.Second)

	// A whitelist-update silences the blocked host.
	before = e.backend.hit("GET /sync/whitelist")
	e.backend.set(func(b *backend) { b.whitelist = append(b.whitelist, e.ip(hostBlocked)+"/32") })
	e.backend.push("whitelist-update", nil)
	eventually(t, 30*time.Second, "whitelist re-fetched", func() bool { return e.backend.hit("GET /sync/whitelist") > before })
	time.Sleep(time.Second) // applied right after the fetch

	blockedAlerts := len(e.backend.alertsFor(e.ip(hostBlocked)))
	suspiciousAlerts := len(e.backend.alertsFor(e.ip(hostSuspicious)))
	lowAlerts := len(e.backend.alertsFor(e.ip(hostLow)))
	e.connect(hostBlocked)
	e.connect(hostSuspicious)
	e.connect(hostLow) // marker: 90 is above the new threshold
	eventually(t, 30*time.Second, "marker alert", func() bool { return len(e.backend.alertsFor(e.ip(hostLow))) > lowAlerts })
	time.Sleep(2 * time.Second)
	if n := len(e.backend.alertsFor(e.ip(hostBlocked))); n != blockedAlerts {
		t.Errorf("whitelisted host alerted after whitelist-update (%d -> %d)", blockedAlerts, n)
	}
	if n := len(e.backend.alertsFor(e.ip(hostSuspicious))); n != suspiciousAlerts {
		t.Errorf("score 60 alerted after the threshold rose to 70 (%d -> %d)", suspiciousAlerts, n)
	}
}

// 5: rate limits and server errors delay messages without losing them; a
// permanent rejection drops the message and it is not sent again.
func TestDeliveryRetries(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.standardRules()
	rejected := e.ip(hostRejected)
	var callsMu sync.Mutex
	blockedCalls := 0
	e.backend.set(func(b *backend) {
		b.respond["POST /recommend"] = func(_ int, body []byte) int {
			if strings.Contains(string(body), `"`+rejected+`"`) {
				return 400
			}
			callsMu.Lock() // the sensor sends with several workers
			defer callsMu.Unlock()
			blockedCalls++
			switch blockedCalls {
			case 1:
				return 429
			case 2:
				return 503
			}
			return 0
		}
		// Alerts: two server errors in a row, then accepted.
		b.respond["POST /alert"] = func(n int, _ []byte) int {
			if n <= 2 {
				return 502
			}
			return 0
		}
	})
	e.startBackend()
	s := e.startSensor(sensorImage, "")
	s.waitLog("capture: started", 2*time.Minute)

	e.connect(hostBlocked)
	eventually(t, time.Minute, "recommendation delivered after 429 and 503", func() bool { return len(e.backend.recsFor(e.ip(hostBlocked))) == 1 })
	if n := e.backend.attemptsFor(e.ip(hostBlocked)); n != 3 {
		t.Errorf("blocked host: %d attempts, want 3 (429, 503, ok)", n)
	}
	eventually(t, time.Minute, "alert delivered after two 502", func() bool { return len(e.backend.alertsFor(e.ip(hostBlocked))) == 1 })
	s.waitLog("backend rate limit, holding messages", 5*time.Second)

	e.connect(hostRejected)
	eventually(t, 30*time.Second, "rejected recommendation attempted", func() bool { return e.backend.attemptsFor(rejected) == 1 })
	// Longer than the first retry backoff (5s), then a second connection:
	// the rejection is final and also keeps the IP deduplicated.
	time.Sleep(8 * time.Second)
	e.connect(hostRejected)
	eventually(t, 30*time.Second, "second alert for the rejected host", func() bool { return len(e.backend.alertsFor(rejected)) == 2 })
	time.Sleep(2 * time.Second)
	if n := e.backend.attemptsFor(rejected); n != 1 {
		t.Errorf("rejected recommendation sent %d times, want once", n)
	}
	s.waitLog("message rejected by backend", 5*time.Second)
}

// 6: scores survive a restart; a sensor with stored scores starts at once,
// and an empty or much smaller snapshot does not wipe them.
func TestRestartKeepsScores(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.standardRules()
	e.startBackend()
	vol := e.volume()
	s := e.startSensor(sensorImage, vol)
	s.waitLog("score snapshot loaded", 2*time.Minute)
	s.waitLog("capture: started", 30*time.Second)
	s.stop()

	// The backend now sends no snapshot at all until released.
	e.backend.holdSnapshot()
	e.backend.forget()
	s = e.startSensor(sensorImage, vol)
	s.waitLog("capture: started", time.Minute)
	if strings.Contains(s.logs(), "score snapshot loaded") {
		t.Fatal("snapshot loaded although the backend held it")
	}
	e.connect(hostBlocked)
	e.wantRecommendation(hostBlocked, blockDecision(95, blockThreshold, blockName))

	// An empty snapshot is refused.
	e.backend.set(func(b *backend) { b.scores = nil })
	e.backend.openGate()
	s.waitLog("score snapshot is empty", 30*time.Second)
	// Next, a snapshot with less than half the IPs: it is merged, not
	// swapped in. The failed sync is retried after 10s.
	e.backend.set(func(b *backend) { b.scores = []score{{e.ip(hostLow), 30}} })
	alerts := len(e.backend.alertsFor(e.ip(hostBlocked)))
	e.connect(hostBlocked)
	eventually(t, 30*time.Second, "alert from kept scores", func() bool { return len(e.backend.alertsFor(e.ip(hostBlocked))) > alerts })

	s.waitLog("merged instead of replaced", time.Minute)
	alerts = len(e.backend.alertsFor(e.ip(hostBlocked)))
	e.connect(hostBlocked)
	eventually(t, 30*time.Second, "alert after the merged snapshot", func() bool { return len(e.backend.alertsFor(e.ip(hostBlocked))) > alerts })
}

// 7: a volume written by the last v1 release works with v2.
func TestUpgradeFromV1(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.standardRules()
	e.startBackend()
	vol := e.volume()

	v1 := e.startSensor(v1Image, vol,
		"NFG_ARBITER_HOST="+net.JoinHostPort(e.ip(1), fmt.Sprint(e.port)),
		"STREAMING_SKIP_VERIFY_TLS=true", // v1: plain ws
		"LOG_TO_LOKI=false",
	)
	eventually(t, 2*time.Minute, "v1 stored the snapshot", func() bool {
		out, err := run("docker", "run", "--rm", "-v", vol+":/data", "--entrypoint", "sqlite3", v1Image,
			"/data/ip_scores.db", "SELECT count(*) FROM ip_scores")
		return err == nil && strings.TrimSpace(out) == "5"
	})
	v1.stop()

	// v2 must use v1's scores before any snapshot of its own.
	e.backend.holdSnapshot()
	s := e.startSensor(sensorImage, vol)
	s.waitLog("capture: started", time.Minute)
	e.connect(hostBlocked)
	e.wantRecommendation(hostBlocked, blockDecision(95, blockThreshold, blockName))

	e.backend.openGate()
	s.waitLog("score snapshot loaded", time.Minute)
	eventually(t, 90*time.Second, "heartbeat", func() bool { return e.backend.pingCount() > 0 })
}

// 8: a backend that is unreachable at startup is picked up when it comes.
func TestBackendDownAtStart(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.standardRules()
	e.reservePort()
	s := e.startSensor(sensorImage, "")
	s.waitLog("sync failed", time.Minute)
	s.waitLog("update stream: connect failed", 30*time.Second)

	e.backend.start(fmt.Sprintf(":%d", e.port))
	s.waitLog("capture: started", 2*time.Minute)
	e.connect(hostBlocked)
	e.wantRecommendation(hostBlocked, blockDecision(95, blockThreshold, blockName))
	eventually(t, 2*time.Minute, "websocket reconnected", func() bool { return e.backend.wsConnectCount() > 0 })
}
