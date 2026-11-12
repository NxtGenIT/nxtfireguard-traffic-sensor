// Package config reads the sensor's static settings from the environment.
// Everything the backend controls (capture on/off, syslog on/off, alert
// threshold, blocklists, whitelist) is not here; it arrives at runtime.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Secret is a credential that never shows up in logs or dumps.
type Secret string

func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

func (s Secret) GoString() string { return s.String() }

func (s Secret) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(s.String())), nil }

func (s Secret) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Reveal returns the raw value, for request headers only.
func (s Secret) Reveal() string { return string(s) }

type Config struct {
	Debug bool

	SensorName string
	AuthSecret Secret

	// ArbiterURL is the score-proxy base URL; StreamURL is its websocket.
	ArbiterURL            string
	StreamURL             string
	InsecureSkipVerifyTLS bool

	HeartbeatURL        string
	HeartbeatIdentifier string

	DBPath             string
	ScoreCacheSize     int
	RecommendCacheSize int

	SyslogAddr string

	// Workers evaluate flows; QueueSize bounds flows waiting for them.
	Workers   int
	QueueSize int
}

// Load reads the configuration through lookup (os.LookupEnv in production).
// The returned warnings describe ignored or legacy settings.
func Load(lookup func(string) (string, bool)) (Config, []string, error) {
	e := env{lookup: lookup}
	cfg := Config{
		Debug:                 e.bool("DEBUG", false),
		SensorName:            e.str("TRAFFIC_SENSOR_NAME", ""),
		AuthSecret:            Secret(e.str("AUTH_SECRET", "")),
		ArbiterURL:            strings.TrimRight(e.str("NFG_ARBITER_URL", "https://arbiter.nxtfireguard.de"), "/"),
		InsecureSkipVerifyTLS: e.bool("STREAMING_SKIP_VERIFY_TLS", false),
		HeartbeatURL:          strings.TrimRight(e.str("HEARTBEAT_URL", "https://heartbeat.nxtfireguard.de"), "/"),
		HeartbeatIdentifier:   e.str("HEARTBEAT_IDENTIFIER", ""),
		DBPath:                e.str("SQLITE_DB_PATH", "/data/ip_scores.db"),
		ScoreCacheSize:        e.int("IP_SCORE_CACHE_SIZE", 10000),
		RecommendCacheSize:    e.int("RECOMMENDATIONS_CACHE_SIZE", 10000),
		Workers:               e.int("EVALUATION_WORKERS", 8),
		QueueSize:             e.int("EVALUATION_QUEUE_SIZE", 4096),
	}
	port := e.int("SYSLOG_PORT", 514)
	cfg.SyslogAddr = net.JoinHostPort(e.str("SYSLOG_LISTEN_ADDR", "0.0.0.0"), strconv.Itoa(port))

	var errs []error
	if port < 1 || port > 65535 {
		// 0 would bind a random port no sender knows about.
		errs = append(errs, fmt.Errorf("SYSLOG_PORT=%d is not a port (1-65535)", port))
	}
	if cfg.SensorName == "" {
		errs = append(errs, errors.New("TRAFFIC_SENSOR_NAME is required"))
	}
	if cfg.AuthSecret == "" {
		errs = append(errs, errors.New("AUTH_SECRET is required"))
	}
	for _, n := range []struct {
		name string
		v    int
	}{{"IP_SCORE_CACHE_SIZE", cfg.ScoreCacheSize}, {"RECOMMENDATIONS_CACHE_SIZE", cfg.RecommendCacheSize}, {"EVALUATION_WORKERS", cfg.Workers}, {"EVALUATION_QUEUE_SIZE", cfg.QueueSize}} {
		if n.v <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", n.name))
		}
	}

	stream, err := streamURL(cfg.ArbiterURL, e.str("NFG_ARBITER_HOST", ""))
	if err != nil {
		errs = append(errs, err)
	}
	cfg.StreamURL = stream

	warnings := e.errs
	for _, legacy := range []string{"LOG_TO_LOKI", "LOKI_ADDRESS"} {
		if _, ok := lookup(legacy); ok {
			warnings = append(warnings, legacy+" is no longer supported and is ignored; logs go to stdout")
		}
	}
	if cfg.HeartbeatIdentifier == "" {
		warnings = append(warnings, "HEARTBEAT_IDENTIFIER is empty; no heartbeats will be sent")
	}
	return cfg, warnings, errors.Join(errs...)
}

// streamURL derives the update websocket from the REST base URL, so http
// maps to ws and https to wss. host overrides the host part, which is what
// NFG_ARBITER_HOST used to configure on its own.
func streamURL(base, host string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("NFG_ARBITER_URL %q is not an absolute URL", base)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("NFG_ARBITER_URL %q must use http or https", base)
	}
	if host != "" {
		// As before: NFG_ARBITER_HOST names the websocket server on its own,
		// so the REST URL's path prefix does not apply to it. The scheme
		// still follows NFG_ARBITER_URL; main derived it from
		// STREAMING_SKIP_VERIFY_TLS, which turned TLS off entirely.
		u.Host = host
		u.Path = ""
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/sync/ws/updates"
	return u.String(), nil
}

type env struct {
	lookup func(string) (string, bool)
	errs   []string
}

func (e *env) str(key, def string) string {
	if v, ok := e.lookup(key); ok && v != "" {
		return v
	}
	return def
}

func (e *env) bool(key string, def bool) bool {
	v := e.str(key, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Sprintf("%s=%q is not a boolean, using %v", key, v, def))
		return def
	}
	return b
}

func (e *env) int(key string, def int) int {
	v := e.str(key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Sprintf("%s=%q is not an integer, using %d", key, v, def))
		return def
	}
	return n
}
