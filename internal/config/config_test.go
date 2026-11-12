package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func load(vars map[string]string) (Config, []string, error) {
	return Load(func(k string) (string, bool) { v, ok := vars[k]; return v, ok })
}

var minimal = map[string]string{"TRAFFIC_SENSOR_NAME": "s", "AUTH_SECRET": "top-secret"}

func TestDefaults(t *testing.T) {
	cfg, _, err := load(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ArbiterURL != "https://arbiter.nxtfireguard.de" || cfg.StreamURL != "wss://arbiter.nxtfireguard.de/sync/ws/updates" ||
		cfg.HeartbeatURL != "https://heartbeat.nxtfireguard.de" || cfg.SyslogAddr != "0.0.0.0:514" || cfg.DBPath != "/data/ip_scores.db" {
		t.Fatalf("%+v", cfg)
	}
}

func TestRequired(t *testing.T) {
	_, _, err := load(map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "TRAFFIC_SENSOR_NAME") || !strings.Contains(err.Error(), "AUTH_SECRET") {
		t.Fatalf("err %v", err)
	}
}

func TestStreamURL(t *testing.T) {
	for _, c := range []struct{ url, host, want string }{
		{"http://localhost:8080", "", "ws://localhost:8080/sync/ws/updates"},
		{"https://arbiter.example/api/", "", "wss://arbiter.example/api/sync/ws/updates"},
		{"https://arbiter.example", "stream.example:8443", "wss://stream.example:8443/sync/ws/updates"},
		// An explicit host names the websocket server on its own, as before:
		// the REST path prefix does not carry over.
		{"https://gw.example/nfg", "arbiter.example", "wss://arbiter.example/sync/ws/updates"},
	} {
		vars := map[string]string{"NFG_ARBITER_URL": c.url, "NFG_ARBITER_HOST": c.host}
		for k, v := range minimal {
			vars[k] = v
		}
		cfg, _, err := load(vars)
		if err != nil || cfg.StreamURL != c.want {
			t.Errorf("%s + %q: %q %v, want %q", c.url, c.host, cfg.StreamURL, err, c.want)
		}
	}
	vars := map[string]string{"NFG_ARBITER_URL": "ftp://x"}
	for k, v := range minimal {
		vars[k] = v
	}
	if _, _, err := load(vars); err == nil {
		t.Error("ftp URL accepted")
	}
}

func TestWarnings(t *testing.T) {
	vars := map[string]string{"LOG_TO_LOKI": "true", "SYSLOG_PORT": "abc", "HEARTBEAT_IDENTIFIER": "x"}
	for k, v := range minimal {
		vars[k] = v
	}
	cfg, warnings, err := load(vars)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "LOG_TO_LOKI") || !strings.Contains(joined, "SYSLOG_PORT") || cfg.SyslogAddr != "0.0.0.0:514" {
		t.Fatalf("warnings %q addr %s", warnings, cfg.SyslogAddr)
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	cfg, _, _ := load(minimal)
	js, _ := json.Marshal(cfg)
	for _, out := range []string{fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), string(js), cfg.AuthSecret.String()} {
		if strings.Contains(out, "top-secret") {
			t.Fatalf("secret leaked: %s", out)
		}
	}
	if cfg.AuthSecret.Reveal() != "top-secret" {
		t.Fatal("Reveal")
	}
}
