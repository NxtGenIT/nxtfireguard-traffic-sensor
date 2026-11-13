// Package nfg talks to the NxtFireGuard backend: score-proxy (REST and the
// update websocket) and the heartbeat server. The JSON shapes here are the
// wire format score-proxy expects and must not change.
package nfg

import (
	"encoding/json"
	"time"
)

// SensorConfig is GET /sync.
type SensorConfig struct {
	SniffTraffic   bool  `json:"sniffTraffic"`
	RunSyslog      bool  `json:"runSyslog"`
	AlertThreshold int32 `json:"alertThreshold"`
}

// Blocklist is one entry of GET /sync/blocklist.
type Blocklist struct {
	ID                          int    `json:"id"`
	Name                        string `json:"name"`
	ShouldIncludePrivateIPs     bool   `json:"shouldIncludePrivateIPs"`
	ShouldIncludePublicIPs      bool   `json:"shouldIncludePublicIPs"`
	NfgScoreThresholdPrivateIPs int32  `json:"nfgScoreThresholdPrivateIPs"`
	NfgScoreThresholdPublicIPs  int32  `json:"nfgScoreThresholdPublicIPs"`
}

type blocklistsResponse struct {
	Blocklists []Blocklist `json:"blocklists"`
}

type whitelistResponse struct {
	CIDRs []string `json:"cidrs"`
}

// Score is one record of the GET /sync/score snapshot and of a live
// score-update push.
type Score struct {
	IP          string    `json:"ip"`
	Score       int32     `json:"score"`
	LastUpdated time.Time `json:"last_updated"`
}

// Source says where a flow was observed.
type Source struct {
	Type string // "interface" or "syslog"
	Name string // interface name or syslog client address
}

// Alert is POST /alert. IPType is "source" or "destination": the role of IP
// in the observed flow; RelatedIP is the other end.
type Alert struct {
	IPType     string `json:"ipType"`
	IP         string `json:"ip"`
	RelatedIP  string `json:"relatedIp"`
	SourceType string `json:"sourceType"`
	SourceName string `json:"sourceName"`
}

// Decision is one blocklist verdict inside a recommendation.
type Decision struct {
	Block     bool   `json:"block"`
	Reason    string `json:"reason"`
	Blocklist string `json:"blocklist"`
}

// Recommendation is POST /recommend.
type Recommendation struct {
	IP        string     `json:"ip"`
	Decisions []Decision `json:"decisions"`
}

// Update is a message on the update websocket. Only score-update carries
// data; the other types tell the sensor to re-fetch that resource.
type Update struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

const (
	UpdateScore     = "score-update"
	UpdateBlocklist = "blocklist-update"
	UpdateWhitelist = "whitelist-update"
	UpdateConfig    = "config-update"
)

type ScoreUpdate struct {
	IP        string    `json:"ip"`
	Score     int32     `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}
