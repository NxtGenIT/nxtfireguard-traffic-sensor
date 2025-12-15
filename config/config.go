package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Debug                    bool
	SensorName               string
	AuthSecret               string
	HeartbeatIdentifier      string
	HeartbeatUrl             string
	NfgArbiterUrl            string
	NfgArbiterHost           string
	InsecureSkipVerifyTLS    bool
	SqliteDbPath             string
	IpScoreCacheSize         int
	RecommendationsCacheSize int
	LogToLoki                bool
	LokiAddress              string
	WsKeepalivePeriod        time.Duration
	SniffTraffic             bool
	RunSyslog                bool
	SyslogListenAddr         string
	SyslogPort               int
	AlertThreshold           int32
}

func Load() *Config {
	debug, _ := strconv.ParseBool(getEnv("DEBUG", "false"))
	insecureSkipVerify, _ := strconv.ParseBool(getEnv("STREAMING_SKIP_VERIFY_TLS", "false"))
	logToLoki, _ := strconv.ParseBool(getEnv("LOG_TO_LOKI", "true"))

	cfg := &Config{
		Debug:                    debug,
		SensorName:               getEnv("TRAFFIC_SENSOR_NAME", ""),
		AuthSecret:               getEnv("AUTH_SECRET", ""),
		HeartbeatIdentifier:      getEnv("HEARTBEAT_IDENTIFIER", ""),
		HeartbeatUrl:             getEnv("HEARTBEAT_URL", "https://heartbeat.nxtfireguard.de"),
		NfgArbiterUrl:            getEnv("NFG_ARBITER_URL", "https://arbiter.nxtfireguard.de"),
		NfgArbiterHost:           getEnv("NFG_ARBITER_HOST", "arbiter.nxtfireguard.de"),
		InsecureSkipVerifyTLS:    insecureSkipVerify,
		SqliteDbPath:             getEnv("SQLITE_DB_PATH", "/data/ip_scores.db"),
		IpScoreCacheSize:         getEnvInt("IP_SCORE_CACHE_SIZE", 1000),
		RecommendationsCacheSize: getEnvInt("RECOMMENDATIONS_CACHE_SIZE", 100),
		LogToLoki:                logToLoki,
		LokiAddress:              getEnv("LOKI_ADDRESS", "https://loki.nxtfireguard.de"),
		WsKeepalivePeriod:        30 * time.Second,
		SyslogListenAddr:         getEnv("SYSLOG_LISTEN_ADDR", "0.0.0.0"),
		SyslogPort:               getEnvInt("SYSLOG_PORT", 514),
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, defaultValue int) int {
	valueStr, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}

	valueInt, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("Error converting '%s' to int, using default %d: %v", key, defaultValue, err)
		return defaultValue
	}
	return valueInt
}
