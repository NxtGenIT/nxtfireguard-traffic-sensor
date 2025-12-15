package arbiter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/blocklist"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sqlite"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type Update struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type ScoreUpdate struct {
	Ip        string    `json:"ip"`
	Score     int32     `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}

type UpdateStreamerImpl struct {
	conn *websocket.Conn
	mu   sync.RWMutex
}

func NewUpdateStreamerImpl() *UpdateStreamerImpl {
	return &UpdateStreamerImpl{}
}

func (u *UpdateStreamerImpl) SetConn(c *websocket.Conn) {
	u.mu.Lock()
	u.conn = c
	u.mu.Unlock()
}

func (u *UpdateStreamerImpl) GetConn() *websocket.Conn {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.conn
}

func (u *UpdateStreamerImpl) StartListening(rootCtx context.Context, cfg *config.Config, wm *whitelist.WhitelistManager, wg *sync.WaitGroup) {
	zap.L().Info("[update] Started listening on websocket...")

	// Channel for processing updates asynchronously
	updateChan := make(chan Update, 100) // Buffer size to handle bursts

	// Start worker goroutines to process updates
	numWorkers := 4 // 4 update types -> 4 goroutines
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			for update := range updateChan {
				zap.L().Debug("[update] Worker processing update",
					zap.Int("workerID", workerID),
					zap.String("type", update.Type))
				ProcessUpdate(rootCtx, cfg, wm, update, wg)
			}
		}(i)
	}

	go func() {
		conn := u.GetConn()
		defer func() {
			if r := recover(); r != nil {
				zap.L().Error("Recovered from panic in websocket read loop", zap.Any("recover", r))
				u.SetConn(nil)
				if conn != nil {
					conn.Close()
				}
			}
		}()
		for {
			currentConn := u.GetConn()
			if currentConn != conn {
				zap.L().Info("[update] Connection replaced, exiting read loop")
				break
			}
			if conn == nil {
				time.Sleep(2 * time.Second)
				continue
			}

			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			conn.SetPongHandler(func(_ string) error {
				zap.L().Debug("[update] Received pong")
				conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				return nil
			})

			for {
				// Check if connection is still the same before reading
				currentConn := u.GetConn()
				if currentConn != conn {
					// Connection was replaced externally, exit this read loop
					zap.L().Info("[update] Connection replaced, exiting read loop")
					break
				}

				_, msg, err := conn.ReadMessage()
				if err != nil {
					if wsCloseErr, ok := err.(*websocket.CloseError); ok {
						zap.L().Error("[update] Close error", zap.Int("code", wsCloseErr.Code), zap.String("text", wsCloseErr.Text))
					} else if errors.Is(err, io.EOF) {
						zap.L().Error("[update] EOF received")
					} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						zap.L().Error("[update] Read timeout", zap.Error(err))
					} else {
						zap.L().Error("[update] Read error", zap.Error(err))
					}

					u.SetConn(nil)
					conn.Close()
					break
				}

				var data Update
				if err := json.Unmarshal(msg, &data); err != nil {
					zap.L().Error("Failed to unmarshal update", zap.ByteString("payload", msg), zap.Error(err))
					continue
				}

				// Process async in channel
				select {
				case updateChan <- data:
					// Successfully queued
				default:
					// Channel full - log warning but don't block the read loop
					zap.L().Warn("[update] Update channel full, dropping update",
						zap.String("type", data.Type))
				}
			}
		}
	}()
}

func PingKeepalive(u *UpdateStreamerImpl, period time.Duration) {
	zap.L().Info("[update] Starting config updater websocket keepalive pings...")

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	defer func() {
		if r := recover(); r != nil {
			zap.L().Error("PingKeepalive panicked", zap.Any("reason", r))
		}
	}()

	for {
		<-ticker.C
		conn := u.GetConn()
		if conn == nil {
			zap.L().Warn("WebSocket connection is nil, stopping keepalive")
			continue // wait until StartWebSocketClient sets a new conn
		}

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			zap.L().Warn("[update] Failed to send client ping, closing connection", zap.Error(err))
			u.SetConn(nil)
			conn.Close()
			continue // next tick will check for new conn
		}
	}
}

func StartUpdateWebSocketClient(rootCtx context.Context, cfg *config.Config, wm *whitelist.WhitelistManager, updater *UpdateStreamerImpl, wg *sync.WaitGroup) error {
	var scheme string
	if cfg.InsecureSkipVerifyTLS {
		scheme = "ws"
	} else {
		scheme = "wss"
	}

	u := url.URL{
		Scheme: scheme,
		Host:   cfg.NfgArbiterHost,
		Path:   "/sync/ws/updates",
	}
	headers := http.Header{}
	headers.Set("X_AUTH_KEY", cfg.AuthSecret)
	headers.Set("X_SENSOR_NAME", cfg.SensorName)

	dialer := websocket.DefaultDialer
	if cfg.InsecureSkipVerifyTLS {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	// Backoff configuration
	initialBackoff := 1 * time.Second
	maxBackoff := 5 * time.Minute
	currentBackoff := initialBackoff
	backoffMultiplier := 2.0

	for {
		zap.L().Info("[update] Connecting to update WebSocket", zap.String("url", u.String()))
		conn, _, err := dialer.Dial(u.String(), headers)
		if err != nil {
			zap.L().Error("[update] Connection failed",
				zap.Error(err),
				zap.Duration("retryIn", currentBackoff))
			time.Sleep(currentBackoff)

			// Increase backoff exponentially up to max
			currentBackoff = time.Duration(float64(currentBackoff) * backoffMultiplier)
			if currentBackoff > maxBackoff {
				currentBackoff = maxBackoff
			}
			continue
		}

		// Reset backoff on successful connection
		currentBackoff = initialBackoff
		zap.L().Info("[update] Connected to update WebSocket")
		updater.SetConn(conn)

		go func() {
			defer func() {
				if r := recover(); r != nil {
					zap.L().Error("PingKeepalive goroutine panicked", zap.Any("reason", r))
				}
			}()
			PingKeepalive(updater, cfg.WsKeepalivePeriod)
		}()

		updater.StartListening(rootCtx, cfg, wm, wg)

		// Wait until disconnected
		for {
			time.Sleep(5 * time.Second)
			if updater.GetConn() == nil {
				break
			}
		}

		zap.L().Warn("[update] WebSocket disconnected, retrying...",
			zap.Duration("retryIn", currentBackoff))
		time.Sleep(currentBackoff)

		// Increase backoff for next potential failure
		currentBackoff = time.Duration(float64(currentBackoff) * backoffMultiplier)
		if currentBackoff > maxBackoff {
			currentBackoff = maxBackoff
		}
	}
}

func ProcessUpdate(rootCtx context.Context, cfg *config.Config, wm *whitelist.WhitelistManager, data Update, wg *sync.WaitGroup) {
	switch data.Type {
	case "score-update":
		var s ScoreUpdate
		if err := json.Unmarshal(data.Data, &s); err != nil {
			zap.L().Error("Failed to parse score-update", zap.Error(err))
			return
		}
		zap.L().Info("[update] Processing score-update",
			zap.String("IP:", s.Ip),
			zap.Int32("NFG-Score:", s.Score),
		)
		err := sqlite.UpsertIpScore(types.ScoreRecord{IP: s.Ip, NFGScore: s.Score})
		if err != nil {
			zap.L().Error("Failed to upsert ip score", zap.Error(err))
			return
		}
		sqlite.ScoreCache.Remove(s.Ip)
		removeRecommendCacheEntriesByIP(s.Ip)
	case "blocklist-update":
		zap.L().Info("[update] Processing blocklist-update")
		err := blocklist.Sync(cfg)
		if err != nil {
			zap.L().Error("Failed to re-sync blocklists", zap.Error(err))
			return
		}
		// Invalidate entire recommendations cache
		InitRecommendCache(cfg.RecommendationsCacheSize)
	case "whitelist-update":
		zap.L().Info("[update] Processing whitelist-update")
		if err := wm.Sync(cfg); err != nil {
			zap.L().Error("Failed to re-sync whitelists", zap.Error(err))
			return
		}
	case "config-update":
		zap.L().Info("[update] Processing alert-threshold-update")
		if err := SyncSensorConfig(rootCtx, cfg, wm, wg); err != nil {
			zap.L().Error("Failed to re-sync whitelists", zap.Error(err))
			return
		}
	default:
		zap.L().Warn("Unknown update type received", zap.String("type", data.Type))
	}
}
