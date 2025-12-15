package arbiter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/recommender"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"go.uber.org/zap"
)

// recommend attempts to send a recommendation, queuing it for retry if rate limited
func recommend(cfg *config.Config, ip string, decisions []types.Decision) error {
	err := recommendInternal(cfg, ip, decisions)

	// If rate limited, queue for retry
	if err != nil && isRateLimitError(err) {
		zap.L().Warn("Recommendation rate limited, queuing for retry",
			zap.String("ip", ip),
		)
		GetRetryQueue(cfg).Add("recommendation", RecommendationData{
			IP:        ip,
			Decisions: decisions,
		})
		return nil // Don't return error since we queued it
	}

	return err
}

// recommendInternal is the actual HTTP call (used by retry queue)
func recommendInternal(cfg *config.Config, ip string, decisions []types.Decision) error {
	payload := struct {
		IP        string           `json:"ip"`
		Decisions []types.Decision `json:"decisions"`
	}{
		IP:        ip,
		Decisions: decisions,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		zap.L().Error("Failed to marshal block report payload",
			zap.Error(err),
			zap.String("ip", ip),
		)
		return fmt.Errorf("failed to marshal block report payload: %w", err)
	}

	maxRetries := 3
	backoff := time.Second

	zap.L().Debug("Sending recommendation request",
		zap.String("ip", ip),
		zap.String("url", fmt.Sprintf("%s/recommend", cfg.NfgArbiterUrl)),
	)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/recommend", cfg.NfgArbiterUrl), bytes.NewBuffer(body))
		if err != nil {
			zap.L().Error("Failed to create request",
				zap.Error(err),
				zap.String("ip", ip),
			)
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X_AUTH_KEY", cfg.AuthSecret)
		req.Header.Set("X_SENSOR_NAME", cfg.SensorName)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			zap.L().Warn("Request failed, retrying",
				zap.Int("attempt", attempt+1),
				zap.String("ip", ip),
				zap.Error(err),
			)
			if attempt < maxRetries {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			zap.L().Error("Failed to send request after retries",
				zap.Int("maxRetries", maxRetries),
				zap.String("ip", ip),
				zap.Error(err),
			)
			return fmt.Errorf("failed to send request after retries: %w", err)
		}
		defer resp.Body.Close()

		// Check for rate limit - don't retry on 429, let caller queue it
		if resp.StatusCode == http.StatusTooManyRequests {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return &RateLimitError{
				StatusCode: resp.StatusCode,
				Message:    string(bodyBytes),
			}
		}

		if resp.StatusCode == http.StatusOK {
			zap.L().Debug("Recommendation request succeeded",
				zap.String("ip", ip),
				zap.Int("status", resp.StatusCode),
			)
			return nil
		}

		// Retry if status code is 5xx
		if resp.StatusCode >= 500 && attempt < maxRetries {
			zap.L().Warn("Server error, retrying",
				zap.Int("attempt", attempt+1),
				zap.String("ip", ip),
				zap.Int("status", resp.StatusCode),
			)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		// Non-retriable error
		bodyBytes, _ := io.ReadAll(resp.Body)
		zap.L().Error("Non-retriable error from recommendation request",
			zap.String("ip", ip),
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(bodyBytes)),
		)
		return fmt.Errorf("non-retriable error, status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	zap.L().Error("Request failed after all attempts",
		zap.Int("maxRetries", maxRetries),
		zap.String("ip", ip),
	)
	return fmt.Errorf("request failed after %d attempts", maxRetries)
}

// EvaluateAndAct evaluates an IP and takes appropriate action
func EvaluateAndAct(cfg *config.Config, ipType string, ip string, relatedIp string, source types.Source) {
	start := time.Now()

	zap.L().Debug("Evaluating IP", zap.String("ip", ip))

	valid := net.ParseIP(ip)
	if valid == nil {
		zap.L().Debug("Not a valid IP Address, skipping",
			zap.String("ip", ip),
		)
		return
	}

	decisions, score := recommender.ShouldBlock(ip)

	if score >= cfg.AlertThreshold {
		err := SendAlert(ipType, ip, relatedIp, source, cfg)
		if err != nil {
			zap.L().Error("Error sending alert", zap.Error(err))
		}
	}

	// Filter only the blocking ones
	var blocksToReport []types.Decision
	for _, d := range decisions {
		if d.Block {
			zap.L().Debug("Blocking decision made",
				zap.String("ip", ip),
				zap.String("blocklist", d.Blocklist),
				zap.String("reason", d.Reason),
			)
			blocksToReport = append(blocksToReport, d)
		}
	}

	// If there are any blocking decisions, act on them
	if len(blocksToReport) > 0 {
		zap.L().Debug("Reporting block", zap.String("ip", ip))
		key := generateCacheKey(ip, blocksToReport)

		if _, found := RecommendCache.Get(key); found {
			zap.L().Debug("Duplicate recommendation skipped", zap.String("ip", ip))
			return
		}

		zap.L().Debug("Reporting block", zap.String("ip", ip))
		RecommendCache.Add(key, struct{}{})
		recommend(cfg, ip, blocksToReport)
	} else {
		zap.L().Debug("No blocking decision", zap.String("ip", ip))
	}

	zap.L().Debug("Finished processing IP",
		zap.String("ip", ip),
		zap.Duration("duration", time.Since(start)),
	)
}
