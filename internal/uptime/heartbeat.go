package uptime

import (
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

func SendHeartbeat(sensorName string, apikey string, identifier string, url string) error {
	var resp *http.Response
	var req *http.Request
	var err error

	maxRetries := 3
	backoff := time.Second

	zap.L().Debug("Sending heartbeat")

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err = http.NewRequest("GET", fmt.Sprintf("%s/ping/%s", url, identifier), nil)
		if err != nil {
			zap.L().Error("Failed to create request",
				zap.Error(err),
				zap.String("url", url),
				zap.String("identifier", identifier),
			)
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("apikey", apikey)

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			zap.L().Warn("Request failed, retrying",
				zap.Int("attempt", attempt+1),
				zap.String("url", url),
				zap.String("identifier", identifier),
				zap.Error(err),
			)
			if attempt < maxRetries {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			zap.L().Error("Failed to send request after retries",
				zap.Int("maxRetries", maxRetries),
				zap.String("url", url),
				zap.String("identifier", identifier),
				zap.Error(err),
			)
			return fmt.Errorf("failed to send request after retries: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			zap.L().Info("Heartbeat request succeeded",
				zap.Int("status", resp.StatusCode),
			)
			return nil // success
		}

		// Retry if status code is 5xx
		if resp.StatusCode >= 500 && attempt < maxRetries {
			zap.L().Warn("Server error, retrying",
				zap.Int("attempt", attempt+1),
				zap.String("url", url),
				zap.String("identifier", identifier),
				zap.Int("status", resp.StatusCode),
			)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}
	}

	zap.L().Error("Request failed after all attempts",
		zap.Int("maxRetries", maxRetries),
		zap.String("url", url),
		zap.String("identifier", identifier),
	)
	return fmt.Errorf("request failed after %d attempts", maxRetries)
}
