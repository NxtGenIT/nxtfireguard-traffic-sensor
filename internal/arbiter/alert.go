package arbiter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/utils"
	"go.uber.org/zap"
)

// SendAlert attempts to send an alert, queuing it for retry if rate limited
func SendAlert(ipType string, ip string, relatedIp string, source types.Source, cfg *config.Config) error {
	err := sendAlertInternal(ipType, ip, relatedIp, source, cfg)

	// If rate limited, queue for retry
	if err != nil && isRateLimitError(err) {
		zap.L().Warn("Alert rate limited, queuing for retry",
			zap.String("ip", ip),
		)
		GetRetryQueue(cfg).Add("alert", AlertData{
			IpType:    ipType,
			Ip:        ip,
			RelatedIp: relatedIp,
			Source:    source,
		})
		return nil // Don't return error since we queued it
	}

	return err
}

// sendAlertInternal is the actual HTTP call used by the retry queue
func sendAlertInternal(ipType string, ip string, relatedIp string, source types.Source, cfg *config.Config) error {
	payload := struct {
		IpType     string `json:"ipType"`
		Ip         string `json:"ip"`
		RelatedIp  string `json:"relatedIp"`
		SourceType string `json:"sourceType"`
		SourceName string `json:"sourceName"`
	}{
		IpType:     ipType,
		Ip:         ip,
		RelatedIp:  relatedIp,
		SourceType: source.SourceType,
		SourceName: source.SourceName,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		zap.L().Error("Failed to marshal alert payload",
			zap.Error(err),
			zap.String("ip", ip),
		)
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	client := utils.NewAPIClient(cfg)
	resp, err := client.DoRequest(utils.RequestOptions{
		Endpoint: "/alert",
		Method:   "POST",
		Body:     bytes.NewReader(body),
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for rate limit
	if resp.StatusCode == http.StatusTooManyRequests {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return &RateLimitError{
			StatusCode: resp.StatusCode,
			Message:    string(bodyBytes),
		}
	}

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("alert request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	zap.L().Debug("Sent alert successfully",
		zap.String("ip", ip),
		zap.String("sourceType", source.SourceType),
		zap.String("sourceName", source.SourceName),
	)
	return nil
}
