package alert

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/utils"
	"go.uber.org/zap"
)

var AlertThreshold int32

func Sync(cfg *config.Config) error {
	client := utils.NewAPIClient(cfg)

	resp, err := client.DoRequest(utils.RequestOptions{
		Endpoint: "/sync/alert-threshold",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var response types.AlertThresholdResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		zap.L().Error("Failed to decode alert threshold response", zap.Error(err))
		return fmt.Errorf("failed to decode response: %w", err)
	}

	AlertThreshold = response.AlertThreshold

	zap.L().Info("Stored alert threshold", zap.Int("threshold", int(AlertThreshold)))
	return nil
}

func Send(ip string, relatedIp string, source types.Source, cfg *config.Config) error {
	payload := struct {
		Ip         string `json:"ip"`
		RelatedIp  string `json:"relatedIp"`
		SourceType string `json:"sourceType"`
		SourceName string `json:"sourceName"`
	}{
		Ip:         ip,
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

	zap.L().Debug("Sent alert successfully",
		zap.String("ip", ip),
		zap.String("sourceType", source.SourceType),
		zap.String("sourceName", source.SourceName),
	)

	return nil
}
