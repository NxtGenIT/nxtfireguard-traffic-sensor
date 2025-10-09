package whitelist

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/utils"
	"github.com/yl2chen/cidranger"
	"go.uber.org/zap"
)

// Sync fetches the whitelist from the API and updates the manager.
func (wm *WhitelistManager) Sync(cfg *config.Config) error {
	client := utils.NewAPIClient(cfg)

	resp, err := client.DoRequest(utils.RequestOptions{
		Endpoint: "/sync/whitelist",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var response types.WhitelistResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		zap.L().Error("Failed to decode whitelist response", zap.Error(err))
		return fmt.Errorf("failed to decode response: %w", err)
	}

	ranger := cidranger.NewPCTrieRanger()
	for _, cidr := range response.CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			zap.L().Warn("Invalid CIDR in whitelist", zap.String("cidr", cidr), zap.Error(err))
			continue
		}
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}

	wm.mutex.Lock()
	wm.ranger = ranger
	wm.mutex.Unlock()

	zap.L().Info("Whitelists synced", zap.Int("CIDR count (private + global whitelist)", len(response.CIDRs)))
	return nil
}
