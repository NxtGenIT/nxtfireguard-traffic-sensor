package blocklist

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/utils"
	"go.uber.org/zap"
)

var storedBlocklists []types.Blocklist
var blocklistMutex sync.RWMutex

func Sync(cfg *config.Config) error {
	client := utils.NewAPIClient(cfg)

	resp, err := client.DoRequest(utils.RequestOptions{
		Endpoint: "/sync/blocklist",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var response types.BlocklistsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		zap.L().Error("Failed to decode blocklist response", zap.Error(err))
		return fmt.Errorf("failed to decode response: %w", err)
	}

	blocklistMutex.Lock()
	storedBlocklists = response.Blocklists
	blocklistMutex.Unlock()

	zap.L().Info("Stored blocklists", zap.Int("count", len(response.Blocklists)))
	return nil
}
