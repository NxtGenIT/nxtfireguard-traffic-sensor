package bootstrap

import (
	"context"
	"sync"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/arbiter"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/blocklist"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sqlite"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"go.uber.org/zap"
)

func InitializeSystem(rootCtx context.Context, cfg *config.Config, wm *whitelist.WhitelistManager, wg *sync.WaitGroup) error {
	if err := arbiter.SyncSensorConfig(rootCtx, cfg, wm, wg); err != nil {
		return err
	}

	// Sync IP score DB
	if err := arbiter.Sync(cfg); err != nil {
		return err
	}

	// Pull blocklist/s
	if err := blocklist.Sync(cfg); err != nil {
		return err
	}

	// Pull whitelist/s
	if err := wm.Sync(cfg); err != nil {
		return err
	}

	// Init SQL IP Score cache
	if err := sqlite.InitCache(cfg.IpScoreCacheSize); err != nil {
		return err
	}

	// Init Recommendations cache
	if err := arbiter.InitRecommendCache(cfg.RecommendationsCacheSize); err != nil {
		return err
	}

	zap.L().Info("Traffic Sensor bootstrapped successfully.")
	return nil
}
