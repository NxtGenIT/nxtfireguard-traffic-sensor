package arbiter

import (
	"context"
	"sync"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/syslog"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/traffic"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"go.uber.org/zap"
)

type RuntimeControllers struct {
	mu            sync.Mutex
	trafficCancel context.CancelFunc
	syslogCancel  context.CancelFunc
}

var controllers = &RuntimeControllers{}

func HandleChangeSniffTraffic(rootCtx context.Context, cfg *config.Config, whitelistManager *whitelist.WhitelistManager, wg *sync.WaitGroup) {
	controllers.mu.Lock()
	defer controllers.mu.Unlock()

	// Stop current monitor if running
	if controllers.trafficCancel != nil {
		controllers.trafficCancel()
		controllers.trafficCancel = nil
		zap.L().Info("Stopped traffic monitoring")
	}

	if cfg.SniffTraffic {
		ctx, cancel := context.WithCancel(rootCtx)
		controllers.trafficCancel = cancel

		wg.Add(1)
		go func() {
			defer wg.Done()
			zap.L().Info("Started traffic monitoring")
			traffic.MonitorAllInterfaces(ctx, cfg, whitelistManager, EvaluateAndAct, wg)
		}()
	}
}

func HandleChangeRunSyslog(rootCtx context.Context, cfg *config.Config, whitelistManager *whitelist.WhitelistManager, wg *sync.WaitGroup) {
	controllers.mu.Lock()
	defer controllers.mu.Unlock()

	if controllers.syslogCancel != nil {
		controllers.syslogCancel()
		controllers.syslogCancel = nil
		zap.L().Info("Stopped syslog server")
	}

	if cfg.RunSyslog {
		ctx, cancel := context.WithCancel(rootCtx)
		controllers.syslogCancel = cancel

		wg.Add(1)
		go func() {
			defer wg.Done()
			zap.L().Info("Started syslog server")
			syslog.StartSyslogServer(ctx, cfg, whitelistManager, EvaluateAndAct, wg)
		}()
	}
}
