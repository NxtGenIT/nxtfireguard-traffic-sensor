// Command traffic-sensor watches network traffic and syslog for connections
// to or from IPs that NxtFireGuard scores as malicious, and reports them.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/assets"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/logging"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/scores"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sensor"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	fmt.Print(assets.LogoContent)
	_ = godotenv.Load() // optional .env for local runs

	cfg, warnings, err := config.Load(os.LookupEnv)
	log := logging.Setup(cfg.Debug, zap.String("service", "traffic-sensor"), zap.String("version", version), zap.String("sensor", cfg.SensorName))
	defer log.Sync() //nolint:errcheck // nothing to do if stdout is gone
	for _, w := range warnings {
		log.Warn(w)
	}
	if err != nil {
		log.Fatal("invalid configuration", zap.Error(err))
	}
	log.Info("starting", zap.Any("config", cfg))

	store, err := scores.Open(cfg.DBPath, cfg.ScoreCacheSize)
	if err != nil {
		log.Fatal("cannot open score database", zap.Error(err))
	}
	defer store.Close() //nolint:errcheck // process exits next

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sensor.New(cfg, nfg.New(cfg, version), store).Run(ctx)
	log.Info("stopped")
}
