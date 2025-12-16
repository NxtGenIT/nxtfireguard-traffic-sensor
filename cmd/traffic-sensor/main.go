package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/assets"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/arbiter"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/blocklist"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/bootstrap"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sqlite"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/uptime"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/utils"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

func main() {
	fmt.Print(assets.LogoContent)

	var wg sync.WaitGroup

	// Root context for shutdown
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// Shutdown hook
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopChan
		zap.L().Info("Received termination signal, shutting down...")
		rootCancel()
	}()

	godotenv.Load()
	cfg := config.Load()
	log.Printf("Config loaded: %+v", cfg)

	utils.InitLogger(cfg)

	zap.L().Info("Traffic Sensor starting up...")

	err := sqlite.Init(cfg.SqliteDbPath)
	if err != nil {
		log.Fatalf("DB init failed: %v", err)
	}

	wm := whitelist.NewWhitelistManager()

	if err := bootstrap.InitializeSystem(rootCtx, cfg, wm, &wg); err != nil {
		zap.L().Fatal("Startup failed", zap.Error(err))
	}

	// WS connection for receiving updates
	updaterWs := arbiter.NewUpdateStreamerImpl()

	// Start initial services dynamically
	if err := arbiter.SyncSensorConfig(rootCtx, cfg, wm, nil); err != nil {
		zap.L().Error("Failed to perform initial runtime control sync", zap.Error(err))
	}

	// Start Update Web Socket
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := arbiter.StartUpdateWebSocketClient(rootCtx, cfg, wm, updaterWs, &wg)
		if err != nil {
			zap.L().Fatal("Updater WebSocket client failed to start", zap.Error(err))
		}
	}()

	// Periodically sync in case the WebSocket missed updates
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-rootCtx.Done():
				zap.L().Info("Config sync loop exiting")
				return
			case <-ticker.C:
				if err := arbiter.SyncSensorConfig(rootCtx, cfg, wm, nil); err != nil {
					zap.L().Error("Failed to sync sensor config", zap.Error(err))
				}
				if err := wm.Sync(cfg); err != nil {
					zap.L().Error("Failed to sync whitelists", zap.Error(err))
				}
				if err := blocklist.Sync(cfg); err != nil {
					zap.L().Error("Failed to sync blocklists", zap.Error(err))
				}
				if err := arbiter.Sync(cfg); err != nil {
					zap.L().Error("Failed to sync ip-scores", zap.Error(err))
				}

			}
		}
	}()

	// Start sending heartbeats
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-rootCtx.Done():
				zap.L().Info("Heartbeat loop exiting")
				return
			case <-ticker.C:
				uptime.SendHeartbeat(cfg.SensorName, cfg.AuthSecret, cfg.HeartbeatIdentifier, cfg.HeartbeatUrl)
			}
		}
	}()

	<-rootCtx.Done()
	zap.L().Info("Shutdown signal received, waiting for goroutines...")
	wg.Wait()
	zap.L().Info("All goroutines finished, exiting")
}
