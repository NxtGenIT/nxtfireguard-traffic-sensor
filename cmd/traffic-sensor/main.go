package main

import (
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
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/bootstrap"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sqlite"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/syslog"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/traffic"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/uptime"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/utils"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

func main() {
	fmt.Print(assets.LogoContent)

	// Setup shutdown hook
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopChan
		zap.L().Info("Received termination signal, exiting...")
		os.Exit(0)
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

	if err := bootstrap.InitializeSystem(cfg, wm); err != nil {
		zap.L().Fatal("Startup failed", zap.Error(err))
	}

	// WS connection for receiving updates (IP-Scores, whitelists)
	updaterWs := arbiter.NewUpdateStreamerImpl()
	log.Printf("updater: %+v", updaterWs)

	var wg sync.WaitGroup
	wg.Add(2)

	// Start interface monitor in a goroutine
	go func() {
		defer wg.Done()
		traffic.MonitorAllInterfaces(cfg, wm)
	}()

	// Start syslog server in a goroutine
	go func() {
		defer wg.Done()
		syslog.StartSyslogServer(cfg, wm)
	}()

	// Start Update Web Socket
	go func() {
		defer wg.Done()
		err := arbiter.StartUpdateWebSocketClient(cfg, wm, updaterWs)
		if err != nil {
			zap.L().Fatal("Updater WebSocket client failed to start", zap.Error(err))
			os.Exit(1)
		}
	}()

	// Start sending heartbeats
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			uptime.SendHeartbeat(cfg.SensorName, cfg.AuthSecret, cfg.HeartbeatIdentifier, cfg.HeartbeatUrl)
			<-ticker.C
		}
	}()

	wg.Wait()
}
