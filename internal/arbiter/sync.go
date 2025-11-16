package arbiter

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sqlite"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/syslog"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/traffic"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/utils"
	"go.uber.org/zap"
)

func Sync(cfg *config.Config) error {
	client := utils.NewAPIClient(cfg)

	resp, err := client.DoRequest(utils.RequestOptions{
		Endpoint: "/sync/score",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Untar and gunzip response
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		zap.L().Error("Failed to open gzip reader for sync data",
			zap.Error(err),
		)
		return fmt.Errorf("failed to open gzip reader: %w", err)
	}
	defer gzr.Close()

	tarReader := tar.NewReader(gzr)
	var allRecords []types.ScoreRecord

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			zap.L().Error("Error reading from tar archive during sync", zap.Error(err))
			return fmt.Errorf("error reading tar archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue // skip non-regular files
		}

		data, err := io.ReadAll(tarReader)
		if err != nil {
			zap.L().Error("Failed to read file from tar archive",
				zap.String("filename", header.Name),
				zap.Error(err),
			)
			return fmt.Errorf("failed to read file: %w", err)
		}

		var records []types.ScoreRecord
		if err := json.Unmarshal(data, &records); err != nil {
			zap.L().Error("Failed to parse JSON file from sync archive",
				zap.String("filename", header.Name),
				zap.Error(err),
			)
			return fmt.Errorf("failed to parse json file '%s': %w", header.Name, err)
		}

		allRecords = append(allRecords, records...)
	}

	zap.L().Info("Processed records from sync",
		zap.Int("recordCount", len(allRecords)),
	)

	// Store in SQLite
	if err := sqlite.BulkUpsertIpScores(allRecords); err != nil {
		zap.L().Error("Bulk insert of IP scores failed",
			zap.Int("recordCount", len(allRecords)),
			zap.Error(err),
		)
		return fmt.Errorf("bulk insert failed: %w", err)
	}

	zap.L().Info("IP score sync completed successfully")
	return nil
}

func ReSync(cfg *config.Config) error {
	client := utils.NewAPIClient(cfg)

	resp, err := client.DoRequest(utils.RequestOptions{
		Endpoint: "/score-updates",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		zap.L().Error("Failed to read response body", zap.Error(err))
		return fmt.Errorf("failed to read response body: %w", err)
	}

	type rawRecord struct {
		IP        string    `json:"ip"`
		Score     int32     `json:"score"`
		Timestamp time.Time `json:"timestamp"`
	}

	var rawRecords []rawRecord
	if err := json.Unmarshal(body, &rawRecords); err != nil {
		zap.L().Error("Failed to parse response JSON", zap.Error(err))
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Deduplicate: keep latest timestamp per IP
	deduped := make(map[string]rawRecord)
	for _, rec := range rawRecords {
		if existing, found := deduped[rec.IP]; !found || rec.Timestamp.After(existing.Timestamp) {
			deduped[rec.IP] = rec
		}
	}

	// Reformat for DB insert
	var allRecords []types.ScoreRecord
	for _, rec := range deduped {
		allRecords = append(allRecords, types.ScoreRecord{
			IP:       rec.IP,
			NFGScore: rec.Score,
		})
	}

	// Store into SQLite
	if err := sqlite.BulkUpsertIpScores(allRecords); err != nil {
		zap.L().Error("Bulk insert of IP scores failed",
			zap.Int("recordCount", len(allRecords)),
			zap.Error(err),
		)
		return fmt.Errorf("bulk insert failed: %w", err)
	}

	// Remove new IPs from cache
	for _, rec := range allRecords {
		sqlite.ScoreCache.Remove(rec.IP)
	}

	zap.L().Info("IP score sync completed successfully",
		zap.Int("insertedRecords", len(allRecords)),
	)
	return nil
}

// ReloadSubsystems dynamically updates traffic and syslog based on config
func ReloadSubsystems(rootCtx context.Context, cfg *config.Config, wm *whitelist.WhitelistManager, wg *sync.WaitGroup) {
	controllers.mu.Lock()
	defer controllers.mu.Unlock()

	// === TRAFFIC MONITOR ===
	if controllers.trafficCancel != nil {
		controllers.trafficCancel() // stop traffic monitor
		controllers.trafficCancel = nil
		zap.L().Info("Stopped traffic monitoring")
	}

	if cfg.SniffTraffic {
		ctx, cancel := context.WithCancel(rootCtx)
		controllers.trafficCancel = cancel

		// DON'T call wg.Add(1) here - this is for reloadable subsystems
		go func() {
			// DON'T call defer wg.Done() here
			zap.L().Info("Started traffic monitoring")
			var subsystemWg sync.WaitGroup // Use local WaitGroup
			subsystemWg.Add(1)
			traffic.MonitorAllInterfaces(ctx, cfg, wm, EvaluateAndAct, &subsystemWg)
			subsystemWg.Wait()
			zap.L().Info("Traffic monitoring goroutine exited")
		}()
	}

	// === SYSLOG ===
	if controllers.syslogCancel != nil {
		controllers.syslogCancel() // stop syslog
		controllers.syslogCancel = nil
		zap.L().Info("Stopped syslog server")
	}

	if cfg.RunSyslog {
		ctx, cancel := context.WithCancel(context.Background())
		controllers.syslogCancel = cancel

		// DON'T call wg.Add(1) here either
		go func() {
			// DON'T call defer wg.Done() here
			zap.L().Info("Started syslog server")
			var subsystemWg sync.WaitGroup // Use local WaitGroup
			subsystemWg.Add(1)
			syslog.StartSyslogServer(ctx, cfg, wm, EvaluateAndAct, &subsystemWg)
			subsystemWg.Wait()
			zap.L().Info("Syslog server goroutine exited")
		}()
	}

	zap.L().Info("Subsystem reload complete")
}

func SyncSensorConfig(rootCtx context.Context, cfg *config.Config, whitelistManager *whitelist.WhitelistManager, wg *sync.WaitGroup) error {
	client := utils.NewAPIClient(cfg)

	resp, err := client.DoRequest(utils.RequestOptions{
		Endpoint: "/sync",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var response types.SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		zap.L().Error("Failed to decode alert threshold response", zap.Error(err))
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if cfg.SniffTraffic != response.SniffTraffic || cfg.RunSyslog != response.RunSyslog {
		cfg.SniffTraffic = response.SniffTraffic
		cfg.RunSyslog = response.RunSyslog
		ReloadSubsystems(rootCtx, cfg, whitelistManager, wg) // Pass wg but don't use it
	}

	// Update alert threshold
	cfg.AlertThreshold = response.AlertThreshold

	zap.L().Info("Stored alert threshold", zap.Int("threshold", int(cfg.AlertThreshold)))
	return nil
}
