package arbiter

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sqlite"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/syslog"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/traffic"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/utils"
	"go.uber.org/zap"
)

const streamBatchSize = 10000

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

	// Use a channel to stream records for batch processing
	recordChan := make(chan types.ScoreRecord, streamBatchSize)
	errChan := make(chan error, 1)

	// Start background goroutine to batch insert records
	go func() {
		errChan <- batchInsertFromChannel(recordChan)
	}()

	totalRecords := 0

	// Stream through tar archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			close(recordChan)
			<-errChan // Wait for goroutine to finish
			zap.L().Error("Error reading from tar archive during sync", zap.Error(err))
			return fmt.Errorf("error reading tar archive: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue // skip non-regular files
		}

		// Stream JSON records from this file
		decoder := json.NewDecoder(tarReader)

		// Expect array of records
		// Read opening bracket
		if _, err := decoder.Token(); err != nil {
			close(recordChan)
			<-errChan
			zap.L().Error("Failed to read JSON array start",
				zap.String("filename", header.Name),
				zap.Error(err),
			)
			return fmt.Errorf("failed to read json array start in '%s': %w", header.Name, err)
		}

		// Stream individual records
		for decoder.More() {
			var record types.ScoreRecord
			if err := decoder.Decode(&record); err != nil {
				close(recordChan)
				<-errChan
				zap.L().Error("Failed to decode record",
					zap.String("filename", header.Name),
					zap.Error(err),
				)
				return fmt.Errorf("failed to decode record in '%s': %w", header.Name, err)
			}

			recordChan <- record
			totalRecords++

			// Log progress for large datasets
			if totalRecords%100000 == 0 {
				zap.L().Info("Sync progress",
					zap.Int("recordsProcessed", totalRecords),
				)
			}
		}

		// Read closing bracket
		if _, err := decoder.Token(); err != nil {
			close(recordChan)
			<-errChan
			zap.L().Error("Failed to read JSON array end",
				zap.String("filename", header.Name),
				zap.Error(err),
			)
			return fmt.Errorf("failed to read json array end in '%s': %w", header.Name, err)
		}
	}

	// Close channel to signal completion
	close(recordChan)

	// Wait for batch inserter to finish and check for errors
	if err := <-errChan; err != nil {
		zap.L().Error("Batch insert failed during sync",
			zap.Int("totalRecords", totalRecords),
			zap.Error(err),
		)
		return fmt.Errorf("batch insert failed: %w", err)
	}

	zap.L().Info("IP score sync completed successfully",
		zap.Int("totalRecords", totalRecords),
	)
	return nil
}

func batchInsertFromChannel(recordChan <-chan types.ScoreRecord) error {
	batch := make([]types.ScoreRecord, 0, streamBatchSize)
	totalProcessed := 0

	for record := range recordChan {
		batch = append(batch, record)

		// When batch is full, insert it
		if len(batch) >= streamBatchSize {
			if err := sqlite.BulkUpsertIpScores(batch); err != nil {
				return err
			}
			totalProcessed += len(batch)
			zap.L().Debug("Processed batch",
				zap.Int("batchSize", len(batch)),
				zap.Int("totalProcessed", totalProcessed),
			)
			batch = batch[:0] // Reset batch keeping capacity
		}
	}

	// Insert remaining records
	if len(batch) > 0 {
		if err := sqlite.BulkUpsertIpScores(batch); err != nil {
			return err
		}
		totalProcessed += len(batch)
	}

	zap.L().Info("Batch insertion completed",
		zap.Int("totalProcessed", totalProcessed),
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
