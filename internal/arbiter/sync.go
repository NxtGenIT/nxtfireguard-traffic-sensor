package arbiter

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sqlite"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
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
