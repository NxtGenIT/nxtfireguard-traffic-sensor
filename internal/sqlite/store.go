package sqlite

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"go.uber.org/zap"
)

func BulkUpsertIpScores(records []types.ScoreRecord) error {
	if len(records) == 0 {
		return nil
	}

	const maxSQLiteParams = 999                       // SQLite's SQLITE_MAX_VARIABLE_NUMBER
	const paramsPerRecord = 3                         // updated_at, ip, score
	maxBatchSize := maxSQLiteParams / paramsPerRecord // 333 records per statement

	db := GetDB()

	// Process in SQLite-friendly batches
	for i := 0; i < len(records); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(records) {
			end = len(records)
		}

		batch := records[i:end]
		if err := upsertBatch(db, batch); err != nil {
			return fmt.Errorf("failed to upsert batch: %w", err)
		}
	}

	return nil
}

func upsertBatch(db *sql.DB, batch []types.ScoreRecord) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Build multi-value INSERT
	placeholders := make([]string, len(batch))
	args := make([]interface{}, 0, len(batch)*3)

	for i, rec := range batch {
		placeholders[i] = "(?, ?, ?)"
		args = append(args, rec.LastUpdated, rec.IP, rec.NFGScore)
	}

	query := fmt.Sprintf(
		"INSERT OR REPLACE INTO ip_scores (updated_at, ip, score) VALUES %s",
		strings.Join(placeholders, ", "),
	)

	if _, err := tx.Exec(query, args...); err != nil {
		return fmt.Errorf("failed to execute batch insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func UpsertIpScore(record types.ScoreRecord) error {
	zap.L().Info("Starting IP score upsert")

	db := GetDB()

	tx, err := db.Begin()
	if err != nil {
		zap.L().Error("Failed to begin transaction for upsert",
			zap.Error(err),
		)
		return err
	}

	stmt, err := tx.Prepare("INSERT OR REPLACE INTO ip_scores (updated_at, ip, score) VALUES (?, ?, ?)")
	if err != nil {
		zap.L().Error("Failed to prepare statement for upsert",
			zap.Error(err),
		)
		return err
	}
	defer stmt.Close()

	if _, err := stmt.Exec(record.LastUpdated, record.IP, record.NFGScore); err != nil {
		zap.L().Error("Failed to execute statement for record",
			zap.Time("last_updated", record.LastUpdated),
			zap.String("ip", record.IP),
			zap.Int32("score", record.NFGScore),
			zap.Error(err),
		)
		_ = tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		zap.L().Error("Failed to commit transaction for upsert",
			zap.Error(err),
		)
		return err
	}

	zap.L().Info("Successfully upserted IP score")
	return nil
}
