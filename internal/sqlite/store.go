package sqlite

import (
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"go.uber.org/zap"
)

func BulkUpsertIpScores(records []types.ScoreRecord) error {
	zap.L().Info("Starting bulk upsert of IP scores",
		zap.Int("recordCount", len(records)),
	)

	db := GetDB()

	tx, err := db.Begin()
	if err != nil {
		zap.L().Error("Failed to begin transaction for bulk upsert",
			zap.Int("recordCount", len(records)),
			zap.Error(err),
		)
		return err
	}

	stmt, err := tx.Prepare("INSERT OR REPLACE INTO ip_scores (updated_at, ip, score) VALUES (?, ?, ?)")
	if err != nil {
		zap.L().Error("Failed to prepare statement for bulk upsert",
			zap.Int("recordCount", len(records)),
			zap.Error(err),
		)
		return err
	}
	defer stmt.Close()

	for _, rec := range records {
		if _, err := stmt.Exec(rec.LastUpdated, rec.IP, rec.NFGScore); err != nil {
			zap.L().Error("Failed to execute statement for record",
				zap.Time("last_updated", rec.LastUpdated),
				zap.String("ip", rec.IP),
				zap.Int32("score", rec.NFGScore),
				zap.Error(err),
			)
			_ = tx.Rollback()
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		zap.L().Error("Failed to commit transaction for bulk upsert",
			zap.Int("recordCount", len(records)),
			zap.Error(err),
		)
		return err
	}

	zap.L().Info("Successfully bulk upserted IP scores",
		zap.Int("recordCount", len(records)),
	)
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
