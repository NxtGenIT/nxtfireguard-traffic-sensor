package sqlite

import (
	"database/sql"
	"fmt"
	"math"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

type cachedScore struct {
	score     int32
	updatedAt time.Time
	cachedAt  time.Time
}

const cacheTTL = 5 * time.Minute

// Decay configuration
const (
	decayHalfLife      = 72 * time.Hour
	minDecayMultiplier = 0.3
)

var ScoreCache *lru.Cache[string, cachedScore]

func InitCache(maxEntries int) error {
	cache, err := lru.New[string, cachedScore](maxEntries)
	if err != nil {
		zap.L().Error("Failed to create LRU cache",
			zap.Int("maxEntries", maxEntries),
			zap.Error(err),
		)
		return fmt.Errorf("failed to create LRU cache %w", err)
	}

	zap.L().Info("Initialized score cache",
		zap.Int("maxEntries", maxEntries),
		zap.Duration("cacheTTL", cacheTTL),
		zap.Duration("decayHalfLife", decayHalfLife),
	)

	ScoreCache = cache
	return nil
}

// calculateDecayMultiplier applies exponential decay based on time since last update
func calculateDecayMultiplier(updatedAt time.Time) float64 {
	hoursOld := time.Since(updatedAt).Hours()

	// Exponential decay: multiplier = 0.5^(hours/halfLife)
	decay := math.Pow(0.5, hoursOld/decayHalfLife.Hours())

	// Apply minimum multiplier floor
	if decay < minDecayMultiplier {
		decay = minDecayMultiplier
	}

	return decay
}

// applyDecay applies time-based decay to the score
func applyDecay(originalScore int32, updatedAt time.Time) int32 {
	if originalScore == 0 {
		return 0
	}

	multiplier := calculateDecayMultiplier(updatedAt)
	decayedScore := float64(originalScore) * multiplier

	// Round to nearest integer
	result := int32(math.Round(decayedScore))

	zap.L().Debug("Applied time-based decay to score",
		zap.Int32("originalScore", originalScore),
		zap.Time("updatedAt", updatedAt),
		zap.Float64("decayMultiplier", multiplier),
		zap.Int32("decayedScore", result),
		zap.Duration("age", time.Since(updatedAt)),
	)

	return result
}

func Lookup(ip string) (*int32, error) {
	if ScoreCache == nil {
		zap.L().Error("Score cache not initialized",
			zap.String("ip", ip),
		)
		return nil, fmt.Errorf("score cache not initialized")
	}

	// Check cache
	if entry, ok := ScoreCache.Get(ip); ok {
		if time.Since(entry.cachedAt) < cacheTTL {
			// Apply decay to cached score
			decayedScore := applyDecay(entry.score, entry.updatedAt)

			zap.L().Debug("Score retrieved from cache",
				zap.String("ip", ip),
				zap.Int32("originalScore", entry.score),
				zap.Int32("decayedScore", decayedScore),
				zap.Time("updatedAt", entry.updatedAt),
				zap.Time("cachedAt", entry.cachedAt),
			)

			return &decayedScore, nil
		}

		zap.L().Debug("Cache entry expired, falling back to DB",
			zap.String("ip", ip),
			zap.Time("cachedAt", entry.cachedAt),
		)
	}

	// Cache miss, fetch from DB
	record, err := DBLookup(ip)
	if err != nil {
		if err == sql.ErrNoRows {
			zap.L().Debug("No score found in DB for IP, returning 0",
				zap.String("ip", ip),
			)
			defaultScore := int32(0)
			return &defaultScore, nil
		}

		zap.L().Error("Failed to lookup score from DB",
			zap.String("ip", ip),
			zap.Error(err),
		)
		return nil, err
	}

	// Store in cache with original score and updated_at timestamp
	ScoreCache.Add(ip, cachedScore{
		score:     record.NFGScore,
		updatedAt: record.UpdatedAt,
		cachedAt:  time.Now(),
	})

	zap.L().Debug("Score stored in cache",
		zap.String("ip", ip),
		zap.Int32("score", record.NFGScore),
		zap.Time("updatedAt", record.UpdatedAt),
	)

	// Apply decay before returning
	decayedScore := applyDecay(record.NFGScore, record.UpdatedAt)

	return &decayedScore, nil
}

func DBLookup(ip string) (types.ScoreDBRecord, error) {
	var record types.ScoreDBRecord
	db := GetDB()

	query := "SELECT ip, score, updated_at FROM ip_scores WHERE ip = ?"
	row := db.QueryRow(query, ip)

	err := row.Scan(&record.IP, &record.NFGScore, &record.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			zap.L().Debug("No score found in DB for IP",
				zap.String("ip", ip),
			)
			return types.ScoreDBRecord{}, err
		}

		zap.L().Error("Failed to scan DB row for IP score",
			zap.String("ip", ip),
			zap.Error(err),
		)
		return types.ScoreDBRecord{}, err
	}

	zap.L().Debug("Score retrieved from DB",
		zap.String("ip", ip),
		zap.Int32("score", record.NFGScore),
		zap.Time("updatedAt", record.UpdatedAt),
		zap.Duration("age", time.Since(record.UpdatedAt)),
	)

	return record, nil
}
