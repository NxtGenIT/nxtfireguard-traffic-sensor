package sqlite

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

type cachedScore struct {
	score    int32
	cachedAt time.Time
}

const cacheTTL = 5 * time.Minute

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
	)
	ScoreCache = cache
	return nil
}

func Lookup(ip string) (*int32, error) {
	// dev return 90 for dev
	if strings.HasPrefix(ip, "172.22") {
		var score *int32 = new(int32)
		*score = 90
		return score, nil
	}

	if ScoreCache == nil {
		zap.L().Error("Score cache not initialized",
			zap.String("ip", ip),
		)
		return nil, fmt.Errorf("cache initialized init")
	}

	if entry, ok := ScoreCache.Get(ip); ok {
		if time.Since(entry.cachedAt) < cacheTTL {
			zap.L().Debug("Score retrieved from cache",
				zap.String("ip", ip),
				zap.Int32("score", entry.score),
				zap.Time("cachedAt", entry.cachedAt),
			)
			return &entry.score, nil
		}
		zap.L().Debug("Cache entry expired, falling back to DB",
			zap.String("ip", ip),
			zap.Time("cachedAt", entry.cachedAt),
		)
		// cache miss, fall through to DB
	}

	score, err := DBLookup(ip)
	if err != nil {
		zap.L().Error("Failed to lookup score from DB",
			zap.String("ip", ip),
			zap.Error(err),
		)
		return nil, err
	}

	// Store in cache
	if score != nil {
		ScoreCache.Add(ip, cachedScore{score: *score, cachedAt: time.Now()})
		zap.L().Debug("Score stored in cache",
			zap.String("ip", ip),
			zap.Int32("score", *score),
		)
	}

	return score, nil
}

func DBLookup(ip string) (*int32, error) {
	var score int32
	db := GetDB()

	query := "SELECT score FROM ip_scores WHERE ip = ?"
	row := db.QueryRow(query, ip)
	err := row.Scan(&score)
	if err != nil {
		// If no record is found, return 0
		if err == sql.ErrNoRows {
			zero := int32(0)
			return &zero, nil
		}
		// For other errors, log and return error
		zap.L().Error("Failed to scan DB row for IP score",
			zap.String("ip", ip),
			zap.Error(err),
		)
		return nil, err
	}

	zap.L().Debug("Score retrieved from DB",
		zap.String("ip", ip),
		zap.Int32("score", score),
	)
	return &score, nil
}
