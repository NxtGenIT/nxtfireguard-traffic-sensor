package arbiter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

var RecommendCache *lru.Cache[string, struct{}]

func InitRecommendCache(maxEntries int) error {
	cache, err := lru.New[string, struct{}](maxEntries)
	if err != nil {
		zap.L().Error("Failed to create LRU cache for recommendations",
			zap.Int("maxEntries", maxEntries),
			zap.Error(err),
		)
		return fmt.Errorf("failed to create LRU cache for recommendations %w", err)
	}
	zap.L().Info("Initialized recommendations cache",
		zap.Int("maxEntries", maxEntries),
	)
	RecommendCache = cache
	return nil
}

func generateCacheKey(ip string, decisions []types.Decision) string {
	sort.Slice(decisions, func(i, j int) bool {
		return decisions[i].Reason+decisions[i].Blocklist < decisions[j].Reason+decisions[j].Blocklist
	})

	// Serialize decisions to JSON or hash for compactness
	decisionsJSON, _ := json.Marshal(decisions)
	decisionsHash := sha256.Sum256(decisionsJSON)
	hashStr := hex.EncodeToString(decisionsHash[:8]) // first 8 bytes for brevity

	return fmt.Sprintf("ip:%s:decisions:%s", ip, hashStr)
}

func removeRecommendCacheEntriesByIP(ip string) {
	prefix := fmt.Sprintf("ip:%s:", ip)
	for _, key := range RecommendCache.Keys() {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			RecommendCache.Remove(key)
		}
	}
}
