package traffic

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Tracks seen connections to avoid duplicate processing
type ConnectionTracker struct {
	connections map[string]time.Time
	mu          sync.RWMutex
	ttl         time.Duration
	cleanupDone chan struct{}
}

// Creates a new connection tracker with specified TTL
func NewConnectionTracker(ttl time.Duration) *ConnectionTracker {
	ct := &ConnectionTracker{
		connections: make(map[string]time.Time),
		ttl:         ttl,
		cleanupDone: make(chan struct{}),
	}
	return ct
}

// Star begins the cleanup goroutine
func (ct *ConnectionTracker) Start(ctx context.Context) {
	go ct.cleanup(ctx)
}

// connectionKey creates a normalized key for a connection
// Normalizes bidirectional connections to the same key
func (ct *ConnectionTracker) connectionKey(src, dst string, srcPort, dstPort uint16, protocol string) string {
	// Normalize so A->B and B->A are the same connection
	if src < dst || (src == dst && srcPort < dstPort) {
		return fmt.Sprintf("%s:%s:%d-%s:%d", protocol, src, srcPort, dst, dstPort)
	}
	return fmt.Sprintf("%s:%s:%d-%s:%d", protocol, dst, dstPort, src, srcPort)
}

// MarkSeen marks a connection as seen and returns true if it's new
func (ct *ConnectionTracker) MarkSeen(src, dst string, srcPort, dstPort uint16, protocol string) bool {
	key := ct.connectionKey(src, dst, srcPort, dstPort, protocol)

	ct.mu.Lock()
	defer ct.mu.Unlock()

	if _, exists := ct.connections[key]; exists {
		// Update timestamp for existing connection
		ct.connections[key] = time.Now()
		return false
	}

	// New connection
	ct.connections[key] = time.Now()
	return true
}

// cleanup periodically removes expired connections
func (ct *ConnectionTracker) cleanup(ctx context.Context) {
	ticker := time.NewTicker(ct.ttl / 2)
	defer ticker.Stop()
	defer close(ct.cleanupDone)

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("Connection tracker cleanup stopping")
			return
		case <-ticker.C:
			ct.mu.Lock()
			now := time.Now()
			expired := 0
			for key, timestamp := range ct.connections {
				if now.Sub(timestamp) > ct.ttl {
					delete(ct.connections, key)
					expired++
				}
			}
			if expired > 0 {
				zap.L().Debug("Cleaned up expired connections",
					zap.Int("expired", expired),
					zap.Int("remaining", len(ct.connections)))
			}
			ct.mu.Unlock()
		}
	}
}

// GetStats returns current tracker statistics
func (ct *ConnectionTracker) GetStats() (total int, ttl time.Duration) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.connections), ct.ttl
}

// Close waits for cleanup to finish
func (ct *ConnectionTracker) Close() {
	<-ct.cleanupDone
}
