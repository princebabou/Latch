package enforcementapi

import (
	"sync"
	"time"
)

// replayCache rejects duplicate idempotency keys. It is intentionally bounded;
// saturation fails closed rather than evicting a still-live request.
type replayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	window  time.Duration
	limit   int
	now     func() time.Time
}

type claimResult uint8

const (
	claimAccepted claimResult = iota
	claimDuplicate
	claimCapacity
)

func newReplayCache(window time.Duration, limit int, now func() time.Time) *replayCache {
	if now == nil {
		now = time.Now
	}
	return &replayCache{entries: make(map[string]time.Time), window: window, limit: limit, now: now}
}

func (cache *replayCache) claim(requestID string) claimResult {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.now()
	for id, expiresAt := range cache.entries {
		if !expiresAt.After(now) {
			delete(cache.entries, id)
		}
	}
	if _, exists := cache.entries[requestID]; exists {
		return claimDuplicate
	}
	if len(cache.entries) >= cache.limit {
		return claimCapacity
	}
	cache.entries[requestID] = now.Add(cache.window)
	return claimAccepted
}
