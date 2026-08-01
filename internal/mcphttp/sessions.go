package mcphttp

import (
	"sync"
	"time"

	"github.com/princebabou/Latch/internal/mcpadapter"
)

type sessionEntry struct {
	session  *mcpadapter.Session
	lastSeen time.Time
}

type sessionCache struct {
	mu      sync.Mutex
	entries map[string]sessionEntry
	limit   int
	ttl     time.Duration
	now     func() time.Time
}

func newSessionCache(limit int, ttl time.Duration, now func() time.Time) *sessionCache {
	if now == nil {
		now = time.Now
	}
	return &sessionCache{entries: make(map[string]sessionEntry), limit: limit, ttl: ttl, now: now}
}

func (c *sessionCache) get(id string) (*mcpadapter.Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	entry, exists := c.entries[id]
	if !exists {
		return nil, false
	}
	if now.Sub(entry.lastSeen) > c.ttl {
		delete(c.entries, id)
		return nil, false
	}
	entry.lastSeen = now
	c.entries[id] = entry
	return entry.session, true
}

func (c *sessionCache) put(id string, session *mcpadapter.Session) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if existing, exists := c.entries[id]; exists {
		return existing.session == session
	}
	if len(c.entries) >= c.limit {
		c.prune(now)
	}
	if len(c.entries) >= c.limit {
		var oldestID string
		var oldest time.Time
		for candidate, entry := range c.entries {
			if oldestID == "" || entry.lastSeen.Before(oldest) {
				oldestID, oldest = candidate, entry.lastSeen
			}
		}
		delete(c.entries, oldestID)
	}
	c.entries[id] = sessionEntry{session: session, lastSeen: now}
	return true
}

func (c *sessionCache) remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, id)
}

func (c *sessionCache) prune(now time.Time) {
	cutoff := now.Add(-c.ttl)
	for id, entry := range c.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(c.entries, id)
		}
	}
}
