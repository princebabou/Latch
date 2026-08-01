package enforcementapi

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplayCacheRejectsDuplicatesAndExpiresClaims(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	cache := newReplayCache(time.Minute, 2, func() time.Time { return now })
	if cache.claim("first") != claimAccepted || cache.claim("first") != claimDuplicate {
		t.Fatal("duplicate claim was not rejected")
	}
	if cache.claim("second") != claimAccepted || cache.claim("third") != claimCapacity {
		t.Fatal("bounded cache did not fail closed")
	}
	now = now.Add(time.Minute)
	if cache.claim("third") != claimAccepted {
		t.Fatal("expired entries were not pruned")
	}
}

func TestReplayCacheAllowsOnlyOneConcurrentClaim(t *testing.T) {
	cache := newReplayCache(time.Minute, 100, time.Now)
	var accepted atomic.Int32
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if cache.claim("same-request") == claimAccepted {
				accepted.Add(1)
			}
		}()
	}
	group.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d concurrent claims, want 1", accepted.Load())
	}
}
