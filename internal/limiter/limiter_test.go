package limiter

import (
	"testing"
	"time"
)

func TestLimiter_UnlimitedWhenZeroRPM(t *testing.T) {
	mgr := NewManager(1*time.Minute, 1*time.Minute)
	defer mgr.Close()

	for i := 0; i < 50; i++ {
		res := mgr.Allow("/test", "tok-1", 0, 0)
		if !res.Allowed {
			t.Fatalf("expected request %d to be allowed when rpm=0", i)
		}
	}
}

func TestLimiter_BurstAndRateEnforcement(t *testing.T) {
	mgr := NewManager(1*time.Minute, 1*time.Minute)
	defer mgr.Close()

	// 60 RPM with a burst of 3
	rpm := 60
	burst := 3

	// First 3 requests should pass (consuming the burst capacity)
	for i := 1; i <= burst; i++ {
		res := mgr.Allow("/api", "tok-alice", rpm, burst)
		if !res.Allowed {
			t.Fatalf("expected burst request %d to be allowed", i)
		}
		if res.Remaining != burst-i {
			t.Errorf("expected remaining %d, got %d", burst-i, res.Remaining)
		}
	}

	// 4th immediate request should be rejected
	res := mgr.Allow("/api", "tok-alice", rpm, burst)
	if res.Allowed {
		t.Fatalf("expected 4th request to be rejected by rate limiter")
	}
	if res.RetryAfter <= 0 {
		t.Errorf("expected RetryAfter > 0, got %v", res.RetryAfter)
	}

	// Wait 1.1 seconds (should refill ~1 token at 60 RPM = 1 token/sec)
	time.Sleep(1100 * time.Millisecond)

	resAfterWait := mgr.Allow("/api", "tok-alice", rpm, burst)
	if !resAfterWait.Allowed {
		t.Fatalf("expected request after wait to be allowed, got retryAfter: %v", resAfterWait.RetryAfter)
	}
}

func TestLimiter_ClientTokenIsolation(t *testing.T) {
	mgr := NewManager(1*time.Minute, 1*time.Minute)
	defer mgr.Close()

	// Token Alice consumes all 2 burst tokens
	mgr.Allow("/api", "alice", 60, 2)
	mgr.Allow("/api", "alice", 60, 2)

	// Alice is now rate limited
	aliceBlocked := mgr.Allow("/api", "alice", 60, 2)
	if aliceBlocked.Allowed {
		t.Fatalf("expected alice to be rate limited")
	}

	// Token Bob on the same route must NOT be affected!
	bobAllowed := mgr.Allow("/api", "bob", 60, 2)
	if !bobAllowed.Allowed {
		t.Fatalf("expected bob to be allowed independently of alice")
	}
}

func TestLimiter_PruneInactive(t *testing.T) {
	mgr := NewManager(10*time.Millisecond, 20*time.Millisecond)
	defer mgr.Close()

	mgr.Allow("/api", "old-client", 60, 5)

	mgr.mu.RLock()
	countBefore := len(mgr.buckets)
	mgr.mu.RUnlock()
	if countBefore != 1 {
		t.Fatalf("expected 1 bucket before wait, got %d", countBefore)
	}

	// Wait for TTL + cleanup ticker
	time.Sleep(50 * time.Millisecond)

	mgr.mu.RLock()
	countAfter := len(mgr.buckets)
	mgr.mu.RUnlock()
	if countAfter != 0 {
		t.Fatalf("expected inactive bucket to be pruned, got %d", countAfter)
	}
}
