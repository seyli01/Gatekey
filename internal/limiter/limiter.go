package limiter

import (
	"math"
	"sync"
	"time"
)

// Result contains the verdict and telemetry headers for a rate limit check.
type Result struct {
	Allowed    bool
	RetryAfter time.Duration
	Limit      int
	Remaining  int
}

// bucket implements a thread-safe, zero-allocation Token Bucket algorithm.
type bucket struct {
	mu         sync.Mutex
	rate       float64   // tokens added per second
	capacity   float64   // maximum burst capacity
	tokens     float64   // current available tokens
	lastRefill time.Time // time of last token calculation
	lastAccess time.Time // time of last request check
}

func newBucket(rate float64, capacity float64) *bucket {
	now := time.Now()
	return &bucket{
		rate:       rate,
		capacity:   capacity,
		tokens:     capacity, // start full
		lastRefill: now,
		lastAccess: now,
	}
}

func (b *bucket) take() (bool, time.Duration, int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.lastAccess = now

	// Calculate refilled tokens based on time elapsed
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now

	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true, 0, int(b.tokens)
	}

	// Calculate wait time until at least 1 token is available
	missing := 1.0 - b.tokens
	secondsNeeded := missing / b.rate
	retryAfter := time.Duration(math.Ceil(secondsNeeded)) * time.Second
	if retryAfter < 1*time.Second {
		retryAfter = 1 * time.Second
	}

	return false, retryAfter, 0
}

type limiterKey struct {
	routePrefix string
	clientToken string
}

// Manager manages independent rate-limiting buckets per route and client token.
type Manager struct {
	mu       sync.RWMutex
	buckets  map[limiterKey]*bucket
	stopChan chan struct{}
}

// NewManager creates a new rate limiter manager with automatic inactive bucket pruning.
func NewManager(cleanupInterval, ttl time.Duration) *Manager {
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Minute
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	m := &Manager{
		buckets:  make(map[limiterKey]*bucket),
		stopChan: make(chan struct{}),
	}

	go m.cleanupLoop(cleanupInterval, ttl)
	return m
}

// Allow evaluates if a request from clientToken on routePrefix is allowed under rpm (req/min) and burst limits.
func (m *Manager) Allow(routePrefix, clientToken string, rpm int, burst int) Result {
	if rpm <= 0 {
		return Result{Allowed: true, Limit: 0, Remaining: -1}
	}

	if burst <= 0 {
		burst = int(math.Max(1, float64(rpm)/6.0))
	}

	ratePerSec := float64(rpm) / 60.0
	capFloat := float64(burst)

	key := limiterKey{routePrefix: routePrefix, clientToken: clientToken}

	m.mu.RLock()
	b, exists := m.buckets[key]
	m.mu.RUnlock()

	if !exists {
		m.mu.Lock()
		b, exists = m.buckets[key]
		if !exists {
			b = newBucket(ratePerSec, capFloat)
			m.buckets[key] = b
		}
		m.mu.Unlock()
	} else {
		// Update configuration dynamically if it changed on reload
		b.mu.Lock()
		b.rate = ratePerSec
		b.capacity = capFloat
		b.mu.Unlock()
	}

	allowed, retryAfter, remaining := b.take()
	return Result{
		Allowed:    allowed,
		RetryAfter: retryAfter,
		Limit:      rpm,
		Remaining:  remaining,
	}
}

func (m *Manager) cleanupLoop(interval, ttl time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case now := <-ticker.C:
			m.pruneInactive(now, ttl)
		}
	}
}

func (m *Manager) pruneInactive(now time.Time, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := now.Add(-ttl)
	for k, b := range m.buckets {
		b.mu.Lock()
		last := b.lastAccess
		b.mu.Unlock()

		if last.Before(cutoff) {
			delete(m.buckets, k)
		}
	}
}

// Close gracefully terminates the background cleaner goroutine.
func (m *Manager) Close() {
	close(m.stopChan)
}
