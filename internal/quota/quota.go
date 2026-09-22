package quota

import (
	"sync"
	"time"

	"gatekey/internal/apierror"
	"gatekey/internal/config"
	"gatekey/internal/logging"
)

// TokenUsage holds the cumulative token and dollar consumption for a specific client token on a route.
type TokenUsage struct {
	PromptTokens     uint64  `json:"prompt_tokens"`
	CompletionTokens uint64  `json:"completion_tokens"`
	TotalTokens      uint64  `json:"total_tokens"`
	TotalCostUSD     float64 `json:"total_cost_usd"`

	// Period stamps the accounting window these counters belong to. A counter
	// whose period is not the current one is simply read as zero, which resets
	// budgets without a timer, without a goroutine and without walking the map:
	// the check costs one string comparison under a lock already held. Because the
	// period is persisted, a server that was down for a month comes back up and
	// sees the stale window immediately. Empty means the counters never reset.
	Period string `json:"period,omitempty"`
}

// Period identifies the accounting window containing now, in UTC so a budget does
// not reset twice a year with daylight saving.
//
// The returned value carries its own granularity, which is what later lets stale
// entries be recognised without knowing which route wrote them.
func Period(reset string, now time.Time) string {
	switch reset {
	case config.QuotaResetDaily:
		return now.UTC().Format(dailyLayout)
	case config.QuotaResetMonthly:
		return now.UTC().Format(monthlyLayout)
	default:
		return ""
	}
}

const (
	monthlyLayout = "2006-01"
	dailyLayout   = "2006-01-02"
)

// isStale reports whether a stored period has been superseded. The stored string
// is self-describing -- "2006-01" monthly, "2006-01-02" daily, empty for a
// counter that never resets -- so the pruner needs no per-route configuration.
func isStale(period string, now time.Time) bool {
	switch len(period) {
	case len(monthlyLayout):
		return period != now.UTC().Format(monthlyLayout)
	case len(dailyLayout):
		return period != now.UTC().Format(dailyLayout)
	default:
		return false
	}
}

// Manager tracks and enforces token and budget quotas per client token with atomic disk persistence.
type Manager struct {
	mu       sync.RWMutex
	filePath string
	stopChan chan struct{}
	wg       sync.WaitGroup
	usages   map[string]*TokenUsage // key: routePrefix + ":" + clientToken

	// dirty holds the keys Record touched since the last flush. A flush writes
	// those and nothing else, so its cost follows traffic, not install count.
	dirty map[string]struct{}

	// saveMu serializes flushes and compactions, and guards journal and
	// retryCompact. Neither is ever taken on the request path.
	saveMu       sync.Mutex
	journal      *journal
	retryCompact bool // the last compaction failed and is due again
}

// NewManager creates a new Quota Manager, loads saved state, and starts the periodic flusher.
func NewManager(filePath string, flushInterval time.Duration) *Manager {
	if filePath == "" {
		filePath = "quotas.json"
	}
	if flushInterval <= 0 {
		flushInterval = 60 * time.Second
	}

	m := &Manager{
		filePath: filePath,
		stopChan: make(chan struct{}),
		dirty:    make(map[string]struct{}),
		journal:  newJournal(filePath),
	}
	m.usages = m.journal.load()

	m.wg.Add(1)
	go m.flusherLoop(flushInterval)

	return m
}

func makeKey(routePrefix, clientToken string) string {
	return routePrefix + ":" + clientToken
}

// totalKey names the counter shared by every install of a route. Route prefixes
// always start with '/', so no per-install key can ever take this form.
func totalKey(routePrefix string) string {
	return "*" + routePrefix
}

// Check verifies whether the client token has exceeded its max_tokens or max_budget_usd limits,
// and whether the route as a whole has exceeded its total limits.
//
// Enforcement is deliberately soft: an LLM only reports its token usage once the
// response has been produced, so Check can only see what previous requests already
// consumed. Requests issued concurrently near the limit all pass, and the cap can
// therefore be overshot by roughly one batch of in-flight requests. Size the limit
// as a circuit breaker, not as an exact spending cap. This matters most for the
// total limits, where the batch is every install's in-flight requests together.
//
// The returned usage is always the install's own: the total describes the
// operator's spending and is not the caller's to see.
func (m *Manager) Check(routePrefix, clientToken string, q config.QuotaConfig) (bool, TokenUsage, *apierror.APIError) {
	// If no quotas are configured for this route, allow immediately
	if !q.Enabled() {
		return true, TokenUsage{}, nil
	}

	m.mu.RLock()
	usage := m.read(makeKey(routePrefix, clientToken))
	total := m.read(totalKey(routePrefix))
	m.mu.RUnlock()

	// A counter carried over from a previous window has already lapsed. Reading it
	// as zero is what resets the budget, and it happens lazily on the first request
	// of the new window rather than on a schedule.
	period := Period(q.Reset, time.Now())
	if usage.Period != period {
		usage = TokenUsage{Period: period}
	}
	if total.Period != period {
		total = TokenUsage{Period: period}
	}

	// 1. Check token count limit
	if q.MaxTokens > 0 && usage.TotalTokens >= q.MaxTokens {
		err := apierror.NewTokenQuotaExceeded(q.MaxTokens, usage.TotalTokens)
		return false, usage, &err
	}

	// 2. Check dollar budget limit
	if q.MaxBudgetUSD > 0 && usage.TotalCostUSD >= q.MaxBudgetUSD {
		err := apierror.NewBudgetQuotaExceeded(q.MaxBudgetUSD, usage.TotalCostUSD)
		return false, usage, &err
	}

	// 3. Check the route's total limits
	if (q.TotalMaxTokens > 0 && total.TotalTokens >= q.TotalMaxTokens) ||
		(q.TotalBudgetUSD > 0 && total.TotalCostUSD >= q.TotalBudgetUSD) {
		err := apierror.NewTotalQuotaExceeded()
		return false, usage, &err
	}

	return true, usage, nil
}

// read returns a copy of a counter, or a zero one. The caller holds m.mu.
func (m *Manager) read(key string) TokenUsage {
	if u, ok := m.usages[key]; ok {
		return *u
	}
	return TokenUsage{}
}

// Record updates the token usage and estimated dollar cost for a client token.
//
// model selects the price when the route prices models individually; an empty or
// unknown name falls back to the route default.
func (m *Manager) Record(routePrefix, clientToken, model string, promptTokens, completionTokens uint64, q config.QuotaConfig) TokenUsage {
	pricing := q.PricingFor(model)
	totalTokens := promptTokens + completionTokens
	if totalTokens == 0 {
		return TokenUsage{}
	}

	// Default to gpt-4o-mini baseline if pricing is zero
	promptPrice := pricing.PromptUSD
	if promptPrice <= 0 {
		promptPrice = 0.15 // $0.15 per 1M prompt tokens
	}
	compPrice := pricing.CompletionUSD
	if compPrice <= 0 {
		compPrice = 0.60 // $0.60 per 1M completion tokens
	}

	cost := (float64(promptTokens) / 1000000.0 * promptPrice) + (float64(completionTokens) / 1000000.0 * compPrice)

	period := Period(q.Reset, time.Now())

	m.mu.Lock()
	defer m.mu.Unlock()

	// The route total is kept whether or not a total limit is set, so that a limit
	// added later starts from what the route has really spent this window.
	m.add(totalKey(routePrefix), period, promptTokens, completionTokens, cost)
	return m.add(makeKey(routePrefix, clientToken), period, promptTokens, completionTokens, cost)
}

// add charges one call to a counter. The caller holds m.mu for writing.
func (m *Manager) add(key, period string, promptTokens, completionTokens uint64, cost float64) TokenUsage {
	// A missing entry and one left over from a past window are the same thing: a
	// fresh counter for the current window.
	current, exists := m.usages[key]
	if !exists || current.Period != period {
		current = &TokenUsage{Period: period}
		m.usages[key] = current
	}

	current.PromptTokens += promptTokens
	current.CompletionTokens += completionTokens
	current.TotalTokens += promptTokens + completionTokens
	current.TotalCostUSD += cost
	m.dirty[key] = struct{}{}

	return *current
}

// GetTotalUsage retrieves the usage of a route across every install.
func (m *Manager) GetTotalUsage(routePrefix string) TokenUsage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.read(totalKey(routePrefix))
}

// GetUsage retrieves current usage for a token.
func (m *Manager) GetUsage(routePrefix, clientToken string) TokenUsage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.read(makeKey(routePrefix, clientToken))
}

func (m *Manager) flusherLoop(interval time.Duration) {
	defer m.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			m.flush()
			// A clean shutdown leaves a single compact file and no log: the next
			// start reads one file, and lapsed counters are pruned on the way out.
			m.compact()
			return
		case <-ticker.C:
			m.flush()
			m.saveMu.Lock()
			due := m.retryCompact || m.journal.needsCompaction(time.Now())
			m.saveMu.Unlock()
			if due {
				m.compact()
			}
		}
	}
}

// flush appends the counters that changed since the last flush.
//
// The lock is held only to copy those counters out. Encoding and disk I/O happen
// after it is released: the previous version marshalled the whole map under the
// write lock, which stalled every request for about 50 ms every flush at 10,000
// installs and about 300 ms at 100,000.
func (m *Manager) flush() {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()

	m.mu.Lock()
	if len(m.dirty) == 0 {
		m.mu.Unlock()
		return
	}
	lines := make([]logLine, 0, len(m.dirty))
	for key := range m.dirty {
		if u, ok := m.usages[key]; ok {
			lines = append(lines, logLine{Key: key, Usage: *u})
		}
	}
	clear(m.dirty)
	m.mu.Unlock()
	if len(lines) == 0 {
		return
	}

	if err := m.journal.append(lines); err != nil {
		logging.Warn("quota: could not append to the journal, will retry", "path", m.journal.logPath, "error", err)
		// Re-arm the keys so the next tick writes them again. Values are full
		// states, not deltas, so a line that did land before the error is only
		// written twice, never counted twice.
		m.mu.Lock()
		for i := range lines {
			m.dirty[lines[i].Key] = struct{}{}
		}
		m.mu.Unlock()
	}
}

// compact rewrites the snapshot from memory and discards the log, dropping
// counters whose window has lapsed. They already read as zero, so this loses
// nothing; it keeps the map from growing one dead entry per install per month.
//
// It runs only when the log has grown as large as the snapshot, or once a day.
// The walk over every counter happens under the read lock, so quota checks --
// the part of a request the client waits on -- carry on during it; only Record,
// which runs once a response is over, waits. Encoding and writing happen after.
func (m *Manager) compact() {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()

	// The snapshot will carry every pending change, so the pending set moves with
	// it: left in place, the next flush would append all of it again -- after a
	// long gap, every counter. It is taken before the copy, so the copy is at
	// least as recent as every change it takes over. A Record landing after this
	// point marks a fresh set and is flushed as usual.
	m.mu.Lock()
	pending := m.dirty
	m.dirty = make(map[string]struct{})
	m.mu.Unlock()

	now := time.Now()
	var stale []string
	m.mu.RLock()
	snap := make(map[string]TokenUsage, len(m.usages))
	for key, u := range m.usages {
		if isStale(u.Period, now) {
			stale = append(stale, key)
			continue
		}
		snap[key] = *u
	}
	m.mu.RUnlock()

	if err := m.journal.compact(snap, now); err != nil {
		logging.Warn("quota: could not compact the journal, will retry", "path", m.filePath, "error", err)
		// The changes did not reach the disk after all: hand them back.
		m.mu.Lock()
		for key := range pending {
			m.dirty[key] = struct{}{}
		}
		m.mu.Unlock()
		m.retryCompact = true
		return
	}
	m.retryCompact = false

	if len(stale) > 0 {
		m.mu.Lock()
		for _, key := range stale {
			// A Record since the copy has moved it into the current window.
			if u, ok := m.usages[key]; ok && isStale(u.Period, now) {
				delete(m.usages, key)
			}
		}
		m.mu.Unlock()
	}
}

// Close flushes data to disk and stops the periodic worker.
func (m *Manager) Close() {
	close(m.stopChan)
	m.wg.Wait()
}
