package metrics

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Event represents a completed HTTP request's telemetry data.
type Event struct {
	Timestamp   time.Time
	RoutePrefix string
	InstallID   string // empty for a caller that never authenticated
	StatusCode  int
	Duration    time.Duration
	BytesSent   int64
}

// InstallStats aggregates metrics for one installation.
//
// Keyed by install ID in the clear. These used to be client tokens -- secrets --
// and were masked to their first three and last four characters; install IDs are
// not secrets, and that masking merged every pair of installs sharing those seven
// characters into one line of statistics.
type InstallStats struct {
	InstallID    string        `json:"install_id"`
	TotalCalls   uint64        `json:"total_calls"`
	SuccessCalls uint64        `json:"success_calls"`
	ErrorCalls   uint64        `json:"error_calls"`
	TotalLatency time.Duration `json:"-"`
	AvgLatencyMs float64       `json:"avg_latency_ms"`
	TotalBytes   int64         `json:"total_bytes"`
	LastSeen     time.Time     `json:"last_seen"`
}

// RouteStats aggregates metrics for a specific routing prefix.
type RouteStats struct {
	RoutePrefix  string        `json:"route_prefix"`
	TotalCalls   uint64        `json:"total_calls"`
	SuccessCalls uint64        `json:"success_calls"`
	ErrorCalls   uint64        `json:"error_calls"`
	TotalLatency time.Duration `json:"-"`
	AvgLatencyMs float64       `json:"avg_latency_ms"`
	TotalBytes   int64         `json:"total_bytes"`
}

// TimeBucket represents time-series telemetry for generating graphs and historical trends.
type TimeBucket struct {
	Timestamp    time.Time `json:"timestamp"`
	TotalCalls   uint64    `json:"total_calls"`
	Errors       uint64    `json:"errors"`
	AvgLatencyMs float64   `json:"avg_latency_ms"`
}

// GlobalSummary provides high-level system-wide health and throughput figures.
type GlobalSummary struct {
	TotalCalls   uint64  `json:"total_calls"`
	SuccessCalls uint64  `json:"success_calls"`
	ClientErrors uint64  `json:"client_errors_4xx"`
	ServerErrors uint64  `json:"server_errors_5xx"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	TotalBytes   int64   `json:"total_bytes"`
	Uptime       string  `json:"uptime"`
}

// Report is the top-level structured metrics payload returned by GET /metrics and saved to disk.
//
// History comes at three resolutions, each oldest first. The older the data, the
// coarser it is kept: a month of per-minute points would be 43,200 of them to
// draw a line a graph shows as a few hundred pixels. The three together stay
// under about 250 KB whatever the traffic, and never grow.
type Report struct {
	GeneratedAt   time.Time                `json:"generated_at"`
	Global        GlobalSummary            `json:"global"`
	Routes        map[string]*RouteStats   `json:"routes"`
	Installs      map[string]*InstallStats `json:"installs"`
	History       []TimeBucket             `json:"history"`        // per minute, last 24 hours
	HourlyHistory []TimeBucket             `json:"history_hourly"` // per hour, last 30 days
	DailyHistory  []TimeBucket             `json:"history_daily"`  // per day, last 365 days
}

// installRetention drops installs unseen for a month: the map otherwise kept
// one line per installation ever seen, including those long uninstalled.
const installRetention = 30 * 24 * time.Hour

// series is one resolution of the call history: fixed-width time buckets, kept
// for a fixed span. Every event is counted into all three series directly, so
// no series is derived from another and none can drift from the rest.
type series struct {
	step    time.Duration
	keep    time.Duration
	buckets map[int64]*timeBucketAgg // key: bucket start, as Unix seconds
}

func newSeries(step, keep time.Duration) *series {
	return &series{step: step, keep: keep, buckets: make(map[int64]*timeBucketAgg)}
}

// Buckets start on UTC boundaries: Truncate works on absolute time, so a day
// bucket begins at 00:00 UTC whatever the server's time zone.
func (s *series) add(ev Event, isSuccess bool) {
	start := ev.Timestamp.Truncate(s.step)
	b, ok := s.buckets[start.Unix()]
	if !ok {
		b = &timeBucketAgg{timestamp: start.UTC()}
		s.buckets[start.Unix()] = b
	}
	b.totalCalls++
	b.totalLatency += ev.Duration
	if !isSuccess {
		b.errors++
	}
}

// prune drops buckets older than the series keeps, and reports whether it did.
func (s *series) prune(now time.Time) bool {
	pruned := false
	for key, b := range s.buckets {
		if now.Sub(b.timestamp) > s.keep {
			delete(s.buckets, key)
			pruned = true
		}
	}
	return pruned
}

// list returns the buckets in time order: map order is random, and a graph
// needs time order.
func (s *series) list() []TimeBucket {
	out := make([]TimeBucket, 0, len(s.buckets))
	for _, b := range s.buckets {
		out = append(out, TimeBucket{
			Timestamp:    b.timestamp,
			TotalCalls:   b.totalCalls,
			Errors:       b.errors,
			AvgLatencyMs: avgMs(b.totalLatency, b.totalCalls),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out
}

// load restores buckets saved by list. History used to be written and never
// read back, so every restart emptied the graph.
func (s *series) load(saved []TimeBucket) {
	for _, b := range saved {
		ts := b.Timestamp.UTC()
		s.buckets[ts.Unix()] = &timeBucketAgg{
			timestamp:    ts,
			totalCalls:   b.TotalCalls,
			errors:       b.Errors,
			totalLatency: latencyFrom(b.AvgLatencyMs, b.TotalCalls),
		}
	}
}

// Collector manages asynchronous, non-blocking telemetry aggregation and periodic disk persistence.
type Collector struct {
	mu           sync.RWMutex
	wg           sync.WaitGroup
	eventsChan   chan Event
	filePath     string
	startedAt    time.Time
	stopChan     chan struct{}
	global       GlobalSummary
	routes       map[string]*RouteStats
	installs     map[string]*InstallStats
	minutely     *series
	hourly       *series
	daily        *series
	totalLatency time.Duration

	// changed records whether anything happened since the last write. An idle
	// server then writes nothing at all, instead of rewriting the same file
	// every minute for as long as it runs.
	changed bool
}

type timeBucketAgg struct {
	timestamp    time.Time
	totalCalls   uint64
	errors       uint64
	totalLatency time.Duration
}

// NewCollector constructs a new metrics collector and starts the background aggregation worker.
func NewCollector(filePath string, flushInterval time.Duration) *Collector {
	if filePath == "" {
		filePath = "metrics.json"
	}
	if flushInterval <= 0 {
		flushInterval = 60 * time.Second
	}

	c := &Collector{
		eventsChan: make(chan Event, 8192),
		filePath:   filePath,
		startedAt:  time.Now().UTC(),
		stopChan:   make(chan struct{}),
		routes:     make(map[string]*RouteStats),
		installs:   make(map[string]*InstallStats),
		minutely:   newSeries(time.Minute, 24*time.Hour),
		hourly:     newSeries(time.Hour, 30*24*time.Hour),
		daily:      newSeries(24*time.Hour, 365*24*time.Hour),
	}

	// Load existing snapshot if available to retain history across reboots
	c.loadFromDisk()

	c.wg.Add(1)
	go c.workerLoop(flushInterval)
	return c
}

// Record sends an event to the background worker channel non-blockingly (0 nanoseconds on hot path).
func (c *Collector) Record(ev Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	select {
	case c.eventsChan <- ev:
	default:
		// Drop under extreme pressure to never slow down proxy forwarding
	}
}

// GetReport returns an in-memory snapshot of all current metrics.
func (c *Collector) GetReport() Report {
	c.mu.RLock()
	defer c.mu.RUnlock()

	summary := c.global
	summary.Uptime = time.Since(c.startedAt).Round(time.Second).String()

	routesCopy := make(map[string]*RouteStats, len(c.routes))
	for k, v := range c.routes {
		cp := *v
		routesCopy[k] = &cp
	}

	installsCopy := make(map[string]*InstallStats, len(c.installs))
	for k, v := range c.installs {
		cp := *v
		installsCopy[k] = &cp
	}

	return Report{
		GeneratedAt:   time.Now().UTC(),
		Global:        summary,
		Routes:        routesCopy,
		Installs:      installsCopy,
		History:       c.minutely.list(),
		HourlyHistory: c.hourly.list(),
		DailyHistory:  c.daily.list(),
	}
}

func (c *Collector) workerLoop(flushInterval time.Duration) {
	defer c.wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case ev := <-c.eventsChan:
			c.processEvent(ev)
		case <-ticker.C:
			c.flushIfChanged()
		case <-c.stopChan:
			// Drain remaining events before exit
			for {
				select {
				case ev := <-c.eventsChan:
					c.processEvent(ev)
				default:
					c.flushIfChanged()
					return
				}
			}
		}
	}
}

// avgMs is a mean latency in milliseconds, kept to sub-millisecond precision:
// truncating the total to whole milliseconds first, as this used to, reported
// 0 ms for every route faster than a millisecond per call.
func avgMs(total time.Duration, calls uint64) float64 {
	if calls == 0 {
		return 0
	}
	return float64(total) / float64(time.Millisecond) / float64(calls)
}

// latencyFrom rebuilds a latency total from its persisted average. Only the
// average is saved; without this, the first request after a restart divided a
// total of one request's latency by every call ever made, and the average read
// close to zero until enough new traffic diluted the history.
func latencyFrom(avg float64, calls uint64) time.Duration {
	return time.Duration(avg * float64(calls) * float64(time.Millisecond))
}

func (c *Collector) processEvent(ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.changed = true

	isSuccess := ev.StatusCode >= 200 && ev.StatusCode < 400
	isClientErr := ev.StatusCode >= 400 && ev.StatusCode < 500
	isServerErr := ev.StatusCode >= 500

	// 1. Global Aggregation
	c.global.TotalCalls++
	c.global.TotalBytes += ev.BytesSent
	c.totalLatency += ev.Duration
	if isSuccess {
		c.global.SuccessCalls++
	}
	if isClientErr {
		c.global.ClientErrors++
	}
	if isServerErr {
		c.global.ServerErrors++
	}
	c.global.AvgLatencyMs = avgMs(c.totalLatency, c.global.TotalCalls)

	// 2. Route Aggregation
	if ev.RoutePrefix != "" {
		rStats, exists := c.routes[ev.RoutePrefix]
		if !exists {
			rStats = &RouteStats{RoutePrefix: ev.RoutePrefix}
			c.routes[ev.RoutePrefix] = rStats
		}
		rStats.TotalCalls++
		rStats.TotalBytes += ev.BytesSent
		rStats.TotalLatency += ev.Duration
		if isSuccess {
			rStats.SuccessCalls++
		} else {
			rStats.ErrorCalls++
		}
		rStats.AvgLatencyMs = avgMs(rStats.TotalLatency, rStats.TotalCalls)
	}

	// 3. Installation Aggregation
	if ev.InstallID != "" {
		iStats, exists := c.installs[ev.InstallID]
		if !exists {
			iStats = &InstallStats{InstallID: ev.InstallID}
			c.installs[ev.InstallID] = iStats
		}
		iStats.TotalCalls++
		iStats.TotalBytes += ev.BytesSent
		iStats.TotalLatency += ev.Duration
		iStats.LastSeen = ev.Timestamp
		if isSuccess {
			iStats.SuccessCalls++
		} else {
			iStats.ErrorCalls++
		}
		iStats.AvgLatencyMs = avgMs(iStats.TotalLatency, iStats.TotalCalls)
	}

	// 4. History, at every resolution
	for _, sr := range []*series{c.minutely, c.hourly, c.daily} {
		sr.add(ev, isSuccess)
	}
}

// prune drops history past each series' span and installs unseen for a month.
// It runs on the worker, just before a write, never on a request.
func (c *Collector) prune(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, sr := range []*series{c.minutely, c.hourly, c.daily} {
		if sr.prune(now) {
			c.changed = true
		}
	}
	for id, s := range c.installs {
		if now.Sub(s.LastSeen) > installRetention {
			delete(c.installs, id)
			c.changed = true
		}
	}
}

// flushIfChanged writes the report when something happened since the last write.
func (c *Collector) flushIfChanged() {
	c.prune(time.Now())
	c.mu.RLock()
	changed := c.changed
	c.mu.RUnlock()
	if changed {
		c.Flush()
	}
}

// Flush writes the report to disk: to a temporary file, synced, then renamed
// over the previous one, so a crash leaves either the old report or the new one.
func (c *Collector) Flush() {
	c.mu.Lock()
	c.changed = false
	c.mu.Unlock()

	if err := c.write(c.GetReport()); err != nil {
		c.mu.Lock()
		c.changed = true // try again next tick
		c.mu.Unlock()
	}
}

func (c *Collector) write(report Report) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(c.filePath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	// Install IDs enumerate a tenant's users: owner-only, like quotas.json.
	tmpFile := c.filePath + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	if err := os.Rename(tmpFile, c.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	return nil
}

func (c *Collector) loadFromDisk() {
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return
	}

	var saved Report
	if err := json.Unmarshal(data, &saved); err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.global = saved.Global
	c.totalLatency = latencyFrom(saved.Global.AvgLatencyMs, saved.Global.TotalCalls)
	for k, r := range saved.Routes {
		if r != nil {
			r.TotalLatency = latencyFrom(r.AvgLatencyMs, r.TotalCalls)
			c.routes[k] = r
		}
	}
	// A report written before installs replaced masked tokens has no
	// "installs" key; its masked lines cannot be mapped back, and are dropped.
	for k, s := range saved.Installs {
		if s != nil {
			s.TotalLatency = latencyFrom(s.AvgLatencyMs, s.TotalCalls)
			c.installs[k] = s
		}
	}
	c.minutely.load(saved.History)
	c.hourly.load(saved.HourlyHistory)
	c.daily.load(saved.DailyHistory)
}

// Close gracefully flushes metrics to disk and shuts down the telemetry worker.
func (c *Collector) Close() {
	close(c.stopChan)
	c.wg.Wait()
}
