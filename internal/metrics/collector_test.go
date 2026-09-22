package metrics

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitFor polls until the worker has processed n events. Record hands events to
// a goroutine, so a test cannot read the report straight after recording.
func waitFor(t *testing.T, col *Collector, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if col.GetReport().Global.TotalCalls >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("worker processed %d events, want %d", col.GetReport().Global.TotalCalls, n)
}

func TestMetricsCollector_RecordAndAggregation(t *testing.T) {
	tmpDir := t.TempDir()
	metricsPath := filepath.Join(tmpDir, "metrics.json")

	col := NewCollector(metricsPath, time.Hour)
	defer col.Close()

	col.Record(Event{RoutePrefix: "/groq", InstallID: "inst-prod-999", StatusCode: 200, Duration: 100 * time.Millisecond, BytesSent: 500})
	col.Record(Event{RoutePrefix: "/groq", InstallID: "inst-prod-999", StatusCode: 200, Duration: 200 * time.Millisecond, BytesSent: 700})
	col.Record(Event{RoutePrefix: "/groq", StatusCode: 401, Duration: 10 * time.Millisecond, BytesSent: 50})
	waitFor(t, col, 3)

	report := col.GetReport()
	if report.Global.SuccessCalls != 2 {
		t.Errorf("expected 2 success calls, got %d", report.Global.SuccessCalls)
	}
	if report.Global.ClientErrors != 1 {
		t.Errorf("expected 1 client error, got %d", report.Global.ClientErrors)
	}
	if report.Global.TotalBytes != 1250 {
		t.Errorf("expected 1250 total bytes, got %d", report.Global.TotalBytes)
	}
	if groq := report.Routes["/groq"]; groq == nil || groq.TotalCalls != 3 {
		t.Fatalf("expected 3 calls on /groq, got %+v", groq)
	}

	inst := report.Installs["inst-prod-999"]
	if inst == nil || inst.TotalCalls != 2 {
		t.Fatalf("expected 2 calls for the install, got %+v", inst)
	}
	// An unauthenticated caller has no install ID and must not get a line.
	if len(report.Installs) != 1 {
		t.Errorf("expected 1 install, got %d", len(report.Installs))
	}

	col.Flush()
	fileData, err := os.ReadFile(metricsPath)
	if err != nil {
		t.Fatalf("failed to read metrics file: %v", err)
	}
	var saved Report
	if err := json.Unmarshal(fileData, &saved); err != nil {
		t.Fatalf("failed to unmarshal saved metrics JSON: %v", err)
	}
	if saved.Global.TotalCalls != 3 {
		t.Errorf("saved report total calls mismatch: expected 3, got %d", saved.Global.TotalCalls)
	}
	info, _ := os.Stat(metricsPath)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("metrics file mode = %o, want 600: it lists every installation", perm)
	}
}

// The old masking kept three leading and four trailing characters, so two
// installs sharing them were merged into one line.
func TestMetricsCollector_InstallsAreNeverMerged(t *testing.T) {
	col := NewCollector(filepath.Join(t.TempDir(), "metrics.json"), time.Hour)
	defer col.Close()

	col.Record(Event{InstallID: "inst_aaaa_0001_9f3c", StatusCode: 200})
	col.Record(Event{InstallID: "inst_bbbb_0002_9f3c", StatusCode: 200})
	waitFor(t, col, 2)

	if got := len(col.GetReport().Installs); got != 2 {
		t.Errorf("got %d install lines, want 2", got)
	}
}

// Sub-millisecond calls used to average to exactly 0 ms, because the total was
// truncated to whole milliseconds before dividing.
func TestMetricsCollector_SubMillisecondLatencyIsNotZero(t *testing.T) {
	col := NewCollector(filepath.Join(t.TempDir(), "metrics.json"), time.Hour)
	defer col.Close()

	col.Record(Event{RoutePrefix: "/r", StatusCode: 200, Duration: 400 * time.Microsecond})
	waitFor(t, col, 1)

	if got := col.GetReport().Global.AvgLatencyMs; math.Abs(got-0.4) > 1e-9 {
		t.Errorf("AvgLatencyMs = %v, want 0.4", got)
	}
}

// Only the average is persisted. The total behind it must be rebuilt on load,
// or the first request after a restart drags the average towards zero.
func TestMetricsCollector_AverageLatencySurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	first := NewCollector(path, time.Hour)
	for i := 0; i < 99; i++ {
		first.Record(Event{RoutePrefix: "/r", StatusCode: 200, Duration: 100 * time.Millisecond})
	}
	waitFor(t, first, 99)
	first.Close()

	second := NewCollector(path, time.Hour)
	defer second.Close()
	second.Record(Event{RoutePrefix: "/r", StatusCode: 200, Duration: 100 * time.Millisecond})
	waitFor(t, second, 100)

	report := second.GetReport()
	if got := report.Global.AvgLatencyMs; math.Abs(got-100) > 0.01 {
		t.Errorf("global average = %v ms after restart, want 100", got)
	}
	if got := report.Routes["/r"].AvgLatencyMs; math.Abs(got-100) > 0.01 {
		t.Errorf("route average = %v ms after restart, want 100", got)
	}
}

// History was written to disk but never read back, so a restart emptied it.
// It must also come out in time order: it is read by a graph.
func TestMetricsCollector_HistorySurvivesARestartInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	now := time.Now().UTC().Truncate(time.Minute)

	first := NewCollector(path, time.Hour)
	for _, ago := range []time.Duration{3, 1, 2} {
		first.Record(Event{Timestamp: now.Add(-ago * time.Minute), StatusCode: 200})
	}
	waitFor(t, first, 3)
	first.Close()

	second := NewCollector(path, time.Hour)
	defer second.Close()
	history := second.GetReport().History
	if len(history) != 3 {
		t.Fatalf("history has %d buckets after restart, want 3", len(history))
	}
	for i := 1; i < len(history); i++ {
		if !history[i-1].Timestamp.Before(history[i].Timestamp) {
			t.Fatalf("history out of order: %v then %v", history[i-1].Timestamp, history[i].Timestamp)
		}
	}
}

// Both maps used to grow forever: a bucket per minute of uptime, and a line per
// installation ever seen.
func TestMetricsCollector_OldHistoryAndGoneInstallsArePruned(t *testing.T) {
	col := NewCollector(filepath.Join(t.TempDir(), "metrics.json"), time.Hour)
	defer col.Close()

	now := time.Now().UTC()
	col.Record(Event{Timestamp: now.Add(-25 * time.Hour), InstallID: "gone", StatusCode: 200})
	col.Record(Event{Timestamp: now.Add(-31 * 24 * time.Hour), InstallID: "long-gone", StatusCode: 200})
	col.Record(Event{Timestamp: now, InstallID: "active", StatusCode: 200})
	waitFor(t, col, 3)

	col.prune(now)
	report := col.GetReport()
	if len(report.History) != 1 {
		t.Errorf("history has %d buckets, want 1: older than a day must go", len(report.History))
	}
	if _, ok := report.Installs["long-gone"]; ok {
		t.Error("an install unseen for a month must be dropped")
	}
	if _, ok := report.Installs["gone"]; !ok {
		t.Error("an install seen yesterday must be kept")
	}
	// Pruning trims detail, never the totals.
	if report.Global.TotalCalls != 3 {
		t.Errorf("TotalCalls = %d, want 3", report.Global.TotalCalls)
	}
}

// An idle server must not rewrite an unchanged file every minute.
func TestMetricsCollector_IdleServerDoesNotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	col := NewCollector(path, time.Hour)
	defer col.Close()

	col.flushIfChanged()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("nothing happened, yet a file was written (err=%v)", err)
	}

	col.Record(Event{RoutePrefix: "/r", StatusCode: 200})
	waitFor(t, col, 1)
	col.flushIfChanged()
	first, err := os.Stat(path)
	if err != nil {
		t.Fatalf("a change must be written: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	col.flushIfChanged()
	second, _ := os.Stat(path)
	if !second.ModTime().Equal(first.ModTime()) {
		t.Error("an idle tick rewrote the file")
	}
}

// Each resolution keeps its own span: a minute for a day, an hour for a month,
// a day for a year. Older data survives, only coarser.
func TestMetricsCollector_HistoryResolutionsKeepTheirOwnSpan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	col := NewCollector(path, time.Hour)

	now := time.Now().UTC()
	for _, ago := range []time.Duration{
		time.Minute,          // every resolution
		25 * time.Hour,       // hourly and daily
		31 * 24 * time.Hour,  // daily only
		400 * 24 * time.Hour, // nowhere
	} {
		col.Record(Event{Timestamp: now.Add(-ago), StatusCode: 200})
	}
	waitFor(t, col, 4)
	col.prune(now)

	check := func(r Report) {
		t.Helper()
		if got := len(r.History); got != 1 {
			t.Errorf("per-minute history has %d buckets, want 1", got)
		}
		if got := len(r.HourlyHistory); got != 2 {
			t.Errorf("hourly history has %d buckets, want 2", got)
		}
		if got := len(r.DailyHistory); got != 3 {
			t.Errorf("daily history has %d buckets, want 3", got)
		}
	}
	check(col.GetReport())

	// And all three come back after a restart.
	col.Close()
	reloaded := NewCollector(path, time.Hour)
	defer reloaded.Close()
	check(reloaded.GetReport())
}

// The three series count the same calls: summing any one of them over the span
// they all cover gives the same total.
func TestMetricsCollector_ResolutionsAgree(t *testing.T) {
	col := NewCollector(filepath.Join(t.TempDir(), "metrics.json"), time.Hour)
	defer col.Close()

	now := time.Now().UTC()
	for i := 0; i < 300; i++ {
		col.Record(Event{Timestamp: now.Add(-time.Duration(i) * 13 * time.Second), StatusCode: 200})
	}
	waitFor(t, col, 300)

	sum := func(bs []TimeBucket) (n uint64) {
		for _, b := range bs {
			n += b.TotalCalls
		}
		return n
	}
	r := col.GetReport()
	if m, h, d := sum(r.History), sum(r.HourlyHistory), sum(r.DailyHistory); m != 300 || h != 300 || d != 300 {
		t.Errorf("per minute %d, hourly %d, daily %d: all should be 300", m, h, d)
	}
}
