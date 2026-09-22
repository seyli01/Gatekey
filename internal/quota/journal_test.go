package quota

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gatekey/internal/config"
)

var monthly = config.QuotaConfig{Reset: config.QuotaResetMonthly}

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	n := 0
	for s := bufio.NewScanner(f); s.Scan(); {
		n++
	}
	return n
}

// The point of the journal: a flush writes what changed, not everything.
func TestJournal_FlushWritesOnlyChangedCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	m := NewManager(path, time.Hour)
	defer m.Close()

	for _, id := range []string{"a", "b", "c", "d", "e"} {
		m.Record("/r", id, "", 10, 10, monthly)
	}
	// Each record also charges the route total: one more counter.
	m.flush()
	if got := countLines(t, path+".log"); got != 6 {
		t.Fatalf("first flush: %d lines, want 5 installs + the route total", got)
	}

	m.Record("/r", "c", "", 10, 10, monthly)
	m.flush()
	if got := countLines(t, path+".log"); got != 8 {
		t.Errorf("one install changed, so it and the route total should be appended: got %d lines, want 8", got)
	}

	m.flush() // nothing changed
	if got := countLines(t, path+".log"); got != 8 {
		t.Errorf("an idle flush must not write: got %d lines, want 8", got)
	}
}

// A crash is a manager that never reached Close: the log alone must restore it.
func TestJournal_StateSurvivesACrashWithoutCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	first := NewManager(path, time.Hour)
	first.Record("/r", "inst", "", 100, 50, monthly)
	first.flush()
	first.Record("/r", "inst", "", 100, 50, monthly)
	first.flush()
	// no Close: the process died here

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("no compaction ran, so there should be no snapshot yet (err=%v)", err)
	}

	second := NewManager(path, time.Hour)
	defer second.Close()
	if got := second.GetUsage("/r", "inst").TotalTokens; got != 300 {
		t.Errorf("TotalTokens = %d, want 300 replayed from the log", got)
	}
}

// A crash in the middle of an append leaves half a line. Loading must skip it,
// and the next append must not glue its first counter onto the fragment.
func TestJournal_TornTailIsSkippedAndDoesNotEatTheNextLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	first := NewManager(path, time.Hour)
	first.Record("/r", "a", "", 100, 0, monthly)
	first.flush()

	f, err := os.OpenFile(path+".log", os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"k":"/r:a","u":{"total_tok`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	second := NewManager(path, time.Hour)
	if got := second.GetUsage("/r", "a").TotalTokens; got != 100 {
		t.Fatalf("TotalTokens = %d, want 100: the torn line must be ignored", got)
	}
	second.Record("/r", "b", "", 7, 0, monthly)
	second.flush()
	// crash again, then reload
	third := NewManager(path, time.Hour)
	defer third.Close()
	if got := third.GetUsage("/r", "b").TotalTokens; got != 7 {
		t.Errorf("TotalTokens(b) = %d, want 7: the line after a torn tail was lost", got)
	}
}

// Compaction replaces the snapshot, then removes the log. A crash between the
// two leaves a log that is older than the snapshot; replaying it must not move
// any counter backwards.
func TestJournal_StaleLogAfterCompactionCrashDoesNotRollBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	first := NewManager(path, time.Hour)
	first.Record("/r", "inst", "", 100, 0, monthly)
	first.flush() // log: 100
	first.Record("/r", "inst", "", 100, 0, monthly)

	stale, err := os.ReadFile(path + ".log")
	if err != nil {
		t.Fatal(err)
	}
	first.compact() // snapshot: 200, log removed
	if err := os.WriteFile(path+".log", stale, 0o600); err != nil {
		t.Fatal(err) // the removal "never happened"
	}

	second := NewManager(path, time.Hour)
	defer second.Close()
	if got := second.GetUsage("/r", "inst").TotalTokens; got != 200 {
		t.Errorf("TotalTokens = %d, want 200: an older log line rolled the counter back", got)
	}
}

// A new window resets a counter to zero, so "larger wins" alone would resurrect
// last month's spend. The later window must win even though it is smaller.
func TestJournal_LaterWindowWinsEvenWhenSmaller(t *testing.T) {
	old := TokenUsage{TotalTokens: 5000, Period: "2026-08"}
	fresh := TokenUsage{TotalTokens: 10, Period: "2026-09"}
	if !supersedes(old, fresh) {
		t.Error("September must supersede August")
	}
	if supersedes(fresh, old) {
		t.Error("August must not supersede September")
	}
	if supersedes(TokenUsage{TotalTokens: 200}, TokenUsage{TotalTokens: 100}) {
		t.Error("within a window a smaller counter is an older one")
	}
}

// A clean shutdown folds everything into one compact snapshot and leaves no log.
func TestJournal_CloseLeavesASingleCompactSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	m := NewManager(path, time.Hour)
	m.Record("/r", "inst", "", 1, 2, monthly)
	m.Close()

	if _, err := os.Stat(path + ".log"); !os.IsNotExist(err) {
		t.Errorf("the log should be gone after a clean shutdown (err=%v)", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\n  ") {
		t.Error("the snapshot should be compact, not indented")
	}
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("snapshot mode = %o, want 600: it lists every installation", perm)
	}
}

// The log compacts itself once it outgrows the snapshot, so it cannot grow
// without bound on a server that is never restarted.
func TestJournal_LogIsCompactedOnceItOutgrowsTheSnapshot(t *testing.T) {
	j := newJournal(filepath.Join(t.TempDir(), "quotas.json"))
	now := time.Now()
	j.snapBytes = 4 << 20
	j.logBytes = 3 << 20
	if j.needsCompaction(now) {
		t.Error("a log smaller than the snapshot should wait")
	}
	j.logBytes = 4 << 20
	if !j.needsCompaction(now) {
		t.Error("a log as large as the snapshot should compact")
	}
	j.snapBytes, j.logBytes = 10, 100
	if j.needsCompaction(now) {
		t.Error("below the minimum size, the log should wait")
	}
	if !j.needsCompaction(now.Add(25 * time.Hour)) {
		t.Error("a day-old log should compact, so lapsed counters get pruned")
	}
}

// A compaction writes every pending change into the snapshot; the next flush
// must not append them all again.
func TestJournal_CompactionConsumesPendingChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	m := NewManager(path, time.Hour)
	defer m.Close()

	for _, id := range []string{"a", "b", "c"} {
		m.Record("/r", id, "", 1, 1, monthly)
	}
	m.compact()
	m.flush()
	if got := countLines(t, path+".log"); got != 0 {
		t.Errorf("flush after compaction wrote %d lines, want 0", got)
	}
}

// If the snapshot cannot be written, the pending changes must still be flushed.
func TestJournal_FailedCompactionHandsChangesBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quotas.json")
	m := NewManager(path, time.Hour)
	defer m.Close()

	m.Record("/r", "a", "", 1, 1, monthly)
	// A directory where the temporary snapshot goes makes the write fail.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	m.compact()
	if !m.retryCompact {
		t.Error("a failed compaction must be retried")
	}
	os.Remove(path + ".tmp")
	m.flush()
	if got := countLines(t, path+".log"); got != 2 {
		t.Errorf("flush after a failed compaction wrote %d lines, want 2 (install + route total)", got)
	}
}

// Records racing flushes and compactions must all reach the disk: after a
// restart, every token recorded is still counted, none twice.
//
// Every record goes to a different install on purpose. Lines carry full values,
// so a lost write to an install that records again is repaired by its next line;
// only an install seen once exposes a change that fell between two sets.
func TestJournal_NoUpdateLostUnderConcurrentFlushAndCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	m := NewManager(path, time.Hour)

	const workers, perWorker = 8, 500
	done := make(chan struct{})
	go func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			if i%3 == 0 {
				m.compact()
			} else {
				m.flush()
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("inst-%d", w*perWorker+i)
				m.Check("/r", id, monthly)
				m.Record("/r", id, "", 1, 0, monthly)
			}
		}(w)
	}
	wg.Wait()
	close(done)

	// Crash, not Close: whatever made it to disk through flush and compaction
	// alone must add up.
	m.flush()
	reloaded := NewManager(path, time.Hour)
	defer reloaded.Close()

	var total uint64
	for i := 0; i < workers*perWorker; i++ {
		total += reloaded.GetUsage("/r", fmt.Sprintf("inst-%d", i)).TotalTokens
	}
	if total != workers*perWorker {
		t.Errorf("reloaded %d tokens, want %d", total, workers*perWorker)
	}
}
