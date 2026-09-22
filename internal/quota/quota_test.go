package quota

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gatekey/internal/config"
)

func TestQuotaManager_CheckAndRecord(t *testing.T) {
	tmpDir := t.TempDir()
	quotaFile := filepath.Join(tmpDir, "quotas.json")

	mgr := NewManager(quotaFile, 1*time.Minute)
	defer mgr.Close()

	cfg := config.QuotaConfig{
		MaxTokens:    1000,
		MaxBudgetUSD: 1.00,
		PricingPerMillion: config.PricingConfig{
			PromptUSD:     0.15,
			CompletionUSD: 0.60,
		},
	}

	route := "/openai"
	token := "tok-test"

	// 1. Initial check must pass with 0 tokens used
	allowed, usage, err := mgr.Check(route, token, cfg)
	if !allowed || err != nil {
		t.Fatalf("expected initial check to pass, got err: %v", err)
	}
	if usage.TotalTokens != 0 {
		t.Errorf("expected 0 tokens initially, got %d", usage.TotalTokens)
	}

	// 2. Record 500 prompt tokens and 300 completion tokens (800 total)
	mgr.Record(route, token, "", 500, 300, cfg)

	allowed, usage, err = mgr.Check(route, token, cfg)
	if !allowed || err != nil {
		t.Fatalf("expected check after 800 tokens to pass, got err: %v", err)
	}
	if usage.TotalTokens != 800 {
		t.Errorf("expected 800 tokens, got %d", usage.TotalTokens)
	}

	// 3. Record 300 more tokens -> 1100 tokens (exceeds 1000 max)
	mgr.Record(route, token, "", 100, 200, cfg)

	allowed, usage, err = mgr.Check(route, token, cfg)
	if allowed || err == nil {
		t.Fatalf("expected check to FAIL after exceeding 1000 tokens")
	}
	if err.Code != "token_quota_exceeded" {
		t.Errorf("expected error code token_quota_exceeded, got %s", err.Code)
	}
	if err.Status != 402 {
		t.Errorf("expected HTTP 402 Payment Required, got %d", err.Status)
	}
}

func TestQuotaManager_DollarBudgetExceeded(t *testing.T) {
	tmpDir := t.TempDir()
	quotaFile := filepath.Join(tmpDir, "quotas.json")

	mgr := NewManager(quotaFile, 1*time.Minute)
	defer mgr.Close()

	cfg := config.QuotaConfig{
		MaxTokens:    0,    // Unlimited token count
		MaxBudgetUSD: 0.05, // Cap at $0.05
		PricingPerMillion: config.PricingConfig{
			PromptUSD:     10.00, // $10 per 1M tokens
			CompletionUSD: 20.00,
		},
	}

	route := "/anthropic"
	token := "tok-expensive"

	// Record 4000 prompt tokens -> 4000 * 10 / 1M = $0.04 (under $0.05)
	mgr.Record(route, token, "", 4000, 0, cfg)
	allowed, _, err := mgr.Check(route, token, cfg)
	if !allowed || err != nil {
		t.Fatalf("expected $0.04 to be under $0.05 budget")
	}

	// Record 2000 more prompt tokens -> adds $0.02 -> total $0.06 (over $0.05)
	mgr.Record(route, token, "", 2000, 0, cfg)
	allowed, _, err = mgr.Check(route, token, cfg)
	if allowed || err == nil {
		t.Fatalf("expected budget limit to be exceeded")
	}
	if err.Code != "budget_quota_exceeded" {
		t.Errorf("expected budget_quota_exceeded, got %s", err.Code)
	}
}

func TestQuotaManager_PersistenceAcrossReboots(t *testing.T) {
	tmpDir := t.TempDir()
	quotaFile := filepath.Join(tmpDir, "quotas.json")

	// Instance 1
	mgr1 := NewManager(quotaFile, 1*time.Minute)
	mgr1.Record("/test", "tok-reboot", "", 1234, 5678, config.QuotaConfig{PricingPerMillion: config.PricingConfig{PromptUSD: 1.0, CompletionUSD: 2.0}})
	mgr1.Close() // Forces disk flush

	// Instance 2 (simulating reboot)
	mgr2 := NewManager(quotaFile, 1*time.Minute)
	defer mgr2.Close()

	usage := mgr2.GetUsage("/test", "tok-reboot")
	if usage.PromptTokens != 1234 || usage.CompletionTokens != 5678 || usage.TotalTokens != 1234+5678 {
		t.Fatalf("usage did not persist correctly across reboots: %+v", usage)
	}
}

func TestParser_JSONAndSSE(t *testing.T) {
	// Standard JSON
	rawJSON := []byte(`{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":15,"completion_tokens":42,"total_tokens":57}}`)
	prompt, comp, found := ExtractUsageFromJSON(rawJSON)
	if !found || prompt != 15 || comp != 42 {
		t.Errorf("ExtractUsageFromJSON failed: prompt=%d, comp=%d, found=%v", prompt, comp, found)
	}

	// SSE Chunk
	sseLine := `data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`
	promptSSE, compSSE, foundSSE := ExtractUsageFromSSELine(sseLine)
	if !foundSSE || promptSSE != 10 || compSSE != 20 {
		t.Errorf("ExtractUsageFromSSELine failed: prompt=%d, comp=%d, found=%v", promptSSE, compSSE, foundSSE)
	}

	// SSE [DONE] must be safely skipped
	_, _, foundDone := ExtractUsageFromSSELine("data: [DONE]")
	if foundDone {
		t.Errorf("expected [DONE] to return found=false")
	}
}

func TestPeriod(t *testing.T) {
	now := time.Date(2026, 9, 21, 14, 30, 0, 0, time.UTC)

	cases := map[string]string{
		config.QuotaResetNever:   "",
		config.QuotaResetMonthly: "2026-09",
		config.QuotaResetDaily:   "2026-09-21",
		"":                       "",
	}
	for reset, want := range cases {
		if got := Period(reset, now); got != want {
			t.Errorf("Period(%q) = %q, want %q", reset, got, want)
		}
	}

	// Windows are computed in UTC so a budget does not reset twice a year when
	// daylight saving shifts the local clock.
	paris := time.FixedZone("CEST", 2*60*60)
	lateEvening := time.Date(2026, 9, 21, 1, 30, 0, 0, paris) // 2026-09-20 23:30 UTC
	if got := Period(config.QuotaResetDaily, lateEvening); got != "2026-09-20" {
		t.Errorf("Period should use UTC, got %q", got)
	}
}

// lapse rewrites a stored counter's window to simulate the passing of time,
// which is the only part of this behaviour a test cannot reach by waiting.
func lapse(t *testing.T, m *Manager, route, clientToken, period string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	usage, exists := m.usages[makeKey(route, clientToken)]
	if !exists {
		t.Fatalf("no usage recorded for %s:%s", route, clientToken)
	}
	usage.Period = period
}

func TestManager_LapsedWindowResetsTheBudget(t *testing.T) {
	mgr := NewManager(filepath.Join(t.TempDir(), "quotas.json"), time.Hour)
	defer mgr.Close()

	cfg := config.QuotaConfig{MaxTokens: 1000, Reset: config.QuotaResetMonthly}

	mgr.Record("/openai", "install-abc", "", 900, 200, cfg)
	if allowed, _, _ := mgr.Check("/openai", "install-abc", cfg); allowed {
		t.Fatal("1100 tokens against a 1000 ceiling must be refused")
	}

	lapse(t, mgr, "/openai", "install-abc", "2026-08")

	allowed, usage, _ := mgr.Check("/openai", "install-abc", cfg)
	if !allowed {
		t.Fatal("a new month must start from a clean budget")
	}
	if usage.TotalTokens != 0 {
		t.Errorf("TotalTokens = %d, want 0 at the start of a window", usage.TotalTokens)
	}

	// Spending in the new window starts from zero rather than topping up the old.
	if got := mgr.Record("/openai", "install-abc", "", 10, 5, cfg); got.TotalTokens != 15 {
		t.Errorf("TotalTokens = %d, want 15", got.TotalTokens)
	}
}

// The default is unchanged: counters accumulate for the lifetime of the install.
func TestManager_NeverResetKeepsAccumulating(t *testing.T) {
	mgr := NewManager(filepath.Join(t.TempDir(), "quotas.json"), time.Hour)
	defer mgr.Close()

	cfg := config.QuotaConfig{MaxTokens: 1000} // Reset left empty
	mgr.Record("/openai", "install-abc", "", 600, 0, cfg)
	got := mgr.Record("/openai", "install-abc", "", 600, 0, cfg)

	if got.TotalTokens != 1200 {
		t.Errorf("TotalTokens = %d, want 1200", got.TotalTokens)
	}
	if got.Period != "" {
		t.Errorf("Period = %q, want empty for a lifetime counter", got.Period)
	}
	if allowed, _, _ := mgr.Check("/openai", "install-abc", cfg); allowed {
		t.Error("a lifetime counter past its ceiling must stay refused")
	}
}

// Lapsed entries are dropped when the file is written, so the map does not keep
// one dead counter per installation per month forever.
func TestManager_LapsedEntriesArePrunedOnFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	mgr := NewManager(path, time.Hour)

	monthly := config.QuotaConfig{MaxTokens: 1000, Reset: config.QuotaResetMonthly}
	lifetime := config.QuotaConfig{MaxTokens: 1000}

	mgr.Record("/openai", "install-old", "", 10, 10, monthly)
	mgr.Record("/openai", "install-now", "", 10, 10, monthly)
	mgr.Record("/openai", "install-forever", "", 10, 10, lifetime)

	lapse(t, mgr, "/openai", "install-old", "2020-01")

	mgr.Close() // flushes on the way out

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading quotas file: %v", err)
	}
	var saved map[string]*TokenUsage
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decoding quotas file: %v", err)
	}

	if _, found := saved[makeKey("/openai", "install-old")]; found {
		t.Error("a lapsed counter must not survive the flush")
	}
	if _, found := saved[makeKey("/openai", "install-now")]; !found {
		t.Error("the current window's counter must be persisted")
	}
	// A lifetime counter has no window and must never be pruned.
	if _, found := saved[makeKey("/openai", "install-forever")]; !found {
		t.Error("a lifetime counter must survive the flush")
	}
}

// A restart in a new window must not resurrect the previous window's spend.
func TestManager_LapsedWindowDoesNotSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	cfg := config.QuotaConfig{MaxTokens: 1000, Reset: config.QuotaResetMonthly}

	first := NewManager(path, time.Hour)
	first.Record("/openai", "install-abc", "", 900, 200, cfg)
	lapse(t, first, "/openai", "install-abc", "2020-01")
	first.saveWithoutPruning(t)

	second := NewManager(path, time.Hour)
	defer second.Close()

	allowed, usage, _ := second.Check("/openai", "install-abc", cfg)
	if !allowed {
		t.Fatal("a counter from a past window must not block a restarted server")
	}
	if usage.TotalTokens != 0 {
		t.Errorf("TotalTokens = %d, want 0", usage.TotalTokens)
	}
}

// saveWithoutPruning persists the map as-is, bypassing the pruner, so a test can
// produce the on-disk state a server left behind before its window lapsed.
func (m *Manager) saveWithoutPruning(t *testing.T) {
	t.Helper()
	m.mu.RLock()
	data, err := json.MarshalIndent(m.usages, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		t.Fatalf("marshalling usages: %v", err)
	}
	if err := os.WriteFile(m.filePath, data, 0o600); err != nil {
		t.Fatalf("writing quotas file: %v", err)
	}
}

// A total limit caps the route across installs: each install stays well under
// its own limit, yet together they close the route for everyone, including an
// install that has spent nothing.
func TestManager_TotalLimitCapsTheRouteAcrossInstalls(t *testing.T) {
	mgr := NewManager(filepath.Join(t.TempDir(), "quotas.json"), time.Hour)
	defer mgr.Close()

	cfg := config.QuotaConfig{MaxTokens: 1000, TotalMaxTokens: 1500}
	mgr.Record("/r", "a", "", 400, 400, cfg)
	if ok, _, err := mgr.Check("/r", "b", cfg); !ok {
		t.Fatalf("800 of 1500 spent, b must pass: %v", err)
	}
	mgr.Record("/r", "b", "", 400, 400, cfg)

	for _, install := range []string{"a", "b", "fresh"} {
		ok, usage, err := mgr.Check("/r", install, cfg)
		if ok || err == nil || err.Code != "total_quota_exceeded" {
			t.Fatalf("%s: route total is 1600 of 1500, want total_quota_exceeded, got ok=%v err=%v", install, ok, err)
		}
		// The caller sees its own usage, never the route's.
		if install == "fresh" && usage.TotalTokens != 0 {
			t.Errorf("fresh install was shown %d tokens, want its own 0", usage.TotalTokens)
		}
	}
	if got := mgr.GetTotalUsage("/r").TotalTokens; got != 1600 {
		t.Errorf("route total = %d, want 1600", got)
	}
	// Another route has its own total.
	if ok, _, _ := mgr.Check("/other", "a", cfg); !ok {
		t.Error("the total of /r closed /other")
	}
}

func TestManager_TotalBudgetInDollars(t *testing.T) {
	mgr := NewManager(filepath.Join(t.TempDir(), "quotas.json"), time.Hour)
	defer mgr.Close()

	cfg := config.QuotaConfig{
		TotalBudgetUSD:    1.00,
		PricingPerMillion: config.PricingConfig{PromptUSD: 1, CompletionUSD: 1},
	}
	mgr.Record("/r", "a", "", 600_000, 0, cfg) // $0.60
	if ok, _, _ := mgr.Check("/r", "b", cfg); !ok {
		t.Fatal("$0.60 of $1 spent, must pass")
	}
	mgr.Record("/r", "b", "", 500_000, 0, cfg) // $1.10 in total
	if ok, _, err := mgr.Check("/r", "c", cfg); ok || err.Code != "total_quota_exceeded" {
		t.Fatalf("$1.10 of $1 spent, want total_quota_exceeded, got ok=%v err=%v", ok, err)
	}
}

// The route total resets with the window, survives a restart through the
// journal, and never collides with an install, whatever its name.
func TestManager_TotalResetsPersistsAndIsolated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotas.json")
	cfg := config.QuotaConfig{TotalMaxTokens: 100, Reset: config.QuotaResetDaily}

	first := NewManager(path, time.Hour)
	first.Record("/r", "a", "", 60, 60, cfg)
	first.Close()

	second := NewManager(path, time.Hour)
	defer second.Close()
	if got := second.GetTotalUsage("/r").TotalTokens; got != 120 {
		t.Fatalf("route total after restart = %d, want 120", got)
	}
	if ok, _, _ := second.Check("/r", "a", cfg); ok {
		t.Fatal("route total survived the restart yet did not block")
	}
	// An install named like the total's key gets its own counter.
	if got := second.GetUsage("/r", "*/r").TotalTokens; got != 0 {
		t.Errorf("install %q reads the route total: %d", "*/r", got)
	}

	// Yesterday's total is lapsed: the route is open again today.
	second.mu.Lock()
	second.usages[totalKey("/r")].Period = "2000-01-01"
	second.mu.Unlock()
	if ok, _, err := second.Check("/r", "a", cfg); !ok {
		t.Fatalf("a lapsed total must not block: %v", err)
	}
}
