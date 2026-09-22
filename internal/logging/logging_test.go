package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"INFO":    slog.LevelInfo,
		" debug ": slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"error":   slog.LevelError,
	}
	for name, want := range cases {
		got, err := ParseLevel(name)
		if err != nil {
			t.Errorf("ParseLevel(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", name, got, want)
		}
	}

	// A typo must be refused rather than silently defaulting, or an operator who
	// asked for quiet logs would keep getting noisy ones without being told.
	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("expected an unknown level to be refused")
	}
}

// The level is what keeps a busy server from paying for a line per request.
func TestNew_LevelFiltersOutput(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(LevelWarn, FormatText, &buf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Debug("debug line")
	logger.Info("info line")
	logger.Warn("warn line")
	logger.Error("error line")

	out := buf.String()
	for _, dropped := range []string{"debug line", "info line"} {
		if strings.Contains(out, dropped) {
			t.Errorf("%q must be filtered out at warn level", dropped)
		}
	}
	for _, kept := range []string{"warn line", "error line"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q must survive at warn level", kept)
		}
	}
}

// JSON output is what makes the logs ingestible by an aggregator.
func TestNew_JSONFormatIsMachineReadable(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(LevelInfo, FormatJSON, &buf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Info("token rejected", "remote", "203.0.113.7:4321", "reason", "expired")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	if record["msg"] != "token rejected" {
		t.Errorf("msg = %v", record["msg"])
	}
	if record["remote"] != "203.0.113.7:4321" {
		t.Errorf("remote = %v", record["remote"])
	}
	if record["level"] != "INFO" {
		t.Errorf("level = %v", record["level"])
	}
}

func TestNew_RejectsUnknownFormat(t *testing.T) {
	if _, err := New(LevelInfo, "xml", &bytes.Buffer{}); err == nil {
		t.Error("expected an unknown format to be refused")
	}
}

// Configure is called on reload while requests are in flight, so swapping the
// logger must not race with the calls using it.
func TestConfigure_IsSafeUnderConcurrentUse(t *testing.T) {
	t.Cleanup(func() { Set(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))) })

	var mu sync.Mutex
	var buf bytes.Buffer
	Set(slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, buf: &buf}, nil)))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = Configure(LevelDebug, FormatJSON, &lockedWriter{mu: &mu, buf: &buf})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			Info("in flight", "i", i)
		}
	}()
	wg.Wait()
}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
