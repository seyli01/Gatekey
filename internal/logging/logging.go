// Package logging centralises how Gatekey emits diagnostics.
//
// Every component logs through the single logger this package owns rather than
// through the standard log package, so verbosity and format are decided once, in
// configuration, instead of being fixed at each call site. It is built on
// log/slog from the standard library, which keeps the dependency count at zero
// while giving structured records a log aggregator can ingest.
//
// The default, before any configuration is read, is human-readable text at info
// level on stderr, so a failure during start-up is still reported.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

// Accepted values for server.log_level.
const (
	LevelError = "error"
	LevelWarn  = "warn"
	LevelInfo  = "info"
	LevelDebug = "debug"
)

// Accepted values for server.log_format.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// current holds the active logger. It is swapped atomically because a
// configuration reload can replace it while requests are in flight.
var current atomic.Pointer[slog.Logger]

func init() {
	logger, err := New(LevelInfo, FormatText, os.Stderr)
	if err != nil {
		panic(fmt.Sprintf("logging: building the default logger: %v", err))
	}
	current.Store(logger)
}

// ParseLevel converts a configured level name into its slog equivalent.
func ParseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", LevelInfo:
		return slog.LevelInfo, nil
	case LevelError:
		return slog.LevelError, nil
	case LevelWarn:
		return slog.LevelWarn, nil
	case LevelDebug:
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("unknown log level %q, want one of %q, %q, %q, %q",
			name, LevelError, LevelWarn, LevelInfo, LevelDebug)
	}
}

// New builds a logger for a level and output format.
func New(level, format string, out io.Writer) (*slog.Logger, error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatText:
		handler = slog.NewTextHandler(out, opts)
	case FormatJSON:
		handler = slog.NewJSONHandler(out, opts)
	default:
		return nil, fmt.Errorf("unknown log format %q, want %q or %q", format, FormatText, FormatJSON)
	}

	return slog.New(handler), nil
}

// Configure replaces the active logger. A reload calls it, so the swap is atomic
// and in-flight requests see either the old logger or the new one.
func Configure(level, format string, out io.Writer) error {
	logger, err := New(level, format, out)
	if err != nil {
		return err
	}
	current.Store(logger)
	return nil
}

// Set installs a logger directly, for tests that need to capture output.
func Set(logger *slog.Logger) {
	current.Store(logger)
}

// L returns the active logger.
func L() *slog.Logger { return current.Load() }

// Convenience wrappers, so call sites read as one line.
func Debug(msg string, args ...any) { current.Load().Debug(msg, args...) }
func Info(msg string, args ...any)  { current.Load().Info(msg, args...) }
func Warn(msg string, args ...any)  { current.Load().Warn(msg, args...) }
func Error(msg string, args ...any) { current.Load().Error(msg, args...) }
