package proxy

import (
	"net/http"
	"runtime/debug"
	"time"

	"gatekey/internal/apierror"
	"gatekey/internal/logging"
)

// statusRecorder captures the response HTTP status code for structured access logging.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// RecoveryAndLoggingMiddleware provides:
// 1. Crash immunization: catches any panic, logs stack trace, returns HTTP 500 JSON.
// 2. Centralized structured access logging: METHOD, PATH, STATUS, LATENCY, IP.
func RecoveryAndLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		defer func() {
			if p := recover(); p != nil {
				stack := debug.Stack()
				logging.Error("panic recovered", "panic", p, "stack", string(stack))
				apierror.ErrInternal.Write(w)
			}
		}()

		next.ServeHTTP(rec, r)

		// One record per proxied call, at debug level: it is what you want while
		// building and pure noise, and pure I/O cost, on a busy server. Probes are
		// dropped entirely, since they say nothing and arrive constantly.
		if r.URL.Path != "/healthz" && r.URL.Path != "/metrics" {
			logging.Debug("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.statusCode,
				"duration", time.Since(start).Round(time.Microsecond).String(),
				"remote", r.RemoteAddr)
		}
	})
}
