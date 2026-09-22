package routes

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"gatekey/internal/apierror"
	"gatekey/internal/config"
	"gatekey/internal/logging"
	"gatekey/internal/metrics"
	"gatekey/internal/proxy"
	"gatekey/internal/token"
)

// Options contains the dependencies needed to mount all application routes.
type Options struct {
	Gateway   *proxy.Gateway
	ConfigMgr *config.Manager
	Collector *metrics.Collector
}

// NewRouter builds and returns the configured HTTP handler with all endpoints mounted
// and wrapped in the recovery and access logging middleware.
func NewRouter(opts Options) http.Handler {
	mux := http.NewServeMux()

	// 1. Healthcheck endpoint
	mux.HandleFunc("/healthz", HealthzHandler())

	// 2. Metrics telemetry endpoint (strictly restricted to loopback)
	if opts.Collector != nil {
		mux.HandleFunc("/metrics", loopbackOnly("/metrics", MetricsHandler(opts.Collector)))
	}

	// 3. Admin Hot-Reload endpoint (strictly restricted to loopback)
	if opts.ConfigMgr != nil {
		mux.HandleFunc("/-/reload", loopbackOnly("/-/reload", ReloadHandler(opts.ConfigMgr)))
	}

	// 4. Public token refresh endpoint
	if opts.Gateway != nil {
		mux.HandleFunc("/-/refresh", RefreshHandler(opts.Gateway.Issuer))
	}

	// 5. Reverse Proxy Gateway
	if opts.Gateway != nil {
		mux.HandleFunc("/", opts.Gateway.ServeHTTP)
	}

	return proxy.RecoveryAndLoggingMiddleware(mux)
}

// loopbackOnly restricts a handler to 127.0.0.1 / [::1].
//
// Both administrative endpoints expose operational secrets: /-/reload mutates the
// running configuration, and /metrics reports active routes, per-install usage
// and spend. Neither may ever be reachable from the public internet.
func loopbackOnly(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			clientHost = r.RemoteAddr
		}
		clientIP := net.ParseIP(clientHost)
		if clientIP == nil || !clientIP.IsLoopback() {
			logging.Warn("admin endpoint refused", "endpoint", name, "remote", r.RemoteAddr)
			apierror.NewForbidden("admin endpoint restricted to localhost").Write(w)
			return
		}
		next(w, r)
	}
}

// HealthzHandler returns a handler for the /healthz liveness probe.
func HealthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			apierror.NewMethodNotAllowed("GET").Write(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// MetricsHandler returns a handler that exports JSON telemetry metrics.
func MetricsHandler(collector *metrics.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			apierror.NewMethodNotAllowed("GET").Write(w)
			return
		}
		report := collector.GetReport()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	}
}

// ReloadHandler returns a handler for the admin configuration reload endpoint.
// Callers must wrap it in loopbackOnly.
func ReloadHandler(mgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			apierror.NewMethodNotAllowed("POST").Write(w)
			return
		}

		logging.Info("reload requested", "remote", r.RemoteAddr)
		reloadedCfg, err := mgr.Reload()
		if err != nil {
			logging.Error("reload failed, keeping the active configuration", "err", err)
			apierror.NewBadRequest(fmt.Sprintf("reload failed: %v", err)).Write(w)
			return
		}

		logging.Info("configuration reloaded", "routes", len(reloadedCfg.Routes))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":        "reloaded",
			"active_routes": len(reloadedCfg.Routes),
		})
	}
}

// maxRefreshBody caps the refresh request body. A refresh token is a couple of
// hundred bytes, so anything larger is not a client of this endpoint.
const maxRefreshBody = 4096

// RefreshHandler exchanges a refresh token for a fresh access token.
//
// Unlike the other /-/ endpoints this one is deliberately reachable from
// anywhere: the client application calls it from wherever it runs, and the
// refresh token it presents is itself the credential, so there is no separate
// secret to protect. The issuer is read through a function rather than captured,
// so a reload that rotates the signing key or extends the denylist takes effect
// on the next request.
//
// Every failure answers with the same opaque 401: telling a caller whether a
// token was forged, expired or revoked would hand an attacker a free oracle.
func RefreshHandler(issuerFn func() *token.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			apierror.NewMethodNotAllowed("POST").Write(w)
			return
		}

		issuer := issuerFn()
		if issuer == nil {
			apierror.ErrRouteNotFound.Write(w)
			return
		}

		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxRefreshBody)).Decode(&body); err != nil || body.RefreshToken == "" {
			apierror.NewBadRequest(`body must be a JSON object carrying a non-empty "refresh_token"`).Write(w)
			return
		}

		grant, err := issuer.Refresh(body.RefreshToken)
		if err != nil {
			logging.Info("refresh rejected", "remote", r.RemoteAddr, "reason", err)
			apierror.ErrInvalidToken.Write(w)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		// The response carries a bearer credential: no cache may keep a copy.
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": grant.Access,
			"expires_at":   grant.ExpiresAt.UTC().Format(time.RFC3339),
			"expires_in":   int(time.Until(grant.ExpiresAt).Seconds()),
		})
	}
}
