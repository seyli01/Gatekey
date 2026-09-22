package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gatekey/internal/config"
	"gatekey/internal/metrics"
	"gatekey/internal/proxy"
	"gatekey/internal/token"
)

// mustIssuer builds the token issuer a gateway needs from a configuration's
// signing key.
func mustIssuer(t *testing.T, cfg *config.Config) *token.Issuer {
	t.Helper()
	issuer, err := token.NewIssuer([]byte(cfg.Tokens.SigningKey), cfg.Tokens.ParsedAccessTTL, cfg.Tokens.ParsedRefreshTTL)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return issuer
}

func setupTestRouter(t *testing.T, initialContent string) (http.Handler, *config.Manager, *metrics.Collector) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(initialContent), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatalf("failed to create config manager: %v", err)
	}

	metricsCol := metrics.NewCollector(filepath.Join(tmpDir, "metrics.json"), 1*time.Minute)
	t.Cleanup(func() { metricsCol.Close() })

	issuer := mustIssuer(t, cfgMgr.Get())

	gateway := proxy.NewGateway(cfgMgr.Get(), issuer)
	gateway.AttachConfigManager(cfgMgr)
	gateway.SetMetricsCollector(metricsCol)

	router := NewRouter(Options{
		Gateway:   gateway,
		ConfigMgr: cfgMgr,
		Collector: metricsCol,
	})

	return router, cfgMgr, metricsCol
}

func TestEndpoints_Healthz(t *testing.T) {
	rawCfg := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/dummy"
    target_url: "http://127.0.0.1:9999"
`
	router, _, _ := setupTestRouter(t, rawCfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK on /healthz, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("unexpected body: %s", rec.Body.String())
	}
}

func TestEndpoints_Metrics(t *testing.T) {
	rawCfg := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/dummy"
    target_url: "http://127.0.0.1:9999"
`
	router, _, _ := setupTestRouter(t, rawCfg)

	// 1. Telemetry leaks routes, masked tokens and spend: remote IPs must be refused.
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "203.0.113.7:4321"
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden on /metrics from remote IP, got %d", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "uptime") {
			t.Errorf("telemetry leaked to a remote caller: %s", rec.Body.String())
		}
	}

	// 2. Allowed loopback IP
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK on /metrics, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "uptime") {
			t.Errorf("expected telemetry output, got: %s", rec.Body.String())
		}
	}
}

func TestEndpoints_AdminReloadLoopback(t *testing.T) {
	rawCfg := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/dummy"
    target_url: "http://127.0.0.1:9999"
`
	router, _, _ := setupTestRouter(t, rawCfg)

	// 1. Disallowed non-loopback IP
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/-/reload", nil)
		req.RemoteAddr = "192.168.1.50:4321"
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for remote IP, got %d", rec.Code)
		}
	}

	// 2. Allowed loopback IP
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/-/reload", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for loopback IP, got %d. Body: %s", rec.Code, rec.Body.String())
		}
	}
}

// setupRefreshRouter mounts a router whose gateway has signed tokens enabled.
func setupRefreshRouter(t *testing.T) (http.Handler, *token.Issuer) {
	t.Helper()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix: "/openai",
			TargetURL:  "http://127.0.0.1:9999",
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gateway := proxy.NewGateway(cfg, issuer)
	t.Cleanup(gateway.Close)
	gateway.SetIssuer(issuer)

	return NewRouter(Options{Gateway: gateway}), issuer
}

func postRefresh(t *testing.T, router http.Handler, body, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/-/refresh", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	router.ServeHTTP(rec, req)
	return rec
}

// Unlike /metrics and /-/reload this endpoint must answer remote callers: the
// client application refreshing its token runs wherever the user is.
func TestEndpoints_RefreshIsReachableRemotely(t *testing.T) {
	router, issuer := setupRefreshRouter(t)

	pair, err := issuer.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	rec := postRefresh(t, router, `{"refresh_token":"`+pair.Refresh+`"}`, "203.0.113.7:4321")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from a remote IP, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q: the body carries a bearer credential", got, "no-store")
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want a positive number of seconds", body.ExpiresIn)
	}
	if _, err := issuer.VerifyAccess(body.AccessToken, "/openai"); err != nil {
		t.Errorf("the returned access token does not verify: %v", err)
	}
}

// Every rejection must look the same, so a caller cannot use the endpoint to
// learn whether a token was forged, expired or revoked.
func TestEndpoints_RefreshRejectionsAreOpaque(t *testing.T) {
	router, issuer := setupRefreshRouter(t)

	pair, err := issuer.Issue("install-revoked", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	issuer.SetDenylist(token.NewDenylist([]string{"install-revoked"}))

	forged, err := issuer.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cases := map[string]string{
		"revoked install":         pair.Refresh,
		"access token as refresh": forged.Access,
		"garbage":                 "not-a-token",
		"empty string":            "",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			rec := postRefresh(t, router, `{"refresh_token":"`+raw+`"}`, "203.0.113.7:4321")
			if rec.Code == http.StatusOK {
				t.Fatalf("expected a rejection, got 200: %s", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "revoked") || strings.Contains(rec.Body.String(), "expired") {
				t.Errorf("the response discloses why it failed: %s", rec.Body.String())
			}
		})
	}
}

func TestEndpoints_RefreshRejectsBadRequests(t *testing.T) {
	router, _ := setupRefreshRouter(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/-/refresh", nil)
	req.RemoteAddr = "203.0.113.7:4321"
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /-/refresh: status = %d, want 405", rec.Code)
	}

	if rec := postRefresh(t, router, `{"refresh_token":`, "203.0.113.7:4321"); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON: status = %d, want 400", rec.Code)
	}
	if rec := postRefresh(t, router, `{}`, "203.0.113.7:4321"); rec.Code != http.StatusBadRequest {
		t.Errorf("missing field: status = %d, want 400", rec.Code)
	}
}
