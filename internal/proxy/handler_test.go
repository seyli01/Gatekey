package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gatekey/internal/config"
	"gatekey/internal/credential"
	"gatekey/internal/quota"
	"gatekey/internal/token"
)

// mustIssuer builds the token issuer a gateway needs, from the signing key the
// test configuration declares.
func mustIssuer(t *testing.T, cfg *config.Config) *token.Issuer {
	t.Helper()
	issuer, err := token.NewIssuer([]byte(cfg.Tokens.SigningKey), cfg.Tokens.ParsedAccessTTL, cfg.Tokens.ParsedRefreshTTL)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return issuer
}

// mustToken mints an access token for a route in one line.
func mustToken(t *testing.T, issuer *token.Issuer, installID, routePrefix string) string {
	t.Helper()
	pair, err := issuer.Issue(installID, routePrefix)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return pair.Access
}

func TestProxy_AuthenticationAndHeaderInjection(t *testing.T) {
	// Upstream test server
	var receivedAuthHeader string
	var receivedClientToken string
	var receivedPath string
	var receivedHost string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedClientToken = r.Header.Get("X-App-Token")
		receivedPath = r.URL.Path
		receivedHost = r.Host

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"upstream":"success"}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:     ":8080",
			AuthHeader: "X-App-Token",
		},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{
			{
				PathPrefix: "/openai",
				TargetURL:  upstream.URL,
				InjectHeaders: map[string]string{
					"Authorization": "Bearer upstream-openai-secret",
				},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)

	gateway := NewGateway(cfg, issuer)
	openaiTok := mustToken(t, issuer, "install-openai", "/openai")

	// 1. Request without token -> 401 Unauthorized
	{
		req := httptest.NewRequest(http.MethodGet, "/openai/v1/models", nil)
		rec := httptest.NewRecorder()
		gateway.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for missing token, got %d", rec.Code)
		}
	}

	// 2. Request with invalid token -> 401 Unauthorized
	{
		req := httptest.NewRequest(http.MethodGet, "/openai/v1/models", nil)
		req.Header.Set("X-App-Token", "wrong-token")
		rec := httptest.NewRecorder()
		gateway.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for wrong token, got %d", rec.Code)
		}
	}

	// 3. Request for unknown route -> 404 Not Found
	{
		req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
		req.Header.Set("X-App-Token", openaiTok)
		rec := httptest.NewRecorder()
		gateway.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 for unknown route, got %d", rec.Code)
		}
	}

	// 4. Request with valid token -> 200 OK + Header injection + Token purge
	{
		req := httptest.NewRequest(http.MethodGet, "/openai/v1/models", nil)
		req.Header.Set("X-App-Token", openaiTok)
		rec := httptest.NewRecorder()
		gateway.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for valid token, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		if receivedClientToken != "" {
			t.Errorf("expected X-App-Token to be stripped upstream, got %q", receivedClientToken)
		}

		if receivedAuthHeader != "Bearer upstream-openai-secret" {
			t.Errorf("expected Authorization header to be injected, got %q", receivedAuthHeader)
		}

		if receivedPath != "/v1/models" {
			t.Errorf("expected stripped path /v1/models, got %q", receivedPath)
		}

		expectedHost := strings.TrimPrefix(upstream.URL, "http://")
		if receivedHost != expectedHost {
			t.Errorf("expected host %q, got %q", expectedHost, receivedHost)
		}
	}
}

func TestProxy_SSEStreaming(t *testing.T) {
	// Upstream SSE server sending 3 chunks with flushes
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected flusher")
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		for i := 1; i <= 3; i++ {
			_, _ = fmt.Fprintf(w, "data: event %d\n\n", i)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			AuthHeader: "X-App-Token",
		},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{
			{
				PathPrefix: "/stream",
				TargetURL:  upstream.URL,
			},
		},
	}
	_ = cfg.Validate()

	issuer := mustIssuer(t, cfg)

	gateway := NewGateway(cfg, issuer)
	streamTok := mustToken(t, issuer, "install-stream", "/stream")
	proxyServer := httptest.NewServer(gateway)
	defer proxyServer.Close()

	req, err := http.NewRequest(http.MethodGet, proxyServer.URL+"/stream/events", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-App-Token", streamTok)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	receivedEvents := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("unexpected read error: %v", err)
		}

		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data: event") {
			receivedEvents++
		}
	}

	if receivedEvents != 3 {
		t.Errorf("expected 3 streamed SSE events, got %d", receivedEvents)
	}
}

func BenchmarkGateway_RoutingAndAuth(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			AuthHeader: "X-App-Token",
		},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{
			{
				PathPrefix: "/bench",
				TargetURL:  upstream.URL,
				InjectHeaders: map[string]string{
					"Authorization": "Bearer secret",
				},
			},
		},
	}
	_ = cfg.Validate()

	issuer, err := token.NewIssuer([]byte(cfg.Tokens.SigningKey), cfg.Tokens.ParsedAccessTTL, cfg.Tokens.ParsedRefreshTTL)
	if err != nil {
		b.Fatalf("NewIssuer: %v", err)
	}
	pair, err := issuer.Issue("bench-install", "/bench")
	if err != nil {
		b.Fatalf("Issue: %v", err)
	}

	gw := NewGateway(cfg, issuer)

	req := httptest.NewRequest(http.MethodGet, "/bench/v1/test", nil)
	req.Header.Set("X-App-Token", pair.Access)
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rec = httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
	}
}

func TestProxy_MaxBodySizeExceeded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read body to trigger MaxBytesReader limit
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			AuthHeader:    "X-App-Token",
			MaxBodySizeMB: 1, // 1 MB limit for test
		},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{
			{
				PathPrefix: "/upload",
				TargetURL:  upstream.URL,
			},
		},
	}
	_ = cfg.Validate()

	issuer := mustIssuer(t, cfg)

	gateway := NewGateway(cfg, issuer)
	uploadTok := mustToken(t, issuer, "install-upload", "/upload")
	server := httptest.NewServer(gateway)
	defer server.Close()

	// 1. Send payload within limit (500 KB) -> 200 OK
	{
		smallBody := strings.Repeat("A", 500*1024)
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/upload/data", strings.NewReader(smallBody))
		req.Header.Set("X-App-Token", uploadTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("small payload request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK for 500KB payload, got %d", resp.StatusCode)
		}
	}

	// 2. Send payload exceeding limit (2 MB) -> 413 Request Entity Too Large
	{
		largeBody := strings.Repeat("B", 2*1024*1024)
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/upload/data", strings.NewReader(largeBody))
		req.Header.Set("X-App-Token", uploadTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("large payload request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("expected 413 Request Entity Too Large for 2MB payload, got %d", resp.StatusCode)
		}
	}
}

func TestProxy_RateLimiting(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			AuthHeader: "X-App-Token",
		},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{
			{
				PathPrefix: "/limited",
				TargetURL:  upstream.URL,
				RateLimit: config.RateLimitConfig{
					RequestsPerMinute: 60,
					Burst:             2, // Can only do 2 requests before waiting
				},
			},
		},
	}
	_ = cfg.Validate()

	issuer := mustIssuer(t, cfg)

	gateway := NewGateway(cfg, issuer)
	aliceTok := mustToken(t, issuer, "install-alice", "/limited")
	bobTok := mustToken(t, issuer, "install-bob", "/limited")
	defer gateway.Close()
	server := httptest.NewServer(gateway)
	defer server.Close()

	client := &http.Client{}

	// Request 1 for Alice -> 200 OK, remaining = 1
	{
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/limited/v1/test", nil)
		req.Header.Set("X-App-Token", aliceTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req 1 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on req 1, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-RateLimit-Remaining") != "1" {
			t.Errorf("expected X-RateLimit-Remaining: 1, got %s", resp.Header.Get("X-RateLimit-Remaining"))
		}
	}

	// Request 2 for Alice -> 200 OK, remaining = 0
	{
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/limited/v1/test", nil)
		req.Header.Set("X-App-Token", aliceTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req 2 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on req 2, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-RateLimit-Remaining") != "0" {
			t.Errorf("expected X-RateLimit-Remaining: 0, got %s", resp.Header.Get("X-RateLimit-Remaining"))
		}
	}

	// Request 3 for Alice -> 429 Too Many Requests, Retry-After present
	{
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/limited/v1/test", nil)
		req.Header.Set("X-App-Token", aliceTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req 3 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("expected 429 Too Many Requests on req 3, got %d", resp.StatusCode)
		}
		if resp.Header.Get("Retry-After") == "" {
			t.Errorf("expected Retry-After header on 429 response, got none")
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(bodyBytes), "rate_limit_exceeded") {
			t.Errorf("expected rate_limit_exceeded in body, got: %s", string(bodyBytes))
		}
	}

	// Request 1 for Bob -> 200 OK (must NOT be blocked by Alice's exhaustion)
	{
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/limited/v1/test", nil)
		req.Header.Set("X-App-Token", bobTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req bob failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on bob's first req, got %d", resp.StatusCode)
		}
	}
}

func TestProxy_QuotaEnforcement(t *testing.T) {
	// Upstream test server simulating OpenAI responses
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "sse") {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n"))
			_, _ = w.Write([]byte("data: {\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":50,\"total_tokens\":150}}\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Hello world"}}],"usage":{"prompt_tokens":600,"completion_tokens":400,"total_tokens":1000}}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:     ":8080",
			AuthHeader: "X-App-Token",
		},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{
			{
				PathPrefix: "/tokens",
				TargetURL:  upstream.URL,
				Quota: config.QuotaConfig{
					MaxTokens: 1500, // 1500 tokens limit. 1st req uses 1000, 2nd req uses 1000 (total 2000), 3rd blocked
					PricingPerMillion: config.PricingConfig{
						PromptUSD:     5.0,
						CompletionUSD: 15.0,
					},
				},
			},
			{
				PathPrefix: "/budget",
				TargetURL:  upstream.URL,
				Quota: config.QuotaConfig{
					MaxBudgetUSD: 0.015, // $0.015 limit. Each req costs (600*10 + 400*20)/1M = $0.014. 2nd req completes, 3rd blocked ($0.028 > $0.015)
					PricingPerMillion: config.PricingConfig{
						PromptUSD:     10.0,
						CompletionUSD: 20.0,
					},
				},
			},
			{
				PathPrefix: "/stream",
				TargetURL:  upstream.URL,
				Quota: config.QuotaConfig{
					MaxTokens: 200, // 200 tokens limit. Each stream req uses 150 tokens. 2nd req pushes to 300, 3rd blocked
				},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)

	gw := NewGateway(cfg, issuer)
	budgetTok := mustToken(t, issuer, "install-budget", "/budget")
	quotaTok1 := mustToken(t, issuer, "install-quota-1", "/tokens")
	quotaTok2 := mustToken(t, issuer, "install-quota-2", "/tokens")
	streamQuotaTok := mustToken(t, issuer, "install-stream-q", "/stream")
	defer gw.Close()

	quotaDB := filepath.Join(t.TempDir(), "quotas.json")
	qm := quota.NewManager(quotaDB, 10*time.Millisecond)
	gw.SetQuotaManager(qm)

	server := httptest.NewServer(gw)
	defer server.Close()
	client := server.Client()

	// --- 1. Token Quota Limit Testing ---
	// Request 1: client-token-1 -> 200 OK (0 tokens used previously)
	{
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/tokens/chat/completions", strings.NewReader(`{}`))
		req.Header.Set("X-App-Token", quotaTok1)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req 1 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Quota-Tokens-Limit") != "1500" {
			t.Errorf("expected limit 1500, got %s", resp.Header.Get("X-Quota-Tokens-Limit"))
		}
		if resp.Header.Get("X-Quota-Tokens-Used") != "0" {
			t.Errorf("expected used 0, got %s", resp.Header.Get("X-Quota-Tokens-Used"))
		}
	}

	// Request 2: client-token-1 -> 200 OK (1000 tokens used previously < 1500 limit)
	{
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/tokens/chat/completions", strings.NewReader(`{}`))
		req.Header.Set("X-App-Token", quotaTok1)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req 2 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Quota-Tokens-Used") != "1000" {
			t.Errorf("expected used 1000, got %s", resp.Header.Get("X-Quota-Tokens-Used"))
		}
	}

	// Request 3: client-token-1 -> 402 Payment Required (2000 tokens used >= 1500 limit)
	{
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/tokens/chat/completions", strings.NewReader(`{}`))
		req.Header.Set("X-App-Token", quotaTok1)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("req 3 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusPaymentRequired {
			t.Fatalf("expected 402 Payment Required, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Quota-Tokens-Used") != "2000" {
			t.Errorf("expected used 2000, got %s", resp.Header.Get("X-Quota-Tokens-Used"))
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "token_quota_exceeded") {
			t.Errorf("expected token_quota_exceeded error, got: %s", string(body))
		}
	}

	// Request 1: client-token-2 -> 200 OK (client isolation)
	{
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/tokens/chat/completions", strings.NewReader(`{}`))
		req.Header.Set("X-App-Token", quotaTok2)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client 2 req failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for isolated client 2, got %d", resp.StatusCode)
		}
	}

	// --- 2. Dollar Budget Limit Testing ---
	// Request 1: client-budget -> 200 OK
	{
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/budget/chat/completions", strings.NewReader(`{}`))
		req.Header.Set("X-App-Token", budgetTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("budget req 1 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	}

	// Request 2: client-budget -> 200 OK ($0.014 used previously < $0.015 limit)
	{
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/budget/chat/completions", strings.NewReader(`{}`))
		req.Header.Set("X-App-Token", budgetTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("budget req 2 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	}

	// Request 3: client-budget -> 402 Payment Required ($0.028 used previously >= $0.015 limit)
	{
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/budget/chat/completions", strings.NewReader(`{}`))
		req.Header.Set("X-App-Token", budgetTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("budget req 3 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusPaymentRequired {
			t.Fatalf("expected 402 Payment Required for budget, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "budget_quota_exceeded") {
			t.Errorf("expected budget_quota_exceeded error, got: %s", string(body))
		}
	}

	// --- 3. Streaming SSE Quota Testing ---
	// Request 1: client-stream -> 200 OK (0 tokens previously)
	{
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/stream/sse", nil)
		req.Header.Set("X-App-Token", streamQuotaTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("stream req 1 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "Hello") {
			t.Errorf("expected stream body content, got: %s", string(body))
		}
	}

	// Request 2: client-stream -> 200 OK (150 tokens used previously < 200 limit)
	{
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/stream/sse", nil)
		req.Header.Set("X-App-Token", streamQuotaTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("stream req 2 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	}

	// Request 3: client-stream -> 402 Payment Required (300 tokens used previously >= 200 limit)
	{
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/stream/sse", nil)
		req.Header.Set("X-App-Token", streamQuotaTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("stream req 3 failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusPaymentRequired {
			t.Fatalf("expected 402 Payment Required for stream, got %d", resp.StatusCode)
		}
	}
}

// End-to-end guard for the Anthropic accounting bug: the observer used to stop at
// the first usage block, so message_start's input_tokens were recorded and every
// output token — the expensive half — was billed as zero.
func TestProxy_AnthropicStreamingUsageIsFullyRecorded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)

		chunks := []string{
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2145,\"output_tokens\":1}}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Bonjour\"}}\n\n",
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":873}}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		}
		for _, c := range chunks {
			_, _ = w.Write([]byte(c))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix: "/anthropic",
			TargetURL:  upstream.URL,
			Quota: config.QuotaConfig{
				MaxTokens: 100000,
				PricingPerMillion: config.PricingConfig{
					PromptUSD:     3.0,
					CompletionUSD: 15.0,
				},
			},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)

	gw := NewGateway(cfg, issuer)
	anthropicTok := mustToken(t, issuer, "install-anthropic", "/anthropic")
	defer gw.Close()

	qm := quota.NewManager(filepath.Join(t.TempDir(), "quotas.json"), 1*time.Minute)
	gw.SetQuotaManager(qm)

	server := httptest.NewServer(gw)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/anthropic/v1/messages", strings.NewReader(`{"stream":true}`))
	req.Header.Set("X-App-Token", anthropicTok)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	usage := waitUsage(t, qm, "/anthropic", "install-anthropic")
	if usage.PromptTokens != 2145 {
		t.Errorf("expected 2145 prompt tokens, got %d", usage.PromptTokens)
	}
	if usage.CompletionTokens != 873 {
		t.Errorf("expected 873 completion tokens, got %d", usage.CompletionTokens)
	}

	// 2145 * $3/1M + 873 * $15/1M = $0.006435 + $0.013095 = $0.01953
	const want = 0.01953
	if diff := usage.TotalCostUSD - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("expected cost $%.6f, got $%.6f", want, usage.TotalCostUSD)
	}
}

// signedTokenFixture builds a gateway with two routes and quotas enabled, so
// identity keying and route binding can both be observed.
func signedTokenFixture(t *testing.T, upstreamURL string, q config.QuotaConfig) (*Gateway, *token.Issuer) {
	t.Helper()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{
			{
				PathPrefix: "/openai",
				TargetURL:  upstreamURL,
				Quota:      q,
			},
			{
				PathPrefix: "/anthropic",
				TargetURL:  upstreamURL,
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	t.Cleanup(gw.Close)

	return gw, issuer
}

func TestProxy_TokenIsBoundToItsRouteAndKind(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	gw, issuer := signedTokenFixture(t, upstream.URL, config.QuotaConfig{})
	server := httptest.NewServer(gw)
	defer server.Close()

	pair, err := issuer.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	call := func(path, tok string) int {
		req, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
		req.Header.Set("X-App-Token", tok)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if got := call("/openai/v1/models", pair.Access); got != http.StatusOK {
		t.Errorf("signed access token: status = %d, want 200", got)
	}
	// A token minted for /openai must not reach another route's budget.
	if got := call("/anthropic/v1/messages", pair.Access); got != http.StatusUnauthorized {
		t.Errorf("cross-route token: status = %d, want 401", got)
	}
	// The refresh token is not a proxy credential, however long it lives.
	if got := call("/openai/v1/models", pair.Refresh); got != http.StatusUnauthorized {
		t.Errorf("refresh token on proxy path: status = %d, want 401", got)
	}
	if got := call("/openai/v1/models", "not-a-token"); got != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", got)
	}
}

// Quotas key on the install ID, not on the token string. Were they keyed on the
// token, every refresh would mint a fresh key and silently reset the budget the
// installation had already spent.
func TestProxy_QuotaFollowsInstallAcrossRefresh(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":600,"completion_tokens":0}}`))
	}))
	defer upstream.Close()

	gw, issuer := signedTokenFixture(t, upstream.URL, config.QuotaConfig{MaxTokens: 1000})
	qm := quota.NewManager(filepath.Join(t.TempDir(), "quotas.json"), 1*time.Minute)
	gw.SetQuotaManager(qm)

	server := httptest.NewServer(gw)
	defer server.Close()

	pair, err := issuer.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	call := func(tok string) int {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/openai/v1/chat/completions", nil)
		req.Header.Set("X-App-Token", tok)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	// Spend 600 of the 1000 allowed tokens under the original access token.
	if got := call(pair.Access); got != http.StatusOK {
		t.Fatalf("first call: status = %d, want 200", got)
	}

	// Rotate the credential the way a client would after the access TTL elapses.
	grant, err := issuer.Refresh(pair.Refresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if grant.Access == pair.Access {
		t.Fatal("refresh must mint a different access token")
	}

	// Spending another 600 takes the install to 1200, past its 1000 cap.
	if got := call(grant.Access); got != http.StatusOK {
		t.Fatalf("second call: status = %d, want 200", got)
	}
	if got := call(grant.Access); got != http.StatusPaymentRequired {
		t.Errorf("third call: status = %d, want 402 -- the refreshed token reset the budget", got)
	}
}

// A denylisted install must lose access on the very next request, with no cache
// able to keep it alive.
func TestProxy_DenylistCutsAccessImmediately(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw, issuer := signedTokenFixture(t, upstream.URL, config.QuotaConfig{})
	server := httptest.NewServer(gw)
	defer server.Close()

	pair, err := issuer.Issue("install-stolen", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	call := func() int {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/openai/v1/models", nil)
		req.Header.Set("X-App-Token", pair.Access)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if got := call(); got != http.StatusOK {
		t.Fatalf("before revocation: status = %d, want 200", got)
	}

	issuer.SetDenylist(token.NewDenylist([]string{"install-stolen"}))

	if got := call(); got != http.StatusUnauthorized {
		t.Errorf("after revocation: status = %d, want 401", got)
	}
}

// The Rewrite closure runs on the request path, long after updateRoutes released
// the lock it wrote gw.authHeader under. Reading that field from inside the
// closure races with a concurrent reload, and the consequence is not academic:
// the request would strip whatever header the reload just installed instead of
// the one it authenticated with, forwarding the client's credential upstream.
func TestProxy_ReloadDuringTrafficDoesNotLeakTheClientToken(t *testing.T) {
	var leaked atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-App-Token") != "" {
			leaked.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Both configurations authenticate on X-App-Token; only the upstream path
	// differs, so every request stays authorised while reloads keep rewriting the
	// field the closure used to read.
	build := func(strip bool) *config.Config {
		cfg := &config.Config{
			Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
			Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
			Routes: []config.RouteConfig{{
				PathPrefix:  "/openai",
				TargetURL:   upstream.URL,
				StripPrefix: &strip,
			}},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config validation failed: %v", err)
		}
		return cfg
	}

	baseCfg := build(true)
	issuer := mustIssuer(t, baseCfg)
	gw := NewGateway(baseCfg, issuer)
	defer gw.Close()

	accessToken := mustToken(t, issuer, "install-abc", "/openai")

	server := httptest.NewServer(gw)
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			gw.updateRoutes(build(i%2 == 0))
		}
	}()

	for i := 0; i < 200; i++ {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/openai/v1/models", nil)
		req.Header.Set("X-App-Token", accessToken)
		resp, err := server.Client().Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	<-done

	if leaked.Load() {
		t.Error("a client credential reached the upstream during a reload")
	}
}

// Without an allowlist every caller header reaches the provider. Some of them are
// not inert: OpenAI-Organization decides who gets billed, and OpenAI-Beta switches
// on behaviour the operator never chose.
func TestProxy_HeaderAllowlist(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix: "/openai",
			TargetURL:  upstream.URL,
			// The route opts one provider header in, and nothing else.
			ForwardHeaders: []string{"OpenAI-Beta"},
			InjectHeaders:  map[string]string{"Authorization": "Bearer upstream-secret"},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	defer gw.Close()
	accessTok := mustToken(t, issuer, "install-abc", "/openai")

	server := httptest.NewServer(gw)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/openai/v1/chat", strings.NewReader("{}"))
	req.Header.Set("X-App-Token", accessTok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("OpenAI-Beta", "assistants=v2")
	req.Header.Set("OpenAI-Organization", "org-someone-elses")
	req.Header.Set("Cookie", "session=private")
	req.Header.Set("X-Internal-Trace", "leak-me")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	got := <-received

	// Allowed through.
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type must always be forwarded, got %q", got.Get("Content-Type"))
	}
	if got.Get("OpenAI-Beta") != "assistants=v2" {
		t.Errorf("an allowlisted header must be forwarded, got %q", got.Get("OpenAI-Beta"))
	}
	if got.Get("Authorization") != "Bearer upstream-secret" {
		t.Errorf("injected secret = %q", got.Get("Authorization"))
	}

	// Dropped.
	for _, name := range []string{"Openai-Organization", "Cookie", "X-Internal-Trace", "X-App-Token"} {
		if v := got.Get(name); v != "" {
			t.Errorf("%s reached the upstream with value %q", name, v)
		}
	}
}

// The caller's credential is never forwarded, even if forward_headers names it.
// A configuration mistake must not be able to hand it to the provider.
func TestProxy_AuthHeaderIsNeverForwardable(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix: "/openai",
			TargetURL:  upstream.URL,
			// Deliberately wrong: the operator allowlisted the credential header.
			ForwardHeaders: []string{"X-App-Token"},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	defer gw.Close()
	accessTok := mustToken(t, issuer, "install-abc", "/openai")

	server := httptest.NewServer(gw)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/openai/v1/models", nil)
	req.Header.Set("X-App-Token", accessTok)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if v := (<-received).Get("X-App-Token"); v != "" {
		t.Errorf("the caller's credential reached the upstream: %q", v)
	}
}

// A route may narrow the server-wide body limit, so a text-only route does not
// accept the tens of megabytes a vision route needs.
func TestProxy_PerRouteBodySizeOverride(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token", MaxBodySizeMB: 50},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{
			{PathPrefix: "/vision", TargetURL: upstream.URL}, // inherits 50 MB
			{PathPrefix: "/text", TargetURL: upstream.URL, MaxBodySizeMB: 1},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	defer gw.Close()
	visionTok := mustToken(t, issuer, "install-vision", "/vision")
	textTok := mustToken(t, issuer, "install-text", "/text")

	server := httptest.NewServer(gw)
	defer server.Close()

	post := func(path, tok string, size int) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+path+"/upload", strings.NewReader(strings.Repeat("a", size)))
		req.Header.Set("X-App-Token", tok)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	const twoMB = 2 * 1024 * 1024
	if got := post("/vision", visionTok, twoMB); got != http.StatusOK {
		t.Errorf("2 MB under a 50 MB route: status = %d, want 200", got)
	}
	if got := post("/text", textTok, twoMB); got != http.StatusRequestEntityTooLarge {
		t.Errorf("2 MB against a 1 MB route: status = %d, want 413", got)
	}
	if got := post("/text", textTok, 512); got != http.StatusOK {
		t.Errorf("512 B against a 1 MB route: status = %d, want 200", got)
	}
}

// An upstream that accepts the connection and stalls forever must not pin a
// connection and a goroutine for the lifetime of the process.
func TestProxy_RequestTimeoutCutsAStalledUpstream(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	defer close(release)

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix:     "/slow",
			TargetURL:      upstream.URL,
			RequestTimeout: "150ms",
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	defer gw.Close()
	slowTok := mustToken(t, issuer, "install-slow", "/slow")

	server := httptest.NewServer(gw)
	defer server.Close()

	start := time.Now()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/slow/hang", nil)
	req.Header.Set("X-App-Token", slowTok)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 once the deadline passes", resp.StatusCode)
	}
	if elapsed > 3*time.Second {
		t.Errorf("the request took %v; the deadline did not fire", elapsed)
	}
}

// A single route commonly serves models an order of magnitude apart in price.
// Charging them all at one rate makes max_budget_usd meaningless, so the model
// the provider reports has to select the price.
func TestProxy_PerModelPricing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		model := r.URL.Query().Get("m")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"model":%q,"usage":{"prompt_tokens":1000000,"completion_tokens":0,"total_tokens":1000000}}`, model)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix: "/openai",
			TargetURL:  upstream.URL,
			Quota: config.QuotaConfig{
				MaxTokens:         100000000,
				PricingPerMillion: config.PricingConfig{PromptUSD: 1.00},
				PricingByModel: map[string]config.PricingConfig{
					"gpt-5":      {PromptUSD: 10.00},
					"gpt-5-mini": {PromptUSD: 0.20},
				},
			},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	defer gw.Close()

	server := httptest.NewServer(gw)
	defer server.Close()

	// Exactly one million prompt tokens, so the recorded cost is the unit price.
	spend := func(t *testing.T, install, model string) float64 {
		t.Helper()
		qm := quota.NewManager(filepath.Join(t.TempDir(), "quotas.json"), time.Hour)
		gw.SetQuotaManager(qm)

		req, _ := http.NewRequest(http.MethodGet, server.URL+"/openai/v1/chat?m="+model, nil)
		req.Header.Set("X-App-Token", mustToken(t, issuer, install, "/openai"))
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		return waitUsage(t, qm, "/openai", install).TotalCostUSD
	}

	cases := map[string]struct {
		model string
		want  float64
	}{
		"priced model":            {"gpt-5", 10.00},
		"versioned name prefixes": {"gpt-5-2026-01-01", 10.00},
		"longest prefix wins":     {"gpt-5-mini-2026-01-01", 0.20},
		"unknown falls back":      {"claude-opus-5", 1.00},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := spend(t, "install-"+tc.model, tc.model)
			if diff := got - tc.want; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("cost for %q = $%.4f, want $%.4f", tc.model, got, tc.want)
			}
		})
	}
}

// End to end: the route carries an expiring OAuth credential, and the upstream
// must receive a freshly renewed token that the caller never saw.
func TestProxy_OAuthCredentialIsRenewedAndInjected(t *testing.T) {
	var issued atomic.Int64
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := issued.Add(1)
		fmt.Fprintf(w, `{"access_token":"live-%d","expires_in":3600,"token_type":"Bearer"}`, n)
	}))
	defer tokenServer.Close()

	seen := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix: "/claude",
			TargetURL:  upstream.URL,
			Credential: config.CredentialConfig{
				Type:         config.CredentialTypeOAuth,
				TokenURL:     tokenServer.URL,
				ClientID:     "cid",
				RefreshToken: "refresh-v1",
			},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	store, err := credential.NewFileStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	gw.SetCredentialStore(store)
	defer gw.Close()
	accessTok := mustToken(t, issuer, "install-abc", "/claude")

	server := httptest.NewServer(gw)
	defer server.Close()

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/claude/v1/messages", nil)
		req.Header.Set("X-App-Token", accessTok)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if got := <-seen; got != "Bearer live-1" {
			t.Errorf("upstream saw %q, want the renewed OAuth token", got)
		}
	}

	// Two proxied requests, one renewal: the token is cached, not re-fetched.
	if got := issued.Load(); got != 1 {
		t.Errorf("renewed %d times for 2 requests, want 1", got)
	}
}

// A rejected refresh token needs a human, so the caller must be told that
// plainly instead of receiving an opaque provider error later.
func TestProxy_OAuthReauthRequiredIsReported(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer tokenServer.Close()

	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix: "/claude",
			TargetURL:  upstream.URL,
			Credential: config.CredentialConfig{
				Type:         config.CredentialTypeOAuth,
				TokenURL:     tokenServer.URL,
				RefreshToken: "revoked",
			},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	store, err := credential.NewFileStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	gw.SetCredentialStore(store)
	defer gw.Close()

	server := httptest.NewServer(gw)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/claude/v1/messages", nil)
	req.Header.Set("X-App-Token", mustToken(t, issuer, "install-abc", "/claude"))
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if !strings.Contains(string(body), "reauth_required") {
		t.Errorf("body = %s, want the reauth_required code", body)
	}
	// Never fail open: no request may reach the provider without a credential.
	if reached {
		t.Error("the request reached the upstream despite an unusable credential")
	}
}

// waitUsage returns an install's usage once the gateway has recorded it.
//
// The gateway records usage after the last byte is sent, so a client can finish
// reading the response first; reading the counter straight away failed about
// once in a hundred runs.
func waitUsage(t *testing.T, qm *quota.Manager, route, install string) quota.TokenUsage {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if u := qm.GetUsage(route, install); u.TotalTokens > 0 {
			return u
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no usage recorded for %s on %s", install, route)
	return quota.TokenUsage{}
}

// A route with only a total limit must still be checked, and the caller that
// hits it learns nothing about the operator's spending.
func TestProxy_TotalQuotaAcrossInstalls(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":600,"completion_tokens":400,"total_tokens":1000}}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token"},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{
			PathPrefix: "/r",
			TargetURL:  upstream.URL,
			Quota:      config.QuotaConfig{TotalMaxTokens: 1500},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	defer gw.Close()
	qm := quota.NewManager(filepath.Join(t.TempDir(), "quotas.json"), time.Hour)
	gw.SetQuotaManager(qm)
	server := httptest.NewServer(gw)
	defer server.Close()

	call := func(install string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/r/chat/completions", strings.NewReader(`{}`))
		req.Header.Set("X-App-Token", mustToken(t, issuer, install, "/r"))
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	for _, install := range []string{"a", "b"} {
		if resp := call(install); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", install, resp.StatusCode)
		}
		waitUsage(t, qm, "/r", install)
	}

	resp := call("c")
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("route total is 2000 of 1500: got %d, want 402", resp.StatusCode)
	}
	for name := range resp.Header {
		if strings.HasPrefix(name, "X-Quota-") {
			t.Errorf("header %s exposed on a route with no per-install limit", name)
		}
	}
}

// Responses larger than the copy buffer, and many at once sharing the pool,
// must still arrive byte for byte.
func TestProxy_LargeResponsesSurviveTheSmallCopyBuffer(t *testing.T) {
	payload := make([]byte, 5<<20+123) // several hundred buffers' worth, not a multiple
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{PathPrefix: "/r", TargetURL: upstream.URL}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	issuer := mustIssuer(t, cfg)
	gw := NewGateway(cfg, issuer)
	defer gw.Close()
	server := httptest.NewServer(gw)
	defer server.Close()
	tok := mustToken(t, issuer, "inst", "/r")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, server.URL+"/r/file", nil)
			req.Header.Set("X-App-Token", tok)
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(got, payload) {
				t.Errorf("got %d bytes (err %v), want %d identical bytes", len(got), err, len(payload))
			}
		}()
	}
	wg.Wait()
}
