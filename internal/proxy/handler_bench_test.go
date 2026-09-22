package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gatekey/internal/config"
	"gatekey/internal/token"
)

// BenchmarkProxy_InProcess measures the pure routing, token verification, header injection and handler execution
// without TCP loopback overhead.
func BenchmarkProxy_InProcess(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
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
				PathPrefix: "/bench",
				TargetURL:  upstream.URL,
				InjectHeaders: map[string]string{
					"Authorization": "Bearer upstream-token",
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
	defer gw.Close()

	// Pre-warm token cache
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/bench/v1/ping", nil)
		req.Header.Set("X-App-Token", pair.Access)
		gw.ServeHTTP(rec, req)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest(http.MethodGet, "/bench/v1/ping", nil)
		req.Header.Set("X-App-Token", pair.Access)
		rec := httptest.NewRecorder()

		for pb.Next() {
			rec.Body.Reset()
			gw.ServeHTTP(rec, req)
		}
	})
}

// BenchmarkProxy_RealTCP measures end-to-end performance over real TCP loopback with HTTP keep-alive.
func BenchmarkProxy_RealTCP(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
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
				PathPrefix: "/bench",
				TargetURL:  upstream.URL,
				InjectHeaders: map[string]string{
					"Authorization": "Bearer upstream-token",
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
	defer gw.Close()

	proxyServer := httptest.NewServer(gw)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/bench/v1/ping", nil)
		req.Header.Set("X-App-Token", pair.Access)

		for pb.Next() {
			resp, err := client.Do(req)
			if err != nil {
				b.Fatalf("request failed: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}
