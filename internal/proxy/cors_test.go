package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gatekey/internal/config"
)

const allowedOrigin = "https://app.example.com"

// corsSetup serves one route through the CORS wrapper, in front of an upstream
// that sets CORS headers of its own and counts the calls it receives.
func corsSetup(t *testing.T, origins ...string) (*Gateway, http.Handler, *config.Config, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token", CORSOrigins: origins},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{PathPrefix: "/r", TargetURL: upstream.URL}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	gw := NewGateway(cfg, mustIssuer(t, cfg))
	t.Cleanup(gw.Close)
	return gw, gw.CORS(gw), cfg, &calls
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func preflight(origin string) *http.Request {
	r := httptest.NewRequest(http.MethodOptions, "/r/v1/chat/completions", nil)
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "content-type, x-app-token, x-stainless-os")
	return r
}

// Off by default: native apps and backends need no CORS, and a page must not be
// able to read anything.
func TestCORS_OffByDefault(t *testing.T) {
	gw, h, _, _ := corsSetup(t)
	r := httptest.NewRequest(http.MethodPost, "/r/v1/chat/completions", strings.NewReader(`{}`))
	r.Header.Set("Origin", allowedOrigin)
	r.Header.Set("X-App-Token", mustToken(t, gw.Issuer(), "inst", "/r"))
	rec := serve(h, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	// The upstream's own "*" must not leak through either.
	for name := range rec.Header() {
		if strings.HasPrefix(name, "Access-Control-") {
			t.Errorf("CORS is off, yet %s = %q was sent", name, rec.Header().Get(name))
		}
	}
}

// A preflight from an allowed origin is answered here, without a token, and
// never reaches the provider.
func TestCORS_PreflightFromAllowedOrigin(t *testing.T) {
	_, h, _, calls := corsSetup(t, allowedOrigin)
	rec := serve(h, preflight(allowedOrigin))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rec.Code)
	}
	for name, want := range map[string]string{
		"Access-Control-Allow-Origin":  allowedOrigin,
		"Access-Control-Allow-Headers": "content-type, x-app-token, x-stainless-os",
		"Access-Control-Max-Age":       corsPreflightMaxAge,
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if !strings.Contains(rec.Header().Get("Access-Control-Allow-Methods"), "POST") {
		t.Errorf("Allow-Methods %q lacks POST", rec.Header().Get("Access-Control-Allow-Methods"))
	}
	if calls.Load() != 0 {
		t.Error("a preflight reached the provider")
	}
}

func TestCORS_RefusedOriginGetsNoHeaders(t *testing.T) {
	gw, h, _, calls := corsSetup(t, allowedOrigin)

	rec := serve(h, preflight("https://evil.example"))
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("refused preflight: status %d, Allow-Origin %q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}

	r := httptest.NewRequest(http.MethodPost, "/r/v1/chat/completions", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("X-App-Token", mustToken(t, gw.Issuer(), "inst", "/r"))
	rec = serve(h, r)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("refused origin was allowed: %q", got)
	}
	if !strings.Contains(strings.Join(rec.Header().Values("Vary"), ","), "Origin") {
		t.Error("responses must vary on Origin, or a cache could serve one origin's answer to another")
	}
	if calls.Load() != 1 {
		t.Errorf("provider saw %d calls, want 1: CORS is enforced by the browser, not by blocking", calls.Load())
	}
}

// The provider's CORS headers would be added next to Gatekey's, and a browser
// refuses a response with two Allow-Origin values.
func TestCORS_ProxiedResponseCarriesExactlyGatekeysHeaders(t *testing.T) {
	gw, h, _, _ := corsSetup(t, allowedOrigin)
	r := httptest.NewRequest(http.MethodPost, "/r/v1/chat/completions", strings.NewReader(`{}`))
	r.Header.Set("Origin", allowedOrigin)
	r.Header.Set("X-App-Token", mustToken(t, gw.Issuer(), "inst", "/r"))
	rec := serve(h, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != allowedOrigin {
		t.Errorf("Allow-Origin = %q, want exactly [%q]", got, allowedOrigin)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("the provider's Allow-Credentials leaked through: %q", got)
	}
}

// Gatekey's own errors must be readable too, or a web app sees an opaque
// network failure instead of "token expired" or "quota exceeded".
func TestCORS_ErrorsAreReadableByTheAllowedOrigin(t *testing.T) {
	_, h, _, _ := corsSetup(t, allowedOrigin)
	r := httptest.NewRequest(http.MethodPost, "/r/v1/chat/completions", strings.NewReader(`{}`))
	r.Header.Set("Origin", allowedOrigin)
	rec := serve(h, r) // no token

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Errorf("401 carries Allow-Origin %q, want %q", got, allowedOrigin)
	}
}

func TestCORS_WildcardAllowsAnyOrigin(t *testing.T) {
	_, h, _, _ := corsSetup(t, "*")
	for _, origin := range []string{"https://a.example", "tauri://localhost"} {
		if got := serve(h, preflight(origin)).Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("%s: Allow-Origin %q, want the origin echoed", origin, got)
		}
	}
	// A request without an Origin is not a browser's cross-origin call.
	r := httptest.NewRequest(http.MethodPost, "/r/v1/chat/completions", strings.NewReader(`{}`))
	if got := serve(h, r).Header().Values("Access-Control-Allow-Origin"); len(got) != 0 {
		t.Errorf("no Origin, yet Allow-Origin %q", got)
	}
}

// Configured origins are matched the way a browser writes them.
func TestCORS_OriginMatchIgnoresCase(t *testing.T) {
	_, h, _, _ := corsSetup(t, "HTTPS://App.Example.com")
	if got := serve(h, preflight(allowedOrigin)).Header().Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Errorf("Allow-Origin %q, want %q", got, allowedOrigin)
	}
}

func TestCORS_ReloadAppliesAtOnce(t *testing.T) {
	gw, h, cfg, _ := corsSetup(t)
	if got := serve(h, preflight(allowedOrigin)).Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("CORS off, yet Allow-Origin %q", got)
	}

	cfg.Server.CORSOrigins = []string{allowedOrigin}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	gw.updateRoutes(cfg)
	if got := serve(h, preflight(allowedOrigin)).Header().Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Errorf("after reload, Allow-Origin %q, want %q", got, allowedOrigin)
	}
}

// A streamed answer must still stream through the wrapper.
func TestCORS_StreamingStillFlushes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: one\n\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Listen: ":8080", AuthHeader: "X-App-Token", CORSOrigins: []string{allowedOrigin}},
		Tokens: config.TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []config.RouteConfig{{PathPrefix: "/r", TargetURL: upstream.URL}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	gw := NewGateway(cfg, mustIssuer(t, cfg))
	defer gw.Close()
	server := httptest.NewServer(gw.CORS(gw))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/r/stream", strings.NewReader(`{}`))
	req.Header.Set("Origin", allowedOrigin)
	req.Header.Set("X-App-Token", mustToken(t, gw.Issuer(), "inst", "/r"))
	client := server.Client()
	client.Timeout = 5 * time.Second // a buffered stream fails instead of hanging
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The upstream never ends the stream: reading the first event proves it was
	// flushed rather than buffered until the end.
	buf := make([]byte, len("data: one\n\n"))
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "data: one\n\n" {
		t.Fatalf("first event %q, err %v", buf, err)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Errorf("stream carries Allow-Origin %q", got)
	}
}
