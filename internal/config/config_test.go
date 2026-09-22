package config

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestConfigLoadAndValidation(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	t.Setenv("MOCK_OPENAI_KEY", "sk-secret-test-key-12345")

	content := `
server:
  listen: ":9090"
  auth_header: "X-Custom-Token"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
    inject_headers:
      Authorization: "Bearer ${MOCK_OPENAI_KEY}"
  - path_prefix: "/anthropic"
    target_url: "https://api.anthropic.com"
    strip_prefix: false
    inject_headers:
      x-api-key: "anthropic-secret"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.Server.Listen != ":9090" {
		t.Errorf("expected listen :9090, got %s", cfg.Server.Listen)
	}
	if cfg.Server.AuthHeader != "X-Custom-Token" {
		t.Errorf("expected auth_header X-Custom-Token, got %s", cfg.Server.AuthHeader)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(cfg.Routes))
	}

	// Check route 1
	r0 := cfg.Routes[0]
	if r0.PathPrefix != "/openai" {
		t.Errorf("expected /openai, got %s", r0.PathPrefix)
	}
	if !r0.ShouldStripPrefix() {
		t.Errorf("expected strip_prefix to default to true")
	}
	if r0.InjectHeaders["Authorization"] != "Bearer sk-secret-test-key-12345" {
		t.Errorf("env var expansion failed: %s", r0.InjectHeaders["Authorization"])
	}

	// Check route 2
	r1 := cfg.Routes[1]
	if r1.ShouldStripPrefix() {
		t.Errorf("expected strip_prefix false, got true")
	}
}

func TestConfigManagerReload(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	validContent1 := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/test"
    target_url: "https://example.com"
`
	if err := os.WriteFile(cfgPath, []byte(validContent1), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	mgr, err := NewManager(cfgPath)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	if len(mgr.Get().Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(mgr.Get().Routes))
	}

	// Update file with invalid yaml
	if err := os.WriteFile(cfgPath, []byte("invalid: yaml: ["), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Reload should fail, but current config must be preserved
	if _, err := mgr.Reload(); err == nil {
		t.Errorf("expected error on invalid config reload, got nil")
	}
	if len(mgr.Get().Routes) != 1 {
		t.Errorf("expected config to be preserved after failed reload")
	}

	// Update with valid content 2
	validContent2 := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/test"
    target_url: "https://example.com"
  - path_prefix: "/new"
    target_url: "https://api.new.com"
`
	if err := os.WriteFile(cfgPath, []byte(validContent2), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	reloaded, err := mgr.Reload()
	if err != nil {
		t.Fatalf("failed to reload valid config: %v", err)
	}
	if len(reloaded.Routes) != 2 {
		t.Errorf("expected 2 routes after reload, got %d", len(reloaded.Routes))
	}
	if len(mgr.Get().Routes) != 2 {
		t.Errorf("expected manager to reflect 2 routes, got %d", len(mgr.Get().Routes))
	}
}

func TestConfigManagerAutoWatcher(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	initial := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/initial"
    target_url: "https://initial.com"
`
	if err := os.WriteFile(cfgPath, []byte(initial), 0600); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	mgr, err := NewManager(cfgPath)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	reloadedChan := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.StartWatcher(ctx, 30*time.Millisecond, func(cfg *Config) {
		reloadedChan <- len(cfg.Routes)
	}, nil)

	// Modify config file
	updated := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/initial"
    target_url: "https://initial.com"
  - path_prefix: "/auto-detected"
    target_url: "https://auto.com"
`
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(cfgPath, []byte(updated), 0600); err != nil {
		t.Fatalf("failed to update config file: %v", err)
	}

	select {
	case count := <-reloadedChan:
		if count != 2 {
			t.Errorf("expected 2 routes after auto-detection, got %d", count)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for auto-watcher to detect file change")
	}
}

// An undefined variable used to expand to "", shipping `Authorization: Bearer ` to
// the provider and surfacing as an unexplained 401. It must fail at load instead.
func TestLoad_UndefinedEnvVarIsRejected(t *testing.T) {
	raw := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
    inject_headers:
      Authorization: "Bearer ${DEFINITELY_UNSET_KEY_FOR_TEST}"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected Load to fail on an undefined environment variable")
	}
	if !strings.Contains(err.Error(), "DEFINITELY_UNSET_KEY_FOR_TEST") {
		t.Errorf("error should name the missing variable, got: %v", err)
	}
}

func TestLoad_EscapedDollarIsLiteral(t *testing.T) {
	raw := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
    inject_headers:
      X-Secret: "pa$$word"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected $$ to expand to a literal $, got: %v", err)
	}
	if got := cfg.Routes[0].InjectHeaders["X-Secret"]; got != "pa$word" {
		t.Errorf("expected literal %q, got %q", "pa$word", got)
	}
}

func TestLoad_TokensDefaultsAndValidation(t *testing.T) {
	const strongKey = "0123456789abcdef0123456789abcdef" // exactly MinKeyLen

	cases := []struct {
		name       string
		tokensYAML string
		wantErr    string
		check      func(t *testing.T, cfg *Config)
	}{
		{
			// The signing key is the only credential Gatekey has; without it no
			// caller could ever be authenticated, so starting is refused.
			name:       "absent signing key refused",
			tokensYAML: "",
			wantErr:    "signing_key is required",
		},
		{
			name:       "defaults applied",
			tokensYAML: "tokens:\n  signing_key: \"" + strongKey + "\"\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.Tokens.ParsedAccessTTL != DefaultAccessTTL {
					t.Errorf("access TTL = %v, want %v", cfg.Tokens.ParsedAccessTTL, DefaultAccessTTL)
				}
				if cfg.Tokens.ParsedRefreshTTL != DefaultRefreshTTL {
					t.Errorf("refresh TTL = %v, want %v", cfg.Tokens.ParsedRefreshTTL, DefaultRefreshTTL)
				}
			},
		},
		{
			name:       "explicit durations parsed",
			tokensYAML: "tokens:\n  signing_key: \"" + strongKey + "\"\n  access_ttl: \"5m\"\n  refresh_ttl: \"168h\"\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.Tokens.ParsedAccessTTL != 5*time.Minute {
					t.Errorf("access TTL = %v, want 5m", cfg.Tokens.ParsedAccessTTL)
				}
				if cfg.Tokens.ParsedRefreshTTL != 168*time.Hour {
					t.Errorf("refresh TTL = %v, want 168h", cfg.Tokens.ParsedRefreshTTL)
				}
			},
		},
		{
			name:       "short key refused",
			tokensYAML: "tokens:\n  signing_key: \"too-short\"\n",
			wantErr:    "signing_key must be at least",
		},
		{
			name:       "unparsable duration refused",
			tokensYAML: "tokens:\n  signing_key: \"" + strongKey + "\"\n  access_ttl: \"15 minutes\"\n",
			wantErr:    "invalid access_ttl",
		},
		{
			// A refresh token shorter-lived than the access token it mints would
			// expire mid-session and lock the application out.
			name:       "refresh shorter than access refused",
			tokensYAML: "tokens:\n  signing_key: \"" + strongKey + "\"\n  access_ttl: \"1h\"\n  refresh_ttl: \"5m\"\n",
			wantErr:    "must be at least access_ttl",
		},
		{
			name:       "empty denylist entry refused",
			tokensYAML: "tokens:\n  signing_key: \"" + strongKey + "\"\n  denylist:\n    - \"\"\n",
			wantErr:    "denylist entry 0 cannot be empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.tokensYAML + `
server:
  listen: ":8080"
routes:
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
`
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatalf("writing config: %v", err)
			}

			cfg, err := Load(path)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got none", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tc.check(t, cfg)
		})
	}
}

func TestServerConfig_StatePath(t *testing.T) {
	var noDir ServerConfig
	if got := noDir.StatePath("quotas.json"); got != "quotas.json" {
		t.Errorf("StatePath = %q, want the bare name when state_dir is unset", got)
	}

	withDir := ServerConfig{StateDir: "/var/lib/gatekey"}
	if got := withDir.StatePath("quotas.json"); got != "/var/lib/gatekey/quotas.json" {
		t.Errorf("StatePath = %q, want it rooted in state_dir", got)
	}
}

func TestLoad_QuotaReset(t *testing.T) {
	load := func(t *testing.T, reset string) (*Config, error) {
		t.Helper()
		raw := `
server:
  listen: ":8080"
  state_dir: "/var/lib/gatekey"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
    quota:
      max_tokens: 1000
      reset: "` + reset + `"
`
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatalf("writing config: %v", err)
		}
		return Load(path)
	}

	for _, reset := range []string{"monthly", "MONTHLY", " daily ", "never"} {
		t.Run("accepts "+reset, func(t *testing.T) {
			cfg, err := load(t, reset)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			want := strings.ToLower(strings.TrimSpace(reset))
			if cfg.Routes[0].Quota.Reset != want {
				t.Errorf("Reset = %q, want %q", cfg.Routes[0].Quota.Reset, want)
			}
			if cfg.Server.StateDir != "/var/lib/gatekey" {
				t.Errorf("StateDir = %q", cfg.Server.StateDir)
			}
		})
	}

	// A typo must fail loudly rather than silently fall back to lifetime counters,
	// which would leave a budget that never resets while the file says otherwise.
	if _, err := load(t, "monthy"); err == nil {
		t.Error("expected a misspelled reset window to be refused")
	} else if !strings.Contains(err.Error(), "quota reset must be") {
		t.Errorf("error = %v, want it to name the accepted values", err)
	}
}

func TestLoad_QuotaResetDefaultsToNever(t *testing.T) {
	raw := `
server:
  listen: ":8080"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Routes[0].Quota.Reset != QuotaResetNever {
		t.Errorf("Reset = %q, want %q so existing configurations keep their behaviour", cfg.Routes[0].Quota.Reset, QuotaResetNever)
	}
	if cfg.Server.StateDir != "" {
		t.Errorf("StateDir = %q, want empty by default", cfg.Server.StateDir)
	}
}

func TestLoad_ServerTimeoutsAndLogging(t *testing.T) {
	load := func(t *testing.T, serverExtra, routeExtra string) (*Config, error) {
		t.Helper()
		raw := `
server:
  listen: ":8080"
` + serverExtra + `
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/openai"
    target_url: "https://api.openai.com"
` + routeExtra
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatalf("writing config: %v", err)
		}
		return Load(path)
	}

	t.Run("defaults", func(t *testing.T) {
		cfg, err := load(t, "", "")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Server.ParsedResponseHeaderTimeout != DefaultResponseHeaderTimeout {
			t.Errorf("response header timeout = %v, want %v", cfg.Server.ParsedResponseHeaderTimeout, DefaultResponseHeaderTimeout)
		}
		if cfg.Server.ParsedRequestTimeout != DefaultRequestTimeout {
			t.Errorf("request timeout = %v, want %v", cfg.Server.ParsedRequestTimeout, DefaultRequestTimeout)
		}
		// A route with no opinion inherits the server ceiling.
		if cfg.Routes[0].ParsedRequestTimeout != DefaultRequestTimeout {
			t.Errorf("route timeout = %v, want it inherited", cfg.Routes[0].ParsedRequestTimeout)
		}
		if cfg.Server.LogFormat != "text" {
			t.Errorf("log_format = %q, want text", cfg.Server.LogFormat)
		}
	})

	t.Run("route overrides the server ceiling", func(t *testing.T) {
		cfg, err := load(t, "  request_timeout: \"10m\"", "    request_timeout: \"30s\"\n")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Server.ParsedRequestTimeout != 10*time.Minute {
			t.Errorf("server timeout = %v", cfg.Server.ParsedRequestTimeout)
		}
		if cfg.Routes[0].ParsedRequestTimeout != 30*time.Second {
			t.Errorf("route timeout = %v, want 30s", cfg.Routes[0].ParsedRequestTimeout)
		}
	})

	t.Run("zero disables the ceiling", func(t *testing.T) {
		cfg, err := load(t, "", "    request_timeout: \"0\"\n")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Routes[0].ParsedRequestTimeout != 0 {
			t.Errorf("route timeout = %v, want 0", cfg.Routes[0].ParsedRequestTimeout)
		}
	})

	for name, extra := range map[string]string{
		"bad log level":    "  log_level: \"verbose\"",
		"bad log format":   "  log_format: \"xml\"",
		"bad duration":     "  request_timeout: \"ten minutes\"",
		"negative timeout": "  response_header_timeout: \"-5s\"",
	} {
		t.Run(name+" refused", func(t *testing.T) {
			if _, err := load(t, extra, ""); err == nil {
				t.Fatal("expected the configuration to be refused")
			}
		})
	}
}

func TestValidate_ForwardHeadersAndBodySize(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Listen: ":8080", MaxBodySizeMB: 50},
		Tokens: TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
		Routes: []RouteConfig{{
			PathPrefix: "/openai",
			TargetURL:  "https://api.openai.com",
			// Mixed case on purpose: HTTP header names are case-insensitive, so the
			// allowlist must canonicalise rather than compare raw strings.
			ForwardHeaders: []string{"openai-BETA"},
			MaxBodySizeMB:  1,
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	allowed := cfg.Routes[0].ParsedForwardHeaders
	for _, name := range append([]string{"Openai-Beta"}, BaseForwardedHeaders...) {
		if _, found := allowed[name]; !found {
			t.Errorf("%q must be in the allowlist", name)
		}
	}
	if _, found := allowed["Cookie"]; found {
		t.Error("Cookie must not be allowlisted by default")
	}

	if got := cfg.Routes[0].MaxBodyBytes(&cfg.Server); got != 1024*1024 {
		t.Errorf("route body limit = %d, want 1 MB", got)
	}

	// A route that says nothing falls back to the server-wide limit.
	bare := RouteConfig{}
	if got := bare.MaxBodyBytes(&cfg.Server); got != 50*1024*1024 {
		t.Errorf("inherited body limit = %d, want 50 MB", got)
	}
}

func TestValidate_RejectsBadRouteSettings(t *testing.T) {
	base := func(mutate func(*RouteConfig)) *Config {
		route := RouteConfig{PathPrefix: "/openai", TargetURL: "https://api.openai.com"}
		mutate(&route)
		return &Config{
			Server: ServerConfig{Listen: ":8080"},
			Tokens: TokensConfig{SigningKey: "0123456789abcdef0123456789abcdef"},
			Routes: []RouteConfig{route},
		}
	}

	cases := map[string]func(*RouteConfig){
		"negative body size":     func(r *RouteConfig) { r.MaxBodySizeMB = -1 },
		"empty forward header":   func(r *RouteConfig) { r.ForwardHeaders = []string{"  "} },
		"unparsable timeout":     func(r *RouteConfig) { r.RequestTimeout = "soon" },
		"negative route ceiling": func(r *RouteConfig) { r.RequestTimeout = "-1s" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := base(mutate).Validate(); err == nil {
				t.Fatal("expected the configuration to be refused")
			}
		})
	}
}

func TestQuotaConfig_PricingFor(t *testing.T) {
	q := QuotaConfig{
		PricingPerMillion: PricingConfig{PromptUSD: 1, CompletionUSD: 2},
		PricingByModel: map[string]PricingConfig{
			"gpt-5":      {PromptUSD: 10, CompletionUSD: 30},
			"gpt-5-mini": {PromptUSD: 0.2, CompletionUSD: 0.8},
		},
	}

	cases := map[string]PricingConfig{
		"gpt-5":                 {PromptUSD: 10, CompletionUSD: 30},
		"gpt-5-2026-01-01":      {PromptUSD: 10, CompletionUSD: 30}, // prefix match
		"gpt-5-mini":            {PromptUSD: 0.2, CompletionUSD: 0.8},
		"gpt-5-mini-2026-01-01": {PromptUSD: 0.2, CompletionUSD: 0.8}, // longest prefix wins
		"claude-opus-5":         {PromptUSD: 1, CompletionUSD: 2},     // unknown -> route default
		"":                      {PromptUSD: 1, CompletionUSD: 2},
	}
	for model, want := range cases {
		if got := q.PricingFor(model); got != want {
			t.Errorf("PricingFor(%q) = %+v, want %+v", model, got, want)
		}
	}

	// With no per-model table at all, every model takes the route price.
	bare := QuotaConfig{PricingPerMillion: PricingConfig{PromptUSD: 5, CompletionUSD: 7}}
	if got := bare.PricingFor("gpt-5"); got != bare.PricingPerMillion {
		t.Errorf("PricingFor with no table = %+v", got)
	}
}

// A reference in a comment is documentation, not configuration: it used to fail
// the load, which is why config.example.yaml could not be loaded as shipped.
func TestLoad_EnvReferenceInACommentIsIgnored(t *testing.T) {
	cfg, err := parse([]byte(`
# Headers support ${ANY_VAR} expansion.
tokens:
  signing_key: "0123456789abcdef0123456789abcdef" # or ${GATEKEY_SIGNING_KEY}
routes:
  - path_prefix: "/r"
    target_url: "https://api.example.com"
`))
	if err != nil {
		t.Fatalf("a commented reference failed the load: %v", err)
	}
	if cfg.Routes[0].PathPrefix != "/r" {
		t.Errorf("route %q", cfg.Routes[0].PathPrefix)
	}
}

// A secret is inserted as a value. Substituted into the raw text, a quote in it
// ended the string early and the rest became YAML.
func TestLoad_EnvValueCannotRewriteTheStructure(t *testing.T) {
	t.Setenv("TRICKY_KEY", "sk-1\"\n    X-Injected: \"yes")
	cfg, err := parse([]byte(`
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/r"
    target_url: "https://api.example.com"
    inject_headers:
      Authorization: "Bearer ${TRICKY_KEY}"
`))
	if err != nil {
		t.Fatal(err)
	}
	headers := cfg.Routes[0].InjectHeaders
	if _, injected := headers["X-Injected"]; injected || len(headers) != 1 {
		t.Fatalf("the value rewrote the configuration: %q", headers)
	}
	if got := headers["Authorization"]; got != "Bearer sk-1\"\n    X-Injected: \"yes" {
		t.Errorf("Authorization = %q, want the secret verbatim", got)
	}
}

// An unquoted reference still decodes to the field's type.
func TestLoad_EnvNumberDecodesAsANumber(t *testing.T) {
	t.Setenv("MAX_TOKENS", "5000")
	cfg, err := parse([]byte(`
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/r"
    target_url: "https://api.example.com"
    quota:
      max_tokens: ${MAX_TOKENS}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Routes[0].Quota.MaxTokens; got != 5000 {
		t.Errorf("max_tokens = %d, want 5000", got)
	}
}

// The shipped example must load once its real variables are set.
func TestLoad_ExampleConfigLoads(t *testing.T) {
	data, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Skip("config.example.yaml not found")
	}
	// Set every variable the example names, except ENV_VAR: it only ever
	// appears in a comment, so it must not be required.
	for _, m := range regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`).FindAllStringSubmatch(string(data), -1) {
		if m[1] != "ENV_VAR" {
			t.Setenv(m[1], "0123456789abcdef0123456789abcdef-"+m[1])
		}
	}

	if _, err := parse(data); err != nil {
		t.Fatalf("config.example.yaml does not load: %v", err)
	}
}
