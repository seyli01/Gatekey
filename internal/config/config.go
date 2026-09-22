package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"gatekey/internal/logging"
	"gatekey/internal/token"
)

// DefaultMaxBodySizeMB is the standard maximum request body size limit (50 MB).
const DefaultMaxBodySizeMB = 50

// DefaultResponseHeaderTimeout bounds the wait for an upstream's first byte.
const DefaultResponseHeaderTimeout = 60 * time.Second

// DefaultRequestTimeout is the absolute ceiling on one exchange. It is far above
// any legitimate generation, because cutting a working stream is worse than
// holding a wedged connection a little longer.
const DefaultRequestTimeout = 15 * time.Minute

// BaseForwardedHeaders are relayed upstream whatever a route configures. They
// carry no caller-controlled meaning to the provider and HTTP needs them.
var BaseForwardedHeaders = []string{
	"Content-Type",
	"Accept",
	"Accept-Encoding",
}

// ServerConfig defines global server settings.
type ServerConfig struct {
	Listen        string `yaml:"listen"`           // e.g. ":8080"
	AuthHeader    string `yaml:"auth_header"`      // e.g. "X-App-Token", defaults to "X-App-Token"
	MaxBodySizeMB int    `yaml:"max_body_size_mb"` // Maximum allowed request body in MB (defaults to 50 MB)

	// StateDir is where the runtime writes quotas.json and metrics.json. It
	// defaults to the working directory, which is fine for a shell but fails on a
	// read-only root filesystem such as a scratch container image, where it must
	// point at the one mounted writable volume. It is read once at startup: moving
	// it takes a restart, not a reload.
	StateDir string `yaml:"state_dir"`

	// LogLevel and LogFormat decide verbosity and output shape once, centrally.
	// A request line per call is useful while developing and is pure noise, and
	// pure I/O cost, on a busy server.
	LogLevel  string `yaml:"log_level"`  // error | warn | info (default) | debug
	LogFormat string `yaml:"log_format"` // text (default) | json

	// ResponseHeaderTimeout bounds the wait for an upstream's *first* byte. It is
	// the guard against a provider that accepts the connection and then never
	// answers, which would otherwise pin a connection and a goroutine forever.
	// It does not limit how long a response may stream once it has begun.
	// Empty uses the default; "0" disables it, leaving no bound at all.
	ResponseHeaderTimeout string `yaml:"response_header_timeout"`

	// RequestTimeout is the absolute ceiling on a whole exchange, streaming
	// included, and catches an upstream that stalls mid-stream. It has to be
	// generous: a long generation legitimately runs for minutes. Routes may
	// override it; "0" disables it.
	RequestTimeout string `yaml:"request_timeout"`

	ParsedResponseHeaderTimeout time.Duration `yaml:"-"`
	ParsedRequestTimeout        time.Duration `yaml:"-"`
}

// StatePath resolves a runtime state file against server.state_dir.
func (s *ServerConfig) StatePath(name string) string {
	if s.StateDir == "" {
		return name
	}
	return filepath.Join(s.StateDir, name)
}

// MaxBodyBytes returns the maximum allowed request body size in bytes.
func (s *ServerConfig) MaxBodyBytes() int64 {
	if s.MaxBodySizeMB <= 0 {
		return int64(DefaultMaxBodySizeMB) * 1024 * 1024
	}
	return int64(s.MaxBodySizeMB) * 1024 * 1024
}

// DefaultAccessTTL is the lifetime stamped into issued access tokens. It is
// short on purpose: an access token travels on every proxied request.
const DefaultAccessTTL = 15 * time.Minute

// DefaultRefreshTTL is the lifetime stamped into issued refresh tokens.
const DefaultRefreshTTL = 720 * time.Hour // 30 days

// TokensConfig configures the stateless, HMAC-signed tokens that are Gatekey's
// only client credential.
//
// There is deliberately no second mechanism. A hand-written constant in a
// configuration file answers the same question a signed token does -- may this
// caller use this route -- but never expires, names nobody, and can only be
// withdrawn by cutting off every caller at once. A signed token with a long
// lifetime covers that use case strictly better.
type TokensConfig struct {
	// SigningKey authenticates issued tokens. Treat it as opaque bytes; generate
	// one with "gatekey genkey". Changing it invalidates every token at once.
	SigningKey string `yaml:"signing_key"`

	AccessTTL  string   `yaml:"access_ttl"`  // Go duration, e.g. "15m" (default 15m)
	RefreshTTL string   `yaml:"refresh_ttl"` // Go duration, e.g. "720h" (default 30 days)
	Denylist   []string `yaml:"denylist"`    // revoked install IDs, cut on the next reload

	// Parsed durations are populated during validation.
	ParsedAccessTTL  time.Duration `yaml:"-"`
	ParsedRefreshTTL time.Duration `yaml:"-"`
}

// validate normalises durations and rejects a signing key too weak to stand
// behind an HMAC-SHA256 tag.
func (t *TokensConfig) validate() error {
	t.SigningKey = strings.TrimSpace(t.SigningKey)

	var err error
	if t.ParsedAccessTTL, err = parseDuration(t.AccessTTL, DefaultAccessTTL); err != nil {
		return fmt.Errorf("invalid access_ttl: %w", err)
	}
	if t.ParsedRefreshTTL, err = parseDuration(t.RefreshTTL, DefaultRefreshTTL); err != nil {
		return fmt.Errorf("invalid refresh_ttl: %w", err)
	}

	if t.SigningKey == "" {
		return fmt.Errorf("signing_key is required (run \"gatekey genkey\")")
	}
	if len(t.SigningKey) < token.MinKeyLen {
		return fmt.Errorf("signing_key must be at least %d characters, got %d (run \"gatekey genkey\")", token.MinKeyLen, len(t.SigningKey))
	}
	if t.ParsedAccessTTL <= 0 {
		return fmt.Errorf("access_ttl must be positive, got %v", t.ParsedAccessTTL)
	}
	if t.ParsedRefreshTTL < t.ParsedAccessTTL {
		return fmt.Errorf("refresh_ttl (%v) must be at least access_ttl (%v)", t.ParsedRefreshTTL, t.ParsedAccessTTL)
	}
	for i, id := range t.Denylist {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("denylist entry %d cannot be empty", i)
		}
	}
	return nil
}

// parseDuration reads an optional Go duration, falling back to a default.
func parseDuration(raw string, fallback time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	return time.ParseDuration(raw)
}

// RateLimitConfig defines rate-limiting constraints for a route.
type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"` // 0 or omitted = disabled
	Burst             int `yaml:"burst"`               // Maximum burst tolerance (default = max(1, rpm/6))
}

// PricingConfig defines cost per million tokens in USD.
type PricingConfig struct {
	PromptUSD     float64 `yaml:"prompt_usd"`     // Cost per 1M prompt tokens (e.g. 0.15)
	CompletionUSD float64 `yaml:"completion_usd"` // Cost per 1M completion tokens (e.g. 0.60)
}

// QuotaConfig defines usage budget limits for a route.
type QuotaConfig struct {
	MaxTokens    uint64  `yaml:"max_tokens"`     // Max lifetime tokens per client token (0 = disabled)
	MaxBudgetUSD float64 `yaml:"max_budget_usd"` // Max lifetime dollar budget per client token (0 = disabled)

	// TotalMaxTokens and TotalBudgetUSD cap the route as a whole, every install
	// together. They sit alongside the per-install limits: a request must fit
	// both. 0 disables each.
	TotalMaxTokens uint64  `yaml:"total_max_tokens"`
	TotalBudgetUSD float64 `yaml:"total_budget_usd"`

	PricingPerMillion PricingConfig `yaml:"pricing_per_million"` // Default price for this route

	// PricingByModel prices individual models, keyed by name. A single route
	// commonly serves models an order of magnitude apart in price, and charging
	// them all at one rate makes max_budget_usd meaningless. Keys match the model
	// reported by the provider, by exact name first and then by longest prefix, so
	// "gpt-5" also prices "gpt-5-2026-01-01". A model absent from this map is
	// charged at PricingPerMillion.
	PricingByModel map[string]PricingConfig `yaml:"pricing_by_model"`

	// Reset names the accounting window. Counters are lifetime by default, which
	// means a route that reaches its ceiling stays shut until someone deletes the
	// state file by hand -- rarely what anyone wants of a monthly budget.
	Reset string `yaml:"reset"`
}

// Enabled reports whether any limit, per install or total, is set.
func (q *QuotaConfig) Enabled() bool {
	return q.MaxTokens > 0 || q.MaxBudgetUSD > 0 || q.TotalMaxTokens > 0 || q.TotalBudgetUSD > 0
}

// Accounting windows accepted by quota.reset.
const (
	QuotaResetNever   = "never"   // lifetime counters (default, preserves old behaviour)
	QuotaResetDaily   = "daily"   // resets at 00:00 UTC
	QuotaResetMonthly = "monthly" // resets on the 1st at 00:00 UTC
)

// PricingFor returns the price to apply to a model, falling back to the route
// default when the model is unknown. Falling back rather than failing is
// deliberate: an unrecognised name must produce the route's ordinary price, never
// a free request.
func (q *QuotaConfig) PricingFor(model string) PricingConfig {
	if model == "" || len(q.PricingByModel) == 0 {
		return q.PricingPerMillion
	}
	if pricing, found := q.PricingByModel[model]; found {
		return pricing
	}

	// Providers append build dates and revisions to model names, so a configured
	// "gpt-5" has to price the "gpt-5-2026-01-01" that actually comes back. The
	// longest match wins, so "gpt-5-mini" beats "gpt-5" for gpt-5-mini-0314.
	best := ""
	for name := range q.PricingByModel {
		if strings.HasPrefix(model, name) && len(name) > len(best) {
			best = name
		}
	}
	if best != "" {
		return q.PricingByModel[best]
	}
	return q.PricingPerMillion
}

// CredentialConfig describes a self-renewing upstream credential.
//
// It complements inject_headers rather than replacing it: a route that
// authenticates with a plain API key needs nothing here. This exists for the one
// thing a fixed header cannot express, a credential that expires -- an OAuth
// subscription to ChatGPT, Claude or Copilot.
type CredentialConfig struct {
	Type         string `yaml:"type"`          // currently only "oauth"
	TokenURL     string `yaml:"token_url"`     // provider's OAuth2 token endpoint
	ClientID     string `yaml:"client_id"`     //
	ClientSecret string `yaml:"client_secret"` // omitted for public clients
	RefreshToken string `yaml:"refresh_token"` // obtained once via the device flow
	Scope        string `yaml:"scope"`

	Header string `yaml:"header"` // defaults to "Authorization"
	Prefix string `yaml:"prefix"` // defaults to "Bearer "
}

// CredentialTypeOAuth is the only credential type implemented.
const CredentialTypeOAuth = "oauth"

// Enabled reports whether the route carries a renewing credential.
func (c *CredentialConfig) Enabled() bool {
	return c != nil && c.Type != ""
}

// validate normalises the block and rejects one that could never authenticate.
func (c *CredentialConfig) validate() error {
	c.Type = strings.ToLower(strings.TrimSpace(c.Type))
	if c.Type == "" {
		return nil
	}
	if c.Type != CredentialTypeOAuth {
		return fmt.Errorf("unknown credential type %q, only %q is supported", c.Type, CredentialTypeOAuth)
	}
	if strings.TrimSpace(c.TokenURL) == "" {
		return fmt.Errorf("token_url is required")
	}
	parsed, err := url.Parse(c.TokenURL)
	if err != nil {
		return fmt.Errorf("invalid token_url %q: %w", c.TokenURL, err)
	}
	// A token endpoint receives the refresh token, so plaintext is never
	// acceptable -- except on loopback, where tests and local providers live.
	if parsed.Scheme != "https" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" && parsed.Hostname() != "::1" {
		return fmt.Errorf("token_url must use https, got %q", parsed.Scheme)
	}
	if strings.TrimSpace(c.RefreshToken) == "" {
		return fmt.Errorf("refresh_token is required")
	}
	if c.Header == "" {
		c.Header = "Authorization"
	}
	if c.Prefix == "" {
		c.Prefix = "Bearer "
	}
	return nil
}

// RouteConfig defines routing rules, target URL, allowed tokens, and upstream headers.
type RouteConfig struct {
	PathPrefix    string            `yaml:"path_prefix"`    // e.g. "/openai"
	TargetURL     string            `yaml:"target_url"`     // e.g. "https://api.openai.com"
	StripPrefix   *bool             `yaml:"strip_prefix"`   // whether to strip path_prefix, defaults to true
	InjectHeaders map[string]string `yaml:"inject_headers"` // headers to inject into upstream request
	RateLimit     RateLimitConfig   `yaml:"rate_limit"`     // optional rate limiting per client token
	Quota         QuotaConfig       `yaml:"quota"`          // optional token & budget quota per client token

	// ForwardHeaders names the caller headers relayed upstream, on top of
	// BaseForwardedHeaders. Everything else is dropped.
	//
	// Without an allowlist every header a caller sends reaches the provider, and
	// some of them are not inert: a caller setting OpenAI-Organization would bill
	// another organisation, and OpenAI-Beta would switch on behaviour the operator
	// never chose. List only what a route genuinely needs.
	ForwardHeaders []string `yaml:"forward_headers"`

	// MaxBodySizeMB overrides the server-wide limit. A vision or audio route needs
	// tens of megabytes; a text-only route accepting the same is memory given away
	// for nothing. 0 inherits the server value.
	MaxBodySizeMB int `yaml:"max_body_size_mb"`

	// RequestTimeout overrides server.request_timeout for this route. Empty
	// inherits it; "0" disables the ceiling.
	RequestTimeout string `yaml:"request_timeout"`

	// Credential is an optional self-renewing upstream credential.
	Credential CredentialConfig `yaml:"credential"`

	// Populated during validation.
	ParsedForwardHeaders map[string]struct{} `yaml:"-"`
	ParsedRequestTimeout time.Duration       `yaml:"-"`

	// ParsedTarget is populated during validation
	ParsedTarget *url.URL `yaml:"-"`
}

// MaxBodyBytes returns the route's body limit in bytes, falling back to the
// server-wide setting when the route does not narrow it.
func (r *RouteConfig) MaxBodyBytes(server *ServerConfig) int64 {
	if r.MaxBodySizeMB > 0 {
		return int64(r.MaxBodySizeMB) * 1024 * 1024
	}
	return server.MaxBodyBytes()
}

// ShouldStripPrefix returns whether the route should strip the path prefix before forwarding.
func (r *RouteConfig) ShouldStripPrefix() bool {
	if r.StripPrefix == nil {
		return true
	}
	return *r.StripPrefix
}

// Config represents the top-level configuration structure.
type Config struct {
	Server ServerConfig  `yaml:"server"`
	Tokens TokensConfig  `yaml:"tokens"`
	Routes []RouteConfig `yaml:"routes"`
}

// DefaultAuthHeader is the fallback header when server.auth_header is omitted.
const DefaultAuthHeader = "X-App-Token"

// DefaultListen is the fallback address when server.listen is omitted.
const DefaultListen = ":8080"

// Validate validates the configuration structure.
func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		c.Server.Listen = DefaultListen
	}
	if c.Server.AuthHeader == "" {
		c.Server.AuthHeader = DefaultAuthHeader
	}
	if c.Server.MaxBodySizeMB <= 0 {
		c.Server.MaxBodySizeMB = DefaultMaxBodySizeMB
	}
	c.Server.StateDir = strings.TrimSpace(c.Server.StateDir)

	if _, err := logging.ParseLevel(c.Server.LogLevel); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	switch c.Server.LogFormat = strings.ToLower(strings.TrimSpace(c.Server.LogFormat)); c.Server.LogFormat {
	case "":
		c.Server.LogFormat = logging.FormatText
	case logging.FormatText, logging.FormatJSON:
	default:
		return fmt.Errorf("server: unknown log_format %q, want %q or %q", c.Server.LogFormat, logging.FormatText, logging.FormatJSON)
	}

	var err error
	if c.Server.ParsedResponseHeaderTimeout, err = parseDuration(c.Server.ResponseHeaderTimeout, DefaultResponseHeaderTimeout); err != nil {
		return fmt.Errorf("server: invalid response_header_timeout: %w", err)
	}
	if c.Server.ParsedResponseHeaderTimeout < 0 {
		return fmt.Errorf("server: response_header_timeout cannot be negative")
	}
	if c.Server.ParsedRequestTimeout, err = parseDuration(c.Server.RequestTimeout, DefaultRequestTimeout); err != nil {
		return fmt.Errorf("server: invalid request_timeout: %w", err)
	}
	if c.Server.ParsedRequestTimeout < 0 {
		return fmt.Errorf("server: request_timeout cannot be negative")
	}

	if err := c.Tokens.validate(); err != nil {
		return fmt.Errorf("tokens: %w", err)
	}

	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route must be defined")
	}

	seenPrefixes := make(map[string]struct{})

	for i := range c.Routes {
		route := &c.Routes[i]

		route.PathPrefix = strings.TrimSpace(route.PathPrefix)
		if route.PathPrefix == "" {
			return fmt.Errorf("route %d: path_prefix cannot be empty", i)
		}
		if !strings.HasPrefix(route.PathPrefix, "/") {
			return fmt.Errorf("route %d: path_prefix must start with '/', got %q", i, route.PathPrefix)
		}
		if _, exists := seenPrefixes[route.PathPrefix]; exists {
			return fmt.Errorf("route %d: duplicate path_prefix %q", i, route.PathPrefix)
		}
		seenPrefixes[route.PathPrefix] = struct{}{}

		route.TargetURL = strings.TrimSpace(route.TargetURL)
		if route.TargetURL == "" {
			return fmt.Errorf("route %d: target_url cannot be empty", i)
		}
		parsedURL, err := url.Parse(route.TargetURL)
		if err != nil {
			return fmt.Errorf("route %d: invalid target_url %q: %w", i, route.TargetURL, err)
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("route %d: target_url scheme must be http or https, got %q", i, parsedURL.Scheme)
		}
		if parsedURL.Host == "" {
			return fmt.Errorf("route %d: target_url host cannot be empty", i)
		}
		route.ParsedTarget = parsedURL

		if route.RateLimit.RequestsPerMinute < 0 {
			return fmt.Errorf("route %d (%s): requests_per_minute cannot be negative", i, route.PathPrefix)
		}
		if route.RateLimit.Burst < 0 {
			return fmt.Errorf("route %d (%s): burst cannot be negative", i, route.PathPrefix)
		}

		if route.Quota.MaxBudgetUSD < 0 {
			return fmt.Errorf("route %d (%s): max_budget_usd cannot be negative", i, route.PathPrefix)
		}
		if route.Quota.TotalBudgetUSD < 0 {
			return fmt.Errorf("route %d (%s): total_budget_usd cannot be negative", i, route.PathPrefix)
		}
		if route.Quota.PricingPerMillion.PromptUSD < 0 || route.Quota.PricingPerMillion.CompletionUSD < 0 {
			return fmt.Errorf("route %d (%s): pricing_per_million values cannot be negative", i, route.PathPrefix)
		}
		for name, pricing := range route.Quota.PricingByModel {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("route %d (%s): pricing_by_model key cannot be empty", i, route.PathPrefix)
			}
			if pricing.PromptUSD < 0 || pricing.CompletionUSD < 0 {
				return fmt.Errorf("route %d (%s): pricing_by_model[%q] values cannot be negative", i, route.PathPrefix, name)
			}
		}

		if err := route.Credential.validate(); err != nil {
			return fmt.Errorf("route %d (%s): credential: %w", i, route.PathPrefix, err)
		}

		if route.MaxBodySizeMB < 0 {
			return fmt.Errorf("route %d (%s): max_body_size_mb cannot be negative", i, route.PathPrefix)
		}

		// The allowlist is built once here, canonicalised, so the request path is
		// a plain map lookup.
		route.ParsedForwardHeaders = make(map[string]struct{}, len(BaseForwardedHeaders)+len(route.ForwardHeaders))
		for _, name := range BaseForwardedHeaders {
			route.ParsedForwardHeaders[textproto.CanonicalMIMEHeaderKey(name)] = struct{}{}
		}
		for _, name := range route.ForwardHeaders {
			name = strings.TrimSpace(name)
			if name == "" {
				return fmt.Errorf("route %d (%s): forward_headers entry cannot be empty", i, route.PathPrefix)
			}
			route.ParsedForwardHeaders[textproto.CanonicalMIMEHeaderKey(name)] = struct{}{}
		}

		routeTimeout, err := parseDuration(route.RequestTimeout, c.Server.ParsedRequestTimeout)
		if err != nil {
			return fmt.Errorf("route %d (%s): invalid request_timeout: %w", i, route.PathPrefix, err)
		}
		if routeTimeout < 0 {
			return fmt.Errorf("route %d (%s): request_timeout cannot be negative", i, route.PathPrefix)
		}
		route.ParsedRequestTimeout = routeTimeout

		switch route.Quota.Reset = strings.ToLower(strings.TrimSpace(route.Quota.Reset)); route.Quota.Reset {
		case "":
			route.Quota.Reset = QuotaResetNever
		case QuotaResetNever, QuotaResetDaily, QuotaResetMonthly:
		default:
			return fmt.Errorf("route %d (%s): quota reset must be %q, %q or %q, got %q",
				i, route.PathPrefix, QuotaResetNever, QuotaResetDaily, QuotaResetMonthly, route.Quota.Reset)
		}
	}

	return nil
}

// expandEnv substitutes ${VAR} and $VAR references from the environment.
//
// Unlike os.ExpandEnv it fails on an undefined variable rather than silently
// substituting an empty string, which would otherwise ship a broken
// `Authorization: Bearer ` header upstream and surface as a puzzling 401 from the
// provider. Write $$ for a literal dollar sign.
func expandEnv(raw string) (string, error) {
	var missing []string
	seen := make(map[string]struct{})

	expanded := os.Expand(raw, func(name string) string {
		if name == "$" {
			return "$"
		}
		if value, ok := os.LookupEnv(name); ok {
			return value
		}
		if _, dup := seen[name]; !dup {
			seen[name] = struct{}{}
			missing = append(missing, name)
		}
		return ""
	})

	if len(missing) > 0 {
		return "", fmt.Errorf("undefined environment variable(s): %s", strings.Join(missing, ", "))
	}

	return expanded, nil
}

// parse expands, unmarshals and validates raw YAML configuration bytes.
func parse(data []byte) (*Config, error) {
	expanded, err := expandEnv(string(data))
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// Load reads and parses a YAML configuration file with environment variable expansion.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	cfg, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("loading config file %s: %w", path, err)
	}

	return cfg, nil
}

// ReloadListener is called whenever the configuration is successfully reloaded.
type ReloadListener func(oldCfg, newCfg *Config)

// Manager manages thread-safe dynamic configuration loading and reloading.
type Manager struct {
	mu          sync.RWMutex
	path        string
	lastModTime time.Time
	lastSize    int64
	lastHash    []byte
	config      *Config
	listeners   []ReloadListener
}

// NewManager creates a new thread-safe Config Manager.
func NewManager(path string) (*Manager, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}

	var modTime time.Time
	var size int64
	if info, err := os.Stat(path); err == nil {
		modTime = info.ModTime()
		size = info.Size()
	}

	initialData, _ := os.ReadFile(path)
	h := sha256.Sum256(initialData)

	return &Manager{
		path:        path,
		lastModTime: modTime,
		lastSize:    size,
		lastHash:    h[:],
		config:      cfg,
	}, nil
}

// OnReload registers a callback hook to be triggered on successful configuration reload.
func (m *Manager) OnReload(listener ReloadListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

// Get returns the current active configuration snapshot.
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// Reload re-reads the config file, validates it, and updates internal state atomically.
// If reloading fails, the previous valid configuration remains active.
func (m *Manager) Reload() (*Config, error) {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", m.path, err)
	}

	newCfg, err := parse(data)
	if err != nil {
		return nil, err
	}

	var modTime time.Time
	var size int64
	if info, err := os.Stat(m.path); err == nil {
		modTime = info.ModTime()
		size = info.Size()
	}

	h := sha256.Sum256(data)

	m.mu.Lock()
	oldCfg := m.config
	m.config = newCfg
	m.lastModTime = modTime
	m.lastSize = size
	m.lastHash = h[:]
	listeners := make([]ReloadListener, len(m.listeners))
	copy(listeners, m.listeners)
	m.mu.Unlock()

	// Notify listeners outside the lock to prevent deadlocks
	for _, l := range listeners {
		l(oldCfg, newCfg)
	}

	return newCfg, nil
}

// StartWatcher starts an ultra-lightweight background polling watcher.
// It uses os.Stat metadata (nanosecond check) to avoid any disk reading or hashing
// unless the file's modification time or size actually changed.
func (m *Manager) StartWatcher(ctx context.Context, interval time.Duration, onReload func(cfg *Config), onError func(err error)) {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Step 1: Stat check only (~300 nanoseconds, zero bytes read from disk)
				info, err := os.Stat(m.path)
				if err != nil {
					continue
				}

				m.mu.RLock()
				modTimeEqual := info.ModTime().Equal(m.lastModTime)
				sizeEqual := info.Size() == m.lastSize
				m.mu.RUnlock()

				// Fast exit: no change in file metadata -> strictly zero allocation, zero IO
				if modTimeEqual && sizeEqual {
					continue
				}

				// Step 2: Only if metadata changed, read and verify content hash
				data, err := os.ReadFile(m.path)
				if err != nil {
					continue
				}

				currentHash := sha256.Sum256(data)

				m.mu.RLock()
				contentChanged := !bytes.Equal(m.lastHash, currentHash[:])
				m.mu.RUnlock()

				if contentChanged {
					newCfg, err := m.Reload()
					if err != nil {
						if onError != nil {
							onError(err)
						}
					} else {
						if onReload != nil {
							onReload(newCfg)
						}
					}
				}
			}
		}
	}()
}
