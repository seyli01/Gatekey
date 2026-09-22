// Package credential supplies the header Gatekey sends upstream to authenticate
// itself to a provider.
//
// A route's inject_headers already covers the ordinary case, where the value is
// an API key read once from configuration and never changes. This package exists
// for the case it cannot express: a credential that expires and has to renew
// itself, which is how OAuth subscriptions to ChatGPT, Claude or Copilot work.
//
// The renewal has to happen inside the proxy. An OAuth access token lives about
// an hour while a proxied request needs a valid one now, and moving the renewal
// outside would mean circulating provider credentials between processes --
// exactly what Gatekey exists to prevent.
package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Failures a caller has to tell apart: one is transient and worth retrying,
// the other needs a human to authorise the application again.
var (
	// ErrRefreshFailed is a transient failure: the network, or the provider
	// answering with a server error.
	ErrRefreshFailed = errors.New("credential: refresh failed")

	// ErrReauthRequired means the refresh token itself was rejected. No amount of
	// retrying fixes it; the operator must run the device flow again.
	ErrReauthRequired = errors.New("credential: re-authorisation required")
)

// Source yields the header to attach to an upstream request.
type Source interface {
	// Header returns the header name and its value, renewing the underlying
	// credential if it is about to expire.
	Header(ctx context.Context) (name, value string, err error)
}

// Store persists a rotated refresh token.
//
// It is not optional. Providers commonly return a *new* refresh token on every
// renewal and invalidate the old one, so a Gatekey that forgot to write it back
// keeps working perfectly until it restarts, and then can never authenticate
// again. That failure arrives hours after the mistake, which is why this is a
// required dependency rather than a setting.
type Store interface {
	Save(name, refreshToken string) error
}

// renewSkew renews a token before it actually expires. Renewing exactly at the
// deadline leaves in-flight requests holding a credential that dies mid-flight,
// and makes every expiry a synchronised stampede.
const renewSkew = 60 * time.Second

// OAuthConfig describes an OAuth2 refresh-token grant.
type OAuthConfig struct {
	Name         string // identifies this credential in the store and in logs
	TokenURL     string
	ClientID     string
	ClientSecret string // optional: public clients have none
	RefreshToken string
	Scope        string

	Header string // defaults to "Authorization"
	Prefix string // defaults to "Bearer "
}

// OAuth renews an access token from a refresh token, on demand.
//
// It is safe for concurrent use. The common path takes a read lock and returns
// the cached token; only a renewal takes the write lock, so a thousand requests
// arriving at expiry produce one call to the provider, not a thousand.
type OAuth struct {
	cfg    OAuthConfig
	store  Store
	client *http.Client
	now    func() time.Time

	mu           sync.RWMutex
	accessToken  string
	expiresAt    time.Time
	refreshToken string
}

// NewOAuth builds an OAuth source. The HTTP client and store are required.
func NewOAuth(cfg OAuthConfig, store Store, client *http.Client) (*OAuth, error) {
	if cfg.TokenURL == "" {
		return nil, errors.New("credential: token_url is required")
	}
	if cfg.RefreshToken == "" {
		return nil, errors.New("credential: refresh_token is required")
	}
	if store == nil {
		return nil, errors.New("credential: a store is required to persist rotated refresh tokens")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Header == "" {
		cfg.Header = "Authorization"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "Bearer "
	}

	return &OAuth{
		cfg:          cfg,
		store:        store,
		client:       client,
		now:          time.Now,
		refreshToken: cfg.RefreshToken,
	}, nil
}

// Header returns the authorisation header, renewing the access token when it is
// missing or close to expiring.
func (o *OAuth) Header(ctx context.Context) (string, string, error) {
	o.mu.RLock()
	token, expires := o.accessToken, o.expiresAt
	o.mu.RUnlock()

	if token != "" && o.now().Before(expires.Add(-renewSkew)) {
		return o.cfg.Header, o.cfg.Prefix + token, nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	// Re-check under the write lock: another request may have renewed while this
	// one waited, and renewing again would burn a rotated refresh token.
	if o.accessToken != "" && o.now().Before(o.expiresAt.Add(-renewSkew)) {
		return o.cfg.Header, o.cfg.Prefix + o.accessToken, nil
	}

	if err := o.renewLocked(ctx); err != nil {
		return "", "", err
	}
	return o.cfg.Header, o.cfg.Prefix + o.accessToken, nil
}

// tokenResponse is the subset of RFC 6749 §5.1 that matters here.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
}

// renewLocked exchanges the refresh token for a new access token. The caller
// holds the write lock.
func (o *OAuth) renewLocked(ctx context.Context) error {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", o.refreshToken)
	if o.cfg.ClientID != "" {
		form.Set("client_id", o.cfg.ClientID)
	}
	if o.cfg.ClientSecret != "" {
		form.Set("client_secret", o.cfg.ClientSecret)
	}
	if o.cfg.Scope != "" {
		form.Set("scope", o.cfg.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRefreshFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRefreshFailed, err)
	}
	defer resp.Body.Close()

	// Cap the read: a token response is small, and an endpoint answering with
	// something enormous must not be able to exhaust memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: reading response: %v", ErrRefreshFailed, err)
	}

	// 400 and 401 mean the grant itself was rejected -- RFC 6749 returns
	// invalid_grant for a revoked or expired refresh token. Retrying cannot help,
	// so this has to be reported as needing a human, not as a blip.
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: provider rejected the refresh token (HTTP %d)", ErrReauthRequired, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: provider returned HTTP %d", ErrRefreshFailed, resp.StatusCode)
	}

	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("%w: malformed token response: %v", ErrRefreshFailed, err)
	}
	if parsed.Error == "invalid_grant" {
		return fmt.Errorf("%w: %s", ErrReauthRequired, parsed.Error)
	}
	if parsed.AccessToken == "" {
		return fmt.Errorf("%w: token response carried no access_token", ErrRefreshFailed)
	}

	o.accessToken = parsed.AccessToken
	lifetime := time.Duration(parsed.ExpiresIn) * time.Second
	if lifetime <= 0 {
		// Providers may omit expires_in. An hour is the common default, and being
		// wrong here only costs a needless renewal.
		lifetime = time.Hour
	}
	o.expiresAt = o.now().Add(lifetime)

	// Persist a rotated refresh token before anything else can fail. If the write
	// does not land, the next restart authenticates with a token the provider has
	// already invalidated.
	if parsed.RefreshToken != "" && parsed.RefreshToken != o.refreshToken {
		o.refreshToken = parsed.RefreshToken
		if err := o.store.Save(o.cfg.Name, parsed.RefreshToken); err != nil {
			return fmt.Errorf("%w: renewed but could not persist the rotated refresh token: %v", ErrRefreshFailed, err)
		}
	}

	return nil
}
