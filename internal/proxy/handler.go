package proxy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gatekey/internal/apierror"
	"gatekey/internal/config"
	"gatekey/internal/credential"
	"gatekey/internal/limiter"
	"gatekey/internal/logging"
	"gatekey/internal/metrics"
	"gatekey/internal/quota"
	"gatekey/internal/token"
)

// credentialHeaderKey carries the resolved upstream credential from ServeHTTP to
// the Rewrite closure, which runs too late to fail a request cleanly.
type credentialHeaderKey struct{}

// routeEntry represents a compiled routing rule and its dedicated reverse proxy.
type routeEntry struct {
	pathPrefix    string
	targetURL     *url.URL
	stripPrefix   bool
	injectHeaders map[string]string
	rateLimit     config.RateLimitConfig
	quota         config.QuotaConfig
	forwardHeader map[string]struct{}
	credential    credential.Source
	maxBodyBytes  int64
	reqTimeout    time.Duration
	proxy         *httputil.ReverseProxy
}

// Gateway handles incoming requests, performs authentication, and forwards traffic.
type Gateway struct {
	mu              sync.RWMutex
	authHeader      string
	maxBodyBytes    int64
	cors            *corsPolicy
	routes          []routeEntry
	issuer          *token.Issuer
	credentials     map[string]credential.Source
	credentialStore credential.Store

	// lastCfg is the configuration currently applied, kept so installing the
	// credential store after construction can rebuild the routes that need it.
	lastCfg          *config.Config
	limiterMgr       *limiter.Manager
	quotaMgr         *quota.Manager
	transport        *http.Transport
	metricsCollector *metrics.Collector
}

// SetMetricsCollector connects a metrics collector to the gateway.
func (gw *Gateway) SetMetricsCollector(col *metrics.Collector) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.metricsCollector = col
}

// SetCredentialStore installs the store used to persist rotated refresh tokens.
// It must be set before the first configuration is applied.
func (gw *Gateway) SetCredentialStore(store credential.Store) {
	gw.mu.Lock()
	gw.credentialStore = store
	cfg := gw.lastCfg
	gw.mu.Unlock()

	// NewGateway compiles the routes before a store can be installed, so any
	// route carrying a credential was skipped. Rebuild now that it can succeed.
	if cfg != nil {
		gw.updateRoutes(cfg)
	}
}

// SetIssuer installs the signed-token issuer, or nil to accept static client
// tokens only. It is replaced wholesale on reload so a rotated signing key or a
// changed denylist takes effect without a restart.
func (gw *Gateway) SetIssuer(iss *token.Issuer) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.issuer = iss
}

// Issuer returns the active issuer, or nil when signed tokens are disabled.
func (gw *Gateway) Issuer() *token.Issuer {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.issuer
}

// NewGateway constructs a new Gateway with an optimized HTTP transport and builds routes.
func NewGateway(cfg *config.Config, issuer *token.Issuer) *Gateway {
	// High performance connection pool transport
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Bounds the wait for the first byte only, never the length of a stream:
		// a provider that accepts the connection and never answers would otherwise
		// hold a connection and a goroutine for the lifetime of the process.
		ResponseHeaderTimeout: cfg.Server.ParsedResponseHeaderTimeout,
	}

	gw := &Gateway{
		issuer:     issuer,
		limiterMgr: limiter.NewManager(1*time.Minute, 15*time.Minute),
		quotaMgr:   quota.NewManager(cfg.Server.StatePath("quotas.json"), 5*time.Second),
		transport:  transport,
	}

	gw.updateRoutes(cfg)
	return gw
}

// SetQuotaManager allows injecting a customized quota manager (useful in tests).
func (gw *Gateway) SetQuotaManager(qm *quota.Manager) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.quotaMgr != nil {
		gw.quotaMgr.Close()
	}
	gw.quotaMgr = qm
}

// Close gracefully terminates background managers.
func (gw *Gateway) Close() {
	if gw.limiterMgr != nil {
		gw.limiterMgr.Close()
	}
	if gw.quotaMgr != nil {
		gw.quotaMgr.Close()
	}
}

// AttachConfigManager hooks the gateway to the config manager so configuration updates
// trigger dynamic route rebuilding and revoked token invalidation.
func (gw *Gateway) AttachConfigManager(mgr *config.Manager) {
	mgr.OnReload(func(oldCfg, newCfg *config.Config) {
		gw.updateRoutes(newCfg)
	})
}

// updateRoutes compiles config routes into sorted route entries.
func (gw *Gateway) updateRoutes(cfg *config.Config) {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	gw.authHeader = cfg.Server.AuthHeader
	if gw.authHeader == "" {
		gw.authHeader = config.DefaultAuthHeader
	}

	// Captured once, by value: the Rewrite closure below runs on the request path
	// long after this lock is released, so reading gw.authHeader from inside it
	// would race with the next reload. Capturing also pins the header a request
	// was authenticated with, instead of whatever a concurrent reload installed.
	authHeader := gw.authHeader
	gw.cors = newCORSPolicy(cfg.Server.ParsedCORSOrigins)

	if gw.credentials == nil {
		gw.credentials = make(map[string]credential.Source)
	}
	// A reload rebuilds routes, but an OAuth source holds a live access token and
	// a possibly-rotated refresh token. Rebuilding it would throw both away and
	// force a needless renewal, so an unchanged credential keeps its source.
	sources := make(map[string]credential.Source, len(cfg.Routes))

	entries := make([]routeEntry, 0, len(cfg.Routes))

	for _, r := range cfg.Routes {
		target := r.ParsedTarget
		forwardHeader := r.ParsedForwardHeaders

		var credSource credential.Source
		if r.Credential.Enabled() {
			if existing, found := gw.credentials[r.PathPrefix]; found {
				credSource = existing
			} else if gw.credentialStore == nil {
				// No store installed yet: SetCredentialStore rebuilds the routes.
				continue
			} else if src, err := buildCredential(r, gw.credentialStore); err != nil {
				logging.Error("route disabled: its credential could not be built",
					"route", r.PathPrefix, "err", err)
				continue
			} else {
				credSource = src
			}
			sources[r.PathPrefix] = credSource
		}
		if target == nil {
			var err error
			target, err = url.Parse(r.TargetURL)
			if err != nil {
				continue
			}
		}

		strip := r.ShouldStripPrefix()
		prefix := r.PathPrefix
		injectHeaders := make(map[string]string, len(r.InjectHeaders))
		for k, v := range r.InjectHeaders {
			injectHeaders[k] = v
		}

		// Configure httputil.ReverseProxy with zero-buffer streaming (SSE friendly)
		proxy := &httputil.ReverseProxy{
			Transport:      gw.transport,
			FlushInterval:  -1, // -1 means flush immediately after each write to client
			ModifyResponse: stripUpstreamCORS,
			Rewrite: func(pr *httputil.ProxyRequest) {
				// Initialize outbound request targeting remote host
				pr.SetURL(target)

				// Adjust target path
				if strip {
					relPath := strings.TrimPrefix(pr.In.URL.Path, prefix)
					if !strings.HasPrefix(relPath, "/") {
						relPath = "/" + relPath
					}
					pr.Out.URL.Path = singleJoiningSlash(target.Path, relPath)
				} else {
					pr.Out.URL.Path = singleJoiningSlash(target.Path, pr.In.URL.Path)
				}

				// Preserve raw query parameters
				pr.Out.URL.RawQuery = pr.In.URL.RawQuery

				// Drop every caller header outside the allowlist. This covers the
				// client's own credential, which authenticates it to Gatekey and has
				// no business reaching the provider, and headers that would steer the
				// provider itself, such as OpenAI-Organization.
				for name := range pr.Out.Header {
					if _, allowed := forwardHeader[name]; !allowed {
						pr.Out.Header.Del(name)
					}
				}
				// Removed again unconditionally: a forward_headers entry naming the
				// auth header would otherwise hand the caller's own credential to the
				// provider. This one is never negotiable.
				pr.Out.Header.Del(authHeader)

				// A renewing credential resolved for this request, if the route has one.
				if pair, ok := pr.In.Context().Value(credentialHeaderKey{}).([2]string); ok {
					pr.Out.Header.Set(pair[0], pair[1])
				}

				// Inject configured secret upstream headers
				for k, v := range injectHeaders {
					pr.Out.Header.Set(k, v)
				}

				// Set Host header to the upstream server
				pr.Out.Host = target.Host
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					limitMB := maxBytesErr.Limit / (1024 * 1024)
					logging.Info("payload too large", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "limit_mb", limitMB)
					apierror.NewPayloadTooLarge(limitMB).Write(w)
					return
				}

				logging.Error("upstream failure", "method", r.Method, "path", r.URL.Path, "target", target.String(), "err", err)
				apierror.ErrBadGateway.Write(w)
			},
		}

		entries = append(entries, routeEntry{
			pathPrefix:    prefix,
			targetURL:     target,
			stripPrefix:   strip,
			injectHeaders: injectHeaders,
			rateLimit:     r.RateLimit,
			quota:         r.Quota,
			forwardHeader: r.ParsedForwardHeaders,
			credential:    credSource,
			maxBodyBytes:  r.MaxBodyBytes(&cfg.Server),
			reqTimeout:    r.ParsedRequestTimeout,
			proxy:         proxy,
		})
	}

	// Sort routes by path prefix length descending for longest-prefix-match
	sort.Slice(entries, func(i, j int) bool {
		return len(entries[i].pathPrefix) > len(entries[j].pathPrefix)
	})

	gw.routes = entries
	gw.credentials = sources
	gw.lastCfg = cfg
	gw.maxBodyBytes = cfg.Server.MaxBodyBytes()
}

type responseObserver struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	usage        quota.Accumulator
}

func (o *responseObserver) WriteHeader(code int) {
	o.statusCode = code
	o.ResponseWriter.WriteHeader(code)
}

func (o *responseObserver) Write(b []byte) (int, error) {
	n, err := o.ResponseWriter.Write(b)
	o.bytesWritten += int64(n)

	// Observe the usage block on the fly, after the bytes have already reached the
	// client, so token accounting never delays a stream.
	o.usage.Observe(b[:n])

	return n, err
}

// Flush pushes a streamed event to the client at once. It goes through
// http.ResponseController so that it reaches the connection through any wrapper
// in between, rather than silently stopping at the first one that does not
// itself implement http.Flusher.
func (o *responseObserver) Flush() {
	_ = http.NewResponseController(o.ResponseWriter).Flush()
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (o *responseObserver) Unwrap() http.ResponseWriter { return o.ResponseWriter }

// ServeHTTP inspects the path, validates the client token, and proxies the request.
func (gw *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	obs := &responseObserver{ResponseWriter: w, statusCode: http.StatusOK}
	var matchedRoute routeEntry
	var found bool
	var matchedPrefix string
	var clientToken string

	// identity keys rate limiting, quotas and telemetry. It is the install ID from
	// the signed token, which survives refresh so a rotating token does not reset
	// the budget it has spent. It stays empty until the caller is authenticated,
	// which also keeps unauthenticated strings out of the per-install maps.
	var identity string

	defer func() {
		gw.mu.RLock()
		col := gw.metricsCollector
		quotaMgr := gw.quotaMgr
		gw.mu.RUnlock()

		if col != nil {
			col.Record(metrics.Event{
				Timestamp:   start,
				RoutePrefix: matchedPrefix,
				InstallID:   identity,
				StatusCode:  obs.statusCode,
				Duration:    time.Since(start),
				BytesSent:   obs.bytesWritten,
			})
		}

		if quotaMgr != nil && matchedPrefix != "" && identity != "" {
			if prompt, completion, ok := obs.usage.Result(); ok {
				quotaMgr.Record(matchedPrefix, identity, obs.usage.Model(), prompt, completion, matchedRoute.quota)
			}
		}
	}()

	gw.mu.RLock()
	authHeader := gw.authHeader
	issuer := gw.issuer
	matchedRoute, found = gw.findRoute(r.URL.Path)
	gw.mu.RUnlock()

	if !found {
		logging.Debug("no route matches", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		apierror.ErrRouteNotFound.Write(obs)
		return
	}

	matchedPrefix = matchedRoute.pathPrefix

	// Unreachable through config, which requires a signing key, but a Gateway can
	// still be constructed without an issuer in code. Fail loudly rather than
	// panicking into the recovery middleware, and never fail open.
	if issuer == nil {
		logging.Error("no token issuer configured, refusing every request")
		apierror.ErrInternal.Write(obs)
		return
	}

	// Extract and validate client token
	clientToken = r.Header.Get(authHeader)
	if clientToken == "" {
		logging.Info("missing credential", "header", authHeader, "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		apierror.ErrMissingToken.Write(obs)
		return
	}

	// One credential, one check: a valid signature, an unexpired deadline, a
	// matching route and an install that has not been revoked. No cache sits in
	// front of it -- recomputing the MAC costs about a microsecond, and a cached
	// verdict outliving the token it approved would silently extend it.
	claims, err := issuer.VerifyAccess(clientToken, matchedRoute.pathPrefix)
	if err != nil {
		logging.Info("token rejected", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "reason", err)
		apierror.ErrInvalidToken.Write(obs)
		return
	}
	identity = claims.InstallID

	// Rate Limit Check
	if matchedRoute.rateLimit.RequestsPerMinute > 0 {
		limRes := gw.limiterMgr.Allow(matchedRoute.pathPrefix, identity, matchedRoute.rateLimit.RequestsPerMinute, matchedRoute.rateLimit.Burst)
		if !limRes.Allowed {
			logging.Info("rate limit exceeded", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "retry_after", limRes.RetryAfter.String())
			retrySec := int(math.Ceil(limRes.RetryAfter.Seconds()))
			obs.Header().Set("X-RateLimit-Limit", strconv.Itoa(limRes.Limit))
			obs.Header().Set("X-RateLimit-Remaining", "0")
			apierror.NewRateLimitExceeded(limRes.Limit, retrySec).Write(obs)
			return
		}
		// Set telemetry headers on allowed requests
		obs.Header().Set("X-RateLimit-Limit", strconv.Itoa(limRes.Limit))
		obs.Header().Set("X-RateLimit-Remaining", strconv.Itoa(limRes.Remaining))
	}

	// Quota & Budget Check
	if matchedRoute.quota.Enabled() {
		allowed, currentUsage, apiErr := gw.quotaMgr.Check(matchedRoute.pathPrefix, identity, matchedRoute.quota)
		if !allowed && apiErr != nil {
			logging.Info("quota exceeded", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "detail", apiErr.Message)
			if matchedRoute.quota.MaxTokens > 0 {
				obs.Header().Set("X-Quota-Tokens-Limit", strconv.FormatUint(matchedRoute.quota.MaxTokens, 10))
				obs.Header().Set("X-Quota-Tokens-Used", strconv.FormatUint(currentUsage.TotalTokens, 10))
			}
			if matchedRoute.quota.MaxBudgetUSD > 0 {
				obs.Header().Set("X-Quota-Budget-Limit", fmt.Sprintf("%.2f", matchedRoute.quota.MaxBudgetUSD))
				obs.Header().Set("X-Quota-Budget-Used", fmt.Sprintf("%.4f", currentUsage.TotalCostUSD))
			}
			apiErr.Write(obs)
			return
		}
		// Set telemetry headers on allowed requests
		if matchedRoute.quota.MaxTokens > 0 {
			obs.Header().Set("X-Quota-Tokens-Limit", strconv.FormatUint(matchedRoute.quota.MaxTokens, 10))
			obs.Header().Set("X-Quota-Tokens-Used", strconv.FormatUint(currentUsage.TotalTokens, 10))
		}
		if matchedRoute.quota.MaxBudgetUSD > 0 {
			obs.Header().Set("X-Quota-Budget-Limit", fmt.Sprintf("%.2f", matchedRoute.quota.MaxBudgetUSD))
			obs.Header().Set("X-Quota-Budget-Used", fmt.Sprintf("%.4f", currentUsage.TotalCostUSD))
		}
	}

	// Token is authorized and within rate limit -> enforce body size limit
	if matchedRoute.maxBodyBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(obs, r.Body, matchedRoute.maxBodyBytes)
	}

	// Resolve the upstream credential before handing over to the proxy, so a
	// renewal failure becomes a clear error here instead of an opaque provider
	// rejection later. The common path is a cached read.
	if matchedRoute.credential != nil {
		name, value, err := matchedRoute.credential.Header(r.Context())
		if err != nil {
			if errors.Is(err, credential.ErrReauthRequired) {
				logging.Error("upstream credential rejected, re-authorisation required",
					"route", matchedPrefix, "err", err)
				apiErr := apierror.NewReauthRequired(matchedPrefix)
				apiErr.Write(obs)
				return
			}
			logging.Error("could not renew the upstream credential", "route", matchedPrefix, "err", err)
			apiErr := apierror.NewCredentialRefreshFailed(matchedPrefix)
			apiErr.Write(obs)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), credentialHeaderKey{}, [2]string{name, value}))
	}

	// Absolute ceiling on the exchange, streaming included. It is the only thing
	// that catches an upstream stalling after it has already sent its headers.
	if matchedRoute.reqTimeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), matchedRoute.reqTimeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	matchedRoute.proxy.ServeHTTP(obs, r)
}

// buildCredential turns a route's credential block into a live source.
func buildCredential(r config.RouteConfig, store credential.Store) (credential.Source, error) {
	refreshToken := r.Credential.RefreshToken

	// A persisted token supersedes the configured one: it is the rotated value,
	// and by now the provider has invalidated whatever the file still says.
	if fs, ok := store.(*credential.FileStore); ok {
		if stored, found := fs.Get(r.PathPrefix); found && stored != "" {
			refreshToken = stored
		}
	}

	return credential.NewOAuth(credential.OAuthConfig{
		Name:         r.PathPrefix,
		TokenURL:     r.Credential.TokenURL,
		ClientID:     r.Credential.ClientID,
		ClientSecret: r.Credential.ClientSecret,
		RefreshToken: refreshToken,
		Scope:        r.Credential.Scope,
		Header:       r.Credential.Header,
		Prefix:       r.Credential.Prefix,
	}, store, nil)
}

func (gw *Gateway) findRoute(path string) (routeEntry, bool) {
	for _, route := range gw.routes {
		if strings.HasPrefix(path, route.pathPrefix) {
			// Ensure boundary matches either exact path or path prefix followed by '/'
			if len(path) == len(route.pathPrefix) || path[len(route.pathPrefix)] == '/' {
				return route, true
			}
		}
	}
	return routeEntry{}, false
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
