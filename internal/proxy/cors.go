package proxy

import (
	"net/http"
	"strings"
)

// corsPreflightMaxAge lets a browser reuse a preflight answer for ten minutes.
// Without it every call from a web page costs an extra round trip first.
const corsPreflightMaxAge = "600"

// corsMethods covers every method a provider API is called with.
const corsMethods = "GET, POST, PUT, PATCH, DELETE"

// corsPolicy decides which browser origins may call Gatekey. A nil policy means
// CORS is off, and no CORS header is ever sent.
type corsPolicy struct {
	anyOrigin bool
	origins   map[string]struct{}
}

func newCORSPolicy(origins map[string]struct{}) *corsPolicy {
	if len(origins) == 0 {
		return nil
	}
	_, anyOrigin := origins["*"]
	return &corsPolicy{anyOrigin: anyOrigin, origins: origins}
}

func (p *corsPolicy) allows(origin string) bool {
	if origin == "" {
		return false
	}
	if p.anyOrigin {
		return true
	}
	_, ok := p.origins[strings.ToLower(origin)]
	return ok
}

// CORS lets the configured web origins call next from a browser.
//
// It is applied to the endpoints a client application calls: the proxied
// routes, /-/refresh and /healthz. The loopback-only endpoints never get it: CORS on
// /metrics would let any page open on the operator's machine read the list of
// installs through the browser, which does run on loopback.
//
// A preflight is answered here, before authentication: the browser sends it
// without the token, and it must never reach the quota, the metrics or the
// provider. The policy is read on every request, so a reload applies at once.
func (gw *Gateway) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gw.mu.RLock()
		policy := gw.cors
		gw.mu.RUnlock()

		if policy == nil {
			next.ServeHTTP(w, r)
			return
		}

		// The answer depends on the Origin, so no cache may serve one origin's
		// answer to another.
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		allowed := policy.allows(origin)

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Add("Vary", "Access-Control-Request-Method, Access-Control-Request-Headers")
			if allowed {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Methods", corsMethods)
				// Provider SDKs send headers of their own (x-stainless-*,
				// anthropic-version...). Allowing what the page asks for is safe:
				// the origin is trusted, and the route's allowlist still decides
				// what reaches the provider.
				if requested := r.Header.Get("Access-Control-Request-Headers"); requested != "" {
					h.Set("Access-Control-Allow-Headers", requested)
				}
				h.Set("Access-Control-Max-Age", corsPreflightMaxAge)
			}
			// A refused origin gets no CORS headers, which is how a browser learns
			// it is refused.
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			// Lets the page read the quota and rate-limit headers, and the
			// provider's own, not only the handful browsers expose by default.
			w.Header().Set("Access-Control-Expose-Headers", "*")
		}
		next.ServeHTTP(w, r)
	})
}

// stripUpstreamCORS removes the provider's CORS headers from its response.
//
// Gatekey alone decides who may call it from a browser. A provider's own
// Access-Control-Allow-Origin would otherwise be added next to Gatekey's, and a
// browser refuses a response carrying two: CORS would break exactly when it is
// switched on. With CORS off, it would let any page read Gatekey's responses.
func stripUpstreamCORS(resp *http.Response) error {
	for name := range resp.Header {
		if strings.HasPrefix(name, "Access-Control-") {
			resp.Header.Del(name)
		}
	}
	return nil
}
