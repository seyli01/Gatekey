package credential

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memStore struct {
	mu     sync.Mutex
	saved  map[string]string
	failed error
}

func newMemStore() *memStore { return &memStore{saved: map[string]string{}} }

func (m *memStore) Save(name, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed != nil {
		return m.failed
	}
	m.saved[name] = token
	return nil
}

func (m *memStore) get(name string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saved[name]
}

func newOAuth(t *testing.T, tokenURL string, store Store) (*OAuth, *time.Time) {
	t.Helper()
	src, err := NewOAuth(OAuthConfig{
		Name: "/claude", TokenURL: tokenURL, ClientID: "cid", RefreshToken: "refresh-v1",
	}, store, nil)
	if err != nil {
		t.Fatalf("NewOAuth: %v", err)
	}
	clock := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return clock }
	return src, &clock
}

func TestOAuth_RenewsAndCaches(t *testing.T) {
	var calls int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600,"token_type":"Bearer"}`, n)
	}))
	defer server.Close()

	src, clock := newOAuth(t, server.URL, newMemStore())

	name, value, err := src.Header(context.Background())
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	if name != "Authorization" || value != "Bearer tok-1" {
		t.Errorf("got %s: %q", name, value)
	}

	// A second call inside the lifetime must not touch the provider.
	if _, _, err := src.Header(context.Background()); err != nil {
		t.Fatalf("Header: %v", err)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("provider called %d times, want 1: the token was not cached", got)
	}

	// Renewal happens before expiry, not at it: a token handed out at the
	// deadline would die in the middle of the request carrying it.
	*clock = clock.Add(3600*time.Second - renewSkew + time.Second)
	if _, value, _ = src.Header(context.Background()); value != "Bearer tok-2" {
		t.Errorf("value = %q, want the renewed token", value)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Errorf("provider called %d times, want 2", got)
	}
}

// Providers invalidate the old refresh token when they rotate it. Failing to
// persist the new one works perfectly until the next restart, and then locks the
// operator out for good.
func TestOAuth_PersistsRotatedRefreshToken(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.Form.Get("refresh_token")
		fmt.Fprint(w, `{"access_token":"a","refresh_token":"refresh-v2","expires_in":3600}`)
	}))
	defer server.Close()

	store := newMemStore()
	src, clock := newOAuth(t, server.URL, store)

	if _, _, err := src.Header(context.Background()); err != nil {
		t.Fatalf("Header: %v", err)
	}
	if got != "refresh-v1" {
		t.Errorf("first renewal sent %q, want refresh-v1", got)
	}
	if saved := store.get("/claude"); saved != "refresh-v2" {
		t.Fatalf("store holds %q, want the rotated refresh-v2", saved)
	}

	// The next renewal must present the rotated token, not the configured one.
	*clock = clock.Add(2 * time.Hour)
	if _, _, err := src.Header(context.Background()); err != nil {
		t.Fatalf("Header: %v", err)
	}
	if got != "refresh-v2" {
		t.Errorf("second renewal sent %q, want the rotated refresh-v2", got)
	}
}

// If the rotated token cannot be persisted the renewal must fail, rather than
// succeed in memory and strand the operator after the next restart.
func TestOAuth_FailsWhenRotationCannotBePersisted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"a","refresh_token":"refresh-v2","expires_in":3600}`)
	}))
	defer server.Close()

	store := newMemStore()
	store.failed = errors.New("disk full")
	src, _ := newOAuth(t, server.URL, store)

	if _, _, err := src.Header(context.Background()); !errors.Is(err, ErrRefreshFailed) {
		t.Fatalf("err = %v, want ErrRefreshFailed", err)
	}
}

// A rejected grant needs a human. Reporting it as transient would have callers
// retrying forever against something that can never succeed.
func TestOAuth_RejectedGrantNeedsReauth(t *testing.T) {
	cases := map[string]func(http.ResponseWriter){
		"400 invalid_grant": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
		},
		"401": func(w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized) },
	}
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				respond(w)
			}))
			defer server.Close()

			src, _ := newOAuth(t, server.URL, newMemStore())
			if _, _, err := src.Header(context.Background()); !errors.Is(err, ErrReauthRequired) {
				t.Errorf("err = %v, want ErrReauthRequired", err)
			}
		})
	}
}

func TestOAuth_TransientFailuresAreNotFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	src, _ := newOAuth(t, server.URL, newMemStore())
	err := errors.New("")
	if _, _, err = src.Header(context.Background()); !errors.Is(err, ErrRefreshFailed) {
		t.Errorf("err = %v, want ErrRefreshFailed", err)
	}
	if errors.Is(err, ErrReauthRequired) {
		t.Error("a 500 must not be reported as needing re-authorisation")
	}
}

// At expiry every in-flight request wants a token at once. They must produce one
// call to the provider, not one each -- and with a rotating refresh token, a
// stampede would burn the grant.
func TestOAuth_ConcurrentRenewalCallsProviderOnce(t *testing.T) {
	var calls int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		time.Sleep(20 * time.Millisecond) // widen the window a stampede would exploit
		fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
	}))
	defer server.Close()

	src, _ := newOAuth(t, server.URL, newMemStore())

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := src.Header(context.Background()); err != nil {
				t.Errorf("Header: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("provider called %d times for 50 concurrent requests, want 1", got)
	}
}

func TestNewOAuth_RequiresItsDependencies(t *testing.T) {
	cases := map[string]OAuthConfig{
		"no token URL":     {RefreshToken: "r"},
		"no refresh token": {TokenURL: "https://example.com/token"},
	}
	for name, cfg := range cases {
		if _, err := NewOAuth(cfg, newMemStore(), nil); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// The store is required, not optional: see the Store doc comment.
	if _, err := NewOAuth(OAuthConfig{TokenURL: "https://x/token", RefreshToken: "r"}, nil, nil); err == nil {
		t.Error("expected a missing store to be refused")
	}
}

func TestFileStore_RoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds", "credentials.json")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, found := store.Get("/claude"); found {
		t.Error("an empty store must report nothing")
	}
	if err := store.Save("/claude", "refresh-v2"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if got, found := reopened.Get("/claude"); !found || got != "refresh-v2" {
		t.Errorf("after restart: got %q (%v), want refresh-v2", got, found)
	}

	// The file holds provider credentials.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o, want 600", perm)
	}
}

// Renewal must scale with the token's lifetime, never with traffic. A source
// that called the provider per request would rate-limit the operator's own
// account and, with a rotating refresh token, burn the grant.
func TestOAuth_CallsScaleWithLifetimeNotTraffic(t *testing.T) {
	var calls int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
	}))
	defer server.Close()

	src, clock := newOAuth(t, server.URL, newMemStore())

	// Three hours of traffic, a thousand requests per hour.
	for hour := 0; hour < 3; hour++ {
		for i := 0; i < 1000; i++ {
			if _, _, err := src.Header(context.Background()); err != nil {
				t.Fatalf("Header: %v", err)
			}
			*clock = clock.Add(3600 * time.Millisecond) // 3000 ticks ≈ 3h
		}
	}

	// Renewal is driven by the clock, not by traffic. A 3600s token is only used
	// for 3540s because of renewSkew, so 10800 seconds of traffic needs one
	// initial fetch plus three renewals.
	const want = 1 + 10800/(3600-60)
	if got := atomic.LoadInt64(&calls); got != want {
		t.Errorf("provider called %d times for 3000 requests over 3 hours, want %d", got, want)
	}
}
