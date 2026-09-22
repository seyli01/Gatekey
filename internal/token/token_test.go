package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testAccessTTL = 15 * time.Minute
const testRefreshTTL = 720 * time.Hour // 30 days

// newTestIssuer returns an Issuer whose clock is driven by the returned pointer,
// so expiry can be exercised without sleeping.
func newTestIssuer(t *testing.T) (*Issuer, *time.Time) {
	t.Helper()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	iss, err := NewIssuer(key, testAccessTTL, testRefreshTTL)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	clock := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	iss.now = func() time.Time { return clock }
	return iss, &clock
}

func TestIssue_RoundTrip(t *testing.T) {
	iss, _ := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if pair.Access == pair.Refresh {
		t.Fatal("access and refresh tokens must differ")
	}
	if !pair.RefreshExpiresAt.After(pair.AccessExpiresAt) {
		t.Fatal("refresh token must outlive the access token")
	}

	claims, err := iss.VerifyAccess(pair.Access, "/openai")
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.InstallID != "install-abc123" {
		t.Errorf("InstallID = %q, want %q", claims.InstallID, "install-abc123")
	}
	if claims.Route != "/openai" {
		t.Errorf("Route = %q, want %q", claims.Route, "/openai")
	}
	if claims.Kind != KindAccess {
		t.Errorf("Kind = %q, want %q", claims.Kind, KindAccess)
	}
}

// An expired access token must be refused even one second past its deadline:
// this bound is the whole reason the access TTL is short.
func TestVerify_AccessExpires(t *testing.T) {
	iss, clock := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	*clock = clock.Add(testAccessTTL - time.Second)
	if _, err := iss.VerifyAccess(pair.Access, "/openai"); err != nil {
		t.Fatalf("token must still be valid one second before expiry: %v", err)
	}

	*clock = clock.Add(2 * time.Second)
	if _, err := iss.VerifyAccess(pair.Access, "/openai"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired past the deadline, got %v", err)
	}

	// The refresh token is untouched by the access token's expiry.
	if _, err := iss.Refresh(pair.Refresh); err != nil {
		t.Fatalf("refresh token must outlive the access token: %v", err)
	}
}

func TestVerify_RefreshExpires(t *testing.T) {
	iss, clock := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	*clock = clock.Add(testRefreshTTL + time.Second)
	if _, err := iss.Refresh(pair.Refresh); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

// Kind confusion is the classic break of a two-token scheme: a long-lived
// refresh token accepted on the proxy path would erase the whole point of a
// short access TTL.
func TestVerify_KindsAreNotInterchangeable(t *testing.T) {
	iss, _ := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := iss.VerifyAccess(pair.Refresh, "/openai"); !errors.Is(err, ErrWrongKind) {
		t.Errorf("refresh token accepted as an access token: %v", err)
	}
	if _, err := iss.Refresh(pair.Access); !errors.Is(err, ErrWrongKind) {
		t.Errorf("access token accepted at the refresh endpoint: %v", err)
	}
}

// A token minted for one route must not reach another, or it would spend a
// budget it was never granted.
func TestVerifyAccess_IsBoundToItsRoute(t *testing.T) {
	iss, _ := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := iss.VerifyAccess(pair.Access, "/anthropic"); !errors.Is(err, ErrWrongRoute) {
		t.Fatalf("expected ErrWrongRoute, got %v", err)
	}
}

// Rewriting the claims without the key must fail, including the privilege
// escalation an attacker would actually attempt: pushing exp far into the future.
func TestVerify_TamperedPayloadIsRejected(t *testing.T) {
	iss, _ := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	parts := strings.Split(pair.Access, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 token segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshalling payload: %v", err)
	}

	claims.ExpiresAt = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	claims.Route = "/anthropic"
	forged, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshalling forged claims: %v", err)
	}

	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]
	if _, err := iss.Verify(tampered, KindAccess); !errors.Is(err, ErrSignature) {
		t.Fatalf("expected ErrSignature on a rewritten payload, got %v", err)
	}
}

func TestVerify_ForeignKeyIsRejected(t *testing.T) {
	iss, _ := newTestIssuer(t)
	other, _ := newTestIssuer(t)

	pair, err := other.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := iss.Verify(pair.Access, KindAccess); !errors.Is(err, ErrSignature) {
		t.Fatalf("expected ErrSignature for a token signed by another key, got %v", err)
	}
}

// The signature covers the version prefix, so the scheme can be revised without
// an old or forged prefix sliding through.
func TestVerify_MalformedInputs(t *testing.T) {
	iss, _ := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.Split(pair.Access, ".")

	cases := map[string]string{
		"empty":             "",
		"no separator":      "gk1",
		"missing signature": parts[0] + "." + parts[1],
		"unknown scheme":    "gk2." + parts[1] + "." + parts[2],
		"no scheme":         parts[1] + "." + parts[2],
		"bad base64 sig":    parts[0] + "." + parts[1] + ".!!!not-base64!!!",
		"empty payload":     "gk1..",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := iss.Verify(raw, KindAccess); err == nil {
				t.Fatalf("expected a verification failure for %q", raw)
			}
		})
	}
}

// Revocation is the only state the design keeps, so it has to cut both tokens of
// an install at once and take effect on the very next request.
func TestDenylist_RevokesEveryTokenOfAnInstall(t *testing.T) {
	iss, _ := newTestIssuer(t)

	revoked, err := iss.Issue("install-stolen", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	kept, err := iss.Issue("install-legit", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	iss.SetDenylist(NewDenylist([]string{"install-stolen"}))

	if _, err := iss.VerifyAccess(revoked.Access, "/openai"); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked access token still accepted: %v", err)
	}
	if _, err := iss.Refresh(revoked.Refresh); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked refresh token still accepted: %v", err)
	}
	if _, err := iss.VerifyAccess(kept.Access, "/openai"); err != nil {
		t.Errorf("unrelated install must keep working: %v", err)
	}
}

func TestDenylist_NilRevokesNothing(t *testing.T) {
	var d *Denylist
	if d.Contains("install-abc123") {
		t.Fatal("the nil denylist must revoke nothing")
	}
}

// Refreshing yields a usable access token while leaving the refresh token in
// place, since the design deliberately does not rotate it.
func TestRefresh_YieldsUsableAccessTokenAndKeepsRefreshValid(t *testing.T) {
	iss, clock := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	*clock = clock.Add(testAccessTTL + time.Second)

	grant, err := iss.Refresh(pair.Refresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if grant.Access == pair.Access {
		t.Fatal("refresh must mint a new access token")
	}
	if !grant.ExpiresAt.Equal(clock.Add(testAccessTTL)) {
		t.Errorf("ExpiresAt = %v, want %v", grant.ExpiresAt, clock.Add(testAccessTTL))
	}

	claims, err := iss.VerifyAccess(grant.Access, "/openai")
	if err != nil {
		t.Fatalf("VerifyAccess on refreshed token: %v", err)
	}
	// The install ID survives rotation: it is what quotas are keyed on, so a
	// refresh must not reset the budget.
	if claims.InstallID != "install-abc123" {
		t.Errorf("InstallID = %q, want %q", claims.InstallID, "install-abc123")
	}

	*clock = clock.Add(testAccessTTL + time.Second)
	if _, err := iss.Refresh(pair.Refresh); err != nil {
		t.Fatalf("the same refresh token must stay usable: %v", err)
	}
}

func TestNewIssuer_RejectsUnsafeParameters(t *testing.T) {
	strong, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cases := []struct {
		name       string
		key        []byte
		accessTTL  time.Duration
		refreshTTL time.Duration
	}{
		{"nil key", nil, testAccessTTL, testRefreshTTL},
		{"short key", []byte("too-short"), testAccessTTL, testRefreshTTL},
		{"zero access TTL", strong, 0, testRefreshTTL},
		{"negative access TTL", strong, -time.Minute, testRefreshTTL},
		{"refresh shorter than access", strong, testAccessTTL, time.Minute},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewIssuer(tc.key, tc.accessTTL, tc.refreshTTL); err == nil {
				t.Fatal("expected NewIssuer to reject these parameters")
			}
		})
	}
}

func TestIssue_RejectsEmptyIdentifiers(t *testing.T) {
	iss, _ := newTestIssuer(t)

	if _, err := iss.Issue("", "/openai"); err == nil {
		t.Error("expected an error for an empty install ID")
	}
	if _, err := iss.Issue("install-abc123", ""); err == nil {
		t.Error("expected an error for an empty route prefix")
	}
}

func TestGenerateKey_IsRandomAndLongEnough(t *testing.T) {
	first, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	second, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if len(first) < MinKeyLen {
		t.Errorf("key length = %d, want at least %d", len(first), MinKeyLen)
	}
	if string(first) == string(second) {
		t.Fatal("two generated keys must not be identical")
	}
}

// NewIssuer copies the key so a caller zeroing its own buffer cannot silently
// break every signature.
func TestNewIssuer_CopiesTheKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	iss, err := NewIssuer(key, testAccessTTL, testRefreshTTL)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for i := range key {
		key[i] = 0
	}

	if _, err := iss.VerifyAccess(pair.Access, "/openai"); err != nil {
		t.Fatalf("issuer must be unaffected by the caller's buffer: %v", err)
	}
}

func TestIssuer_ConcurrentUse(t *testing.T) {
	iss, _ := newTestIssuer(t)

	pair, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	done := make(chan struct{})
	// A reload swapping the denylist must not race verification on the hot path.
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			iss.SetDenylist(NewDenylist([]string{"install-other"}))
		}
	}()

	for i := 0; i < 200; i++ {
		if _, err := iss.VerifyAccess(pair.Access, "/openai"); err != nil {
			t.Errorf("VerifyAccess during reload: %v", err)
			break
		}
	}
	<-done
}

// Claims are otherwise a pure function of install, route and the current second,
// so without a nonce two tokens minted in the same second would be identical and
// a refresh would hand back the very string it replaces.
func TestIssue_TokensAreUniqueWithinTheSameSecond(t *testing.T) {
	iss, _ := newTestIssuer(t) // frozen clock: every call shares one timestamp

	first, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	second, err := iss.Issue("install-abc123", "/openai")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	grant, err := iss.Refresh(first.Refresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	seen := map[string]string{
		first.Access:   "first access",
		second.Access:  "second access",
		first.Refresh:  "first refresh",
		second.Refresh: "second refresh",
		grant.Access:   "renewed access",
	}
	if len(seen) != 5 {
		t.Fatalf("expected 5 distinct tokens, got %d", len(seen))
	}

	// Uniqueness must not come at the cost of validity.
	for raw, label := range seen {
		kind := KindAccess
		if strings.Contains(label, "refresh") {
			kind = KindRefresh
		}
		if _, err := iss.Verify(raw, kind); err != nil {
			t.Errorf("%s does not verify: %v", label, err)
		}
	}
}

// A caller with nowhere to run a refresh loop takes one long-lived token. It must
// still be an ordinary signed token: bound to an install, and revocable.
func TestIssueWithTTL(t *testing.T) {
	iss, clock := newTestIssuer(t)

	const tenYears = 87600 * time.Hour
	pair, err := iss.IssueWithTTL("cron-backend", "/openai", tenYears)
	if err != nil {
		t.Fatalf("IssueWithTTL: %v", err)
	}

	if got := pair.AccessExpiresAt.Sub(*clock); got != tenYears {
		t.Errorf("access lifetime = %v, want %v", got, tenYears)
	}
	// The refresh token must not die before the access token it would renew.
	if pair.RefreshExpiresAt.Before(pair.AccessExpiresAt) {
		t.Error("refresh token expires before the access token")
	}

	*clock = clock.Add(365 * 24 * time.Hour)
	claims, err := iss.VerifyAccess(pair.Access, "/openai")
	if err != nil {
		t.Fatalf("still valid a year later: %v", err)
	}
	if claims.InstallID != "cron-backend" {
		t.Errorf("InstallID = %q", claims.InstallID)
	}

	// Revocation still reaches it, which a static token never allowed.
	iss.SetDenylist(NewDenylist([]string{"cron-backend"}))
	if _, err := iss.VerifyAccess(pair.Access, "/openai"); !errors.Is(err, ErrRevoked) {
		t.Errorf("a long-lived token must stay revocable, got %v", err)
	}
}

func TestIssueWithTTL_RejectsNonPositiveLifetime(t *testing.T) {
	iss, _ := newTestIssuer(t)
	if _, err := iss.IssueWithTTL("install-abc", "/openai", 0); err == nil {
		t.Error("expected a zero lifetime to be refused")
	}
}
